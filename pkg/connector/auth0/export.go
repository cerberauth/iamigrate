package auth0

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/httpx"
	"github.com/cerberauth/iamigrate/pkg/progress"
)

// JSON keys shared by the export, payload and role/organization code.
const (
	keyUserID       = "user_id"
	keyEmail        = "email"
	keyName         = "name"
	keyGivenName    = "given_name"
	keyFamilyName   = "family_name"
	keyNickname     = "nickname"
	keyPicture      = "picture"
	keyAppMetadata  = "app_metadata"
	keyUserMetadata = "user_metadata"
)

// ExportFields are the user profile attributes an export can select, and
// the ones iamigrate knows how to turn into CMF. user_id is always
// exported, as it becomes the CMF source_id.
var ExportFields = []string{
	keyEmail, "email_verified",
	"username",
	"phone_number", "phone_verified",
	keyGivenName, keyFamilyName, keyName, keyNickname, keyPicture,
	"blocked",
	keyAppMetadata, keyUserMetadata,
}

// ExportOptions configures reading users out of an Auth0 tenant as a source.
type ExportOptions struct {
	connector.BaseExportOptions
	// Fields limits the export to some of ExportFields. Empty means all of
	// them. user_id is always included.
	Fields []string
	// ConnectionID limits the export to the users of one connection
	// (con_...). Empty means every connection of the tenant.
	ConnectionID string
	// Limit caps the number of exported users, to try an export on a
	// sample. Zero means no cap.
	Limit int
}

// ValidateExportFields reports an error for any name that isn't one of
// ExportFields (user_id is accepted, as it is always exported).
func ValidateExportFields(fields []string) error {
	for _, f := range fields {
		if f != keyUserID && !slices.Contains(ExportFields, f) {
			return fmt.Errorf("auth0: unknown export field %q (choose from %s)", f, strings.Join(ExportFields, ", "))
		}
	}
	return nil
}

// exportJobRequest is the body of POST /jobs/users-exports.
type exportJobRequest struct {
	ConnectionID string        `json:"connection_id,omitempty"`
	Format       string        `json:"format"`
	Limit        int           `json:"limit,omitempty"`
	Fields       []exportField `json:"fields"`
}

type exportField struct {
	Name string `json:"name"`
}

// exportUser is one line of a JSON users export. Attributes that weren't
// selected, or that a user doesn't have, are simply absent.
type exportUser struct {
	UserID        string         `json:"user_id"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Username      string         `json:"username"`
	PhoneNumber   string         `json:"phone_number"`
	PhoneVerified bool           `json:"phone_verified"`
	GivenName     string         `json:"given_name"`
	FamilyName    string         `json:"family_name"`
	Name          string         `json:"name"`
	Nickname      string         `json:"nickname"`
	Picture       string         `json:"picture"`
	Blocked       bool           `json:"blocked"`
	AppMetadata   map[string]any `json:"app_metadata"`
	UserMetadata  map[string]any `json:"user_metadata"`
}

// userFromExport translates one exported user into CMF. Auth0 never
// exports password hashes through the API, so Password is always nil.
func userFromExport(e exportUser, sourceConnector string) cmf.User {
	u := cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   e.UserID,
		Username:   e.Username,
		Profile: cmf.Profile{
			GivenName:  e.GivenName,
			FamilyName: e.FamilyName,
			Name:       e.Name,
			Nickname:   e.Nickname,
			Picture:    e.Picture,
		},
		Blocked:      e.Blocked,
		AppMetadata:  e.AppMetadata,
		UserMetadata: e.UserMetadata,
		Provenance:   cmf.Provenance{SourceConnector: sourceConnector, ExportedAt: time.Now().UTC()},
	}
	if e.Email != "" {
		u.Emails = []cmf.Contact{{Value: e.Email, Verified: e.EmailVerified, Primary: true}}
	}
	if e.PhoneNumber != "" {
		u.Phones = []cmf.Contact{{Value: e.PhoneNumber, Verified: e.PhoneVerified, Primary: true}}
	}
	return u
}

// Export runs a user export job on the tenant, waits for it, and streams
// its result into w as CMF users: every user of the tenant, whatever their
// connection, with or without a password. The Management API doesn't
// return password hashes, so none are exported (see the export guide for
// how to get them from Auth0 support).
//
// The job is used rather than paging GET /users, which stops at 1000 users.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	manifest := connector.Manifest{}
	opts, ok := eo.(ExportOptions)
	if !ok {
		return manifest, fmt.Errorf("auth0: Export requires auth0.ExportOptions, got %T", eo)
	}
	if err := ValidateExportFields(opts.Fields); err != nil {
		return manifest, err
	}
	if opts.Limit < 0 {
		return manifest, fmt.Errorf("auth0: export limit must not be negative")
	}

	req := exportJobRequest{
		ConnectionID: opts.ConnectionID,
		Format:       "json",
		Limit:        opts.Limit,
		Fields:       []exportField{{Name: keyUserID}},
	}
	fields := opts.Fields
	if len(fields) == 0 {
		fields = ExportFields
	}
	for _, f := range fields {
		if f != keyUserID {
			req.Fields = append(req.Fields, exportField{Name: f})
		}
	}

	var job struct {
		ID string `json:"id"`
	}
	err := retryTransient(ctx, isRateLimited, func() error {
		_, err := c.Client.doJSON(ctx, http.MethodPost, "/jobs/users-exports", req, &job)
		return err
	})
	if err != nil {
		return manifest, fmt.Errorf("auth0: creating export job: %w", err)
	}

	done, err := waitJob(ctx, c.Client, job.ID)
	if err != nil {
		return manifest, err
	}
	if done.Status != "completed" {
		return manifest, fmt.Errorf("auth0: export job %s ended with status %q", job.ID, done.Status)
	}
	if done.Location == "" {
		return manifest, fmt.Errorf("auth0: export job %s completed without a download location", job.ID)
	}

	body, err := download(ctx, done.Location)
	if err != nil {
		return manifest, err
	}
	defer body.Close()

	bar := progress.FromContext(ctx)
	dec := json.NewDecoder(body)
	for {
		var e exportUser
		if err := dec.Decode(&e); err == io.EOF {
			return manifest, nil
		} else if err != nil {
			return manifest, fmt.Errorf("auth0: decoding export result: %w", err)
		}
		bar.Add(1)
		if e.UserID == "" {
			manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{
				SourceID: "", Reason: "no user_id",
			})
			continue
		}
		u := userFromExport(e, Name)
		if err := w.WriteUser(u); err != nil {
			return manifest, fmt.Errorf("auth0: writing user %s: %w", u.SourceID, err)
		}
		manifest.RecordCount++
	}
}

// download opens an export job's result, which Auth0 serves from a signed
// URL that must not receive the Management API token, and which may be
// gzip-compressed. The returned reader yields the plain JSON lines.
func download(ctx context.Context, location string) (io.ReadCloser, error) {
	// No overall timeout: an export can be large, and ctx bounds it.
	hc := &http.Client{Transport: httpx.NewTransport(nil, nil)}

	var resp *http.Response
	err := retryTransient(ctx, isTransient, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return err
		}
		resp, err = hc.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return &APIError{StatusCode: resp.StatusCode, Body: string(b)}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("auth0: downloading export: %w", err)
	}

	br := bufio.NewReader(resp.Body)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("auth0: opening gzip export: %w", err)
		}
		return readCloser{gz, resp.Body}, nil
	}
	return readCloser{br, resp.Body}, nil
}

// readCloser reads from r and closes the underlying body.
type readCloser struct {
	io.Reader
	body io.Closer
}

func (rc readCloser) Close() error { return rc.body.Close() }
