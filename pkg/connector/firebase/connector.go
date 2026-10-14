package firebase

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
)

const (
	// exportPageSize is the number of accounts requested per page during
	// Export; Firebase caps it at 1000.
	exportPageSize = 1000

	// importBatchSize is the most accounts one accounts:batchCreate request
	// takes.
	importBatchSize = 1000
)

// ExportOptions configures reading accounts out of a Firebase project as a
// source.
type ExportOptions struct {
	connector.BaseExportOptions
	// Scrypt is the project's password hash configuration (console: Users
	// > menu > Password hash parameters). Without it, password hashes are
	// still exported but marked non-portable, since nothing outside
	// Firebase could verify them.
	Scrypt *iamhash.FirebaseScryptConfig
}

// Connector is the Firebase Authentication SourceConnector and
// TargetConnector.
type Connector struct {
	Client *Client
}

// New returns a Firebase connector using client.
func New(client *Client) *Connector {
	return &Connector{Client: client}
}

// Name is the connector's identifier, as used for --source/--target.
const Name = "firebase"

func (*Connector) Name() string { return Name }

// Capabilities declares Firebase's import support: bcrypt and scrypt
// password hashes (its own modified scrypt as well as standard scrypt),
// and SMS second factors, the only kind accounts:batchCreate takes.
// Firebase has no organizations/roles concept.
func (*Connector) Capabilities() connector.Capabilities {
	return connector.Capabilities{
		HashAlgorithms: []cmf.Algorithm{cmf.AlgBcrypt, cmf.AlgScrypt},
		MFATypes:       []cmf.MFAType{cmf.MFASMS},
		SupportsOrgs:   false,
		SupportsRoles:  false,
	}
}

// Export streams every account of the Firebase project into w as CMF
// users, paginating with accounts:batchGet.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	manifest := connector.Manifest{
		HashAlgorithmCounts:  map[cmf.Algorithm]int{},
		NonPortableMFACounts: map[cmf.MFAType]int{},
	}
	opts, ok := eo.(ExportOptions)
	if !ok {
		return manifest, fmt.Errorf("firebase: Export requires firebase.ExportOptions, got %T", eo)
	}
	if opts.Scrypt != nil {
		if err := opts.Scrypt.Validate(); err != nil {
			return manifest, err
		}
	}
	bar := progress.FromContext(ctx)

	pageToken := ""
	for {
		select {
		case <-ctx.Done():
			return manifest, ctx.Err()
		default:
		}

		path := c.Client.projectPath(":batchGet") + "?maxResults=" + strconv.Itoa(exportPageSize)
		if pageToken != "" {
			path += "&nextPageToken=" + url.QueryEscape(pageToken)
		}
		var page struct {
			Users         []account `json:"users"`
			NextPageToken string    `json:"nextPageToken"`
		}
		if err := c.Client.doJSON(ctx, http.MethodGet, path, nil, &page); err != nil {
			return manifest, fmt.Errorf("firebase: listing accounts: %w", err)
		}

		for _, a := range page.Users {
			bar.Add(1)
			u, skipReason := userFromAccount(a, opts.Scrypt, Name)
			if skipReason != "" {
				manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{
					SourceID: a.LocalID, Reason: skipReason,
				})
				continue
			}
			if err := w.WriteUser(u); err != nil {
				return manifest, fmt.Errorf("firebase: writing user %s: %w", u.SourceID, err)
			}
			manifest.RecordCount++
			if u.Password != nil {
				manifest.HashAlgorithmCounts[u.Password.Algorithm]++
			}
			for _, f := range u.MFAFactors {
				if !f.Portable {
					manifest.NonPortableMFACounts[f.Type]++
				}
			}
		}

		pageToken = page.NextPageToken
		if pageToken == "" {
			return manifest, nil
		}
	}
}

// batchCreateRequest is an accounts:batchCreate body. Its embedded hash
// parameters apply to every user in Users.
type batchCreateRequest struct {
	Users          []account `json:"users"`
	AllowOverwrite bool      `json:"allowOverwrite,omitempty"`
	SanityCheck    bool      `json:"sanityCheck"`
	iamhash.FirebaseHashParams
}

// batchCreateResponse lists the entries accounts:batchCreate rejected.
type batchCreateResponse struct {
	Error []struct {
		Index   int    `json:"index"`
		Message string `json:"message"`
	} `json:"error"`
}

// pendingBatch accumulates accounts sharing one hash configuration, with
// the bookkeeping to attribute the response back to CMF users.
type pendingBatch struct {
	params   iamhash.FirebaseHashParams
	accounts []account
	sources  []string
	flags    []userFlags
}

// Import creates the CMF users through accounts:batchCreate. A request can
// only declare one hash algorithm and configuration, so users are grouped
// by theirs and each group is sent in batches of up to 1000.
func (c *Connector) Import(ctx context.Context, r *cmf.Reader, _ mapping.Mapping, opts connector.ImportOptions) (connector.ImportReport, error) {
	var report connector.ImportReport
	bar := progress.FromContext(ctx)

	var order []iamhash.FirebaseHashParams
	batches := map[iamhash.FirebaseHashParams]*pendingBatch{}

	for {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		bar.Add(1)

		a, params, flags, err := buildAccount(u)
		if err != nil {
			report.Failed = append(report.Failed, connector.ImportError{
				SourceID: u.SourceID, Code: "TRANSLATION_ERROR", Message: err.Error(),
			})
			continue
		}

		b, ok := batches[params]
		if !ok {
			b = &pendingBatch{params: params}
			batches[params] = b
			order = append(order, params)
		}
		b.accounts = append(b.accounts, a)
		b.sources = append(b.sources, u.SourceID)
		b.flags = append(b.flags, flags)

		if len(b.accounts) == importBatchSize {
			if err := c.flush(ctx, b, opts.Upsert, &report); err != nil {
				return report, err
			}
			*b = pendingBatch{params: params}
		}
	}

	for _, params := range order {
		if b := batches[params]; len(b.accounts) > 0 {
			if err := c.flush(ctx, b, opts.Upsert, &report); err != nil {
				return report, err
			}
		}
	}
	return report, nil
}

// flush sends one batch and records each of its users as succeeded or
// failed in report. It returns an error only when ctx is done; a failed
// request fails the batch's users and the import carries on.
func (c *Connector) flush(ctx context.Context, b *pendingBatch, upsert bool, report *connector.ImportReport) error {
	req := batchCreateRequest{
		Users:              b.accounts,
		AllowOverwrite:     upsert,
		SanityCheck:        true,
		FirebaseHashParams: b.params,
	}
	var resp batchCreateResponse
	if err := c.Client.doJSON(ctx, http.MethodPost, c.Client.projectPath(":batchCreate"), req, &resp); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, id := range b.sources {
			report.Failed = append(report.Failed, connector.ImportError{
				SourceID: id, Code: "REQUEST_ERROR", Message: err.Error(),
			})
		}
		return nil
	}

	rejected := map[int]string{}
	for _, e := range resp.Error {
		rejected[e.Index] = e.Message
	}
	for i, id := range b.sources {
		if msg, bad := rejected[i]; bad {
			report.Failed = append(report.Failed, connector.ImportError{
				SourceID: id, Code: errorCode(msg), Message: msg,
			})
			continue
		}
		report.Succeeded = append(report.Succeeded, id)
		if b.flags[i].requiresPasswordReset {
			report.RequiresPasswordReset = append(report.RequiresPasswordReset, id)
		}
		if b.flags[i].requiresReenrollment {
			report.RequiresReenrollment = append(report.RequiresReenrollment, id)
		}
	}
	return nil
}

// importErrorCode is the ImportError code for a batchCreate entry error
// whose message doesn't start with an error code.
const importErrorCode = "IMPORT_ERROR"

// errorCodeRE matches the leading UPPER_SNAKE error code some batchCreate
// messages start with, e.g. "DUPLICATE_EMAIL : the email is in use".
var errorCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+\b`)

// errorCode returns the error code a batchCreate entry error starts with.
// Firebase's messages are free-form (the emulator, for one, says "localId
// belongs to an existing account"), so a message without a leading code
// gets the generic importErrorCode rather than a word of its prose.
func errorCode(msg string) string {
	if code := errorCodeRE.FindString(msg); code != "" {
		return code
	}
	return importErrorCode
}

// Verify reconciles every CMF user against the live project by looking up
// their email, else phone number, with accounts:lookup, and comparing
// whether the account is disabled and its email verified.
func (c *Connector) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	var report connector.DiffReport
	bar := progress.FromContext(ctx)

	for {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		bar.Add(1)
		report.SourceCount++

		field, value := loginIdentifier(u)
		if value == "" {
			report.NoIdentifier = append(report.NoIdentifier, u.SourceID)
			continue
		}

		var found struct {
			Users []account `json:"users"`
		}
		body := map[string][]string{field: {value}}
		if err := c.Client.doJSON(ctx, http.MethodPost, c.Client.projectPath(":lookup"), body, &found); err != nil {
			return report, fmt.Errorf("firebase: looking up %s: %w", value, err)
		}
		if len(found.Users) == 0 {
			report.MissingInTarget = append(report.MissingInTarget, u.SourceID)
			continue
		}
		report.TargetCount++

		var drift []string
		if found.Users[0].Disabled != u.Blocked {
			drift = append(drift, "blocked")
		}
		if field == "email" && found.Users[0].EmailVerified != u.Emails[0].Verified {
			drift = append(drift, "email_verified")
		}
		if len(drift) > 0 {
			report.AttributeDrift = append(report.AttributeDrift, connector.DriftEntry{SourceID: u.SourceID, Fields: drift})
		}
	}
	return report, nil
}
