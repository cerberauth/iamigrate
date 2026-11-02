package cognito

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
)

// Name is the connector's identifier, as used for --target.
const Name = "cognito"

// Connector is the AWS Cognito user pool TargetConnector.
type Connector struct {
	Client *Client
}

// New returns a Cognito connector using client.
func New(client *Client) *Connector {
	return &Connector{Client: client}
}

func (*Connector) Name() string { return Name }

// Capabilities declares Cognito's import support: no password hash, of any
// algorithm, and no second factor with an existing secret. Cognito can't
// take a user ID (a user's sub is generated), has no organizations or roles
// to import, and updates a user it has with AdminUpdateUserAttributes.
func (*Connector) Capabilities() connector.Capabilities {
	return connector.Capabilities{
		NoPasswords:    true,
		SupportsUpsert: true,
		// The user is created under one of the three; the others are
		// attributes.
		PrimaryIdentifiers: []cmf.Identifier{cmf.IdentifierEmail, cmf.IdentifierUsername, cmf.IdentifierPhone},
	}
}

// Import creates one Cognito user per CMF user with AdminCreateUser, without
// the invitation message. A user is created without a password, which leaves
// it in FORCE_CHANGE_PASSWORD, a state "forgot password" doesn't work in; so
// it is given a random permanent one nobody knows, to be CONFIRMED, and a
// blocked user is disabled. With Upsert, a user the pool already has gets its
// attributes updated instead, and the same two steps if they were left undone.
func (c *Connector) Import(ctx context.Context, r *cmf.Reader, m mapping.Mapping, opts connector.ImportOptions) (connector.ImportReport, error) {
	applier, err := importprep.New(m, c.CheckTargetField, hooks.FromContext(ctx), importprep.WithPrimaryIdentifiers(c.Capabilities().PrimaryIdentifiers))
	if err != nil {
		return connector.ImportReport{}, err
	}
	tr := importprep.NewReader(ctx, r, applier)
	var report connector.ImportReport
	bar := progress.FromContext(ctx)

	for {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		batch, err := tr.ReadBatch()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}

		// The batch's requests are all built before any is sent, for
		// import.payload to see them together.
		var sources []string
		var bodies []any
		var allFlags []userFlags
		var blocked []bool
		for _, p := range batch {
			bar.Add(1)
			req, flags, err := buildUser(p.User, c.Client.UserPoolID)
			if err == nil {
				err = applyFields(&req, p.Fields)
			}
			if err != nil {
				report.Failed = append(report.Failed, connector.ImportError{
					SourceID: p.User.SourceID, Code: "TRANSLATION_ERROR", Message: err.Error(),
				})
				continue
			}
			sources, bodies = append(sources, p.User.SourceID), append(bodies, req)
			allFlags, blocked = append(allFlags, flags), append(blocked, p.User.Blocked)
		}
		if bodies, err = applier.Payloads(ctx, sources, bodies); err != nil {
			return report, err
		}

		for i, source := range sources {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			sub, err := c.importUser(ctx, bodies[i], blocked[i], opts.Upsert)
			if err != nil {
				if ctx.Err() != nil {
					return report, ctx.Err()
				}
				report.Failed = append(report.Failed, importError(source, err))
				continue
			}

			report.Succeeded = append(report.Succeeded, source)
			if sub != "" {
				report.SetTargetID(source, sub)
			}
			if allFlags[i].requiresPasswordReset {
				report.RequiresPasswordReset = append(report.RequiresPasswordReset, source)
			}
			if allFlags[i].requiresReenrollment {
				report.RequiresReenrollment = append(report.RequiresReenrollment, source)
			}
		}
	}

	report.Skipped = append(report.Skipped, tr.Skipped()...)
	return report, nil
}

// importError turns a failed call into the user's ImportError, coded by the
// exception Cognito answered.
func importError(source string, err error) connector.ImportError {
	code := "REQUEST_ERROR"
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Type != "" {
		code = apiErr.Type
	}
	return connector.ImportError{SourceID: source, Code: code, Message: err.Error()}
}

// importUser creates the user body describes, or with upsert updates it if
// the pool has it, then finishes it: a password if it has none yet, and
// disabled if blocked. It returns the user's sub.
func (c *Connector) importUser(ctx context.Context, body any, blocked, upsert bool) (string, error) {
	// A hook may have replaced the request: read it back as it will be sent.
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	var req createUserRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return "", fmt.Errorf("cognito: reading the AdminCreateUser payload: %w", err)
	}

	var created struct {
		User userInfo `json:"User"`
	}
	var user userInfo
	err = c.Client.call(ctx, "AdminCreateUser", body, &created)
	switch {
	case err == nil:
		user = created.User
	case upsert && isCode(err, UsernameExistsCode):
		if user, err = c.getUser(ctx, req.Username); err != nil {
			return "", err
		}
		// Only what differs is sent, so a rerun leaves the attributes that
		// didn't change (an email above all) alone.
		var changed []attribute
		for _, a := range req.UserAttributes {
			if v, ok := user.attr(a.Name); !ok || v != a.Value {
				changed = append(changed, a)
			}
		}
		if len(changed) > 0 {
			update := updateRequest{userKey: c.key(req.Username), UserAttributes: changed}
			if err := c.Client.call(ctx, "AdminUpdateUserAttributes", update, nil); err != nil {
				return "", err
			}
		}
	default:
		return "", err
	}

	if user.UserStatus == statusForceChangePassword {
		pw, err := randomPassword()
		if err != nil {
			return "", fmt.Errorf("cognito: generating a password: %w", err)
		}
		set := setPasswordRequest{userKey: c.key(req.Username), Password: pw, Permanent: true}
		if err := c.Client.call(ctx, "AdminSetUserPassword", set, nil); err != nil {
			return "", fmt.Errorf("setting the password: %w", err)
		}
	}
	if blocked == user.Enabled {
		op := "AdminDisableUser"
		if !blocked {
			op = "AdminEnableUser"
		}
		if err := c.Client.call(ctx, op, c.key(req.Username), nil); err != nil {
			return "", fmt.Errorf("%s: %w", op, err)
		}
	}
	return user.sub(), nil
}

// getUser reads a user by its username (or sub).
func (c *Connector) getUser(ctx context.Context, username string) (userInfo, error) {
	var user userInfo
	err := c.Client.call(ctx, "AdminGetUser", c.key(username), &user)
	return user, err
}

// getBySub reads a user by its sub, with the filter ListUsers takes, which
// works whichever way the pool signs users in. A user it doesn't find is the
// same error AdminGetUser answers.
func (c *Connector) getBySub(ctx context.Context, sub string) (userInfo, error) {
	filter := `sub = "` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(sub) + `"`
	req := listUsersRequest{UserPoolID: c.Client.UserPoolID, Filter: filter, Limit: 1}
	var out struct {
		Users []userInfo `json:"Users"`
	}
	if err := c.Client.call(ctx, "ListUsers", req, &out); err != nil {
		return userInfo{}, err
	}
	if len(out.Users) == 0 {
		return userInfo{}, &APIError{StatusCode: http.StatusBadRequest, Type: "UserNotFoundException", Message: "User does not exist."}
	}
	return out.Users[0], nil
}

// listUsersRequest is a ListUsers body.
type listUsersRequest struct {
	UserPoolID string `json:"UserPoolId"`
	Filter     string `json:"Filter"`
	Limit      int    `json:"Limit"`
}

// userKey addresses a user of a pool, the body of the operations that need
// nothing more: AdminGetUser, AdminEnableUser and AdminDisableUser.
type userKey struct {
	UserPoolID string `json:"UserPoolId"`
	Username   string `json:"Username"`
}

// updateRequest is an AdminUpdateUserAttributes body.
type updateRequest struct {
	userKey
	UserAttributes []attribute `json:"UserAttributes"`
}

// setPasswordRequest is an AdminSetUserPassword body.
type setPasswordRequest struct {
	userKey
	Password  string `json:"Password"`
	Permanent bool   `json:"Permanent"`
}

func (c *Connector) key(username string) userKey {
	return userKey{UserPoolID: c.Client.UserPoolID, Username: username}
}

// isCode reports whether err is the Cognito exception code.
func isCode(err error, code string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Type == code
}

// Verify reconciles every CMF user against the live pool by looking up the
// username it was created under (or its sub, from an import report) with
// AdminGetUser, and comparing whether the user is disabled and its email
// verified.
func (c *Connector) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	return reconcile.Run(ctx, r, c.check)
}

// check looks u up by l's target ID, or by l's identifier, or else by the
// username it is created under.
func (c *Connector) check(ctx context.Context, u cmf.User, l reconcile.Lookup) (reconcile.Found, error) {
	username := l.Identifier
	if username == "" {
		username, _ = login(u)
	}
	if username == "" && l.TargetID == "" {
		return reconcile.Found{NoIdentifier: true}, nil
	}

	var user userInfo
	var err error
	if l.TargetID != "" {
		username = l.TargetID
		user, err = c.getBySub(ctx, l.TargetID)
	} else {
		user, err = c.getUser(ctx, username)
	}
	if err != nil {
		if isCode(err, "UserNotFoundException") {
			return reconcile.Found{Missing: true}, nil
		}
		return reconcile.Found{}, fmt.Errorf("cognito: looking up %s: %w", username, err)
	}

	f := reconcile.Found{Record: user}
	if !user.Enabled != u.Blocked {
		f.Drift = append(f.Drift, "blocked")
	}
	if len(u.Emails) > 0 {
		if v, ok := user.attr(attrEmailVerified); ok && (v == "true") != u.Emails[0].Verified {
			f.Drift = append(f.Drift, "email_verified")
		}
	}
	return f, nil
}
