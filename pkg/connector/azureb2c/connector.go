package azureb2c

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/progress"
)

// Name is the connector's identifier, as used for --source.
const Name = "azure-ad-b2c"

// pageSize is the number of users requested per page; Graph caps $top at 999
// for users.
const pageSize = 999

// Sign-in types of a user's identities.
const (
	signInEmail     = "emailAddress"
	signInUsername  = "userName"
	signInFederated = "federated"
)

// keyFederatedIdentities is the app_metadata key holding the social or
// enterprise identity providers a user signs in with, which CMF has no field
// for.
const keyFederatedIdentities = "federated_identities"

// extensionAttribute matches the Graph name of a B2C custom attribute:
// extension_<b2c-extensions-app client ID without hyphens>_<name>.
var extensionAttribute = regexp.MustCompile(`^extension_[0-9a-fA-F]{32}_(\w+)$`)

// ValidateExtensionAttributes reports an error for any name that isn't the
// Graph name of a B2C custom attribute.
func ValidateExtensionAttributes(names []string) error {
	for _, n := range names {
		if !extensionAttribute.MatchString(n) {
			return fmt.Errorf("azure-ad-b2c: %q is not a custom attribute name (expected extension_<app ID without hyphens>_<name>)", n)
		}
	}
	return nil
}

// ExportOptions configures reading users out of a B2C tenant as a source.
type ExportOptions struct {
	connector.BaseExportOptions
	// ExtensionAttributes are the custom attributes to export, by their Graph
	// name (extension_<app ID>_<name>). Graph returns none of them unless
	// asked. Each lands in user_metadata under its own name, without the
	// extension_<app ID>_ prefix.
	ExtensionAttributes []string
	// Filter is an OData $filter expression limiting the exported users,
	// e.g. "creationType eq 'LocalAccount'". Empty means every user.
	Filter string
	// Limit caps the number of exported users, to try an export on a sample.
	// Zero means no cap.
	Limit int
}

// Connector is the Azure AD B2C SourceConnector.
type Connector struct {
	Client *Client
}

// New returns an Azure AD B2C connector using client.
func New(client *Client) *Connector {
	return &Connector{Client: client}
}

func (*Connector) Name() string { return Name }

// graphUser is the part of a Graph user resource an export reads.
type graphUser struct {
	ID                string     `json:"id"`
	AccountEnabled    *bool      `json:"accountEnabled"`
	DisplayName       string     `json:"displayName"`
	GivenName         string     `json:"givenName"`
	Surname           string     `json:"surname"`
	Mail              string     `json:"mail"`
	OtherMails        []string   `json:"otherMails"`
	MobilePhone       string     `json:"mobilePhone"`
	PreferredLanguage string     `json:"preferredLanguage"`
	Identities        []identity `json:"identities"`
}

// identity is one way a user signs in: with a local email address or user
// name (issuer is the tenant), or through a federated identity provider.
type identity struct {
	SignInType       string `json:"signInType"`
	Issuer           string `json:"issuer"`
	IssuerAssignedID string `json:"issuerAssignedId"`
}

// selectFields are the user properties the export asks for; Graph returns
// only a few of them by default.
var selectFields = []string{
	"id", "accountEnabled", "displayName", "givenName", "surname",
	"mail", "otherMails", "mobilePhone", "preferredLanguage", "identities",
}

// usersURL builds the first page's request URL.
func (c *Client) usersURL(opts ExportOptions) string {
	top := pageSize
	if opts.Limit > 0 && opts.Limit < top {
		top = opts.Limit
	}
	q := url.Values{
		"$select": {strings.Join(append(append([]string{}, selectFields...), opts.ExtensionAttributes...), ",")},
		"$top":    {strconv.Itoa(top)},
	}
	if opts.Filter != "" {
		q.Set("$filter", opts.Filter)
	}
	// Graph reads a "+" as a literal plus, not a space.
	return strings.TrimSuffix(c.BaseURL, "/") + "/users?" + strings.ReplaceAll(q.Encode(), "+", "%20")
}

// userFromGraph translates one Graph user into CMF. Graph never returns a
// password hash, so Password is always nil. The second result is why the
// user can't be exported, empty if it can.
func userFromGraph(g graphUser, raw map[string]any, opts ExportOptions, sourceConnector string) (cmf.User, string) {
	u := cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   g.ID,
		Profile: cmf.Profile{
			GivenName:  g.GivenName,
			FamilyName: g.Surname,
			Name:       g.DisplayName,
			Locale:     g.PreferredLanguage,
		},
		Blocked:    g.AccountEnabled != nil && !*g.AccountEnabled,
		Provenance: cmf.Provenance{SourceConnector: sourceConnector, ExportedAt: time.Now().UTC()},
	}

	// Graph doesn't say whether an address was verified, so none is marked
	// so: the target asks the user to confirm it rather than trusting it.
	seen := map[string]bool{}
	addEmail := func(v string) {
		key := strings.ToLower(v)
		if v == "" || seen[key] {
			return
		}
		seen[key] = true
		u.Emails = append(u.Emails, cmf.Contact{Value: v, Primary: len(u.Emails) == 0})
	}
	var federated []any
	for _, id := range g.Identities {
		switch id.SignInType {
		case signInEmail:
			addEmail(id.IssuerAssignedID)
		case signInUsername:
			if u.Username == "" {
				u.Username = id.IssuerAssignedID
			}
		case signInFederated:
			federated = append(federated, map[string]any{"issuer": id.Issuer, "id": id.IssuerAssignedID})
		}
	}
	addEmail(g.Mail)
	for _, m := range g.OtherMails {
		addEmail(m)
	}
	if g.MobilePhone != "" {
		u.Phones = []cmf.Contact{{Value: g.MobilePhone, Primary: true}}
	}

	if len(federated) > 0 {
		u.AppMetadata = map[string]any{keyFederatedIdentities: federated}
	}
	for _, name := range opts.ExtensionAttributes {
		v, ok := raw[name]
		if !ok || v == nil {
			continue
		}
		if u.UserMetadata == nil {
			u.UserMetadata = map[string]any{}
		}
		u.UserMetadata[extensionAttribute.FindStringSubmatch(name)[1]] = v
	}

	if len(u.Emails) == 0 && u.Username == "" && len(u.Phones) == 0 {
		return u, "no email, username, or phone number"
	}
	return u, ""
}

// Export streams every user of the B2C tenant into w as CMF users,
// following Graph's page links. Users are exported without a password,
// since Graph doesn't return password hashes.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	manifest := connector.Manifest{}
	opts, ok := eo.(ExportOptions)
	if !ok {
		return manifest, fmt.Errorf("azure-ad-b2c: Export requires azureb2c.ExportOptions, got %T", eo)
	}
	if err := ValidateExtensionAttributes(opts.ExtensionAttributes); err != nil {
		return manifest, err
	}
	if opts.Limit < 0 {
		return manifest, fmt.Errorf("azure-ad-b2c: export limit must not be negative")
	}
	bar := progress.FromContext(ctx)

	seen := 0
	next := c.Client.usersURL(opts)
	for next != "" {
		if !c.Client.sameHost(next) {
			return manifest, fmt.Errorf("azure-ad-b2c: refusing to follow page link to another host: %s", next)
		}
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := c.Client.getJSON(ctx, next, &page); err != nil {
			return manifest, fmt.Errorf("azure-ad-b2c: listing users: %w", err)
		}

		for _, rawUser := range page.Value {
			if opts.Limit > 0 && seen >= opts.Limit {
				break
			}
			seen++
			bar.Add(1)

			var g graphUser
			if err := json.Unmarshal(rawUser, &g); err != nil {
				return manifest, fmt.Errorf("azure-ad-b2c: decoding user: %w", err)
			}
			var attrs map[string]any
			if len(opts.ExtensionAttributes) > 0 {
				if err := json.Unmarshal(rawUser, &attrs); err != nil {
					return manifest, fmt.Errorf("azure-ad-b2c: decoding user %s: %w", g.ID, err)
				}
			}
			u, skipReason := userFromGraph(g, attrs, opts, Name)
			if g.ID == "" {
				skipReason = "no id"
			}
			if skipReason != "" {
				manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{SourceID: g.ID, Reason: skipReason})
				continue
			}
			if err := w.WriteUser(u); err != nil {
				return manifest, fmt.Errorf("azure-ad-b2c: writing user %s: %w", u.SourceID, err)
			}
			manifest.RecordCount++
		}
		next = page.NextLink
		if opts.Limit > 0 && seen >= opts.Limit {
			break
		}
	}
	return manifest, nil
}
