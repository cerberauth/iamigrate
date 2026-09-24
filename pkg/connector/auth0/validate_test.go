package auth0

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
)

func TestConnectorValidateUser(t *testing.T) {
	strict := &ConnectionConfig{}
	strict.Options.RequiresUsername = true
	strict.Options.Validation.Username = &UsernameValidation{Min: 3, Max: 5}

	tests := []struct {
		name     string
		cc       *ConnectionConfig
		user     cmf.User
		wantRule string // substring of the single expected problem's Rule; "" means no problems
		wantN    int    // expected problem count when > 1
	}{
		{
			name:     "valid user, no connection config",
			user:     cmf.User{SourceID: "u1", Emails: []cmf.Contact{{Value: "a@example.com"}}, Username: "alice"},
			wantRule: "",
		},
		{
			name:     "missing email",
			user:     cmf.User{SourceID: "u2"},
			wantRule: "required (Auth0 bulk import requires an email)",
		},
		{
			name:     "invalid email format",
			user:     cmf.User{SourceID: "u3", Emails: []cmf.Contact{{Value: "not-an-email"}}},
			wantRule: "invalid email format",
		},
		{
			name: "invalid phone format",
			user: cmf.User{
				SourceID: "u4",
				Emails:   []cmf.Contact{{Value: "a@example.com"}},
				Phones:   []cmf.Contact{{Value: "0123456789"}},
			},
			wantRule: "not E.164 format",
		},
		{
			name: "valid phone format",
			user: cmf.User{
				SourceID: "u5",
				Emails:   []cmf.Contact{{Value: "a@example.com"}},
				Phones:   []cmf.Contact{{Value: "+14155552671"}},
			},
			wantRule: "",
		},
		{
			name:     "username too long, default limits",
			user:     cmf.User{SourceID: "u6", Emails: []cmf.Contact{{Value: "a@example.com"}}, Username: strings.Repeat("a", 16)},
			wantRule: "length must be 1-15 characters",
		},
		{
			name:     "username invalid characters",
			user:     cmf.User{SourceID: "u7", Emails: []cmf.Contact{{Value: "a@example.com"}}, Username: "bad username"},
			wantRule: "characters Auth0 usernames don't allow",
		},
		{
			name:     "requires_username, missing",
			cc:       strict,
			user:     cmf.User{SourceID: "u8", Emails: []cmf.Contact{{Value: "a@example.com"}}},
			wantRule: "required (connection has requires_username)",
		},
		{
			name:     "connection-config overrides username length",
			cc:       strict,
			user:     cmf.User{SourceID: "u9", Emails: []cmf.Contact{{Value: "a@example.com"}}, Username: "ab"},
			wantRule: "length must be 3-5 characters",
		},
		{
			name:     "oversized user_metadata",
			user:     cmf.User{SourceID: "u10", Emails: []cmf.Contact{{Value: "a@example.com"}}, UserMetadata: map[string]any{"bio": strings.Repeat("x", maxMetadataBytes)}},
			wantRule: "exceeds 16384 bytes",
		},
		{
			name:     "empty source_id",
			user:     cmf.User{Emails: []cmf.Contact{{Value: "a@example.com"}}},
			wantRule: "user_id must be 1-128 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{ConnectionConfig: tt.cc}
			problems := c.ValidateUser(tt.user)
			if tt.wantRule == "" {
				require.Empty(t, problems)
				return
			}
			require.NotEmpty(t, problems)
			var found bool
			for _, p := range problems {
				if strings.Contains(p.Rule, tt.wantRule) {
					found = true
				}
				require.Equal(t, tt.user.SourceID, p.SourceID)
			}
			require.True(t, found, "expected a problem with rule containing %q, got %+v", tt.wantRule, problems)
		})
	}
}

func TestLoadConnectionConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connection.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
		"options": {
			"requires_username": true,
			"validation": {"username": {"min": 4, "max": 10}}
		}
	}`), 0o600))

	cc, err := LoadConnectionConfig(path)
	require.NoError(t, err)
	require.True(t, cc.Options.RequiresUsername)
	require.Equal(t, 4, cc.Options.Validation.Username.Min)
	require.Equal(t, 10, cc.Options.Validation.Username.Max)
}

func TestLoadConnectionConfigMissingFile(t *testing.T) {
	_, err := LoadConnectionConfig(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
}
