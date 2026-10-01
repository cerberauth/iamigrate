package kratos

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
)

const testIdentitySchema = `{
	"$id": "https://schemas.ory.sh/presets/kratos/identity.email.schema.json",
	"$schema": "http://json-schema.org/draft-07/schema#",
	"title": "Person",
	"type": "object",
	"properties": {
		"traits": {
			"type": "object",
			"properties": {
				"email": {
					"type": "string",
					"format": "email",
					"ory.sh/kratos": {
						"credentials": {
							"password": {"identifier": true}
						}
					}
				},
				"username": {
					"type": "string",
					"minLength": 3
				}
			},
			"required": ["email"],
			"additionalProperties": false
		}
	}
}`

func writeTestSchema(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.schema.json")
	require.NoError(t, os.WriteFile(path, []byte(testIdentitySchema), 0o600))
	return path
}

func TestLoadIdentitySchema(t *testing.T) {
	schema, err := LoadIdentitySchema(writeTestSchema(t))
	require.NoError(t, err)
	require.Equal(t, []string{"email"}, schema.identifiers)
}

func TestLoadIdentitySchemaMissingFile(t *testing.T) {
	_, err := LoadIdentitySchema(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
}

func TestConnectorValidateUser(t *testing.T) {
	schema, err := LoadIdentitySchema(writeTestSchema(t))
	require.NoError(t, err)

	tests := []struct {
		name     string
		schema   *IdentitySchema
		user     cmf.User
		wantRule string
	}{
		{
			name:     "no schema-file configured: no checks",
			schema:   nil,
			user:     cmf.User{SourceID: "u1"},
			wantRule: "",
		},
		{
			name:     "valid user",
			schema:   schema,
			user:     cmf.User{SourceID: "u2", Emails: []cmf.Contact{{Value: "u2@example.com"}}, Username: "u2u"},
			wantRule: "",
		},
		{
			name:     "missing required email trait",
			schema:   schema,
			user:     cmf.User{SourceID: "u3", Username: "u3username"},
			wantRule: "fails identity schema",
		},
		{
			name:     "username fails minLength, but email is the identifier so it still passes the identifier check",
			schema:   schema,
			user:     cmf.User{SourceID: "u4", Emails: []cmf.Contact{{Value: "u4@example.com"}}, Username: "u4"},
			wantRule: "fails identity schema",
		},
		{
			name:     "no identifier trait value set",
			schema:   schema,
			user:     cmf.User{SourceID: "u5", Username: "u5username"},
			wantRule: "no value set for an identifier trait",
		},
		{
			name:     "additionalProperties rejected via user_metadata",
			schema:   schema,
			user:     cmf.User{SourceID: "u6", Emails: []cmf.Contact{{Value: "u6@example.com"}}, UserMetadata: map[string]any{"extra": "nope"}},
			wantRule: "fails identity schema",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{IdentitySchema: tt.schema}
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
			require.True(t, found, "expected a problem with rule %q, got %+v", tt.wantRule, problems)
		})
	}
}

func TestIdentifierTraits(t *testing.T) {
	var schema map[string]any
	require.NoError(t, json.Unmarshal([]byte(testIdentitySchema), &schema))
	require.Equal(t, []string{"email"}, identifierTraits(schema))
}

func TestValidateUserUsernameRulesWithoutSchema(t *testing.T) {
	c := &Connector{}
	tests := []struct {
		name     string
		username string
		wantRule string
	}{
		{"empty username is not checked", "", ""},
		{"regular username", "alice", ""},
		{"255 multibyte characters", strings.Repeat("é", 255), ""},
		{"over 255 characters", strings.Repeat("a", 256), "must be at most 255 characters"},
		{"only spaces", "   ", "must not be only whitespace"},
		{"only tabs and newlines", "\t\n", "must not be only whitespace"},
		{"spaces around a value", " alice ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems := c.ValidateUser(cmf.User{SourceID: "u1", Username: tt.username})
			if tt.wantRule == "" {
				require.Empty(t, problems)
				return
			}
			require.Len(t, problems, 1)
			require.Equal(t, "u1", problems[0].SourceID)
			require.Equal(t, "username", problems[0].Field)
			require.Equal(t, tt.wantRule, problems[0].Rule)
		})
	}
}
