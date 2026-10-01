package keycloak_test

import (
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/stretchr/testify/require"
)

func TestValidateUserAttributeNames(t *testing.T) {
	c := &keycloak.Connector{}

	t.Run("regular attributes", func(t *testing.T) {
		u := cmf.User{
			SourceID:     "u1",
			UserMetadata: map[string]any{"department": "eng", strings.Repeat("a", 255): "x"},
			AppMetadata:  map[string]any{"plan": "pro"},
		}
		require.Empty(t, c.ValidateUser(u))
	})

	t.Run("name over 255 characters", func(t *testing.T) {
		u := cmf.User{SourceID: "u2", AppMetadata: map[string]any{strings.Repeat("é", 256): "x"}}
		problems := c.ValidateUser(u)
		require.Len(t, problems, 1)
		require.Equal(t, "app_metadata", problems[0].Field)
		require.Equal(t, "attribute name must be at most 255 characters", problems[0].Rule)
		require.Equal(t, "256 characters", problems[0].Value)
	})

	t.Run("reserved profile field names", func(t *testing.T) {
		u := cmf.User{
			SourceID: "u3",
			UserMetadata: map[string]any{
				"email": "a@example.com", "username": "a", "firstName": "A", "lastName": "B",
				"Email": "case differs, so it's kept",
			},
		}
		problems := c.ValidateUser(u)
		require.Len(t, problems, 4)
		var values []string
		for _, p := range problems {
			require.Equal(t, "user_metadata", p.Field)
			require.Contains(t, p.Rule, "reserved by Keycloak")
			values = append(values, p.Value)
		}
		require.Equal(t, []string{"email", "firstName", "lastName", "username"}, values)
	})
}
