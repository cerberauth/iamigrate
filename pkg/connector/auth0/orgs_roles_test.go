package auth0

import (
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
)

func TestOrgBodyOmitsEmptyDisplayName(t *testing.T) {
	body := orgBody(cmf.Organization{Name: "acme"})
	require.Equal(t, map[string]any{"name": "acme"}, body)
}

func TestOrgBodyIncludesDisplayNameAndMetadata(t *testing.T) {
	body := orgBody(cmf.Organization{
		Name: "acme", DisplayName: "Acme Inc.", Metadata: map[string]any{"tier": "gold"},
	})
	require.Equal(t, "Acme Inc.", body["display_name"])
	require.Equal(t, map[string]any{"tier": "gold"}, body["metadata"])
}
