package keycloak

import (
	"bytes"
	"context"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

// primaryUser reads a user with two emails and two phones through the
// identity.primary strategy email_first, as the connector's Import does.
func primaryUser(t *testing.T, builtin string) cmf.User {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	require.NoError(t, w.WriteUser(cmf.User{
		CMFVersion: cmf.Version, SourceID: "u1", Username: "alice",
		Emails: []cmf.Contact{{Value: "old@example.com"}, {Value: "new@example.com", Primary: true}},
		Phones: []cmf.Contact{{Value: "+12025550100"}, {Value: "+12025550142", Primary: true}},
	}))
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"identity.primary": {Strategy: builtin}}}
	a, err := importprep.New(m, (&Connector{}).CheckTargetField, nil, importprep.WithPrimaryIdentifiers((&Connector{}).Capabilities().PrimaryIdentifiers))
	require.NoError(t, err)
	batch, err := importprep.NewReader(context.Background(), r, a).ReadBatch()
	require.NoError(t, err)
	return batch[0].User
}

func TestPrimaryIdentifierBecomesTheUsername(t *testing.T) {
	for builtin, want := range map[string]string{
		"email_first":    "new@example.com",
		"username_first": "alice",
		"phone_first":    "+12025550142",
	} {
		rep, _, err := buildUser(primaryUser(t, builtin))
		require.NoError(t, err)
		require.Equal(t, want, rep.Username, builtin)
		require.Equal(t, "new@example.com", rep.Email, "the flagged email is the user's email")
		require.Equal(t, []string{"+12025550142"}, rep.Attributes[attrPhoneNumber])
	}
}
