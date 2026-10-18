package importprep_test

import (
	"context"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func multiUser(id string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version, SourceID: id, Username: id + "-name",
		Emails: []cmf.Contact{{Value: "old@example.com"}, {Value: id + "@example.com", Primary: true}},
		Phones: []cmf.Contact{{Value: "+12025550100"}, {Value: "+12025550142", Primary: true}},
	}
}

func prepared(t *testing.T, m mapping.Mapping, caps []cmf.Identifier, users ...cmf.User) []importprep.Prepared {
	t.Helper()
	a, err := importprep.New(m, anyPath, nil, importprep.WithPrimaryIdentifiers(caps))
	require.NoError(t, err)
	r := importprep.NewReader(context.Background(), cmfReader(t, users...), a)
	batch, err := r.ReadBatch()
	require.NoError(t, err)
	return batch
}

func primary(builtin string) mapping.Mapping {
	return mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"identity.primary": {Strategy: builtin}}}
}

var allKinds = []cmf.Identifier{cmf.IdentifierEmail, cmf.IdentifierUsername, cmf.IdentifierPhone}

func TestIdentityPrimaryBuiltins(t *testing.T) {
	for builtin, want := range map[string]cmf.Identifier{
		"email_first":    cmf.IdentifierEmail,
		"username_first": cmf.IdentifierUsername,
		"phone_first":    cmf.IdentifierPhone,
	} {
		got := prepared(t, primary(builtin), allKinds, multiUser("a"))[0].User
		require.Equal(t, want, got.Login, builtin)
		require.Equal(t, "a@example.com", got.Emails[0].Value, "the contact flagged primary comes first")
		require.Equal(t, "old@example.com", got.Emails[1].Value)
		require.Equal(t, "+12025550142", got.Phones[0].Value)
	}
}

func TestIdentityPrimaryFallsBackAlongItsOrder(t *testing.T) {
	phoneOnly := cmf.User{CMFVersion: cmf.Version, SourceID: "p", Phones: []cmf.Contact{{Value: "+12025550142"}}}
	require.Equal(t, cmf.IdentifierPhone, prepared(t, primary("email_first"), allKinds, phoneOnly)[0].User.Login)

	emailOnly := cmf.User{CMFVersion: cmf.Version, SourceID: "e", Emails: []cmf.Contact{{Value: "e@example.com"}}}
	require.Equal(t, cmf.IdentifierEmail, prepared(t, primary("phone_first"), allKinds, emailOnly)[0].User.Login)

	// A target taking only email never gets another kind chosen.
	require.Equal(t, cmf.Identifier(""), prepared(t, primary("email_first"), []cmf.Identifier{cmf.IdentifierEmail}, phoneOnly)[0].User.Login)
}

func TestIdentityPrimaryDoesNotChangeTheSourceUsers(t *testing.T) {
	u := multiUser("a")
	prepared(t, primary("email_first"), allKinds, u)
	require.Equal(t, "old@example.com", u.Emails[0].Value)
}

func TestIdentityPrimaryHandler(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		require.Equal(t, "identity.primary", hook)
		require.NotContains(t, item, "password", "the handler is told who the user is, not their credentials")
		switch key {
		case "kind":
			return map[string]any{"identifier": "phone"}
		case "value":
			return map[string]any{"value": "old@example.com"}
		case "both":
			return map[string]any{"identifier": "email", "value": "old@example.com"}
		case "missing":
			return map[string]any{"identifier": "username"}
		case "stranger":
			return map[string]any{"value": "nobody@example.com"}
		}
		return map[string]any{} // no opinion
	}, "")
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"identity.primary": {Handler: "h"}}}
	a, err := importprep.New(m, anyPath, d, importprep.WithPrimaryIdentifiers(allKinds))
	require.NoError(t, err)

	read := func(users ...cmf.User) ([]importprep.Prepared, error) {
		return importprep.NewReader(context.Background(), cmfReader(t, users...), a).ReadBatch()
	}
	batch, err := read(multiUser("kind"), multiUser("value"), multiUser("none"))
	require.NoError(t, err)
	require.Equal(t, 1, rc.Calls("identity.primary"), "one call for the whole batch")
	require.Equal(t, cmf.IdentifierPhone, batch[0].User.Login)
	require.Equal(t, cmf.IdentifierEmail, batch[1].User.Login)
	require.Equal(t, "old@example.com", batch[1].User.Emails[0].Value, "a concrete value picks the contact")
	require.Equal(t, "+12025550142", batch[1].User.Phones[0].Value)
	require.Empty(t, batch[2].User.Login, "an empty answer leaves the connector to pick the kind")
	require.Equal(t, "none@example.com", batch[2].User.Emails[0].Value, "the flagged contact still comes first")

	for id, want := range map[string]string{
		"both":     "either identifier or value",
		"stranger": "none of the user's identifiers",
	} {
		_, err = read(multiUser(id))
		require.ErrorContains(t, err, want)
	}
	_, err = read(cmf.User{CMFVersion: cmf.Version, SourceID: "missing", Emails: []cmf.Contact{{Value: "m@example.com"}}})
	require.ErrorContains(t, err, "the user has no username")
}

func TestIdentityPrimaryHandlerAnswerTheTargetCantHonor(t *testing.T) {
	d, _ := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		return map[string]any{"identifier": "username"}
	}, "")
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"identity.primary": {Handler: "h"}}}
	a, err := importprep.New(m, anyPath, d, importprep.WithPrimaryIdentifiers([]cmf.Identifier{cmf.IdentifierEmail}))
	require.NoError(t, err)
	_, err = importprep.NewReader(context.Background(), cmfReader(t, multiUser("a")), a).ReadBatch()
	require.ErrorContains(t, err, "can't make the username the primary identifier")
}

func TestCheckRejectsAPrimaryTheTargetCantHonor(t *testing.T) {
	for _, tc := range []struct {
		builtin string
		target  connector.TargetConnector
		want    string
	}{
		{"email_first", &auth0.Connector{}, ""},
		{"username_first", &auth0.Connector{}, "auth0 can't make the username its primary identifier"},
		{"phone_first", &auth0.Connector{}, "auth0 can't make the phone its primary identifier"},
		{"username_first", &firebase.Connector{}, "firebase can't make the username"},
		{"phone_first", &firebase.Connector{}, ""},
		{"username_first", &kratos.Connector{}, ""},
		{"username_first", &keycloak.Connector{}, ""},
	} {
		err := importprep.Check(primary(tc.builtin), tc.target)
		if tc.want == "" {
			require.NoError(t, err, tc.target.Name()+" "+tc.builtin)
		} else {
			require.ErrorContains(t, err, tc.want, tc.builtin)
		}
	}
}
