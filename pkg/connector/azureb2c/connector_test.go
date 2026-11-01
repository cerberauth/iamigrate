package azureb2c_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/azureb2c"
	"github.com/stretchr/testify/require"
)

const extAttr = "extension_0123456789abcdef0123456789abcdef_Tier"

// export runs an export of the users in pages (one JSON document per Graph
// page, "@odata.nextLink" filled in) and returns what was written.
func export(t *testing.T, opts azureb2c.ExportOptions, pages ...string) ([]cmf.User, connector.Manifest, []string) {
	t.Helper()
	var queries []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		require.Equal(t, "/users", r.URL.Path)
		queries = append(queries, r.URL.RawQuery)
		i := len(queries) - 1
		page := pages[i]
		if i+1 < len(pages) {
			page = strings.Replace(page, "NEXT", srv.URL+"/users?$skiptoken=p"+string(rune('1'+i)), 1)
		} else {
			page = strings.Replace(page, `,"@odata.nextLink":"NEXT"`, "", 1)
		}
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	client := azureb2c.NewClient("tok")
	client.BaseURL = srv.URL

	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	manifest, err := azureb2c.New(client).Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err != nil {
			break
		}
		users = append(users, u)
	}
	return users, manifest, queries
}

func TestExportMapsGraphUsersToCMF(t *testing.T) {
	page := `{"value":[
	  {"id":"u1","accountEnabled":true,"displayName":"Ada Lovelace","givenName":"Ada","surname":"Lovelace",
	   "mail":"ada@example.com","otherMails":["ADA@example.com","ada@home.example"],"mobilePhone":"+33600000000",
	   "preferredLanguage":"fr-FR",
	   "identities":[{"signInType":"emailAddress","issuer":"acme.onmicrosoft.com","issuerAssignedId":"ada.l@example.com"},
	                 {"signInType":"userName","issuer":"acme.onmicrosoft.com","issuerAssignedId":"ada"},
	                 {"signInType":"federated","issuer":"google.com","issuerAssignedId":"1234"}],
	   "` + extAttr + `":"gold"},
	  {"id":"u2","accountEnabled":false,"identities":[{"signInType":"emailAddress","issuerAssignedId":"bob@example.com"}]}
	]}`
	users, manifest, _ := export(t, azureb2c.ExportOptions{ExtensionAttributes: []string{extAttr}}, page)

	require.Equal(t, 2, manifest.RecordCount)
	require.Empty(t, manifest.SkippedRecords)
	require.Len(t, users, 2)

	ada := users[0]
	require.Equal(t, "u1", ada.SourceID)
	require.Equal(t, "ada", ada.Username)
	require.Equal(t, []cmf.Contact{
		{Value: "ada.l@example.com", Primary: true},
		{Value: "ada@example.com"},
		{Value: "ada@home.example"},
	}, ada.Emails)
	require.Equal(t, []cmf.Contact{{Value: "+33600000000", Primary: true}}, ada.Phones)
	require.Equal(t, cmf.Profile{GivenName: "Ada", FamilyName: "Lovelace", Name: "Ada Lovelace", Locale: "fr-FR"}, ada.Profile)
	require.False(t, ada.Blocked)
	require.Nil(t, ada.Password)
	require.Equal(t, azureb2c.Name, ada.Provenance.SourceConnector)
	require.Equal(t, map[string]any{"Tier": "gold"}, ada.UserMetadata)
	require.Equal(t, map[string]any{"federated_identities": []any{map[string]any{"issuer": "google.com", "id": "1234"}}}, ada.AppMetadata)

	require.True(t, users[1].Blocked)
	require.Equal(t, "bob@example.com", users[1].Emails[0].Value)
}

func TestExportSkipsUsersWithoutAnIdentifier(t *testing.T) {
	page := `{"value":[
	  {"id":"u1","identities":[{"signInType":"federated","issuer":"google.com","issuerAssignedId":"1"}]},
	  {"id":"u2","mail":"ok@example.com"}
	]}`
	users, manifest, _ := export(t, azureb2c.ExportOptions{}, page)

	require.Len(t, users, 1)
	require.Equal(t, 1, manifest.RecordCount)
	require.Equal(t, []connector.SkippedRecord{{SourceID: "u1", Reason: "no email, username, or phone number"}}, manifest.SkippedRecords)
}

func TestExportFollowsPageLinks(t *testing.T) {
	users, manifest, queries := export(t, azureb2c.ExportOptions{Filter: "creationType eq 'LocalAccount'"},
		`{"value":[{"id":"a","mail":"a@example.com"}],"@odata.nextLink":"NEXT"}`,
		`{"value":[{"id":"b","mail":"b@example.com"}]}`,
	)

	require.Len(t, users, 2)
	require.Equal(t, 2, manifest.RecordCount)
	require.Len(t, queries, 2)
	require.Contains(t, queries[0], "%24top=999")
	require.Contains(t, queries[0], "%24filter=creationType%20eq%20%27LocalAccount%27")
	require.Contains(t, queries[0], "identities")
	require.Contains(t, queries[1], "skiptoken=p1")
}

func TestExportAsksForExtensionAttributes(t *testing.T) {
	_, _, queries := export(t, azureb2c.ExportOptions{ExtensionAttributes: []string{extAttr}}, `{"value":[]}`)
	require.Contains(t, queries[0], extAttr)
}

func TestExportLimitStopsPaging(t *testing.T) {
	users, _, queries := export(t, azureb2c.ExportOptions{Limit: 2},
		`{"value":[{"id":"a","mail":"a@example.com"},{"id":"b","mail":"b@example.com"}],"@odata.nextLink":"NEXT"}`,
		`{"value":[{"id":"c","mail":"c@example.com"}]}`,
	)

	require.Len(t, users, 2)
	require.Len(t, queries, 1)
	require.Contains(t, queries[0], "%24top=2")
}

func TestExportRefusesPageLinkToAnotherHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[],"@odata.nextLink":"https://evil.example/users"}`))
	}))
	defer srv.Close()
	client := azureb2c.NewClient("tok")
	client.BaseURL = srv.URL

	_, err := azureb2c.New(client).Export(context.Background(), cmf.NewPlainWriter(&bytes.Buffer{}), azureb2c.ExportOptions{})
	require.ErrorContains(t, err, "another host")
}

func TestExportRetriesThrottledRequests(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"a","mail":"a@example.com"}]}`))
	}))
	defer srv.Close()
	client := azureb2c.NewClient("tok")
	client.BaseURL = srv.URL
	client.Backoff.Initial, client.Backoff.Max = time.Millisecond, time.Millisecond

	manifest, err := azureb2c.New(client).Export(context.Background(), cmf.NewPlainWriter(&bytes.Buffer{}), azureb2c.ExportOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, manifest.RecordCount)
	require.EqualValues(t, 2, calls.Load())
}

func TestExportReportsAPIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied"}}`))
	}))
	defer srv.Close()
	client := azureb2c.NewClient("tok")
	client.BaseURL = srv.URL

	_, err := azureb2c.New(client).Export(context.Background(), cmf.NewPlainWriter(&bytes.Buffer{}), azureb2c.ExportOptions{})
	var apiErr *azureb2c.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusForbidden, apiErr.StatusCode)
	require.Contains(t, apiErr.Body, "Authorization_RequestDenied")
}

func TestExportRejectsBadOptions(t *testing.T) {
	c := azureb2c.New(azureb2c.NewClient("tok"))
	w := cmf.NewPlainWriter(&bytes.Buffer{})

	_, err := c.Export(context.Background(), w, azureb2c.ExportOptions{ExtensionAttributes: []string{"Tier"}})
	require.ErrorContains(t, err, "not a custom attribute name")

	_, err = c.Export(context.Background(), w, azureb2c.ExportOptions{Limit: -1})
	require.ErrorContains(t, err, "must not be negative")

	_, err = c.Export(context.Background(), w, nil)
	require.ErrorContains(t, err, "requires azureb2c.ExportOptions")
}

func TestClientCredentialsFetchesAndCachesToken(t *testing.T) {
	var tokens atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokens.Add(1)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		require.Equal(t, "cid", r.PostForm.Get("client_id"))
		require.Equal(t, "secret", r.PostForm.Get("client_secret"))
		require.Equal(t, "https://graph.microsoft.com/.default", r.PostForm.Get("scope"))
		require.Regexp(t, `^iamigrate/\S+ `, r.Header.Get("User-Agent"))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "graph-token", "expires_in": 3600})
	})
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer graph-token", r.Header.Get("Authorization"))
		require.Regexp(t, `^iamigrate/\S+ `, r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte(`{"value":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := azureb2c.NewClientCredentialsClient("acme.onmicrosoft.com", "cid", "secret")
	client.BaseURL = srv.URL
	client.Credentials.TokenURL = srv.URL + "/token"

	for range 2 {
		_, err := azureb2c.New(client).Export(context.Background(), cmf.NewPlainWriter(&bytes.Buffer{}), azureb2c.ExportOptions{})
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, tokens.Load())
}

func TestClientCredentialsReportsTokenErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	client := azureb2c.NewClientCredentialsClient("acme.onmicrosoft.com", "cid", "bad")
	client.BaseURL = srv.URL
	client.Credentials.TokenURL = srv.URL
	_, err := azureb2c.New(client).Export(context.Background(), cmf.NewPlainWriter(&bytes.Buffer{}), azureb2c.ExportOptions{})
	require.ErrorContains(t, err, "invalid_client")
}

func TestNewClientCredentialsClientUsesTenantTokenEndpoint(t *testing.T) {
	c := azureb2c.NewClientCredentialsClient("acme.onmicrosoft.com", "cid", "secret")
	require.Equal(t, "https://login.microsoftonline.com/acme.onmicrosoft.com/oauth2/v2.0/token", c.Credentials.TokenURL)
}
