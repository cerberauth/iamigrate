package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuth0FlagsClient(t *testing.T) {
	tests := []struct {
		name      string
		flags     auth0Flags
		env       map[string]string
		wantToken string
		wantCreds string // expected client ID when using client credentials
		wantErr   string
	}{
		{name: "token flag", flags: auth0Flags{domain: "t.auth0.com", token: "tok"}, wantToken: "tok"},
		{name: "token env", flags: auth0Flags{domain: "t.auth0.com"}, env: map[string]string{"AUTH0_TOKEN": "tok"}, wantToken: "tok"},
		{name: "client credential flags", flags: auth0Flags{domain: "t.auth0.com", clientID: "cid", clientSecret: "cs"}, wantCreds: "cid"},
		{name: "client credential env", flags: auth0Flags{domain: "t.auth0.com"}, env: map[string]string{"AUTH0_CLIENT_ID": "cid", "AUTH0_CLIENT_SECRET": "cs"}, wantCreds: "cid"},
		{name: "client id flag beats token env", flags: auth0Flags{domain: "t.auth0.com", clientID: "cid"}, env: map[string]string{"AUTH0_TOKEN": "stale", "AUTH0_CLIENT_SECRET": "cs"}, wantCreds: "cid"},
		{name: "token env beats client credential env", flags: auth0Flags{domain: "t.auth0.com"}, env: map[string]string{"AUTH0_TOKEN": "tok", "AUTH0_CLIENT_ID": "cid", "AUTH0_CLIENT_SECRET": "cs"}, wantToken: "tok"},
		{name: "missing secret", flags: auth0Flags{domain: "t.auth0.com", clientID: "cid"}, wantErr: "must be set together"},
		{name: "no credentials", flags: auth0Flags{domain: "t.auth0.com"}, wantErr: "--token"},
		{name: "no domain", flags: auth0Flags{token: "tok"}, wantErr: "--domain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"AUTH0_DOMAIN", "AUTH0_TOKEN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET"} {
				t.Setenv(k, tt.env[k])
			}
			client, err := tt.flags.client()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "https://t.auth0.com/api/v2", client.BaseURL)
			if tt.wantCreds != "" {
				require.NotNil(t, client.Credentials)
				require.Equal(t, tt.wantCreds, client.Credentials.ClientID)
				require.Equal(t, "https://t.auth0.com/oauth/token", client.Credentials.TokenURL)
				require.Equal(t, "https://t.auth0.com/api/v2/", client.Credentials.Audience)
				return
			}
			require.Nil(t, client.Credentials)
			require.Equal(t, tt.wantToken, client.Token)
		})
	}
}
