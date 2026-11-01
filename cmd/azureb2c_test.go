package cmd

import (
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector/azureb2c"
	"github.com/stretchr/testify/require"
)

func TestAzureB2CFlagsClient(t *testing.T) {
	tests := []struct {
		name      string
		flags     azureB2CFlags
		env       map[string]string
		wantToken string
		wantCreds string // expected client ID when using client credentials
		wantErr   string
	}{
		{name: "token flag", flags: azureB2CFlags{accessToken: "tok"}, wantToken: "tok"},
		{name: "token env", env: map[string]string{"AZURE_ACCESS_TOKEN": "tok"}, wantToken: "tok"},
		{name: "client credential flags", flags: azureB2CFlags{tenant: "acme.onmicrosoft.com", clientID: "cid", clientSecret: "cs"}, wantCreds: "cid"},
		{name: "client credential env", env: map[string]string{"AZURE_TENANT_ID": "acme.onmicrosoft.com", "AZURE_CLIENT_ID": "cid", "AZURE_CLIENT_SECRET": "cs"}, wantCreds: "cid"},
		{name: "client id flag beats token env", flags: azureB2CFlags{tenant: "t", clientID: "cid"}, env: map[string]string{"AZURE_ACCESS_TOKEN": "stale", "AZURE_CLIENT_SECRET": "cs"}, wantCreds: "cid"},
		{name: "token env beats client credential env", env: map[string]string{"AZURE_ACCESS_TOKEN": "tok", "AZURE_CLIENT_ID": "cid", "AZURE_CLIENT_SECRET": "cs"}, wantToken: "tok"},
		{name: "missing secret", flags: azureB2CFlags{tenant: "t", clientID: "cid"}, wantErr: "must be set together"},
		{name: "no credentials", flags: azureB2CFlags{tenant: "t"}, wantErr: "--access-token"},
		{name: "no tenant", flags: azureB2CFlags{clientID: "cid", clientSecret: "cs"}, wantErr: "--tenant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"AZURE_TENANT_ID", "AZURE_ACCESS_TOKEN", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"} {
				t.Setenv(k, tt.env[k])
			}
			client, err := tt.flags.client()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantCreds != "" {
				require.NotNil(t, client.Credentials)
				require.Equal(t, tt.wantCreds, client.Credentials.ClientID)
				require.Contains(t, client.Credentials.TokenURL, "/oauth2/v2.0/token")
				return
			}
			require.Nil(t, client.Credentials)
			require.Equal(t, tt.wantToken, client.AccessToken)
		})
	}
}

func TestJobSourceAzureB2C(t *testing.T) {
	t.Setenv("AZURE_ACCESS_TOKEN", "tok")
	ext := "extension_0123456789abcdef0123456789abcdef_Tier"
	params := map[string]string{
		jobs.ParamSource: azureb2c.Name, paramExtensionAttrs: ext, paramFilter: "creationType eq 'LocalAccount'", paramExportLimit: "5",
	}

	src, opts, err := jobSource(&jobs.Job{Params: params})
	require.NoError(t, err)
	require.Equal(t, azureb2c.Name, src.Name())
	require.Equal(t, azureb2c.ExportOptions{
		ExtensionAttributes: []string{ext}, Filter: "creationType eq 'LocalAccount'", Limit: 5,
	}, opts)

	params[paramExtensionAttrs] = "Tier"
	_, _, err = jobSource(&jobs.Job{Params: params})
	require.ErrorContains(t, err, "not a custom attribute name")
}
