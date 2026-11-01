package cmd

import (
	"fmt"

	"github.com/cerberauth/iamigrate/pkg/connector/azureb2c"
	"github.com/spf13/cobra"
)

// azureB2CFlags are the tenant and credential flags of the Azure AD B2C
// source: either a ready Microsoft Graph access token, or an app
// registration's client ID/secret that iamigrate exchanges for one (and
// renews) through the client_credentials grant. The app needs the
// User.Read.All application permission, with admin consent.
//
// Only --tenant is its own flag. The credentials are read from the flags the
// other sources already register for the same purpose (--client-id,
// --client-secret, --access-token), which `export` copies in with
// withCredentials, since a flag can only be defined once per command.
type azureB2CFlags struct {
	tenant       string
	accessToken  string
	clientID     string
	clientSecret string
}

func (f *azureB2CFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.tenant, "tenant", "", "Azure AD B2C tenant domain or directory ID (or $AZURE_TENANT_ID; azure-ad-b2c source)")
}

// withCredentials takes the credential flags shared with other sources.
func (f *azureB2CFlags) withCredentials(accessToken, clientID, clientSecret string) *azureB2CFlags {
	f.accessToken, f.clientID, f.clientSecret = accessToken, clientID, clientSecret
	return f
}

// client builds a Graph client from the flags, falling back to the
// environment. Flags win over the environment: $AZURE_ACCESS_TOKEN is only
// read if neither --client-id nor --client-secret is given, and when both it
// and client credentials are in the environment, the token is used.
func (f *azureB2CFlags) client() (*azureb2c.Client, error) {
	token := f.accessToken
	if f.clientID == "" && f.clientSecret == "" {
		token = flagOrEnv(token, "AZURE_ACCESS_TOKEN")
	}
	if token != "" {
		return azureb2c.NewClient(token), nil
	}

	clientID := flagOrEnv(f.clientID, "AZURE_CLIENT_ID")
	clientSecret := flagOrEnv(f.clientSecret, "AZURE_CLIENT_SECRET")
	switch {
	case clientID != "" && clientSecret != "":
		tenant := flagOrEnv(f.tenant, "AZURE_TENANT_ID")
		if tenant == "" {
			return nil, fmt.Errorf("--tenant (or AZURE_TENANT_ID) is required")
		}
		return azureb2c.NewClientCredentialsClient(tenant, clientID, clientSecret), nil
	case clientID != "" || clientSecret != "":
		return nil, fmt.Errorf("--client-id and --client-secret (or AZURE_CLIENT_ID/AZURE_CLIENT_SECRET) must be set together")
	default:
		return nil, fmt.Errorf("--access-token (or AZURE_ACCESS_TOKEN), or --client-id/--client-secret (or AZURE_CLIENT_ID/AZURE_CLIENT_SECRET), is required")
	}
}
