package cmd

import (
	"fmt"
	"os"

	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/spf13/cobra"
)

// auth0Flags are the tenant and credential flags shared by the Auth0
// commands: either a ready-made Management API token, or a
// Machine-to-Machine application's client ID/secret that iamigrate
// exchanges for one (and renews) through the client_credentials grant.
type auth0Flags struct {
	domain       string
	token        string
	clientID     string
	clientSecret string
}

func (f *auth0Flags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.domain, "domain", "", "Auth0 tenant domain (or $AUTH0_DOMAIN)")
	cmd.Flags().StringVar(&f.token, "token", "", "Auth0 Management API token (or $AUTH0_TOKEN)")
	cmd.Flags().StringVar(&f.clientID, "client-id", "", "Machine-to-Machine application client ID, to get a token via client_credentials (or $AUTH0_CLIENT_ID)")
	cmd.Flags().StringVar(&f.clientSecret, "client-secret", "", "Machine-to-Machine application client secret (or $AUTH0_CLIENT_SECRET)")
	cmd.MarkFlagsMutuallyExclusive("token", "client-id")
	cmd.MarkFlagsMutuallyExclusive("token", "client-secret")
}

// client builds a Management API client from the flags, falling back to
// the environment. Flags win over the environment: $AUTH0_TOKEN is only
// read if neither --client-id nor --client-secret is passed, and when
// both $AUTH0_TOKEN and client credentials are in the environment, the
// token is used.
func (f *auth0Flags) client() (*auth0.Client, error) {
	domain := flagOrEnv(f.domain, "AUTH0_DOMAIN")
	token := f.token
	if f.clientID == "" && f.clientSecret == "" {
		token = flagOrEnv(token, "AUTH0_TOKEN")
	}
	var clientID, clientSecret string
	if token == "" {
		clientID = flagOrEnv(f.clientID, "AUTH0_CLIENT_ID")
		clientSecret = flagOrEnv(f.clientSecret, "AUTH0_CLIENT_SECRET")
	}

	if domain == "" {
		return nil, fmt.Errorf("--domain (or AUTH0_DOMAIN) is required")
	}
	baseURL := "https://" + domain + "/api/v2"
	switch {
	case token != "":
		return auth0.NewClient(baseURL, token), nil
	case clientID != "" && clientSecret != "":
		return auth0.NewClientCredentialsClient(baseURL, "https://"+domain+"/oauth/token", clientID, clientSecret), nil
	case clientID != "" || clientSecret != "":
		return nil, fmt.Errorf("--client-id and --client-secret (or AUTH0_CLIENT_ID/AUTH0_CLIENT_SECRET) must be set together")
	default:
		return nil, fmt.Errorf("--token (or AUTH0_TOKEN), or --client-id/--client-secret (or AUTH0_CLIENT_ID/AUTH0_CLIENT_SECRET), is required")
	}
}

func flagOrEnv(v, env string) string {
	if v == "" {
		return os.Getenv(env)
	}
	return v
}
