package cmd

import (
	"fmt"

	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/spf13/cobra"
)

// keycloakFlags are the server, realm, and credential flags shared by the
// Keycloak commands: either an admin user's username/password (password
// grant, through admin-cli unless --client-id says otherwise), or a
// confidential client's ID/secret whose service account holds the
// realm-management roles (client_credentials grant).
type keycloakFlags struct {
	url          string
	realm        string
	authRealm    string
	clientID     string
	clientSecret string
	username     string
	password     string
}

func (f *keycloakFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.url, "url", "", "Keycloak server URL, e.g. https://keycloak.example.com (or $KEYCLOAK_URL)")
	cmd.Flags().StringVar(&f.realm, "realm", "", "realm to import users into and check them in (or $KEYCLOAK_REALM)")
	cmd.Flags().StringVar(&f.authRealm, "auth-realm", "", "realm the admin user or client authenticates in (or $KEYCLOAK_AUTH_REALM; default: --realm)")
	cmd.Flags().StringVar(&f.clientID, "client-id", "", "client ID: a service-account client, or the client for --username (default admin-cli) (or $KEYCLOAK_CLIENT_ID)")
	cmd.Flags().StringVar(&f.clientSecret, "client-secret", "", "client secret (or $KEYCLOAK_CLIENT_SECRET)")
	cmd.Flags().StringVar(&f.username, "username", "", "admin username, to get a token via the password grant (or $KEYCLOAK_USERNAME)")
	cmd.Flags().StringVar(&f.password, "password", "", "admin password (or $KEYCLOAK_PASSWORD)")
}

// client builds an Admin API client from the flags, falling back to the
// environment.
func (f *keycloakFlags) client() (*keycloak.Client, error) {
	baseURL := flagOrEnv(f.url, "KEYCLOAK_URL")
	realm := flagOrEnv(f.realm, "KEYCLOAK_REALM")
	authRealm := flagOrEnv(f.authRealm, "KEYCLOAK_AUTH_REALM")
	clientID := flagOrEnv(f.clientID, "KEYCLOAK_CLIENT_ID")
	clientSecret := flagOrEnv(f.clientSecret, "KEYCLOAK_CLIENT_SECRET")
	username := flagOrEnv(f.username, "KEYCLOAK_USERNAME")
	password := flagOrEnv(f.password, "KEYCLOAK_PASSWORD")

	if baseURL == "" {
		return nil, fmt.Errorf("--url (or KEYCLOAK_URL) is required")
	}
	if realm == "" {
		return nil, fmt.Errorf("--realm (or KEYCLOAK_REALM) is required")
	}
	if authRealm == "" {
		authRealm = realm
	}

	switch {
	case username != "":
		if password == "" {
			return nil, fmt.Errorf("--password (or KEYCLOAK_PASSWORD) is required with --username")
		}
		if clientID == "" {
			clientID = "admin-cli"
		}
	case clientID != "" && clientSecret != "":
	case clientID != "" || clientSecret != "":
		return nil, fmt.Errorf("--client-id and --client-secret (or KEYCLOAK_CLIENT_ID/KEYCLOAK_CLIENT_SECRET) must be set together")
	default:
		return nil, fmt.Errorf("--username/--password (or KEYCLOAK_USERNAME/KEYCLOAK_PASSWORD), or --client-id/--client-secret (or KEYCLOAK_CLIENT_ID/KEYCLOAK_CLIENT_SECRET), is required")
	}

	return keycloak.NewClient(baseURL, realm, &keycloak.Credentials{
		TokenURL:     keycloak.TokenURL(baseURL, authRealm),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     username,
		Password:     password,
	}), nil
}
