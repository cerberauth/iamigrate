package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCognitoFlagsClient(t *testing.T) {
	keys := map[string]string{"AWS_ACCESS_KEY_ID": "AK", "AWS_SECRET_ACCESS_KEY": "SK"}
	tests := []struct {
		name         string
		flags        cognitoFlags
		env          map[string]string
		wantRegion   string
		wantEndpoint string
		wantToken    string
		wantErr      string
	}{
		{name: "region from the pool ID", flags: cognitoFlags{userPoolID: "eu-west-1_Abc"}, env: keys,
			wantRegion: "eu-west-1", wantEndpoint: "https://cognito-idp.eu-west-1.amazonaws.com"},
		{name: "pool and region from the environment", env: map[string]string{
			"COGNITO_USER_POOL_ID": "eu-west-1_Abc", "AWS_REGION": "us-east-2", "AWS_ACCESS_KEY_ID": "AK", "AWS_SECRET_ACCESS_KEY": "SK",
		}, wantRegion: "us-east-2", wantEndpoint: "https://cognito-idp.us-east-2.amazonaws.com"},
		{name: "flags beat the environment", flags: cognitoFlags{userPoolID: "eu-west-1_Abc", accessKeyID: "FK", secretAccessKey: "FS", sessionToken: "tok"},
			env: keys, wantRegion: "eu-west-1", wantEndpoint: "https://cognito-idp.eu-west-1.amazonaws.com", wantToken: "tok"},
		{name: "service endpoint", flags: cognitoFlags{userPoolID: "eu-west-1_Abc"},
			env:        map[string]string{"AWS_ENDPOINT_URL": "http://all", "AWS_ENDPOINT_URL_COGNITO_IDP": "http://idp", "AWS_ACCESS_KEY_ID": "AK", "AWS_SECRET_ACCESS_KEY": "SK"},
			wantRegion: "eu-west-1", wantEndpoint: "http://idp"},
		{name: "general endpoint", flags: cognitoFlags{userPoolID: "local_Pool", region: "eu-west-1"},
			env:        map[string]string{"AWS_ENDPOINT_URL": "http://all", "AWS_ACCESS_KEY_ID": "AK", "AWS_SECRET_ACCESS_KEY": "SK"},
			wantRegion: "eu-west-1", wantEndpoint: "http://all"},
		{name: "no pool", env: keys, wantErr: "--user-pool-id"},
		{name: "no region", flags: cognitoFlags{userPoolID: "pool"}, env: keys, wantErr: "--region"},
		{name: "no keys", flags: cognitoFlags{userPoolID: "eu-west-1_Abc"}, wantErr: "--access-key-id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{
				"COGNITO_USER_POOL_ID", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
				"AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_COGNITO_IDP",
			} {
				t.Setenv(k, tt.env[k])
			}
			client, err := tt.flags.client()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantRegion, client.Region)
			require.Equal(t, tt.wantEndpoint, client.Endpoint)
			require.Equal(t, tt.wantToken, client.Creds.SessionToken)
		})
	}
}
