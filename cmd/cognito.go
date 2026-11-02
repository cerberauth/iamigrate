package cmd

import (
	"fmt"
	"os"

	"github.com/cerberauth/iamigrate/pkg/connector/cognito"
	"github.com/spf13/cobra"
)

// cognitoFlags are the user pool and credential flags shared by the Cognito
// commands: the pool's ID, and the AWS access keys requests are signed with.
// Each falls back to the environment variable the AWS tools use for it, so
// `aws configure export-credentials --format env` is enough to sign in with
// a profile.
type cognitoFlags struct {
	userPoolID      string
	region          string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	endpointURL     string
}

func (f *cognitoFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.userPoolID, "user-pool-id", "", "Cognito user pool ID, e.g. eu-west-1_AbCdEfGhI (or $COGNITO_USER_POOL_ID)")
	cmd.Flags().StringVar(&f.region, "region", "", "AWS region (or $AWS_REGION; default: the user pool ID's)")
	cmd.Flags().StringVar(&f.accessKeyID, "access-key-id", "", "AWS access key ID (or $AWS_ACCESS_KEY_ID)")
	cmd.Flags().StringVar(&f.secretAccessKey, "secret-access-key", "", "AWS secret access key (or $AWS_SECRET_ACCESS_KEY)")
	cmd.Flags().StringVar(&f.sessionToken, "session-token", "", "AWS session token, for temporary credentials (or $AWS_SESSION_TOKEN)")
	cmd.Flags().StringVar(&f.endpointURL, "endpoint-url", "", "Cognito API URL, to reach an emulator (or $AWS_ENDPOINT_URL_COGNITO_IDP, $AWS_ENDPOINT_URL)")
}

// client builds a Cognito client from the flags, falling back to the
// environment.
func (f *cognitoFlags) client() (*cognito.Client, error) {
	pool := flagOrEnv(f.userPoolID, "COGNITO_USER_POOL_ID")
	if pool == "" {
		return nil, fmt.Errorf("--user-pool-id (or COGNITO_USER_POOL_ID) is required")
	}
	region := flagOrEnv(f.region, "AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = cognito.RegionOf(pool)
	}
	if region == "" {
		return nil, fmt.Errorf("--region (or AWS_REGION) is required: the user pool ID %q doesn't name one", pool)
	}

	creds := cognito.Credentials{
		AccessKeyID:     flagOrEnv(f.accessKeyID, "AWS_ACCESS_KEY_ID"),
		SecretAccessKey: flagOrEnv(f.secretAccessKey, "AWS_SECRET_ACCESS_KEY"),
		SessionToken:    flagOrEnv(f.sessionToken, "AWS_SESSION_TOKEN"),
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("--access-key-id and --secret-access-key (or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY) are required")
	}

	c := cognito.NewClient(region, pool, creds)
	if endpoint := flagOrEnv(f.endpointURL, "AWS_ENDPOINT_URL_COGNITO_IDP"); endpoint != "" {
		c.Endpoint = endpoint
	} else if endpoint := os.Getenv("AWS_ENDPOINT_URL"); endpoint != "" {
		c.Endpoint = endpoint
	}
	return c, nil
}
