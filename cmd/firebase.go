package cmd

import (
	"fmt"
	"os"

	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/spf13/cobra"
)

// emulatorHostEnv is the variable Firebase's tooling uses to point at the
// Auth emulator; when it's set, the commands talk to the emulator instead
// of a real project, with no credentials.
const emulatorHostEnv = "FIREBASE_AUTH_EMULATOR_HOST"

// firebaseFlags are the project and credential flags shared by the Firebase
// commands: a service account key file (a Google credentials file), or a
// ready access token such as `gcloud auth print-access-token`.
type firebaseFlags struct {
	project        string
	serviceAccount string
	accessToken    string
}

func (f *firebaseFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.project, "project", "", "Firebase project ID (or $FIREBASE_PROJECT_ID; default: the service account's project)")
	cmd.Flags().StringVar(&f.serviceAccount, "service-account", "", "service account key JSON path (or $GOOGLE_APPLICATION_CREDENTIALS)")
	cmd.Flags().StringVar(&f.accessToken, "access-token", "", "OAuth2 access token, e.g. from gcloud auth print-access-token (or $FIREBASE_ACCESS_TOKEN)")
	cmd.MarkFlagsMutuallyExclusive("service-account", "access-token")
}

// client builds an Identity Toolkit client from the flags, falling back to
// the environment. Explicit flags beat the environment; a token beats a
// service account within each.
func (f *firebaseFlags) client() (*firebase.Client, error) {
	project := flagOrEnv(f.project, "FIREBASE_PROJECT_ID")

	if host := os.Getenv(emulatorHostEnv); host != "" {
		if project == "" {
			return nil, fmt.Errorf("--project (or FIREBASE_PROJECT_ID) is required with %s", emulatorHostEnv)
		}
		return firebase.NewEmulatorClient(host, project), nil
	}

	creds := &firebase.Credentials{}
	switch {
	case f.accessToken != "":
		creds.AccessToken = f.accessToken
	case f.serviceAccount != "":
		sa, err := firebase.LoadServiceAccount(f.serviceAccount)
		if err != nil {
			return nil, err
		}
		creds.ServiceAccount = sa
	case os.Getenv("FIREBASE_ACCESS_TOKEN") != "":
		creds.AccessToken = os.Getenv("FIREBASE_ACCESS_TOKEN")
	case os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "":
		sa, err := firebase.LoadServiceAccount(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		if err != nil {
			return nil, err
		}
		creds.ServiceAccount = sa
	default:
		return nil, fmt.Errorf("--service-account (or GOOGLE_APPLICATION_CREDENTIALS), or --access-token (or FIREBASE_ACCESS_TOKEN), is required")
	}

	if project == "" && creds.ServiceAccount != nil {
		project = creds.ServiceAccount.ProjectID
	}
	if project == "" {
		return nil, fmt.Errorf("--project (or FIREBASE_PROJECT_ID) is required")
	}
	return firebase.NewClient(project, creds), nil
}

// firebaseHashFlags are the project's password hash parameters, from the
// Firebase console (Authentication > Users > menu > Password hash
// parameters). No API returns them, yet no password hash exported from
// Firebase can be verified elsewhere without them.
type firebaseHashFlags struct {
	signerKey     string
	saltSeparator string
	rounds        int
	memCost       int
}

func (f *firebaseHashFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.signerKey, "hash-signer-key", "", "Firebase project's base64 scrypt signer key (or $FIREBASE_HASH_SIGNER_KEY; firebase source)")
	cmd.Flags().StringVar(&f.saltSeparator, "hash-salt-separator", "", "Firebase project's base64 scrypt salt separator (or $FIREBASE_HASH_SALT_SEPARATOR; firebase source)")
	cmd.Flags().IntVar(&f.rounds, "hash-rounds", 8, "Firebase project's scrypt rounds (firebase source)")
	cmd.Flags().IntVar(&f.memCost, "hash-mem-cost", 14, "Firebase project's scrypt memory cost (firebase source)")
}

// config returns the project's scrypt configuration, or nil when none was
// given, in which case exported password hashes aren't portable.
func (f *firebaseHashFlags) config() (*iamhash.FirebaseScryptConfig, error) {
	signerKey := flagOrEnv(f.signerKey, "FIREBASE_HASH_SIGNER_KEY")
	separator := flagOrEnv(f.saltSeparator, "FIREBASE_HASH_SALT_SEPARATOR")
	if signerKey == "" && separator == "" {
		return nil, nil
	}
	if signerKey == "" {
		return nil, fmt.Errorf("--hash-signer-key (or FIREBASE_HASH_SIGNER_KEY) is required with --hash-salt-separator")
	}
	cfg := iamhash.FirebaseScryptConfig{SignerKey: signerKey, SaltSeparator: separator, Rounds: f.rounds, MemCost: f.memCost}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
