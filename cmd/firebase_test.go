package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFirebaseFlagsClient(t *testing.T) {
	saPath := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(saPath, []byte(`{"project_id":"sa-project","client_email":"sa@x.iam","private_key":"k"}`), 0o600))

	tests := []struct {
		name        string
		flags       firebaseFlags
		env         map[string]string
		wantProject string
		wantToken   string
		wantSA      bool
		wantBaseURL string
		wantErr     string
	}{
		{name: "token flag", flags: firebaseFlags{project: "p", accessToken: "tok"}, wantProject: "p", wantToken: "tok"},
		{name: "token env", flags: firebaseFlags{project: "p"}, env: map[string]string{"FIREBASE_ACCESS_TOKEN": "tok"}, wantProject: "p", wantToken: "tok"},
		{name: "project env", flags: firebaseFlags{accessToken: "tok"}, env: map[string]string{"FIREBASE_PROJECT_ID": "envp"}, wantProject: "envp", wantToken: "tok"},
		{name: "service account flag defaults project", flags: firebaseFlags{serviceAccount: saPath}, wantProject: "sa-project", wantSA: true},
		{name: "service account env", flags: firebaseFlags{project: "p"}, env: map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": saPath}, wantProject: "p", wantSA: true},
		{name: "service account flag beats token env", flags: firebaseFlags{serviceAccount: saPath}, env: map[string]string{"FIREBASE_ACCESS_TOKEN": "stale"}, wantProject: "sa-project", wantSA: true},
		{name: "emulator", flags: firebaseFlags{project: "demo"}, env: map[string]string{emulatorHostEnv: "127.0.0.1:9099"}, wantProject: "demo", wantToken: "owner", wantBaseURL: "http://127.0.0.1:9099/identitytoolkit.googleapis.com"},
		{name: "emulator needs a project", env: map[string]string{emulatorHostEnv: "127.0.0.1:9099"}, wantErr: "--project"},
		{name: "no credentials", flags: firebaseFlags{project: "p"}, wantErr: "--service-account"},
		{name: "no project", flags: firebaseFlags{accessToken: "tok"}, wantErr: "--project"},
		{name: "missing key file", flags: firebaseFlags{serviceAccount: filepath.Join(t.TempDir(), "nope.json")}, wantErr: "reading service account"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"FIREBASE_PROJECT_ID", "FIREBASE_ACCESS_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", emulatorHostEnv} {
				t.Setenv(k, tt.env[k])
			}
			client, err := tt.flags.client()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantProject, client.ProjectID)
			require.Equal(t, tt.wantToken, client.Credentials.AccessToken)
			require.Equal(t, tt.wantSA, client.Credentials.ServiceAccount != nil)
			if tt.wantBaseURL != "" {
				require.Equal(t, tt.wantBaseURL, client.BaseURL)
			}
		})
	}
}

func TestFirebaseHashFlagsConfig(t *testing.T) {
	const key = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="

	tests := []struct {
		name    string
		flags   firebaseHashFlags
		env     map[string]string
		want    bool
		wantErr string
	}{
		{name: "none given", flags: firebaseHashFlags{rounds: 8, memCost: 14}},
		{name: "flags", flags: firebaseHashFlags{signerKey: key, saltSeparator: "Bw==", rounds: 8, memCost: 14}, want: true},
		{name: "env", flags: firebaseHashFlags{rounds: 8, memCost: 14}, env: map[string]string{"FIREBASE_HASH_SIGNER_KEY": key, "FIREBASE_HASH_SALT_SEPARATOR": "Bw=="}, want: true},
		{name: "separator without key", flags: firebaseHashFlags{saltSeparator: "Bw==", rounds: 8, memCost: 14}, wantErr: "--hash-signer-key"},
		{name: "rounds out of range", flags: firebaseHashFlags{signerKey: key, rounds: 12, memCost: 14}, wantErr: "rounds must be 1-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"FIREBASE_HASH_SIGNER_KEY", "FIREBASE_HASH_SALT_SEPARATOR"} {
				t.Setenv(k, tt.env[k])
			}
			cfg, err := tt.flags.config()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if !tt.want {
				require.Nil(t, cfg)
				return
			}
			require.NotNil(t, cfg)
			require.Equal(t, key, cfg.SignerKey)
			require.Equal(t, "Bw==", cfg.SaltSeparator)
		})
	}
}
