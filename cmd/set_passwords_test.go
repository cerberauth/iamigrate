package cmd

import (
	"bytes"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func writeUsers(t *testing.T, path string, users ...cmf.User) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w := cmf.NewPlainWriter(f)
	for _, u := range users {
		u.Provenance = cmf.Provenance{SourceConnector: "test", ExportedAt: time.Unix(0, 0).UTC()}
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
}

func readUsers(t *testing.T, path string) []cmf.User {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r, err := cmf.NewReader(f)
	require.NoError(t, err)
	defer r.Close()
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return users
		}
		require.NoError(t, err)
		users = append(users, u)
	}
}

func runSetPasswordsCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(append([]string{"set-passwords"}, args...))
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestSetPasswords(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "users.cmf.jsonl")
	out := filepath.Join(dir, "with-passwords.cmf.jsonl.gz")
	creds := filepath.Join(dir, "passwords.csv")

	keep, err := bcrypt.GenerateFromPassword([]byte("kept"), bcrypt.MinCost)
	require.NoError(t, err)
	keptPassword := &cmf.Password{
		Algorithm: cmf.AlgBcrypt,
		Hash:      cmf.HashValue{Value: string(keep), Encoding: cmf.EncodingUTF8},
		Portable:  true,
	}
	writeUsers(t, in,
		cmf.User{SourceID: "u1", Emails: []cmf.Contact{{Value: "a@example.com"}}},
		cmf.User{SourceID: "u2", Username: "=evil()", Password: keptPassword},
		cmf.User{SourceID: "u3", Phones: []cmf.Contact{{Value: "+14155552671"}},
			Password: &cmf.Password{Algorithm: cmf.AlgSHA1, Hash: cmf.HashValue{Value: "00", Encoding: cmf.EncodingHex}, Portable: false}},
		cmf.User{SourceID: "u4", Emails: []cmf.Contact{{Value: "d@example.com"}}},
	)

	stdout, stderr, err := runSetPasswordsCmd(t, "--in", in, "--out", out, "--passwords-out", creds, "--hash", "bcrypt:cost=4")
	require.NoError(t, err)
	require.Contains(t, stdout, "set a password for 3 of 4 users (1 kept theirs)")
	require.NotContains(t, stderr, "no --passwords-out given")

	// The output is gzip because of the .gz suffix and still a valid CMF file.
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, []byte{0x1f, 0x8b}, raw[:2])
	users := readUsers(t, out)
	require.Len(t, users, 4)

	info, err := os.Stat(creds)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	cf, err := os.Open(creds)
	require.NoError(t, err)
	defer cf.Close()
	rows, err := csv.NewReader(cf).ReadAll()
	require.NoError(t, err)
	require.Equal(t, []string{"source_id", "email", "username", "phone", "password"}, rows[0])
	require.Len(t, rows, 4) // header + u1, u3, u4: u2 kept its password

	byID := map[string][]string{}
	seen := map[string]bool{}
	for _, row := range rows[1:] {
		byID[row[0]] = row
		require.False(t, seen[row[4]], "password reused")
		seen[row[4]] = true
	}
	require.NotContains(t, byID, "u2")
	require.Equal(t, "a@example.com", byID["u1"][1])
	require.Equal(t, "+14155552671", byID["u3"][3])

	// Each generated password verifies against the hash written for that user.
	for _, u := range users {
		switch u.SourceID {
		case "u2":
			require.Equal(t, keptPassword, u.Password)
		default:
			require.NotNil(t, u.Password)
			require.True(t, u.Password.Portable)
			require.Equal(t, cmf.AlgBcrypt, u.Password.Algorithm)
			require.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.Password.Hash.Value), []byte(byID[u.SourceID][4])))
		}
	}
}

func TestSetPasswordsOverwrite(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "users.cmf.jsonl")
	out := filepath.Join(dir, "out.cmf.jsonl")

	keep, err := bcrypt.GenerateFromPassword([]byte("kept"), bcrypt.MinCost)
	require.NoError(t, err)
	writeUsers(t, in, cmf.User{SourceID: "u1", Password: &cmf.Password{
		Algorithm: cmf.AlgBcrypt, Hash: cmf.HashValue{Value: string(keep), Encoding: cmf.EncodingUTF8}, Portable: true,
	}})

	stdout, stderr, err := runSetPasswordsCmd(t, "--in", in, "--out", out, "--hash", "bcrypt:cost=4", "--overwrite")
	require.NoError(t, err)
	require.Contains(t, stdout, "set a password for 1 of 1 users")
	require.Contains(t, stderr, "no --passwords-out given")

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	require.NotEqual(t, []byte{0x1f, 0x8b}, raw[:2], "no .gz suffix, so plain JSONL")
	u := readUsers(t, out)[0]
	require.Error(t, bcrypt.CompareHashAndPassword([]byte(u.Password.Hash.Value), []byte("kept")))
}

func TestSetPasswordsRejects(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "users.cmf.jsonl")
	writeUsers(t, in, cmf.User{SourceID: "u1"})
	out := filepath.Join(dir, "out.cmf.jsonl")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing hash", []string{"--in", in, "--out", out}, `required flag(s) "hash" not set`},
		{"weak algorithm", []string{"--in", in, "--out", out, "--hash", "md5"}, "unsupported --hash algorithm"},
		{"output is input", []string{"--in", in, "--out", in, "--hash", "bcrypt"}, "--in and --out must be different files"},
		{"passwords file is output", []string{"--in", in, "--out", out, "--passwords-out", out, "--hash", "bcrypt"}, "--out and --passwords-out must be different files"},
		{"length too short", []string{"--in", in, "--out", out, "--hash", "bcrypt", "--length", "4"}, "--length must be between"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := runSetPasswordsCmd(t, tt.args...)
			require.ErrorContains(t, err, tt.want)
			require.NoFileExists(t, out)
		})
	}
}

func TestSetPasswordsRemovesOutputOnFailure(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "users.cmf.jsonl")
	out := filepath.Join(dir, "out.cmf.jsonl")
	creds := filepath.Join(dir, "passwords.csv")
	require.NoError(t, os.WriteFile(in, []byte("{not json}\n"), 0o600))

	_, _, err := runSetPasswordsCmd(t, "--in", in, "--out", out, "--passwords-out", creds, "--hash", "bcrypt:cost=4")
	require.Error(t, err)
	require.NoFileExists(t, out)
	require.NoFileExists(t, creds)
}

func TestCSVSafe(t *testing.T) {
	require.Equal(t, "'=1+1", csvSafe("=1+1"))
	require.Equal(t, "'@x", csvSafe("@x"))
	require.Equal(t, "+14155552671", csvSafe("+14155552671"))
	require.Equal(t, "alice", csvSafe("alice"))
	require.Equal(t, "", csvSafe(""))
}
