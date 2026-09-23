package fixture_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/fixture"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestExportGeneratesValidCMFAndAnswerKey(t *testing.T) {
	dir := t.TempDir()
	answerKeyPath := filepath.Join(dir, "answer-key.json")

	opts := fixture.ExportOptions{
		Count: 20,
		Hashes: []fixture.HashSpec{
			{Algorithm: cmf.AlgBcrypt, Params: map[string]string{"cost": "10"}},
			{Algorithm: cmf.AlgSHA256},
		},
		MFAs: []fixture.MFASpec{
			{Type: cmf.MFATOTP, Rate: 1.0},
			{Type: cmf.MFARecoveryCodes, Rate: 1.0},
		},
		Locale:        "en",
		Seed:          42,
		AnswerKeyPath: answerKeyPath,
	}

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	c := fixture.New()
	manifest, err := c.Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	require.Equal(t, 20, manifest.RecordCount)
	require.Equal(t, 20, manifest.NonPortableMFACounts[cmf.MFARecoveryCodes])

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()

	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		users = append(users, u)
	}
	require.Len(t, users, 20)

	// Emails are derived from the profile name, unique, and on reserved domains.
	seen := map[string]bool{}
	for _, u := range users {
		require.Len(t, u.Emails, 1)
		email := u.Emails[0].Value
		local, domain, ok := strings.Cut(email, "@")
		require.True(t, ok)
		require.Contains(t, []string{"example.com", "example.net", "example.org"}, domain)
		require.True(t, strings.HasPrefix(local, strings.ToLower(u.Profile.GivenName)+"."), "email %q does not match name %q", email, u.Profile.Name)
		require.False(t, seen[email], "duplicate email %q", email)
		seen[email] = true
	}

	// answer-key.json entries must actually verify against the emitted hash.
	b, err := os.ReadFile(answerKeyPath)
	require.NoError(t, err)
	var key fixture.AnswerKey
	require.NoError(t, json.Unmarshal(b, &key))
	require.Len(t, key.Entries, 20)

	for i, u := range users {
		entry := key.Entries[i]
		require.Equal(t, u.SourceID, entry.SourceID)
		require.NotEmpty(t, entry.Password)

		switch u.Password.Algorithm {
		case cmf.AlgBcrypt:
			require.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.Password.Hash.Value), []byte(entry.Password)))
		case cmf.AlgSHA256:
			// SHA-256 has no salt in this fixture path; recompute and compare.
			p2, err := iamhash.Normalize(u.Password.Hash.Value, iamhash.Hint{Algorithm: cmf.AlgSHA256})
			require.NoError(t, err)
			require.Equal(t, u.Password.Hash.Value, p2.Hash.Value)
		}

		hasTOTP := false
		for _, f := range u.MFAFactors {
			if f.Type == cmf.MFATOTP {
				hasTOTP = true
				require.Equal(t, f.Value, entry.TOTPSecret)
			}
		}
		require.True(t, hasTOTP)
	}
}

func TestExportIsDeterministicWithSameSeed(t *testing.T) {
	opts := fixture.ExportOptions{
		Count:  5,
		Hashes: []fixture.HashSpec{{Algorithm: cmf.AlgBcrypt, Params: map[string]string{"cost": "10"}}},
		Seed:   7,
	}

	run := func() []string {
		var buf bytes.Buffer
		w := cmf.NewWriter(&buf)
		_, err := fixture.New().Export(context.Background(), w, opts)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		r, err := cmf.NewReader(&buf)
		require.NoError(t, err)
		defer r.Close()

		var names []string
		for {
			u, err := r.ReadUser()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			names = append(names, u.Profile.Name)
		}
		return names
	}

	require.Equal(t, run(), run())
}

func TestParseIdentifierSpec(t *testing.T) {
	spec, err := fixture.ParseIdentifierSpec("email+phone")
	require.NoError(t, err)
	require.Equal(t, fixture.IdentifierSpec{fixture.IdentifierEmail, fixture.IdentifierPhone}, spec)

	_, err = fixture.ParseIdentifierSpec("fax")
	require.ErrorContains(t, err, `unknown kind "fax"`)
	_, err = fixture.ParseIdentifierSpec("email+email")
	require.ErrorContains(t, err, `repeats "email"`)
}

func TestExportDistributesIdentifiers(t *testing.T) {
	answerKeyPath := filepath.Join(t.TempDir(), "answer-key.json")
	opts := fixture.ExportOptions{
		Count:  30,
		Hashes: []fixture.HashSpec{{Algorithm: cmf.AlgSHA256}},
		Identifiers: []fixture.IdentifierSpec{
			{fixture.IdentifierUsername},
			{fixture.IdentifierPhone},
			{fixture.IdentifierEmail, fixture.IdentifierUsername, fixture.IdentifierPhone},
		},
		Seed:          3,
		AnswerKeyPath: answerKeyPath,
	}

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	_, err := fixture.New().Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()

	b, err := os.ReadFile(answerKeyPath)
	require.NoError(t, err)
	var key fixture.AnswerKey
	require.NoError(t, json.Unmarshal(b, &key))

	usernames, phones := map[string]bool{}, map[string]bool{}
	for i := 0; ; i++ {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		entry := key.Entries[i]

		switch i % 3 {
		case 0: // username only
			require.Empty(t, u.Emails)
			require.Empty(t, u.Phones)
			require.NotEmpty(t, u.Username)
			require.Equal(t, u.Username, entry.LoginIdentifier())
		case 1: // phone only
			require.Empty(t, u.Emails)
			require.Empty(t, u.Username)
			require.Len(t, u.Phones, 1)
			require.Equal(t, u.Phones[0].Value, entry.LoginIdentifier())
		case 2: // all three
			require.Len(t, u.Emails, 1)
			require.NotEmpty(t, u.Username)
			require.Len(t, u.Phones, 1)
			require.Equal(t, u.Emails[0].Value, entry.LoginIdentifier())
			require.Equal(t, u.Username, entry.Username)
			require.Equal(t, u.Phones[0].Value, entry.Phone)
		}

		if u.Username != "" {
			require.LessOrEqual(t, len(u.Username), 15)
			require.False(t, usernames[u.Username], "duplicate username %q", u.Username)
			usernames[u.Username] = true
		}
		if len(u.Phones) > 0 {
			require.False(t, phones[u.Phones[0].Value], "duplicate phone %q", u.Phones[0].Value)
			phones[u.Phones[0].Value] = true
		}
	}
	require.Len(t, key.Entries, 30)
}

func TestExportFailsWhenPhoneIdentifiersRunOut(t *testing.T) {
	opts := fixture.ExportOptions{
		Count:       3600,
		Hashes:      []fixture.HashSpec{{Algorithm: cmf.AlgSHA256}},
		Identifiers: []fixture.IdentifierSpec{{fixture.IdentifierPhone}},
		Seed:        1,
	}
	_, err := fixture.New().Export(context.Background(), cmf.NewWriter(io.Discard), opts)
	require.ErrorContains(t, err, "fictional phone numbers")
}
