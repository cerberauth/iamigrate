package cmf_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
)

func sampleUser(sourceID string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   sourceID,
		Emails: []cmf.Contact{
			{Value: "jane@example.com", Verified: true, Primary: true},
		},
		Profile: cmf.Profile{GivenName: "Jane", FamilyName: "Doe", Locale: "en"},
		Password: &cmf.Password{
			Algorithm: cmf.AlgBcrypt,
			Hash:      cmf.HashValue{Value: "$2b$10$abcdefghijklmnopqrstuv", Encoding: cmf.EncodingUTF8},
			Portable:  true,
		},
		MFAFactors: []cmf.MFAFactor{
			{Type: cmf.MFATOTP, Value: "JBSWY3DPEHPK3PXP", Portable: true},
		},
		Provenance: cmf.Provenance{
			SourceConnector: "fixture",
			ExportedAt:      time.Now().UTC(),
		},
	}
}

func TestWriterReaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)

	users := []cmf.User{sampleUser("u1"), sampleUser("u2")}
	for _, u := range users {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()

	var got []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		got = append(got, u)
	}
	require.Len(t, got, 2)
	require.Equal(t, "u1", got[0].SourceID)
	require.Equal(t, "u2", got[1].SourceID)
}

func TestWriteUserRejectsBadVersion(t *testing.T) {
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	u := sampleUser("u1")
	u.CMFVersion = "9.9"
	require.Error(t, w.WriteUser(u))
}

func TestWriteUserRejectsNullPasswordOK(t *testing.T) {
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	u := sampleUser("u1")
	u.Password = nil
	require.NoError(t, w.WriteUser(u))
}

func TestWriteUserRejectsBadAlgorithm(t *testing.T) {
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	u := sampleUser("u1")
	u.Password.Algorithm = "notreal"
	require.Error(t, w.WriteUser(u))
}

func TestOrganizationsRolesRoundTrip(t *testing.T) {
	var orgBuf, roleBuf bytes.Buffer
	orgs := []cmf.Organization{{SourceID: "o1", Name: "acme"}}
	roles := []cmf.Role{{SourceID: "r1", Name: "admin"}}
	require.NoError(t, cmf.WriteOrganizations(&orgBuf, orgs))
	require.NoError(t, cmf.WriteRoles(&roleBuf, roles))

	gotOrgs, err := cmf.ReadOrganizations(&orgBuf)
	require.NoError(t, err)
	require.Equal(t, orgs, gotOrgs)

	gotRoles, err := cmf.ReadRoles(&roleBuf)
	require.NoError(t, err)
	require.Equal(t, roles, gotRoles)
}
