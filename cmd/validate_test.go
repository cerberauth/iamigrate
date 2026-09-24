package cmd

import (
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/stretchr/testify/require"
)

func TestCheckUser(t *testing.T) {
	caps := connector.Capabilities{
		HashAlgorithms: []cmf.Algorithm{cmf.AlgBcrypt},
		MFATypes:       []cmf.MFAType{cmf.MFATOTP},
	}

	tests := []struct {
		name string
		user cmf.User
		want []connector.Problem
	}{
		{
			name: "supported algorithm and MFA type: no problems",
			user: cmf.User{
				SourceID: "u1",
				Password: &cmf.Password{Algorithm: cmf.AlgBcrypt},
				MFAFactors: []cmf.MFAFactor{
					{Type: cmf.MFATOTP, Portable: true},
				},
			},
			want: nil,
		},
		{
			name: "unsupported algorithm",
			user: cmf.User{SourceID: "u2", Password: &cmf.Password{Algorithm: cmf.AlgSHA1}},
			want: []connector.Problem{
				{SourceID: "u2", Field: "password.algorithm", Rule: "unsupported by target", Value: "sha1"},
			},
		},
		{
			name: "unsupported portable MFA type",
			user: cmf.User{
				SourceID:   "u3",
				MFAFactors: []cmf.MFAFactor{{Type: cmf.MFASMS, Portable: true}},
			},
			want: []connector.Problem{
				{SourceID: "u3", Field: "mfa_factors.type", Rule: "unsupported by target", Value: "sms"},
			},
		},
		{
			name: "non-portable unsupported MFA type is not flagged",
			user: cmf.User{
				SourceID:   "u4",
				MFAFactors: []cmf.MFAFactor{{Type: cmf.MFASMS, Portable: false}},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, checkUser(tt.user, caps))
		})
	}
}

func TestDupTracker(t *testing.T) {
	d := newDupTracker()

	require.Empty(t, d.check(cmf.User{
		SourceID: "u1",
		Emails:   []cmf.Contact{{Value: "a@example.com"}},
		Username: "alice",
		Phones:   []cmf.Contact{{Value: "+14155552671"}},
	}))

	problems := d.check(cmf.User{
		SourceID: "u2",
		Emails:   []cmf.Contact{{Value: "A@EXAMPLE.COM"}},
		Username: "alice",
		Phones:   []cmf.Contact{{Value: "+14155552671"}},
	})
	require.Len(t, problems, 3)
	for _, p := range problems {
		require.Equal(t, "u2", p.SourceID)
		require.Equal(t, "duplicate of u1 within file", p.Rule)
	}

	require.Empty(t, d.check(cmf.User{
		SourceID: "u3",
		Emails:   []cmf.Contact{{Value: "c@example.com"}},
		Username: "carol",
		Phones:   []cmf.Contact{{Value: "+14155552672"}},
	}))
}

func TestProblemString(t *testing.T) {
	p := connector.Problem{SourceID: "u1", Field: "username", Rule: "length must be 1-15 characters", Value: "toolongusername"}
	require.Equal(t, `u1: username length must be 1-15 characters (value="toolongusername")`, p.String())
}
