package fixture

import (
	"crypto/rand"
	"encoding/base32"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/cerberauth/iamigrate/pkg/cmf"
)

func randomTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// generateMFAFactors draws, independently for each spec, whether this user
// is enrolled in that factor type, per spec.Rate.
func generateMFAFactors(f *gofakeit.Faker, specs []MFASpec, email, phone string) ([]cmf.MFAFactor, string) {
	var factors []cmf.MFAFactor
	var totpSecret string
	now := time.Now().UTC()

	for _, spec := range specs {
		if f.Float64Range(0, 1) > spec.Rate {
			continue
		}
		switch spec.Type {
		case cmf.MFATOTP:
			totpSecret = randomTOTPSecret()
			factors = append(factors, cmf.MFAFactor{
				Type: cmf.MFATOTP, Value: totpSecret, Portable: true, EnrolledAt: &now,
			})
		case cmf.MFASMS:
			factors = append(factors, cmf.MFAFactor{Type: cmf.MFASMS, Value: phone, Portable: true, EnrolledAt: &now})
		case cmf.MFAEmail:
			factors = append(factors, cmf.MFAFactor{Type: cmf.MFAEmail, Value: email, Portable: true, EnrolledAt: &now})
		case cmf.MFAWebAuthn:
			factors = append(factors, cmf.MFAFactor{Type: cmf.MFAWebAuthn, Value: "opaque-credential-id", Portable: false, EnrolledAt: &now})
		case cmf.MFARecoveryCodes:
			factors = append(factors, cmf.MFAFactor{Type: cmf.MFARecoveryCodes, Value: "opaque-recovery-codes", Portable: false, EnrolledAt: &now})
		case cmf.MFAPush:
			factors = append(factors, cmf.MFAFactor{Type: cmf.MFAPush, Value: "opaque-device-token", Portable: true, EnrolledAt: &now})
		}
	}
	return factors, totpSecret
}
