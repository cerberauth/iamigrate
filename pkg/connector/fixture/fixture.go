package fixture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
)

// Connector is a SourceConnector generating synthetic CMF users. It's used
// both directly by `iamigrate testdata generate` and, indirectly, as the
// rehearsal path every other connector's validate/import/diff steps also
// run — see DESIGN.md's end-to-end flow diagram.
type Connector struct{}

func New() *Connector { return &Connector{} }

func (*Connector) Name() string { return "fixture" }

// Export generates opts.Count synthetic users, distributing hash
// algorithms evenly across opts.Hashes and drawing MFA enrollment
// independently per opts.MFAs, then writes them to w. If
// opts.AnswerKeyPath is set, it also writes answer-key.json.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	opts, ok := eo.(ExportOptions)
	if !ok {
		return connector.Manifest{}, fmt.Errorf("fixture: Export requires fixture.ExportOptions, got %T", eo)
	}
	if len(opts.Hashes) == 0 {
		return connector.Manifest{}, fmt.Errorf("fixture: at least one --hash spec is required")
	}

	seed := uint64(opts.Seed) //nolint:gosec // deterministic-seed use only, not security sensitive
	f := gofakeit.New(seed)

	manifest := connector.Manifest{
		HashAlgorithmCounts:  map[cmf.Algorithm]int{},
		NonPortableMFACounts: map[cmf.MFAType]int{},
	}
	var answerKey AnswerKey
	emails := map[string]bool{}

	now := time.Now().UTC()
	for i := 0; i < opts.Count; i++ {
		select {
		case <-ctx.Done():
			return manifest, ctx.Err()
		default:
		}

		sourceID, err := randomSourceID()
		if err != nil {
			return manifest, err
		}

		given := f.FirstName()
		family := f.LastName()
		email := uniqueEmail(f, emails, given, family)
		phone := fictionalPhone(f)
		password := f.Password(true, true, true, true, false, 16)

		spec := opts.Hashes[i%len(opts.Hashes)]
		pw, err := generatePassword(spec, password)
		if err != nil {
			return manifest, fmt.Errorf("fixture: generating password for %s: %w", sourceID, err)
		}
		manifest.HashAlgorithmCounts[pw.Algorithm]++

		mfaFactors, totpSecret := generateMFAFactors(f, opts.MFAs, email, phone)
		for _, mfa := range mfaFactors {
			if !mfa.Portable {
				manifest.NonPortableMFACounts[mfa.Type]++
			}
		}

		u := cmf.User{
			CMFVersion: cmf.Version,
			SourceID:   sourceID,
			Emails:     []cmf.Contact{{Value: email, Verified: true, Primary: true}},
			Phones:     phoneContacts(phone, mfaFactors),
			Profile: cmf.Profile{
				GivenName:  given,
				FamilyName: family,
				Name:       given + " " + family,
				Locale:     opts.Locale,
			},
			Password:   &pw,
			MFAFactors: mfaFactors,
			Provenance: cmf.Provenance{
				SourceConnector: "fixture",
				ExportedAt:      now,
			},
		}
		if err := w.WriteUser(u); err != nil {
			return manifest, fmt.Errorf("fixture: writing user %s: %w", sourceID, err)
		}
		manifest.RecordCount++

		if opts.AnswerKeyPath != "" {
			answerKey.Entries = append(answerKey.Entries, AnswerKeyEntry{
				SourceID:   sourceID,
				Email:      email,
				Password:   password,
				TOTPSecret: totpSecret,
			})
		}
	}

	if opts.AnswerKeyPath != "" {
		if err := WriteAnswerKey(opts.AnswerKeyPath, answerKey); err != nil {
			return manifest, err
		}
	}

	return manifest, nil
}

func phoneContacts(phone string, factors []cmf.MFAFactor) []cmf.Contact {
	for _, f := range factors {
		if f.Type == cmf.MFASMS {
			return []cmf.Contact{{Value: phone, Verified: true, Primary: true}}
		}
	}
	return nil
}

// fixtureEmailDomains are RFC 2606 reserved domains, so importing fixtures
// into a real IdP can never send mail to a real inbox.
var fixtureEmailDomains = []string{"example.com", "example.net", "example.org"}

// uniqueEmail derives a "given.family@domain" address from the user's name,
// appending a counter to the local part when that name was already taken.
func uniqueEmail(f *gofakeit.Faker, seen map[string]bool, given, family string) string {
	local := emailLocalPart(given) + "." + emailLocalPart(family)
	domain := f.RandomString(fixtureEmailDomains)
	email := local + "@" + domain
	for n := 2; seen[email]; n++ {
		email = local + strconv.Itoa(n) + "@" + domain
	}
	seen[email] = true
	return email
}

func emailLocalPart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fictionalPhone returns an E.164 number in the NANP 555-0100..0199 range,
// which is reserved for fictional use and never assigned to a subscriber.
func fictionalPhone(f *gofakeit.Faker) string {
	return fmt.Sprintf("+1%d%02d555%04d", f.IntRange(2, 9), f.IntRange(0, 99), f.IntRange(100, 199))
}

func randomSourceID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "fx_" + hex.EncodeToString(b), nil
}
