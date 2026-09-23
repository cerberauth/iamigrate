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
	"github.com/cerberauth/iamigrate/pkg/progress"
)

// Connector is a SourceConnector generating synthetic CMF users. It's used
// both directly by `iamigrate testdata generate` and, indirectly, as the
// rehearsal path every other connector's validate/import/diff steps also
// run — see DESIGN.md's end-to-end flow diagram.
type Connector struct{}

func New() *Connector { return &Connector{} }

func (*Connector) Name() string { return "fixture" }

// Export generates opts.Count synthetic users, distributing hash
// algorithms and login identifiers evenly across opts.Hashes and
// opts.Identifiers and drawing MFA enrollment independently per opts.MFAs,
// then writes them to w. If
// opts.AnswerKeyPath is set, it also writes answer-key.json.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	opts, ok := eo.(ExportOptions)
	if !ok {
		return connector.Manifest{}, fmt.Errorf("fixture: Export requires fixture.ExportOptions, got %T", eo)
	}
	if len(opts.Hashes) == 0 {
		return connector.Manifest{}, fmt.Errorf("fixture: at least one --hash spec is required")
	}
	identifiers := opts.Identifiers
	if len(identifiers) == 0 {
		identifiers = []IdentifierSpec{{IdentifierEmail}}
	}

	seed := uint64(opts.Seed) //nolint:gosec // deterministic-seed use only, not security sensitive
	f := gofakeit.New(seed)

	manifest := connector.Manifest{
		HashAlgorithmCounts:  map[cmf.Algorithm]int{},
		NonPortableMFACounts: map[cmf.MFAType]int{},
	}
	var answerKey AnswerKey
	emails := map[string]bool{}
	usernames := map[string]bool{}
	phones := map[string]bool{}
	bar := progress.FromContext(ctx)

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
		ids := identifiers[i%len(identifiers)]
		phone := fictionalPhone(f)
		if ids.has(IdentifierPhone) {
			if phone, err = uniquePhone(f, phones, phone); err != nil {
				return manifest, err
			}
		}
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
			Phones:     phoneContacts(phone, ids, mfaFactors),
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
		entry := AnswerKeyEntry{SourceID: sourceID, Password: password, TOTPSecret: totpSecret}
		if ids.has(IdentifierEmail) {
			u.Emails = []cmf.Contact{{Value: email, Verified: true, Primary: true}}
			entry.Email = email
		}
		if ids.has(IdentifierUsername) {
			u.Username = uniqueUsername(usernames, given, family)
			entry.Username = u.Username
		}
		if ids.has(IdentifierPhone) {
			entry.Phone = phone
		}
		if err := w.WriteUser(u); err != nil {
			return manifest, fmt.Errorf("fixture: writing user %s: %w", sourceID, err)
		}
		manifest.RecordCount++
		bar.Add(1)

		if opts.AnswerKeyPath != "" {
			answerKey.Entries = append(answerKey.Entries, entry)
		}
	}

	if opts.AnswerKeyPath != "" {
		if err := WriteAnswerKey(opts.AnswerKeyPath, answerKey); err != nil {
			return manifest, err
		}
	}

	return manifest, nil
}

// phoneContacts returns the user's phone contact when phone is one of their
// login identifiers or they're enrolled in SMS MFA.
func phoneContacts(phone string, ids IdentifierSpec, factors []cmf.MFAFactor) []cmf.Contact {
	if ids.has(IdentifierPhone) {
		return []cmf.Contact{{Value: phone, Verified: true, Primary: true}}
	}
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

// usernameMaxLen keeps fixture usernames within Auth0's default username
// length limit (15), counter suffix included.
const usernameMaxLen = 15

// uniqueUsername derives a "given.family" username from the user's name,
// truncated to fit usernameMaxLen and suffixed with a counter when taken.
func uniqueUsername(seen map[string]bool, given, family string) string {
	base := emailLocalPart(given) + "." + emailLocalPart(family)
	username := truncate(base, usernameMaxLen)
	for n := 2; seen[username]; n++ {
		suffix := strconv.Itoa(n)
		username = truncate(base, usernameMaxLen-len(suffix)) + suffix
	}
	seen[username] = true
	return username
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
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

// fixtureAreaCodes are assigned NANP area codes, so phone numbers pass
// libphonenumber-based validation (e.g. Kratos' "tel" format), which
// rejects unassigned ones.
var fixtureAreaCodes = []string{
	"201", "202", "203", "206", "210", "212", "213", "214", "215", "216",
	"267", "301", "303", "305", "310", "312", "313", "314", "347", "401",
	"402", "404", "407", "410", "415", "469", "503", "512", "602", "617",
	"646", "702", "718", "773", "818",
}

// fictionalPhoneCount is how many distinct numbers fictionalPhone can draw.
var fictionalPhoneCount = len(fixtureAreaCodes) * 100

// fictionalPhone returns an E.164 number in the NANP 555-0100..0199 range,
// which is reserved for fictional use and never assigned to a subscriber.
func fictionalPhone(f *gofakeit.Faker) string {
	return fmt.Sprintf("+1%s555%04d", f.RandomString(fixtureAreaCodes), f.IntRange(100, 199))
}

// uniquePhone redraws phone until it's not already in seen, since a phone
// used as a login identifier must be unique. It fails once every fictional
// number is taken.
func uniquePhone(f *gofakeit.Faker, seen map[string]bool, phone string) (string, error) {
	if len(seen) >= fictionalPhoneCount {
		return "", fmt.Errorf("fixture: only %d fictional phone numbers exist; generate fewer users with a phone identifier", fictionalPhoneCount)
	}
	for seen[phone] {
		phone = fictionalPhone(f)
	}
	seen[phone] = true
	return phone, nil
}

func randomSourceID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "fx_" + hex.EncodeToString(b), nil
}
