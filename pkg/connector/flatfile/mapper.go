package flatfile

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// Recognized source column names. A source using this convention needs no
// mapping.yaml edits (see DESIGN.md's "simple case" round-trip); any
// other column is carried through as app_metadata so nothing is silently
// dropped, and flagged as a manual mapping step by `iamigrate map`. A column
// named app_metadata.<key> or user_metadata.<key> is placed explicitly.
const (
	colSourceID          = "source_id"
	colEmail             = "email"
	colEmailVerified     = "email_verified"
	colUsername          = "username"
	colGivenName         = "given_name"
	colFamilyName        = "family_name"
	colLocale            = "locale"
	colBlocked           = "blocked"
	colPassword          = "password"
	colPasswordAlgorithm = "password_algorithm"
	// The columns below describe a raw digest (md5, sha1, sha256, sha512)
	// whose encoding can't be guessed or whose salt is kept apart; a
	// self-describing hash (bcrypt, PHC, LDAP) needs none of them.
	colPasswordEncoding     = "password_encoding"
	colPasswordSalt         = "password_salt"
	colPasswordSaltEncoding = "password_salt_encoding"
	colPasswordSaltPosition = "password_salt_position"

	appMetadataPrefix  = "app_metadata."
	userMetadataPrefix = "user_metadata."
)

// rowToUser converts one flat row into a CMF user. skipReason is non-empty
// when the row can't be represented (e.g. no source_id).
func rowToUser(row map[string]string, hints map[string]cmf.Algorithm) (cmf.User, string, error) {
	sourceID := row[colSourceID]
	if sourceID == "" {
		return cmf.User{}, "missing source_id", nil
	}

	u := cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   sourceID,
		Username:   row[colUsername],
		Profile: cmf.Profile{
			GivenName:  row[colGivenName],
			FamilyName: row[colFamilyName],
			Locale:     row[colLocale],
		},
		Blocked: parseBool(row[colBlocked]),
		Provenance: cmf.Provenance{
			SourceConnector: Name,
			ExportedAt:      time.Now().UTC(),
		},
	}
	if u.Profile.GivenName != "" || u.Profile.FamilyName != "" {
		u.Profile.Name = strings.TrimSpace(u.Profile.GivenName + " " + u.Profile.FamilyName)
	}
	if row[colEmail] != "" {
		verified := true
		if v := row[colEmailVerified]; v != "" {
			verified = parseBool(v)
		}
		u.Emails = []cmf.Contact{{Value: row[colEmail], Verified: verified, Primary: true}}
	}

	if raw := row[colPassword]; raw != "" {
		hint, reason := passwordHint(row, hints)
		if reason != "" {
			return cmf.User{}, reason, nil
		}
		pw, err := iamhash.Normalize(raw, hint)
		if err != nil {
			return cmf.User{}, fmt.Sprintf("password normalization failed: %v", err), nil
		}
		u.Password = &pw
	}

	known := map[string]bool{
		colSourceID: true, colEmail: true, colEmailVerified: true, colUsername: true,
		colGivenName: true, colFamilyName: true, colLocale: true, colBlocked: true,
		colPassword: true, colPasswordAlgorithm: true, colPasswordEncoding: true,
		colPasswordSalt: true, colPasswordSaltEncoding: true, colPasswordSaltPosition: true,
	}
	for k, v := range row {
		if known[k] || v == "" {
			continue
		}
		switch {
		case strings.HasPrefix(k, userMetadataPrefix):
			if u.UserMetadata == nil {
				u.UserMetadata = map[string]any{}
			}
			u.UserMetadata[strings.TrimPrefix(k, userMetadataPrefix)] = v
		default:
			if u.AppMetadata == nil {
				u.AppMetadata = map[string]any{}
			}
			u.AppMetadata[strings.TrimPrefix(k, appMetadataPrefix)] = v
		}
	}

	return u, "", nil
}

// passwordHint reads the columns describing a password hash into the hint
// pkg/hash needs. reason is non-empty when they can't be used.
func passwordHint(row map[string]string, hints map[string]cmf.Algorithm) (hint iamhash.Hint, reason string) {
	if a, ok := hints[colPassword]; ok {
		hint.Algorithm = a
	} else if a := row[colPasswordAlgorithm]; a != "" {
		alg, err := iamhash.ParseAlgorithm(a)
		if err != nil {
			return hint, fmt.Sprintf("%s: %v", colPasswordAlgorithm, err)
		}
		hint.Algorithm = alg
	}

	if e := row[colPasswordEncoding]; e != "" {
		enc, err := parseEncoding(e, cmf.EncodingHex, cmf.EncodingBase64)
		if err != nil {
			return hint, fmt.Sprintf("%s: %v", colPasswordEncoding, err)
		}
		hint.Encoding = enc
	}

	if s := row[colPasswordSalt]; s != "" {
		if row[colPasswordSaltEncoding] == "" {
			return hint, fmt.Sprintf("%s needs %s (hex, base64 or utf8): it can't be guessed", colPasswordSalt, colPasswordSaltEncoding)
		}
		enc, err := parseEncoding(row[colPasswordSaltEncoding], cmf.EncodingHex, cmf.EncodingBase64, cmf.EncodingUTF8)
		if err != nil {
			return hint, fmt.Sprintf("%s: %v", colPasswordSaltEncoding, err)
		}
		if hint.Salt, err = iamhash.DecodeBytes(s, enc); err != nil {
			return hint, fmt.Sprintf("%s: %v", colPasswordSalt, err)
		}
	}
	if p := strings.ToLower(strings.TrimSpace(row[colPasswordSaltPosition])); p != "" {
		switch pos := cmf.SaltPosition(p); pos {
		case cmf.SaltPrefix, cmf.SaltSuffix:
			hint.SaltPosition = pos
		default:
			return hint, fmt.Sprintf("%s: %q is neither prefix nor suffix", colPasswordSaltPosition, row[colPasswordSaltPosition])
		}
	}
	return hint, ""
}

// parseEncoding returns the encoding named by s, which must be one of
// allowed.
func parseEncoding(s string, allowed ...cmf.Encoding) (cmf.Encoding, error) {
	enc := cmf.Encoding(strings.ToLower(strings.TrimSpace(s)))
	for _, a := range allowed {
		if enc == a {
			return enc, nil
		}
	}
	names := make([]string, len(allowed))
	for i, a := range allowed {
		names[i] = string(a)
	}
	return "", fmt.Errorf("%q is not one of %s", s, strings.Join(names, ", "))
}

func parseBool(s string) bool {
	b, _ := strconv.ParseBool(s)
	return b
}

// userToRow flattens a CMF user into a string-keyed row for CSV/JSON
// output. m.Fields, when present, renames CMF field names to
// target-specific column names for a custom target mapping; unmapped
// fields use the CMF field name itself.
func userToRow(u cmf.User, m mapping.Mapping) map[string]string {
	row := map[string]string{
		col(m, "source_id"):   u.SourceID,
		col(m, "username"):    u.Username,
		col(m, "given_name"):  u.Profile.GivenName,
		col(m, "family_name"): u.Profile.FamilyName,
		col(m, "locale"):      u.Profile.Locale,
		col(m, "blocked"):     strconv.FormatBool(u.Blocked),
	}
	if len(u.Emails) > 0 {
		row[col(m, "email")] = u.Emails[0].Value
	}
	if u.Password != nil {
		row[col(m, "password_algorithm")] = string(u.Password.Algorithm)
		row[col(m, "password_hash")] = u.Password.Hash.Value
		row[col(m, "password_encoding")] = string(u.Password.Hash.Encoding)
	}
	if len(u.MFAFactors) > 0 {
		types := make([]string, 0, len(u.MFAFactors))
		for _, f := range u.MFAFactors {
			types = append(types, string(f.Type))
		}
		row[col(m, "mfa_types")] = strings.Join(types, ";")
	}
	return row
}

func col(m mapping.Mapping, cmfField string) string {
	for _, f := range m.Fields {
		if f.CMF == cmfField {
			return f.Source
		}
	}
	return cmfField
}
