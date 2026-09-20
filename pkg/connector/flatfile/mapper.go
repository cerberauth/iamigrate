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
// dropped, and flagged as a manual mapping step by `iamigrate map`.
const (
	colSourceID          = "source_id"
	colEmail             = "email"
	colUsername          = "username"
	colGivenName         = "given_name"
	colFamilyName        = "family_name"
	colLocale            = "locale"
	colBlocked           = "blocked"
	colPassword          = "password"
	colPasswordAlgorithm = "password_algorithm"
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
		u.Emails = []cmf.Contact{{Value: row[colEmail], Verified: true, Primary: true}}
	}

	if raw := row[colPassword]; raw != "" {
		hint := iamhash.Hint{}
		if a, ok := hints[colPassword]; ok {
			hint.Algorithm = a
		} else if a := row[colPasswordAlgorithm]; a != "" {
			hint.Algorithm = cmf.Algorithm(a)
		}
		pw, err := iamhash.Normalize(raw, hint)
		if err != nil {
			return cmf.User{}, fmt.Sprintf("password normalization failed: %v", err), nil
		}
		u.Password = &pw
	}

	known := map[string]bool{
		colSourceID: true, colEmail: true, colUsername: true, colGivenName: true,
		colFamilyName: true, colLocale: true, colBlocked: true, colPassword: true,
		colPasswordAlgorithm: true,
	}
	for k, v := range row {
		if known[k] || v == "" {
			continue
		}
		if u.AppMetadata == nil {
			u.AppMetadata = map[string]any{}
		}
		u.AppMetadata[k] = v
	}

	return u, "", nil
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
