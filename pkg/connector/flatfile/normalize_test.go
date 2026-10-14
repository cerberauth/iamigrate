package flatfile_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// Each directory under testdata/mappings is one source layout: an input.csv
// or input.json, the mapping.yaml describing it, and the expected.json rows
// that mapping must produce. Dropping in a new directory adds a case.
const casesDir = "testdata/mappings"

type mappingCase struct {
	name    string
	input   string
	format  flatfile.Format
	mapping mapping.Mapping
}

func loadCases(t *testing.T) []mappingCase {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(casesDir, "*"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(dirs), 2, "need several mappings to show the engine isn't tied to one")

	var cases []mappingCase
	for _, dir := range dirs {
		c := mappingCase{name: filepath.Base(dir)}
		if _, err := os.Stat(filepath.Join(dir, "input.json")); err == nil {
			c.input, c.format = filepath.Join(dir, "input.json"), flatfile.FormatJSON
		} else {
			c.input, c.format = filepath.Join(dir, "input.csv"), flatfile.FormatCSV
		}
		c.mapping, err = mapping.Load(filepath.Join(dir, "mapping.yaml"))
		require.NoError(t, err)
		cases = append(cases, c)
	}
	return cases
}

func readJSONRows(t *testing.T, path string) []map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var rows []map[string]string
	require.NoError(t, json.Unmarshal(b, &rows))
	return rows
}

func TestPrepareMappings(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.name, func(t *testing.T) {
			// Every output format must carry the same rows.
			for _, outFormat := range []flatfile.Format{flatfile.FormatJSON, flatfile.FormatCSV} {
				out := filepath.Join(t.TempDir(), "prepared."+string(outFormat))
				_, err := flatfile.Prepare(flatfile.PrepareOptions{
					In: c.input, InFormat: c.format, Out: out, OutFormat: outFormat, Mapping: c.mapping,
				})
				require.NoError(t, err)

				var got []map[string]string
				if outFormat == flatfile.FormatJSON {
					got = readJSONRows(t, out)
				} else {
					got = csvToRows(t, out)
				}
				want := readJSONRows(t, filepath.Join(casesDir, c.name, "expected.json"))
				require.Len(t, got, len(want))
				for i := range want {
					require.Equal(t, nonEmpty(want[i]), nonEmpty(got[i]), "record %d (%s)", i+1, outFormat)
				}
			}
		})
	}
}

// A prepared file must export exactly like the original does with the
// mapping, and without needing one.
func TestPreparedFileExportsLikeMappedExport(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.name, func(t *testing.T) {
			prepared := filepath.Join(t.TempDir(), "prepared.csv")
			_, err := flatfile.Prepare(flatfile.PrepareOptions{
				In: c.input, InFormat: c.format, Out: prepared, OutFormat: flatfile.FormatCSV, Mapping: c.mapping,
			})
			require.NoError(t, err)

			mapped, mappedSkips := exportUsers(t, flatfile.ExportOptions{Path: c.input, Format: c.format, Mapping: c.mapping})
			plain, plainSkips := exportUsers(t, flatfile.ExportOptions{Path: prepared, Format: flatfile.FormatCSV})
			require.Equal(t, mapped, plain)
			require.Equal(t, mappedSkips, plainSkips)
		})
	}
}

func TestMappedExportBuildsCMF(t *testing.T) {
	byCase := map[string]mappingCase{}
	for _, c := range loadCases(t) {
		byCase[c.name] = c
	}
	export := func(name string) ([]cmf.User, int) {
		c := byCase[name]
		return exportUsers(t, flatfile.ExportOptions{Path: c.input, Format: c.format, Mapping: c.mapping})
	}

	t.Run("csv-crm", func(t *testing.T) {
		users, skipped := export("csv-crm")
		require.Equal(t, 1, skipped, "the record without a UserID")
		require.Len(t, users, 2)
		jane, john := users[0], users[1]
		require.Equal(t, "c-100", jane.SourceID)
		require.Equal(t, "jane.doe@example.com", jane.Emails[0].Value)
		require.False(t, jane.Blocked)
		require.True(t, john.Blocked)
		require.Equal(t, cmf.AlgBcrypt, jane.Password.Algorithm)
		require.Nil(t, john.Password)
		require.Equal(t, "gold", jane.AppMetadata["plan"])
		require.NotContains(t, john.AppMetadata, "plan", "empty cells are not metadata")
	})

	t.Run("json-nested", func(t *testing.T) {
		users, skipped := export("json-nested")
		require.Zero(t, skipped)
		require.Len(t, users, 2)
		jane, john := users[0], users[1]
		require.Equal(t, "jane@example.com", jane.Emails[0].Value)
		require.True(t, jane.Emails[0].Verified)
		require.False(t, john.Emails[0].Verified)
		require.Equal(t, "fr-FR", jane.Profile.Locale)
		require.Equal(t, "Jane Doe", jane.Profile.Name)
		require.True(t, john.Blocked)
		require.Equal(t, cmf.AlgBcrypt, jane.Password.Algorithm)
		require.Equal(t, "gold", jane.AppMetadata["tier"])
		require.Equal(t, map[string]any{"theme": "dark"}, jane.UserMetadata)
	})

	t.Run("json-wrapped falls back to the email as source_id", func(t *testing.T) {
		users, skipped := export("json-wrapped")
		require.Equal(t, 1, skipped)
		require.Equal(t, []string{"w-1", "john@example.com"}, []string{users[0].SourceID, users[1].SourceID})
		require.Equal(t, "jsmith", users[1].Username)
	})
}

// The password fixtures hold real hashes of the passwords in passwords.json.
// Whatever the source's algorithm, encoding, salt and salt position, the
// exported CMF must still verify the clear password: recomputing the digest
// from it proves nothing was lost or misread on the way.
func TestMappedHashesVerifyAgainstClearPasswords(t *testing.T) {
	verified := 0
	for _, c := range loadCases(t) {
		b, err := os.ReadFile(filepath.Join(casesDir, c.name, "passwords.json"))
		if os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err)
		var clear map[string]string
		require.NoError(t, json.Unmarshal(b, &clear))

		t.Run(c.name, func(t *testing.T) {
			users, skipped := exportUsers(t, flatfile.ExportOptions{Path: c.input, Format: c.format, Mapping: c.mapping})
			require.Zero(t, skipped)
			for _, u := range users {
				password, hasPassword := clear[u.SourceID]
				if !hasPassword {
					require.Nil(t, u.Password, "%s has no password", u.SourceID)
					continue
				}
				require.NotNil(t, u.Password, u.SourceID)
				require.True(t, passwordMatches(t, *u.Password, password), "%s: %s hash doesn't match its password", u.SourceID, u.Password.Algorithm)
				verified++
			}
		})
	}
	require.GreaterOrEqual(t, verified, 10, "the fixtures should cover several algorithms and encodings")
}

func TestMappedHashesAreStoredCanonically(t *testing.T) {
	byName := map[string][]cmf.User{}
	for _, c := range loadCases(t) {
		byName[c.name], _ = exportUsers(t, flatfile.ExportOptions{Path: c.input, Format: c.format, Mapping: c.mapping})
	}

	salted := byName["csv-salted-hex"]
	require.Equal(t, cmf.AlgSHA256, salted[0].Password.Algorithm, `"SHA-256" is sha256`)
	require.Equal(t, "efe240d7bce44b10807f4f903caed452ddf3028166d397fd4e247bb6d3a46b72", salted[0].Password.Hash.Value, "uppercase hex is lowercased")
	require.Equal(t, cmf.SaltSuffix, salted[0].Password.Salt.Position)
	require.Equal(t, cmf.SaltPrefix, salted[1].Password.Salt.Position, `"before" is prefix`)
	require.Equal(t, cmf.EncodingBase64, salted[0].Password.Salt.Encoding, "salts are carried as base64")
	require.Equal(t, "ABEiM0RVZneImaq7zN3u/w==", salted[0].Password.Salt.Value)

	digests := byName["json-digest-base64"]
	require.Equal(t, cmf.EncodingBase64, digests[1].Password.Hash.Encoding)
	require.Equal(t, "y3HNP1mQlTK3gyV/X5fQUCryWCMfnRfL52J5nAu0oPY=", digests[1].Password.Hash.Value, "URL-safe unpadded base64 becomes standard padded")

	combined := byName["csv-combined-column"]
	require.Equal(t, "Xk29fa", string(mustDecode(t, combined[0].Password.Salt)), "the salt is cut out of the packed column")
	require.Equal(t, cmf.SaltPrefix, combined[0].Password.Salt.Position)

	mixed := byName["csv-mixed-schemes"]
	require.Equal(t, cmf.EncodingHex, mixed[0].Password.Hash.Encoding, "no encoding given: hex is detected")
	require.Equal(t, cmf.EncodingBase64, mixed[1].Password.Hash.Encoding, "no encoding given: base64 is detected")
	require.Equal(t, cmf.AlgBcrypt, mixed[2].Password.Algorithm)
	require.Equal(t, cmf.AlgLDAP, mixed[3].Password.Algorithm)
}

// What `prepare` flags: a hash that export would skip, found now rather than
// when importing.
func TestPrepareReportsUnusableHashes(t *testing.T) {
	sha256Hex := "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
	md5Hex := "5f4dcc3b5aa765d61d8327deb882cf99"
	csvFile := "id,hash,algo,enc,salt,salt_enc\n" +
		"ok," + md5Hex + ",md5,hex,,\n" +
		"wrong-algorithm," + sha256Hex + ",md5,hex,,\n" +
		"wrong-encoding," + md5Hex + ",md5,base64,,\n" +
		"not-hex,zz" + md5Hex[2:] + ",md5,hex,,\n" +
		"selfdescribing-label," + md5Hex + ",bcrypt,hex,,\n" +
		"salt-without-encoding," + md5Hex + ",md5,hex,c2FsdA==,\n" +
		"bad-salt," + md5Hex + ",md5,hex,nothex,hex\n"
	dir := t.TempDir()
	in := filepath.Join(dir, "users.csv")
	require.NoError(t, os.WriteFile(in, []byte(csvFile), 0o600))

	m := mapping.Mapping{Fields: []mapping.FieldMapping{
		{Source: "id", CMF: "source_id"}, {Source: "hash", CMF: "password"}, {Source: "algo", CMF: "password_algorithm"},
		{Source: "enc", CMF: "password_encoding"}, {Source: "salt", CMF: "password_salt"}, {Source: "salt_enc", CMF: "password_salt_encoding"},
	}}
	out := filepath.Join(dir, "prepared.csv")
	report, err := flatfile.Prepare(flatfile.PrepareOptions{In: in, InFormat: flatfile.FormatCSV, Out: out, OutFormat: flatfile.FormatCSV, Mapping: m})
	require.NoError(t, err)
	require.FileExists(t, out, "the file is still written")

	reasons := map[string]string{}
	for _, s := range report.Skipped {
		reasons[s.SourceID] = s.Reason
	}
	require.NotContains(t, reasons, "ok")
	require.Contains(t, reasons["wrong-algorithm"], "is not a md5 digest")
	require.Contains(t, reasons["wrong-encoding"], "is not a md5 digest", "hex digits decode, but to the wrong size")
	require.Contains(t, reasons["not-hex"], "not valid hex")
	require.Contains(t, reasons["selfdescribing-label"], "not a valid bcrypt hash")
	require.Contains(t, reasons["salt-without-encoding"], "password_salt_encoding")
	require.Contains(t, reasons["bad-salt"], "password_salt")
	require.Len(t, report.Skipped, 6)
}

func TestMappingErrors(t *testing.T) {
	csvPath := filepath.Join(t.TempDir(), "users.csv")
	require.NoError(t, os.WriteFile(csvPath, []byte("id,active\n1,maybe\n"), 0o644))
	jsonObj := filepath.Join(t.TempDir(), "users.json")
	require.NoError(t, os.WriteFile(jsonObj, []byte(`{"users": [{"id": "1"}]}`), 0o644))

	prepare := func(in string, format flatfile.Format, m mapping.Mapping) error {
		_, err := flatfile.Prepare(flatfile.PrepareOptions{
			In: in, InFormat: format, Out: filepath.Join(t.TempDir(), "out.csv"), OutFormat: flatfile.FormatCSV, Mapping: m,
		})
		return err
	}
	field := func(f mapping.FieldMapping) mapping.Mapping {
		return mapping.Mapping{Fields: []mapping.FieldMapping{f}}
	}

	t.Run("unknown cmf field", func(t *testing.T) {
		require.ErrorContains(t, prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{Source: "id", CMF: "mail"})), `unknown cmf field "mail"`)
	})
	t.Run("empty metadata key", func(t *testing.T) {
		require.ErrorContains(t, prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{Source: "id", CMF: "app_metadata."})), "unknown cmf field")
	})
	t.Run("unknown transform", func(t *testing.T) {
		require.ErrorContains(t, prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{Source: "id", CMF: "source_id", Transform: "trim|reverse"})), `unknown transform "reverse"`)
	})
	t.Run("neither source nor default", func(t *testing.T) {
		require.ErrorContains(t, prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{CMF: "source_id"})), "needs a source, a default, or both")
	})
	t.Run("value that is not a boolean", func(t *testing.T) {
		err := prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{Source: "active", CMF: "blocked"}))
		require.ErrorContains(t, err, "record 1")
		require.ErrorContains(t, err, `"maybe" is not a boolean`)
	})
	t.Run("unknown password algorithm", func(t *testing.T) {
		err := prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{CMF: "password_algorithm", Default: "rot13"}))
		require.ErrorContains(t, err, "record 1")
		require.ErrorContains(t, err, `unknown algorithm "rot13"`)
	})
	t.Run("unknown password encoding", func(t *testing.T) {
		require.ErrorContains(t, prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{CMF: "password_encoding", Default: "base32"})), `"base32" is not one of hex, base64`)
	})
	t.Run("unknown salt position", func(t *testing.T) {
		require.ErrorContains(t, prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{CMF: "password_salt_position", Default: "before"})), "neither prefix nor suffix")
	})
	t.Run("pattern that is not a regular expression", func(t *testing.T) {
		require.ErrorContains(t, prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{Source: "id", CMF: "source_id", Pattern: "("})), "pattern")
	})
	t.Run("pattern without a capture group", func(t *testing.T) {
		require.ErrorContains(t, prepare(csvPath, flatfile.FormatCSV, field(mapping.FieldMapping{Source: "id", CMF: "source_id", Pattern: `\d+`})), "needs a capture group")
	})
	t.Run("JSON object root needs records_path", func(t *testing.T) {
		require.ErrorContains(t, prepare(jsonObj, flatfile.FormatJSON, mapping.Mapping{}), "records_path")
	})
	t.Run("records_path that does not exist", func(t *testing.T) {
		require.ErrorContains(t, prepare(jsonObj, flatfile.FormatJSON, mapping.Mapping{RecordsPath: "data.users"}), `no "data" key`)
	})
	t.Run("output is the input", func(t *testing.T) {
		_, err := flatfile.Prepare(flatfile.PrepareOptions{In: csvPath, InFormat: flatfile.FormatCSV, Out: csvPath, OutFormat: flatfile.FormatCSV})
		require.ErrorContains(t, err, "must differ")
	})
}

func TestPrepareCSVWithBOMAndDeterministicColumns(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "users.csv")
	require.NoError(t, os.WriteFile(in, []byte("\xEF\xBB\xBFuid,mail,zeta,alpha\nu1,jane@example.com,z,a\n"), 0o644))
	out := filepath.Join(dir, "prepared.csv")

	report, err := flatfile.Prepare(flatfile.PrepareOptions{
		In: in, InFormat: flatfile.FormatCSV, Out: out, OutFormat: flatfile.FormatCSV,
		Mapping: mapping.Mapping{Fields: []mapping.FieldMapping{
			{Source: "uid", CMF: "source_id"},
			{Source: "mail", CMF: "email"},
		}},
	})
	require.NoError(t, err, "a BOM must not be glued to the first column's name")
	require.Equal(t, flatfile.PrepareReport{Records: 1}, report)

	b, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, "source_id,email,alpha,zeta\nu1,jane@example.com,a,z\n", string(b))
	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the file can hold password hashes")
}

// exportUsers runs a flat-file export and returns the users, with the
// export time zeroed, and the number of skipped records.
func exportUsers(t *testing.T, opts flatfile.ExportOptions) ([]cmf.User, int) {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	manifest, err := flatfile.New().Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return users, len(manifest.SkippedRecords)
		}
		require.NoError(t, err)
		u.Provenance.ExportedAt = time.Time{}
		users = append(users, u)
	}
}

func csvToRows(t *testing.T, path string) []map[string]string {
	t.Helper()
	in := filepath.Join(t.TempDir(), "in.csv")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(in, b, 0o600))
	// Prepare with no fields reads the CSV back as-is, as JSON.
	out := filepath.Join(t.TempDir(), "out.json")
	_, err = flatfile.Prepare(flatfile.PrepareOptions{In: in, InFormat: flatfile.FormatCSV, Out: out, OutFormat: flatfile.FormatJSON})
	require.NoError(t, err)
	return readJSONRows(t, out)
}

// nonEmpty drops empty cells: a CSV has a column for every key any record
// has, while JSON rows only carry their own.
func nonEmpty(row map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range row {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

func mustDecode(t *testing.T, salt *cmf.SaltValue) []byte {
	t.Helper()
	b, err := iamhash.DecodeBytes(salt.Value, salt.Encoding)
	require.NoError(t, err)
	return b
}

// passwordMatches checks clear against p the way the source system did:
// bcrypt and LDAP SSHA by their own rules, raw digests as
// digest(salt + password) or digest(password + salt).
func passwordMatches(t *testing.T, p cmf.Password, clear string) bool {
	t.Helper()
	switch p.Algorithm {
	case cmf.AlgBcrypt:
		return bcrypt.CompareHashAndPassword([]byte(p.Hash.Value), []byte(clear)) == nil
	case cmf.AlgLDAP:
		require.Equal(t, "SSHA", p.Params["scheme"])
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(p.Hash.Value, "{SSHA}"))
		require.NoError(t, err)
		sum := sha1.Sum(append([]byte(clear), raw[sha1.Size:]...))
		return bytes.Equal(sum[:], raw[:sha1.Size])
	}

	digests := map[cmf.Algorithm]func([]byte) []byte{
		cmf.AlgMD5:    func(b []byte) []byte { s := md5.Sum(b); return s[:] },
		cmf.AlgSHA1:   func(b []byte) []byte { s := sha1.Sum(b); return s[:] },
		cmf.AlgSHA256: func(b []byte) []byte { s := sha256.Sum256(b); return s[:] },
		cmf.AlgSHA512: func(b []byte) []byte { s := sha512.Sum512(b); return s[:] },
	}
	digest, ok := digests[p.Algorithm]
	require.True(t, ok, "no verifier for %s", p.Algorithm)

	want, err := iamhash.DecodeBytes(p.Hash.Value, p.Hash.Encoding)
	require.NoError(t, err)
	data := []byte(clear)
	if p.Salt != nil {
		salt := mustDecode(t, p.Salt)
		if p.Salt.Position == cmf.SaltPrefix {
			data = append(salt, data...)
		} else {
			data = append(data, salt...)
		}
	}
	return bytes.Equal(digest(data), want)
}
