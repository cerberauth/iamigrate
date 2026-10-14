package cmd

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/fixture"
	"github.com/cerberauth/iamigrate/pkg/password"
	"github.com/spf13/cobra"
)

// setPasswordsAlgorithms are the password hashes `set-passwords` can write:
// the memory-hard or iterated ones. The fast digests the fixture generator
// also knows (md5, sha1, ...) are not offered for new credentials.
var setPasswordsAlgorithms = []cmf.Algorithm{cmf.AlgBcrypt, cmf.AlgArgon2, cmf.AlgPBKDF2, cmf.AlgScrypt}

type setPasswordsOptions struct {
	in, out, passwordsOut string
	hash                  fixture.HashSpec
	length                int
	overwrite             bool
}

func newSetPasswordsCmd() *cobra.Command {
	var (
		opts     setPasswordsOptions
		hashSpec string
	)

	cmd := &cobra.Command{
		Use:   "set-passwords",
		Short: "Give users a unique random password in a CMF file, e.g. to import them before their real passwords are known",
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := parsePasswordHash(hashSpec)
			if err != nil {
				return err
			}
			opts.hash = spec
			if opts.length < password.MinLength || opts.length > password.MaxLength {
				return fmt.Errorf("--length must be between %d and %d", password.MinLength, password.MaxLength)
			}
			if err := distinctPaths([][2]string{{"--in", opts.in}, {"--out", opts.out}, {"--passwords-out", opts.passwordsOut}}); err != nil {
				return err
			}
			// A bad hash parameter should fail now, not on the first user
			// after the output files exist.
			if _, err := fixture.HashPassword(opts.hash, "check"); err != nil {
				return fmt.Errorf("--hash %q: %w", hashSpec, err)
			}

			stats, err := runSetPasswords(cmd, opts)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "set a password for %d of %d users (%d kept theirs) -> %s\n",
				stats.set, stats.total, stats.total-stats.set, opts.out)
			if stats.set > 0 {
				if opts.passwordsOut != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "cleartext passwords -> %s (keep it secret, delete it once delivered)\n", opts.passwordsOut)
				} else {
					fmt.Fprintln(cmd.ErrOrStderr(), "iamigrate: no --passwords-out given: the generated passwords are discarded, so users will have to reset their password")
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.in, "in", "", "CMF users.cmf.jsonl[.gz] path (gzip detected automatically)")
	cmd.Flags().StringVar(&opts.out, "out", "", "CMF file to write, gzip-compressed when the path ends in .gz; must differ from --in")
	cmd.Flags().StringVar(&hashSpec, "hash", "", "how to hash the new passwords: <algo>[:<params>] with algo bcrypt|argon2|pbkdf2|scrypt, e.g. bcrypt:cost=10; pick one the target accepts")
	cmd.Flags().StringVar(&opts.passwordsOut, "passwords-out", "", "CSV file to write each new cleartext password to (mode 0600); without it the passwords are discarded")
	cmd.Flags().IntVar(&opts.length, "length", password.DefaultLength, fmt.Sprintf("generated password length, %d-%d", password.MinLength, password.MaxLength))
	cmd.Flags().BoolVar(&opts.overwrite, "overwrite", false, "also replace passwords users already have (default: only users with no password or a non-portable one)")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("out")
	_ = cmd.MarkFlagRequired("hash")
	return cmd
}

type setPasswordsStats struct{ total, set int }

// runSetPasswords streams opts.in into opts.out, replacing passwords as
// opts selects. On failure, the output files are removed rather than left
// half-written.
func runSetPasswords(cmd *cobra.Command, opts setPasswordsOptions) (stats setPasswordsStats, err error) {
	in, err := os.Open(opts.in)
	if err != nil {
		return stats, err
	}
	defer in.Close()
	r, err := cmf.NewReader(in)
	if err != nil {
		return stats, err
	}
	defer r.Close()

	outFile, err := os.Create(opts.out)
	if err != nil {
		return stats, err
	}
	created := []string{opts.out}
	defer func() {
		if err != nil {
			for _, p := range created {
				_ = os.Remove(p)
			}
		}
	}()
	defer outFile.Close()

	newWriter := cmf.NewPlainWriter
	if strings.HasSuffix(opts.out, ".gz") {
		newWriter = cmf.NewWriter
	}
	w := newWriter(outFile)

	var creds *csv.Writer
	if opts.passwordsOut != "" {
		// 0600 from creation, since the file holds cleartext secrets.
		pf, err := os.OpenFile(opts.passwordsOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return stats, err
		}
		created = append(created, opts.passwordsOut)
		defer pf.Close()
		if err := pf.Chmod(0o600); err != nil { // an existing file keeps its old mode otherwise
			return stats, err
		}
		creds = csv.NewWriter(pf)
		if err := creds.Write([]string{"source_id", "email", "username", "phone", "password"}); err != nil {
			return stats, err
		}
	}

	_, bar := startProgress(cmd)
	defer bar.Done()
	bar.Stage("setting passwords", countUsers(bar, opts.in))

	setter := newPasswordSetter(opts)
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return stats, err
		}
		stats.total++
		bar.Add(1)

		pw, err := setter.apply(&u)
		if err != nil {
			return stats, fmt.Errorf("user %q: %w", u.SourceID, err)
		}
		if pw != "" {
			stats.set++
			if creds != nil {
				if err := creds.Write(credentialRow(u, pw)); err != nil {
					return stats, err
				}
			}
		}
		if err := w.WriteUser(u); err != nil {
			return stats, err
		}
	}
	bar.Done()

	if err := w.Close(); err != nil {
		return stats, err
	}
	if creds != nil {
		creds.Flush()
		if err := creds.Error(); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

// passwordSetter gives users generated passwords, never repeating one
// within a run.
type passwordSetter struct {
	hash      fixture.HashSpec
	length    int
	overwrite bool
	used      map[string]struct{}
}

func newPasswordSetter(opts setPasswordsOptions) *passwordSetter {
	return &passwordSetter{hash: opts.hash, length: opts.length, overwrite: opts.overwrite, used: map[string]struct{}{}}
}

// apply replaces u's password when it has none (or only a non-portable one),
// or always with overwrite. It returns the new cleartext password, or "" if
// u was left alone.
func (s *passwordSetter) apply(u *cmf.User) (string, error) {
	if !s.overwrite && u.Password != nil && u.Password.Portable {
		return "", nil
	}
	pw, err := s.generate()
	if err != nil {
		return "", err
	}
	hashed, err := fixture.HashPassword(s.hash, pw)
	if err != nil {
		return "", err
	}
	u.Password = &hashed
	return pw, nil
}

func (s *passwordSetter) generate() (string, error) {
	for {
		pw, err := password.Generate(s.length)
		if err != nil {
			return "", err
		}
		if _, dup := s.used[pw]; dup {
			continue
		}
		s.used[pw] = struct{}{}
		return pw, nil
	}
}

// credentialRow is one passwords CSV line: enough identifiers to tell the
// user which account the password belongs to.
func credentialRow(u cmf.User, pw string) []string {
	var email, phone string
	if len(u.Emails) > 0 {
		email = u.Emails[0].Value
	}
	if len(u.Phones) > 0 {
		phone = u.Phones[0].Value
	}
	return []string{u.SourceID, csvSafe(email), csvSafe(u.Username), csvSafe(phone), pw}
}

// csvSafe defuses spreadsheet formula injection: a field opening with one of
// these characters would be evaluated as a formula when the file is opened
// in Excel or Sheets. The password column is left alone since the generated
// passwords may legitimately begin with a symbol, and E.164 phone numbers
// are left alone since they always begin with a plus.
func csvSafe(s string) string {
	if s == "" || e164RE.MatchString(s) {
		return s
	}
	if strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

var e164RE = regexp.MustCompile(`^\+[0-9]+$`)

func parsePasswordHash(s string) (fixture.HashSpec, error) {
	spec, err := fixture.ParseHashSpec(s)
	if err != nil {
		return fixture.HashSpec{}, err
	}
	for _, a := range setPasswordsAlgorithms {
		if spec.Algorithm == a {
			return spec, nil
		}
	}
	return fixture.HashSpec{}, fmt.Errorf("unsupported --hash algorithm %q (supports bcrypt, argon2, pbkdf2, and scrypt)", spec.Algorithm)
}

// distinctPaths fails if two of the named non-empty paths are the same file,
// so a run can't overwrite the CMF file it is reading or mix up outputs.
func distinctPaths(paths [][2]string) error {
	seen := map[string]string{}
	for _, fp := range paths {
		flag, p := fp[0], fp[1]
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		if other, ok := seen[abs]; ok {
			return fmt.Errorf("%s and %s must be different files", other, flag)
		}
		seen[abs] = flag
	}
	return nil
}
