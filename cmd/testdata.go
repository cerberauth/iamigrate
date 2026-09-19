package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/fixture"
	"github.com/spf13/cobra"
)

func newTestdataCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "testdata", Short: "Synthetic CMF test data"}
	cmd.AddCommand(newTestdataGenerateCmd())
	return cmd
}

func newTestdataGenerateCmd() *cobra.Command {
	var (
		count       int
		hashSpecs   []string
		mfaSpecs    []string
		locale      string
		seed        int64
		outDir      string
		noAnswerKey bool
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a synthetic CMF fixture and answer-key.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(hashSpecs) == 0 {
				return fmt.Errorf("at least one --hash <algo>:<params> is required")
			}
			var hashes []fixture.HashSpec
			for _, s := range hashSpecs {
				spec, err := fixture.ParseHashSpec(s)
				if err != nil {
					return err
				}
				hashes = append(hashes, spec)
			}
			var mfas []fixture.MFASpec
			for _, s := range mfaSpecs {
				spec, err := fixture.ParseMFASpec(s)
				if err != nil {
					return err
				}
				mfas = append(mfas, spec)
			}

			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}

			answerKeyPath := ""
			if !noAnswerKey {
				answerKeyPath = filepath.Join(outDir, "answer-key.json")
			}

			opts := fixture.ExportOptions{
				Count:         count,
				Hashes:        hashes,
				MFAs:          mfas,
				Locale:        locale,
				Seed:          seed,
				AnswerKeyPath: answerKeyPath,
			}

			usersPath := filepath.Join(outDir, "users.cmf.jsonl.gz")
			f, err := os.Create(usersPath)
			if err != nil {
				return err
			}
			defer f.Close()

			w := cmf.NewWriter(f)
			manifest, err := fixture.New().Export(cmd.Context(), w, opts)
			if err != nil {
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}

			if err := writeManifest(outDir, manifest); err != nil {
				return err
			}
			if err := writeGitignore(outDir); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "generated %d users -> %s\n", manifest.RecordCount, usersPath)
			if answerKeyPath != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "answer key -> %s (gitignored)\n", answerKeyPath)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&count, "count", 100, "number of synthetic users to generate")
	cmd.Flags().StringArrayVar(&hashSpecs, "hash", nil, "repeatable: <algo>:<params>, e.g. bcrypt:cost=10")
	cmd.Flags().StringArrayVar(&mfaSpecs, "mfa", nil, "repeatable: <type>:rate=<0-1>, e.g. totp:rate=0.3")
	cmd.Flags().StringVar(&locale, "locale", "en", "locale passed to the fake-data generator")
	cmd.Flags().Int64Var(&seed, "seed", 1, "seed for deterministic output")
	cmd.Flags().StringVar(&outDir, "out", "./fixtures/", "output directory")
	cmd.Flags().BoolVar(&noAnswerKey, "no-answer-key", false, "skip writing answer-key.json")

	return cmd
}

func writeManifest(outDir string, m connector.Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "manifest.json"), b, 0o600)
}

// writeGitignore ensures answer-key.json is gitignored by default within
// the output directory, per DESIGN.md.
func writeGitignore(outDir string) error {
	path := filepath.Join(outDir, ".gitignore")
	if _, err := os.Stat(path); err == nil {
		return nil // don't clobber an existing one
	}
	return os.WriteFile(path, []byte("answer-key.json\n"), 0o600)
}
