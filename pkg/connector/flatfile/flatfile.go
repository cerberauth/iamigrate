// Package flatfile implements a generic CSV/JSON SourceConnector and
// TargetConnector for hand-mapped exports: a flat table of source fields on
// one side, CMF on the other, reconciled through a mapping.Mapping.
package flatfile

import (
	"context"
	"fmt"
	"io"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
)

// Format names the flat-file encoding.
type Format string

const (
	FormatCSV  Format = "csv"
	FormatJSON Format = "json"
)

// ExportOptions configures reading a flat file as a source.
type ExportOptions struct {
	connector.BaseExportOptions
	Path   string
	Format Format
	// HashHints maps a source column name to the cmf.Algorithm it
	// contains, for columns pkg/hash can't detect unambiguously on its
	// own (raw digests) -- see pkg/hash.Hint.
	HashHints map[string]cmf.Algorithm
}

// Connector is a SourceConnector and TargetConnector over flat CSV/JSON
// files. Target-side output location is fixed at construction (via
// NewTarget) rather than passed per-call, since connector.ImportOptions is
// shaped for Auth0's connection_id/upsert semantics, which don't apply to
// a flat file.
type Connector struct {
	targetPath   string
	targetFormat Format
}

// New returns a flatfile connector usable as a SourceConnector.
func New() *Connector { return &Connector{} }

// NewTarget returns a flatfile connector usable as a TargetConnector,
// writing to path in the given format.
func NewTarget(path string, format Format) *Connector {
	return &Connector{targetPath: path, targetFormat: format}
}

// Name is the connector's identifier, as used for --source.
const Name = "flatfile"

func (*Connector) Name() string { return Name }

// Export reads opts.Path (CSV or JSON, per opts.Format), maps each row's
// fields into CMF per m, and writes the result to w.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	opts, ok := eo.(ExportOptions)
	if !ok {
		return connector.Manifest{}, fmt.Errorf("flatfile: Export requires flatfile.ExportOptions, got %T", eo)
	}

	rows, err := readRows(opts.Path, opts.Format)
	if err != nil {
		return connector.Manifest{}, err
	}

	manifest := connector.Manifest{
		HashAlgorithmCounts:  map[cmf.Algorithm]int{},
		NonPortableMFACounts: map[cmf.MFAType]int{},
	}
	bar := progress.FromContext(ctx)
	bar.SetTotal(len(rows))

	for _, row := range rows {
		select {
		case <-ctx.Done():
			return manifest, ctx.Err()
		default:
		}

		bar.Add(1)
		u, skipReason, err := rowToUser(row, opts.HashHints)
		if err != nil {
			return manifest, err
		}
		if skipReason != "" {
			manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{
				SourceID: row["source_id"],
				Reason:   skipReason,
			})
			continue
		}
		if err := w.WriteUser(u); err != nil {
			return manifest, fmt.Errorf("flatfile: writing user %s: %w", u.SourceID, err)
		}
		manifest.RecordCount++
		if u.Password != nil {
			manifest.HashAlgorithmCounts[u.Password.Algorithm]++
		}
		for _, f := range u.MFAFactors {
			if !f.Portable {
				manifest.NonPortableMFACounts[f.Type]++
			}
		}
	}

	return manifest, nil
}

// Capabilities reports what the flatfile target accepts: everything CMF
// can express, since it's a generic sink with no provider-side
// restrictions of its own.
func (*Connector) Capabilities() connector.Capabilities {
	return connector.Capabilities{
		HashAlgorithms: []cmf.Algorithm{
			cmf.AlgBcrypt, cmf.AlgScrypt, cmf.AlgPBKDF2, cmf.AlgArgon2,
			cmf.AlgMD5, cmf.AlgSHA1, cmf.AlgSHA256, cmf.AlgSHA512, cmf.AlgMD4,
			cmf.AlgHMAC, cmf.AlgLDAP,
		},
		MFATypes: []cmf.MFAType{
			cmf.MFATOTP, cmf.MFASMS, cmf.MFAEmail, cmf.MFAWebAuthn, cmf.MFARecoveryCodes, cmf.MFAPush,
		},
		SupportsOrgs:  true,
		SupportsRoles: true,
	}
}

// ValidateUser has no field rules of its own, since flatfile is a generic
// sink with no provider-side restrictions; it always returns no problems.
func (*Connector) ValidateUser(u cmf.User) []connector.Problem { return nil }

// Import writes every CMF user from r out to the flat file this connector
// was constructed with (see NewTarget), applying m's field mapping to
// choose output column names for CSV.
func (c *Connector) Import(ctx context.Context, r *cmf.Reader, m mapping.Mapping, opts connector.ImportOptions) (connector.ImportReport, error) {
	if c.targetPath == "" {
		return connector.ImportReport{}, fmt.Errorf("flatfile: connector was not constructed with NewTarget; no output path configured")
	}

	var report connector.ImportReport
	var rows []map[string]string
	for {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		rows = append(rows, userToRow(u, m))
		report.Succeeded = append(report.Succeeded, u.SourceID)
	}

	if err := writeRows(c.targetPath, c.targetFormat, rows); err != nil {
		return report, err
	}
	return report, nil
}

// Verify is not meaningful for a flat-file target (there's no live system
// to reconcile against).
func (c *Connector) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	return connector.DiffReport{}, fmt.Errorf("flatfile: Verify is not supported (no live system to reconcile against)")
}
