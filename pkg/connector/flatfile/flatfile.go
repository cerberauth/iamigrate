// Package flatfile implements a generic CSV/JSON SourceConnector and
// TargetConnector for hand-mapped exports: a flat table of source fields on
// one side, CMF on the other, reconciled through a mapping.Mapping.
package flatfile

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
	"github.com/cerberauth/iamigrate/pkg/strategy"
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
	// Mapping renames and transforms the file's own columns into the
	// recognized ones; the zero value expects them already.
	Mapping mapping.Mapping
	// Provenance is the source connector the users are recorded as coming
	// from (default flatfile).
	Provenance string
	// Organizations, Roles and Memberships are the source's files of
	// organizations, roles and who holds them, each optional, read through
	// the mapping's sections of the same names. Memberships are joined
	// into the users by source ID.
	Organizations, Roles, Memberships File
}

// Connector is a SourceConnector and TargetConnector over flat CSV/JSON
// files. Target-side output location is fixed at construction (via
// NewTarget) rather than passed per-call, since connector.ImportOptions is
// shaped for Auth0's connection_id/upsert semantics, which don't apply to
// a flat file.
type Connector struct {
	targetPath   string
	targetFormat Format
	directory    *connector.Directory
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
	dir, err := readDirectoryFiles(opts)
	if err != nil {
		return connector.Manifest{}, err
	}
	rows, err := readRows(opts.Path, opts.Format, opts.Mapping.RecordsPath)
	if err != nil {
		return connector.Manifest{}, err
	}
	progress.FromContext(ctx).SetTotal(len(rows))
	// A file is read whole, so its records go through the hooks in one
	// batch.
	return c.ExportRows(ctx, w, &sliceRows{rows: rows}, dir, opts, len(rows))
}

// RowReader yields a source's records one at a time, as flat rows of
// strings; Next returns io.EOF after the last.
type RowReader interface {
	Next() (map[string]string, error)
}

type sliceRows struct {
	rows []map[string]string
	i    int
}

func (s *sliceRows) Next() (map[string]string, error) {
	if s.i >= len(s.rows) {
		return nil, io.EOF
	}
	s.i++
	return s.rows[s.i-1], nil
}

// DirectoryRows are the raw records of a source's organizations, roles and
// memberships, to be mapped through the mapping's sections of the same
// names.
type DirectoryRows struct {
	Organizations, Roles, Memberships []map[string]string
}

// ExportRows is Export over the records rows yields instead of a file:
// each is mapped into CMF per opts.Mapping and written to w, batch records
// at a time (at least one), so a source too large for memory streams
// through, its hooks called once per batch. dir, when not nil, holds the
// source's organizations, roles and memberships, the last joined into the
// users; opts' file fields are ignored.
func (c *Connector) ExportRows(ctx context.Context, w *cmf.Writer, rows RowReader, dir *DirectoryRows, opts ExportOptions, batch int) (connector.Manifest, error) {
	c.directory = nil
	var directory *connector.Directory
	var grants *Grants
	var dirSkipped []connector.SkippedRecord
	if dir != nil {
		var err error
		if directory, grants, dirSkipped, err = mapDirectory(ctx, *dir, opts.Mapping); err != nil {
			return connector.Manifest{}, err
		}
	}

	manifest := connector.Manifest{
		HashAlgorithmCounts:  map[cmf.Algorithm]int{},
		NonPortableMFACounts: map[cmf.MFAType]int{},
	}
	batch = max(batch, 1)
	for read, done := 0, false; !done; {
		var chunk []map[string]string
		for len(chunk) < batch {
			row, err := rows.Next()
			if err == io.EOF {
				done = true
				break
			}
			if err != nil {
				return manifest, err
			}
			chunk = append(chunk, row)
		}
		if len(chunk) == 0 {
			break
		}
		if err := c.exportBatch(ctx, w, chunk, read, grants, opts, &manifest); err != nil {
			return manifest, err
		}
		read += len(chunk)
	}

	if directory != nil {
		manifest.SkippedRecords = append(append(manifest.SkippedRecords, dirSkipped...), grants.Unused()...)
		c.directory = directory
	}
	return manifest, nil
}

// exportBatch maps rows, the records after the first `before` ones, into
// CMF users written to w, and counts them into manifest.
func (c *Connector) exportBatch(ctx context.Context, w *cmf.Writer, rows []map[string]string, before int, grants *Grants, opts ExportOptions, manifest *connector.Manifest) error {
	rows, positions, dropped, err := exportRecord(ctx, rows, before, opts.Mapping)
	if err != nil {
		return err
	}
	manifest.SkippedRecords = append(manifest.SkippedRecords, dropped...)
	if rows, err = idSource(ctx, rows, positions, before, opts.Mapping); err != nil {
		return err
	}
	if rows, err = normalize(ctx, rows, before, opts.Mapping, hooks.FromContext(ctx)); err != nil {
		return err
	}
	detected, err := detectHashes(ctx, rows, opts.HashHints, opts.Mapping)
	if err != nil {
		return err
	}

	bar := progress.FromContext(ctx)
	provenance := opts.Provenance
	if provenance == "" {
		provenance = Name
	}
	for i, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}

		bar.Add(1)
		det := detected[i]
		if det.skip != "" {
			manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{
				SourceID: row[colSourceID],
				Reason:   det.skip,
			})
			continue
		}
		u, skipReason, err := rowToUser(row, opts.HashHints, det.password)
		if err != nil {
			return err
		}
		if skipReason != "" {
			manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{
				SourceID: row["source_id"],
				Reason:   skipReason,
			})
			continue
		}
		u.Provenance.SourceConnector = provenance
		if grants != nil {
			grants.Apply(&u)
		}
		if err := w.WriteUser(u); err != nil {
			return fmt.Errorf("flatfile: writing user %s: %w", u.SourceID, err)
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
	return nil
}

// Directory returns the organizations and roles the last Export read, nil
// when it was given none of their files.
func (c *Connector) Directory() *connector.Directory { return c.directory }

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

// exportRecord hands the raw rows, as read and before any mapping, to the
// mapping's export.record handler, if any, which keeps, drops or replaces
// each. Rows are keyed by their record number (counting the `before`
// records read ahead of them), as they have no source ID yet; so are the
// dropped ones in the manifest. positions are the indexes in rows of those
// kept, nil when all are.
func exportRecord(ctx context.Context, rows []map[string]string, before int, m mapping.Mapping) (kept []map[string]string, positions []int, dropped []connector.SkippedRecord, err error) {
	if m.Strategies[strategy.ExportRecord].Handler == "" {
		return rows, nil, nil, nil
	}
	set, err := strategy.New(strategy.Only(m, strategy.ExportRecord), hooks.FromContext(ctx))
	if err != nil {
		return nil, nil, nil, err
	}
	items := make([]hooks.Item, len(rows))
	for i, row := range rows {
		items[i] = hooks.Item{Key: recordKey(before + i), Data: map[string]any{"record": row}}
	}
	res, err := set.Resolve(ctx, strategy.ExportRecord, items)
	if err != nil || res == nil {
		return rows, nil, nil, err
	}
	for i, row := range rows {
		var a struct {
			Action string            `json:"action"`
			Reason string            `json:"reason"`
			Record map[string]string `json:"record"`
		}
		if err := strategy.Decode(strategy.ExportRecord, recordKey(before+i), res[recordKey(before+i)], &a); err != nil {
			return nil, nil, nil, err
		}
		switch a.Action {
		case "", strategy.ActionKeep:
			kept, positions = append(kept, row), append(positions, i)
		case strategy.ActionReplace:
			if a.Record == nil {
				return nil, nil, nil, fmt.Errorf("%s: %s: replace needs a record", strategy.ExportRecord, recordKey(before+i))
			}
			kept, positions = append(kept, a.Record), append(positions, i)
		case strategy.ActionDrop:
			reason := a.Reason
			if reason == "" {
				reason = "dropped by the " + strategy.ExportRecord + " hook"
			}
			dropped = append(dropped, connector.SkippedRecord{SourceID: recordKey(before + i), Reason: reason})
		default:
			return nil, nil, nil, fmt.Errorf("%s: %s: unknown action %q (keep, drop or replace)", strategy.ExportRecord, recordKey(before+i), a.Action)
		}
	}
	return kept, positions, dropped, nil
}

func recordKey(i int) string { return "record " + strconv.Itoa(i+1) }
