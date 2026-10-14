package flatfile

import (
	"fmt"
	"os"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// PrepareOptions configures rewriting a flat file into the column
// convention `export --source flatfile` reads.
type PrepareOptions struct {
	In        string
	InFormat  Format
	Out       string
	OutFormat Format
	Mapping   mapping.Mapping
}

// PrepareReport summarizes a Prepare run.
type PrepareReport struct {
	Records int
	// Skipped lists the records an export of the output would skip, and
	// why: no source_id, a password hash that can't be read, and so on.
	Skipped []connector.SkippedRecord
}

// Prepare reads opts.In, normalizes every record per opts.Mapping, and
// writes the result to opts.Out. The output exports exactly as the input
// does with the mapping, but needs none.
func Prepare(opts PrepareOptions) (PrepareReport, error) {
	if in, err := os.Stat(opts.In); err == nil {
		if out, err := os.Stat(opts.Out); err == nil && os.SameFile(in, out) {
			return PrepareReport{}, fmt.Errorf("flatfile: --out must differ from --in, which is never modified")
		}
	}

	rows, err := readRows(opts.In, opts.InFormat, opts.Mapping.RecordsPath)
	if err != nil {
		return PrepareReport{}, err
	}
	rows, err = Normalize(rows, opts.Mapping)
	if err != nil {
		return PrepareReport{}, err
	}

	report := PrepareReport{Records: len(rows)}
	for i, row := range rows {
		if _, reason, _ := rowToUser(row, nil); reason != "" {
			id := row[colSourceID]
			if id == "" {
				id = fmt.Sprintf("record %d", i+1)
			}
			report.Skipped = append(report.Skipped, connector.SkippedRecord{SourceID: id, Reason: reason})
		}
	}
	return report, writeRows(opts.Out, opts.OutFormat, rows)
}
