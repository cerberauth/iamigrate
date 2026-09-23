package cmd

import (
	"bytes"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/stretchr/testify/require"
)

func TestPrintImportSummarySeparatesDuplicatedUsers(t *testing.T) {
	report := connector.ImportReport{
		Succeeded: []string{"u1", "u2"},
		Failed: []connector.ImportError{
			{SourceID: "u3", Code: "DUPLICATED_USER"},
			{SourceID: "u4", Code: "DUPLICATED_USER"},
			{SourceID: "u5", Code: "TRANSLATION_ERROR"},
		},
	}

	var out bytes.Buffer
	printImportSummary(&out, report, "import-report.json", false)
	require.Equal(t, "imported: 2 succeeded, 2 already exist, 1 failed -> report import-report.json\n"+
		"  2 already exist: not updated; re-run with --upsert to update them\n"+
		"  1 failed: TRANSLATION_ERROR\n", out.String())
}

func TestPrintImportSummaryWithoutDuplicatedUsers(t *testing.T) {
	report := connector.ImportReport{Succeeded: []string{"u1"}}

	var out bytes.Buffer
	printImportSummary(&out, report, "import-report.json", false)
	require.Equal(t, "imported: 1 succeeded, 0 failed -> report import-report.json\n", out.String())
}
