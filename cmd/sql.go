package cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"

	sqlsrc "github.com/cerberauth/iamigrate/pkg/connector/sql"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// envSQLDSN is where a SQL export reads the connection string from when
// --dsn isn't given. It is what to prefer: a flag is visible in the process
// list and the shell history, and the DSN usually holds a password.
const envSQLDSN = "IAMIGRATE_SQL_DSN"

// sqlExportOptions checks the settings of a SQL export and reads its query,
// so that a mistake stops the command before anything is written or any
// connection is made.
func sqlExportOptions(driver, dsn, query string, m mapping.Mapping) (sqlsrc.ExportOptions, error) {
	if driver == "" {
		return sqlsrc.ExportOptions{}, fmt.Errorf("--driver is required for --source %s (one of %s)", sqlsrc.Name, strings.Join(sqlsrc.Drivers(), ", "))
	}
	if !slices.Contains(sqlsrc.Drivers(), driver) {
		return sqlsrc.ExportOptions{}, fmt.Errorf("unknown --driver %q (one of %s)", driver, strings.Join(sqlsrc.Drivers(), ", "))
	}
	if dsn == "" {
		dsn = os.Getenv(envSQLDSN)
	}
	if dsn == "" {
		return sqlsrc.ExportOptions{}, fmt.Errorf("--dsn (or $%s) is required for --source %s", envSQLDSN, sqlsrc.Name)
	}
	if query == "" {
		return sqlsrc.ExportOptions{}, fmt.Errorf("--query is required for --source %s", sqlsrc.Name)
	}
	if path, ok := strings.CutPrefix(query, "@"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return sqlsrc.ExportOptions{}, fmt.Errorf("reading --query file: %w", err)
		}
		query = string(b)
	}
	if strings.TrimSpace(query) == "" {
		return sqlsrc.ExportOptions{}, fmt.Errorf("--query is empty")
	}
	return sqlsrc.ExportOptions{Driver: driver, DSN: dsn, Query: query, Mapping: m}, nil
}
