package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/connector/sqlsource"
	"github.com/cerberauth/x/fsx"
	"github.com/spf13/cobra"
)

// envSQLDSN is where the sql source's DSN is read from when no flag gives
// it, as job params never hold it.
const envSQLDSN = "SQL_DSN"

// sqlFlags configures the sql source.
type sqlFlags struct {
	driver, dsn, dsnFile                                    string
	query, organizationsQuery, rolesQuery, membershipsQuery string
}

func (f *sqlFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.driver, "driver", "", "database engine: "+strings.Join(sqlsource.Engines(), "|")+" (required; sql source)")
	cmd.Flags().StringVar(&f.dsn, "dsn", "", "database DSN, in the engine's own syntax (or $"+envSQLDSN+", or --dsn-file; sql source)")
	cmd.Flags().StringVar(&f.dsnFile, "dsn-file", "", "file holding the database DSN, e.g. a mounted secret (sql source)")
	cmd.Flags().StringVar(&f.query, "query", "", "SQL selecting the users, one row each, or @file.sql (sql source)")
	cmd.Flags().StringVar(&f.organizationsQuery, "organizations-query", "", "SQL selecting the organizations, or @file.sql, mapped by the organizations section of --mapping (sql source)")
	cmd.Flags().StringVar(&f.rolesQuery, "roles-query", "", "SQL selecting the roles, or @file.sql, mapped by the roles section of --mapping (sql source)")
	cmd.Flags().StringVar(&f.membershipsQuery, "memberships-query", "", "SQL selecting the memberships (user_id, organization, role), or @file.sql, joined into the users (sql source)")
}

// given reports whether any sql source flag is set.
func (f sqlFlags) given() bool {
	return f != sqlFlags{}
}

// options checks the flags and returns the export options they describe,
// the DSN resolved.
func (f sqlFlags) options() (sqlsource.ExportOptions, error) {
	if _, err := sqlsource.Lookup(f.driver); err != nil {
		return sqlsource.ExportOptions{}, fmt.Errorf("--driver: %w", err)
	}
	dsn, err := resolveDSN(f.dsn, f.dsnFile)
	if err != nil {
		return sqlsource.ExportOptions{}, err
	}
	opts := sqlsource.ExportOptions{Driver: f.driver, DSN: dsn}
	for _, q := range []struct {
		flag, value string
		into        *string
	}{
		{"--query", f.query, &opts.Query},
		{"--organizations-query", f.organizationsQuery, &opts.OrganizationsQuery},
		{"--roles-query", f.rolesQuery, &opts.RolesQuery},
		{"--memberships-query", f.membershipsQuery, &opts.MembershipsQuery},
	} {
		if *q.into, err = readQuery(q.value); err != nil {
			return opts, fmt.Errorf("%s: %w", q.flag, err)
		}
	}
	if strings.TrimSpace(opts.Query) == "" {
		return opts, errors.New("--query is required for --source sql")
	}
	return opts, nil
}

// resolveDSN returns the DSN given by flag, else read from file, else from
// $SQL_DSN.
func resolveDSN(flag, file string) (string, error) {
	if flag != "" && file != "" {
		return "", errors.New("--dsn and --dsn-file are mutually exclusive")
	}
	if file != "" {
		b, err := fsx.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("--dsn-file: %w", err)
		}
		flag = strings.TrimSpace(string(b))
	}
	if flag == "" {
		flag = os.Getenv(envSQLDSN)
	}
	if flag == "" {
		return "", fmt.Errorf("a DSN is required: --dsn, --dsn-file or $%s", envSQLDSN)
	}
	return flag, nil
}

// readQuery returns q, or the content of the file it names as @path.
func readQuery(q string) (string, error) {
	path, ok := strings.CutPrefix(q, "@")
	if !ok {
		return q, nil
	}
	b, err := fsx.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
