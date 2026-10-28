package sqlserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUsesEntra(t *testing.T) {
	for dsn, want := range map[string]bool{
		// a SQL login
		"sqlserver://sa:pw@host:1433?database=app":                                      false,
		"server=host;user id=sa;password=pw;database=app":                              false,
		"sqlserver://sa:pw@host?database=app&encrypt=true&TrustServerCertificate=false": false,
		// Microsoft Entra, in the driver's two DSN forms
		"sqlserver://host.database.windows.net?database=app&fedauth=ActiveDirectoryDefault":  true,
		"sqlserver://host.database.windows.net?database=app&FedAuth=ActiveDirectoryAzCli":    true,
		"server=host.database.windows.net;database=app;fedauth=ActiveDirectoryManagedIdentity": true,
		"Server=host;Database=app; FedAuth = ActiveDirectoryServicePrincipal;":                true,
		// an empty value selects nothing
		"sqlserver://host?database=app&fedauth=": false,
		// a password that merely contains the word is not a parameter
		"sqlserver://sa:fedauth=1@host?database=app": false,
	} {
		require.Equal(t, want, usesEntra(dsn), dsn)
	}
}
