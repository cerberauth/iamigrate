package kratos_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/stretchr/testify/require"
)

func TestExportSetsUserAgentOnAdminAPIRequests(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	target := kratos.New(kratos.NewClient(srv.URL), "default")
	var buf bytes.Buffer
	_, err := target.Export(context.Background(), cmf.NewWriter(&buf), kratos.ExportOptions{})
	require.NoError(t, err)
	require.Regexp(t, `^iamigrate/\S+ \(\+https://github\.com/cerberauth/iamigrate\)$`, gotUA)
}
