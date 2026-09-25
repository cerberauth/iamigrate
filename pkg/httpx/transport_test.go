package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/httpx"
	"github.com/stretchr/testify/require"
)

func TestTransportSetsUserAgentAndExtraHeaders(t *testing.T) {
	old := httpx.Version
	httpx.Version = "1.2.3"
	defer func() { httpx.Version = old }()

	var gotUA, gotExtra string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotExtra = r.Header.Get("X-Extra")
	}))
	defer srv.Close()

	client := &http.Client{Transport: httpx.NewTransport(nil, map[string]string{"X-Extra": "value"})}
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, "iamigrate/1.2.3 (+https://github.com/cerberauth/iamigrate)", gotUA)
	require.Equal(t, "value", gotExtra)
}
