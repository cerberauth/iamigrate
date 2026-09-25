// Package httpx provides the http.RoundTripper connector clients use to
// stamp iamigrate's User-Agent (and any provider-specific headers) on
// every outbound request, so tenant/instance logs can identify the tool
// without every call site setting headers itself.
package httpx

import "net/http"

// Version is the iamigrate release version reported in the User-Agent
// header. main sets it from the build-time version before any connector
// client is constructed; it defaults to "dev" for local builds and tests.
var Version = "dev"

// UserAgent returns the User-Agent iamigrate sends on every outbound
// request.
func UserAgent() string {
	return "iamigrate/" + Version + " (+https://github.com/cerberauth/iamigrate)"
}

// Transport wraps a http.RoundTripper, setting the User-Agent header, plus
// any Extra headers, on every request.
type Transport struct {
	// Base is the underlying RoundTripper. http.DefaultTransport is used
	// if nil.
	Base http.RoundTripper
	// Extra holds additional headers to set on every request, e.g.
	// Auth0's Auth0-Client.
	Extra map[string]string
}

// NewTransport wraps base (or http.DefaultTransport if nil) so every
// request through it carries the shared User-Agent and extra.
func NewTransport(base http.RoundTripper, extra map[string]string) *Transport {
	return &Transport{Base: base, Extra: extra}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", UserAgent())
	for k, v := range t.Extra {
		req.Header.Set(k, v)
	}
	return base.RoundTrip(req)
}
