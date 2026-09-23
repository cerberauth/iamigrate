package auth0

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Connection is the subset of an Auth0 connection the import needs to pick
// a target database connection.
type Connection struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ResolveConnectionID looks up the database connection (strategy "auth0",
// which covers both the Auth0 user store and custom databases) to import
// into. With a name, it returns that connection's ID; without one, it
// returns the tenant's only database connection, failing if there are none
// or several. Either way the token needs the read:connections scope; a
// token without it can still import when given the connection ID directly.
func ResolveConnectionID(ctx context.Context, client *Client, name string) (string, error) {
	q := url.Values{"strategy": {"auth0"}, "per_page": {"100"}, "fields": {"id,name"}}
	if name != "" {
		q.Set("name", name)
	}

	var conns []Connection
	if _, err := client.doJSON(ctx, http.MethodGet, "/connections?"+q.Encode(), nil, &conns); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusUnauthorized) {
			return "", fmt.Errorf("auth0: token can't list connections (needs the read:connections scope): %w", err)
		}
		return "", fmt.Errorf("auth0: listing connections: %w", err)
	}

	if name != "" {
		for _, c := range conns {
			if c.Name == name {
				return c.ID, nil
			}
		}
		return "", fmt.Errorf("auth0: no database connection named %q", name)
	}

	switch len(conns) {
	case 0:
		return "", fmt.Errorf("auth0: tenant has no database connection")
	case 1:
		return conns[0].ID, nil
	default:
		names := make([]string, len(conns))
		for i, c := range conns {
			names[i] = c.Name
		}
		return "", fmt.Errorf("auth0: tenant has %d database connections (%s)",
			len(conns), strings.Join(names, ", "))
	}
}
