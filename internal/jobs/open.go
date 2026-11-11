package jobs

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// BucketOpener opens the Bucket a store URI names: its host is the bucket
// (or container), and its path the key prefix the jobs are kept under.
type BucketOpener func(ctx context.Context, u *url.URL) (Bucket, error)

var (
	openersMu sync.RWMutex
	openers   = map[string]BucketOpener{}
)

// RegisterBucket makes OpenStore open URIs of the given scheme with open.
func RegisterBucket(scheme string, open BucketOpener) {
	openersMu.Lock()
	defer openersMu.Unlock()
	openers[scheme] = open
}

// Schemes returns the store URI schemes OpenStore knows, sorted.
func Schemes() []string {
	openersMu.RLock()
	defer openersMu.RUnlock()
	out := make([]string, 0, len(openers))
	for s := range openers {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// OpenStore opens the store at location: a local directory (a path, or a
// file:// URI), or a URI of a registered scheme, such as s3://bucket/prefix.
func OpenStore(ctx context.Context, location string) (Store, error) {
	scheme, _, ok := strings.Cut(location, "://")
	if !ok {
		return NewFileStore(location)
	}
	u, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("jobs: store %q: %w", location, err)
	}
	if scheme == "file" {
		if u.Host != "" && u.Host != "localhost" {
			return nil, fmt.Errorf("jobs: store %q: a file:// URI can't name a host", location)
		}
		return NewFileStore(u.Path)
	}
	openersMu.RLock()
	open, ok := openers[scheme]
	openersMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("jobs: store %q: unsupported scheme %q (supported: a local path, file://%s)",
			location, scheme, strings.Join(prefixed(Schemes()), ""))
	}
	b, err := open(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("jobs: store %q: %w", location, err)
	}
	return NewObjectStore(b), nil
}

func prefixed(schemes []string) []string {
	out := make([]string, len(schemes))
	for i, s := range schemes {
		out[i] = ", " + s + "://"
	}
	return out
}

// KeyPrefix returns the key prefix a store URI's path names: without its
// leading slash, and ending with one unless empty.
func KeyPrefix(u *url.URL) string {
	p := strings.Trim(u.Path, "/")
	if p == "" {
		return ""
	}
	return p + "/"
}
