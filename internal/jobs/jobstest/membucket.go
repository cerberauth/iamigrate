// Package jobstest holds the contract tests every jobs.Store and
// jobs.Bucket must pass, and an in-memory Bucket to run stores on in tests.
package jobstest

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/cerberauth/iamigrate/internal/jobs"
)

// MemBucket is an in-memory jobs.Bucket.
type MemBucket struct {
	mu      sync.Mutex
	objects map[string]memObject
	next    int
}

type memObject struct {
	data    []byte
	version string
}

// NewMemBucket returns an empty MemBucket.
func NewMemBucket() *MemBucket { return &MemBucket{objects: map[string]memObject{}} }

func (b *MemBucket) Get(_ context.Context, key string) ([]byte, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.objects[key]
	if !ok {
		return nil, "", jobs.ErrObjectNotFound
	}
	return append([]byte(nil), o.data...), o.version, nil
}

func (b *MemBucket) Put(_ context.Context, key string, data []byte, match string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.objects[key]
	if (match == "" && ok) || (match != "" && (!ok || o.version != match)) {
		return "", jobs.ErrPrecondition
	}
	b.next++
	v := strconv.Itoa(b.next)
	b.objects[key] = memObject{data: append([]byte(nil), data...), version: v}
	return v, nil
}

func (b *MemBucket) Delete(_ context.Context, key, match string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.objects[key]
	if !ok {
		return jobs.ErrObjectNotFound
	}
	if match != "" && o.version != match {
		return jobs.ErrPrecondition
	}
	delete(b.objects, key)
	return nil
}

func (b *MemBucket) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var keys []string
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}
