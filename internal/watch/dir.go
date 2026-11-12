package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cerberauth/iamigrate/internal/jobs"
)

// isLocal reports whether a bucket location is a local directory: a path,
// or a file:// URI.
func isLocal(location string) bool {
	scheme, _, ok := strings.Cut(location, "://")
	return !ok || scheme == "file"
}

// localPath returns the directory a local bucket location names.
func localPath(location string) string {
	if rest, ok := strings.CutPrefix(location, "file://"); ok {
		if u, err := url.Parse(location); err == nil {
			return u.Path
		}
		return rest
	}
	return location
}

// dirBucket is a local directory watched as a bucket: keys are the paths of
// its regular files, relative to it with forward slashes, and an object's
// version its modification time and size.
type dirBucket struct {
	dir string
}

func openDir(location string) (*dirBucket, error) {
	dir, err := filepath.Abs(localPath(location))
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	return &dirBucket{dir: dir}, nil
}

// path returns the file of key.
func (b *dirBucket) path(key string) string { return filepath.Join(b.dir, filepath.FromSlash(key)) }

func (b *dirBucket) ListObjects(ctx context.Context, prefix string) ([]jobs.Object, error) {
	var objects []jobs.Object
	err := filepath.WalkDir(b.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A file removed while walking is just gone.
			if errors.Is(err, fs.ErrNotExist) && p != b.dir {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(b.dir, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			objects = append(objects, jobs.Object{Key: key, Version: fmt.Sprintf("%x-%x", fi.ModTime().UnixNano(), fi.Size())})
		}
		return nil
	})
	return objects, err
}
