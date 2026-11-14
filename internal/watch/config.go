// Package watch starts jobs on their own, for `iamigrate serve`: a watcher
// creates a job from a template for each new object under a bucket prefix,
// found by listing the bucket or from the bucket's event notifications on a
// queue.
//
// The job ID of a trigger is derived from the watcher, the object and its
// version, and the job store refuses to create a job twice, so an object
// version starts one job at most: across restarts, between replicas sharing
// the store, and when a queue redelivers a notification.
package watch

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cerberauth/x/fsx"
	"gopkg.in/yaml.v3"
)

// DefaultInterval is how often a watcher lists its bucket by default.
const DefaultInterval = time.Minute

// Config is the parsed form of the watchers file.
type Config struct {
	Version int `yaml:"version"`
	// WorkDir is where each triggered job gets a directory of its own, the
	// downloaded object and ${work} paths in it. ./watch/ if empty.
	WorkDir  string          `yaml:"work_dir,omitempty"`
	Watchers []WatcherConfig `yaml:"watchers"`
}

// WatcherConfig is one watcher of the watchers file.
type WatcherConfig struct {
	// Name identifies the watcher, in GET / and in the IDs of its jobs.
	Name string `yaml:"name"`
	// Bucket is where objects are watched: a local directory, or a URI
	// such as s3://bucket/prefix/.
	Bucket string `yaml:"bucket"`
	// Match, if set, is a path.Match pattern an object's base name must
	// match, such as "*.cmf.jsonl.gz".
	Match string `yaml:"match,omitempty"`
	// Template is the job template file: a POST /jobs body.
	Template string `yaml:"template"`
	// Queue, if set, is the URI of a queue the bucket's event
	// notifications arrive on, read instead of listing the bucket.
	Queue string `yaml:"queue,omitempty"`
	// Interval is how often the bucket is listed (DefaultInterval if
	// zero), or, with a queue, how long to wait after it fails.
	Interval time.Duration `yaml:"interval,omitempty"`
}

var validName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// LoadConfig reads the watchers file at p, and the templates it names,
// relative to its directory.
func LoadConfig(p string) (*Config, map[string]*Template, error) {
	b, err := fsx.ReadFile(p)
	if err != nil {
		return nil, nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, nil, fmt.Errorf("watchers %s: parsing: %w", p, err)
	}
	if err := c.validate(); err != nil {
		return nil, nil, fmt.Errorf("watchers %s: %w", p, err)
	}
	dir := filepath.Dir(p)
	if c.WorkDir == "" {
		c.WorkDir = "./watch/"
	}
	if !filepath.IsAbs(c.WorkDir) {
		c.WorkDir = filepath.Join(dir, c.WorkDir)
	}
	if c.WorkDir, err = filepath.Abs(c.WorkDir); err != nil {
		return nil, nil, err
	}
	templates := map[string]*Template{}
	for i := range c.Watchers {
		w := &c.Watchers[i]
		tp := w.Template
		if !filepath.IsAbs(tp) {
			tp = filepath.Join(dir, tp)
		}
		t, err := LoadTemplate(tp)
		if err != nil {
			return nil, nil, fmt.Errorf("watcher %q: %w", w.Name, err)
		}
		templates[w.Name] = t
		if isLocal(w.Bucket) && !filepath.IsAbs(localPath(w.Bucket)) {
			w.Bucket = filepath.Join(dir, localPath(w.Bucket))
		}
	}
	return &c, templates, nil
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", c.Version)
	}
	if len(c.Watchers) == 0 {
		return errors.New("no watchers declared")
	}
	names := map[string]bool{}
	for _, w := range c.Watchers {
		if !validName.MatchString(w.Name) {
			return fmt.Errorf("watcher name %q must be letters, digits, '-' and '_'", w.Name)
		}
		if names[w.Name] {
			return fmt.Errorf("watcher %q is declared twice", w.Name)
		}
		names[w.Name] = true
		if w.Bucket == "" {
			return fmt.Errorf("watcher %q: bucket is required", w.Name)
		}
		if w.Template == "" {
			return fmt.Errorf("watcher %q: template is required", w.Name)
		}
		if w.Match != "" {
			if _, err := path.Match(w.Match, ""); err != nil {
				return fmt.Errorf("watcher %q: match %q: %w", w.Name, w.Match, err)
			}
		}
		if w.Interval < 0 {
			return fmt.Errorf("watcher %q: interval can't be negative", w.Name)
		}
		if w.Queue != "" && isLocal(w.Bucket) {
			return fmt.Errorf("watcher %q: a local directory has no event notifications: remove queue", w.Name)
		}
	}
	return nil
}

// Template is a job template: the body of a POST /jobs, whose param values
// can hold the ${...} variables of the object that triggered the job.
type Template struct {
	Params map[string]string `yaml:"params" json:"params"`
}

// Template variables.
const (
	// VarInput is the local path of the object: the file itself for a
	// local directory, a downloaded copy otherwise.
	VarInput = "input"
	// VarURI is the object's URI.
	VarURI = "uri"
	// VarKey is the object's key under the watched prefix.
	VarKey = "key"
	// VarVersion is the object's version (ETag, generation, ...).
	VarVersion = "version"
	// VarWork is the job's own directory under work_dir, for its outputs.
	VarWork = "work"
	// VarJob is the job's ID.
	VarJob = "job"
)

var (
	templateVars = []string{VarInput, VarURI, VarKey, VarVersion, VarWork, VarJob}
	varRef       = regexp.MustCompile(`\$\{([^}]*)\}`)
)

// LoadTemplate reads the job template file at p.
func LoadTemplate(p string) (*Template, error) {
	b, err := fsx.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var t Template
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("template %s: parsing: %w", p, err)
	}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("template %s: %w", p, err)
	}
	return &t, nil
}

func (t *Template) validate() error {
	if len(t.Params) == 0 {
		return errors.New("params are required")
	}
	usesInput := false
	for _, k := range slices.Sorted(maps.Keys(t.Params)) {
		for _, m := range varRef.FindAllStringSubmatch(t.Params[k], -1) {
			if !slices.Contains(templateVars, m[1]) {
				return fmt.Errorf("param %q: unknown variable ${%s} (known: %s)", k, m[1], strings.Join(templateVars, ", "))
			}
			usesInput = usesInput || m[1] == VarInput
		}
	}
	if !usesInput {
		return fmt.Errorf("no param uses ${%s}, the triggering object", VarInput)
	}
	return nil
}

// Expand returns the template's params with the variables replaced by
// their values in vars.
func (t *Template) Expand(vars map[string]string) map[string]string {
	out := make(map[string]string, len(t.Params))
	for k, v := range t.Params {
		out[k] = varRef.ReplaceAllStringFunc(v, func(ref string) string {
			return vars[ref[2:len(ref)-1]]
		})
	}
	return out
}
