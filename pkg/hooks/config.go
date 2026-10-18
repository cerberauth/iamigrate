package hooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cerberauth/x/fsx"
	"gopkg.in/yaml.v3"
)

// Defaults for a webhook that doesn't set them.
const (
	defaultTimeout   = 10 * time.Second
	defaultRetries   = 3
	defaultBatchSize = 100
)

// OnFailure is what a failed hook call does to its step.
type OnFailure string

const (
	// Fail fails the step.
	Fail OnFailure = "fail"
	// Ignore carries on as if there were no hook: the built-in behavior
	// applies, and the failure is recorded as a Result.
	Ignore OnFailure = "ignore"
)

// Ref points a hook at a handler. A veto or decide event, or a strategy,
// fails its step by default when the handler fails, since carrying on would
// skip the check or decision the operator asked for; a notify event ignores
// the failure by default.
type Ref struct {
	Handler   string    `yaml:"handler"`
	OnFailure OnFailure `yaml:"on_failure,omitempty"`
}

// Config is the parsed form of hooks.yaml.
type Config struct {
	Version  int                      `yaml:"version"`
	Handlers map[string]HandlerConfig `yaml:"handlers"`
	Events   map[string]Ref           `yaml:"events,omitempty"`

	// fingerprint is the sha256 of the file, so a job can tell it is
	// resumed under different hooks than it started with.
	fingerprint string
}

// HandlerConfig declares one handler. Exactly one kind is set; webhook is
// the only one so far.
type HandlerConfig struct {
	Webhook *WebhookConfig `yaml:"webhook,omitempty"`
}

// WebhookConfig is an HTTP handler. The secret signs every request (see
// Sign); it is read from the environment or a file, never written in
// hooks.yaml, so the file can be shared and the secret never lands on a
// persisted job.
type WebhookConfig struct {
	URL        string        `yaml:"url"`
	SecretEnv  string        `yaml:"secret_env,omitempty"`
	SecretFile string        `yaml:"secret_file,omitempty"`
	Timeout    time.Duration `yaml:"timeout,omitempty"`
	// Retries is how many times a call failing with a 5xx, a 429 or a
	// network error is retried; 3 when unset, none when 0.
	Retries *int `yaml:"retries,omitempty"`
	// BatchSize is how many users one call of a per-user strategy carries.
	BatchSize int `yaml:"batch_size,omitempty"`
}

// Load reads and checks a hooks.yaml file. Unknown keys are an error, so a
// misspelled hook point doesn't silently never fire.
func Load(path string) (*Config, error) {
	b, err := fsx.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hooks: reading %s: %w", path, err)
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("hooks: %s: %w", path, err)
	}
	return c, nil
}

// Parse parses and checks the contents of a hooks.yaml file.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	c.fingerprint = hex.EncodeToString(sum[:])
	return &c, nil
}

// Fingerprint identifies the file c was parsed from, "" for no file.
func (c *Config) Fingerprint() string {
	if c == nil {
		return ""
	}
	return c.fingerprint
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", c.Version)
	}
	for _, name := range sortedKeys(c.Handlers) {
		h := c.Handlers[name]
		if h.Webhook == nil {
			return fmt.Errorf("handler %q: no kind set (webhook)", name)
		}
		if err := h.Webhook.validate(); err != nil {
			return fmt.Errorf("handler %q: %w", name, err)
		}
	}
	for _, name := range sortedKeys(c.Events) {
		if IsStrategy(name) {
			return fmt.Errorf("events: %q is a strategy: configure it in mapping.yaml", name)
		}
		if !IsEvent(name) {
			return fmt.Errorf("events: unknown event %q", name)
		}
		if err := c.CheckRef(c.Events[name]); err != nil {
			return fmt.Errorf("events: %s: %w", name, err)
		}
	}
	return nil
}

// CheckRef reports whether r names a declared handler and a known
// on_failure, for mapping.yaml's strategies to check theirs against.
func (c *Config) CheckRef(r Ref) error {
	if r.Handler == "" {
		return errors.New("handler is required")
	}
	if c == nil {
		return fmt.Errorf("handler %q is not declared: no hooks file given (--hooks)", r.Handler)
	}
	if _, ok := c.Handlers[r.Handler]; !ok {
		return fmt.Errorf("handler %q is not declared in the hooks file", r.Handler)
	}
	switch r.OnFailure {
	case "", Fail, Ignore:
		return nil
	}
	return fmt.Errorf("on_failure must be %q or %q, got %q", Fail, Ignore, r.OnFailure)
}

func (w *WebhookConfig) validate() error {
	if w.URL == "" {
		return errors.New("webhook: url is required")
	}
	u, err := url.Parse(w.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("webhook: url %q must be an absolute http(s) URL", w.URL)
	}
	if (w.SecretEnv == "") == (w.SecretFile == "") {
		return errors.New("webhook: exactly one of secret_env and secret_file is required")
	}
	if w.Timeout < 0 || w.BatchSize < 0 || (w.Retries != nil && *w.Retries < 0) {
		return errors.New("webhook: timeout, retries and batch_size can't be negative")
	}
	return nil
}

// secret reads the webhook's signing secret.
func (w *WebhookConfig) secret() ([]byte, error) {
	if w.SecretEnv != "" {
		s := os.Getenv(w.SecretEnv)
		if s == "" {
			return nil, fmt.Errorf("webhook: $%s is not set", w.SecretEnv)
		}
		return []byte(s), nil
	}
	b, err := fsx.ReadFile(w.SecretFile)
	if err != nil {
		return nil, fmt.Errorf("webhook: reading secret: %w", err)
	}
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return nil, fmt.Errorf("webhook: secret file %s is empty", w.SecretFile)
	}
	return []byte(s), nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
