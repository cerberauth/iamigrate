// Package mapping implements the mapping.yaml schema and the engine that
// applies it: source field -> CMF field on export, CMF field -> target
// field on import.
package mapping

import (
	"fmt"

	"github.com/cerberauth/x/fsx"
	"gopkg.in/yaml.v3"
)

// FieldMapping pairs one source field with the CMF field it was written to
// (or, on the import side, one CMF field with the target field it maps to),
// plus any transform applied along the way. Default is the value used when
// the source field is missing or empty; with no Source it is a constant.
// Pattern keeps only the first capture group of a regular expression, to
// split a value that packs several fields (e.g. "sha1$salt$hash"), and
// Values translates source values (e.g. a scheme code to an algorithm name).
type FieldMapping struct {
	Source    string            `yaml:"source,omitempty"`
	CMF       string            `yaml:"cmf"`
	Pattern   string            `yaml:"pattern,omitempty"`
	Values    map[string]string `yaml:"values,omitempty"`
	Transform string            `yaml:"transform,omitempty"`
	Default   string            `yaml:"default,omitempty"`
}

// TransformRef declares a custom transform: a name usable in a field's
// transform pipeline (e.g. "trim|my_fn"), whose values are handed to a
// handler declared in the hooks file.
type TransformRef struct {
	Handler   string `yaml:"handler"`
	OnFailure string `yaml:"on_failure,omitempty"`
}

// TargetField sets one field of the target's user from a CMF field, on
// import: CMF is a dotted path into the CMF user (e.g. profile.locale,
// emails.0.value, app_metadata.plan) and Target a path the target connector
// accepts (e.g. Kratos' traits.locale). Transform and Default work as on a
// FieldMapping; an empty result leaves the target field unset.
type TargetField struct {
	CMF       string `yaml:"cmf"`
	Target    string `yaml:"target"`
	Transform string `yaml:"transform,omitempty"`
	Default   string `yaml:"default,omitempty"`
}

// StrategyRef configures one strategy hook point under `strategies`: a
// built-in Strategy, for the few with named alternatives, or a Handler,
// named in the hooks file, the decision is delegated to.
type StrategyRef struct {
	Strategy  string `yaml:"strategy,omitempty"`
	Handler   string `yaml:"handler,omitempty"`
	OnFailure string `yaml:"on_failure,omitempty"`
}

// MetadataRoute moves one metadata key away from where the target connector
// puts it by default: From is app_metadata or user_metadata, Destination a
// target field path (see TargetField), or "drop" to leave the key out.
type MetadataRoute struct {
	Key         string `yaml:"key"`
	From        string `yaml:"from"`
	Destination string `yaml:"destination"`
}

// What Conflict.OnDuplicate can say about a user the target already has.
const (
	OnDuplicateFail   = "fail"
	OnDuplicateSkip   = "skip"
	OnDuplicateUpsert = "upsert"
)

// Conflict decides what an import does with a user the target already has:
// fail it (the default), skip it (reported as skipped, not failed), or
// upsert it, for a target that can.
type Conflict struct {
	OnDuplicate string `yaml:"on_duplicate"`
}

// MetadataPlacement decides where an opaque metadata key ends up on the
// target side (e.g. Auth0's app_metadata vs user_metadata).
type MetadataPlacement struct {
	Key         string `yaml:"key"`
	Destination string `yaml:"destination"`
}

// ManualStep flags a field or decision the engine couldn't resolve
// automatically, surfaced by `iamigrate map` for the operator to fill in.
type ManualStep struct {
	Field  string `yaml:"field"`
	Reason string `yaml:"reason"`
}

// ID strategies an IDStrategy can name.
const (
	// IDPreserve gives the target user the source ID, as iamigrate does
	// with no strategy.
	IDPreserve = "preserve"
	// IDPrefix puts Prefix in front of the source ID.
	IDPrefix = "prefix"
	// IDTemplate renders Template, a Go text/template over the user's
	// SourceID, Email, Username and Phone.
	IDTemplate = "template"
	// IDUUIDv5 is the RFC 9562 version 5 UUID of the source ID in
	// Namespace, so the same user gets the same UUID on every run.
	IDUUIDv5 = "uuidv5"
)

// IDs configures how users are identified on the target.
type IDs struct {
	// Target decides the user ID each target user gets (the id.target
	// strategy). It is assigned once, into the CMF users file, so every
	// import of it sends the same IDs.
	Target *IDStrategy `yaml:"target,omitempty"`
}

// IDStrategy is a built-in Strategy with its options, or a Handler, named
// in the hooks file, the decision is delegated to.
type IDStrategy struct {
	Strategy  string `yaml:"strategy,omitempty"`
	Prefix    string `yaml:"prefix,omitempty"`
	Template  string `yaml:"template,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	Handler   string `yaml:"handler,omitempty"`
	OnFailure string `yaml:"on_failure,omitempty"`
}

// Assigns reports whether s gives users anything else than their source
// ID, and so has to be applied before an import.
func (s *IDStrategy) Assigns() bool {
	return s != nil && (s.Handler != "" || (s.Strategy != "" && s.Strategy != IDPreserve))
}

func (s *IDStrategy) validate() error {
	if s == nil {
		return nil
	}
	if s.Handler != "" {
		if s.Strategy != "" {
			return fmt.Errorf("mapping: ids.target: set either strategy or handler, not both")
		}
		return nil
	}
	if s.OnFailure != "" {
		return fmt.Errorf("mapping: ids.target: on_failure only applies to a handler")
	}
	need := map[string]string{IDPrefix: s.Prefix, IDTemplate: s.Template, IDUUIDv5: s.Namespace}
	opt := map[string]string{IDPrefix: "prefix", IDTemplate: "template", IDUUIDv5: "namespace"}
	switch s.Strategy {
	case "", IDPreserve:
		return nil
	case IDPrefix, IDTemplate, IDUUIDv5:
		if need[s.Strategy] == "" {
			return fmt.Errorf("mapping: ids.target: strategy %s requires %s", s.Strategy, opt[s.Strategy])
		}
		return nil
	}
	return fmt.Errorf("mapping: ids.target: unknown strategy %q (preserve, prefix, template, uuidv5, or a handler)", s.Strategy)
}

// Mapping is the parsed form of mapping.yaml. RecordsPath is the dotted path
// to the array of users in a JSON source file whose root is an object, e.g.
// "data.users".
type Mapping struct {
	Target       string                  `yaml:"target"`
	ConnectionID string                  `yaml:"connection_id,omitempty"`
	RecordsPath  string                  `yaml:"records_path,omitempty"`
	Fields       []FieldMapping          `yaml:"fields,omitempty"`
	AppMetadata  []MetadataPlacement     `yaml:"app_metadata,omitempty"`
	UserMetadata []MetadataPlacement     `yaml:"user_metadata,omitempty"`
	ManualSteps  []ManualStep            `yaml:"manual_steps,omitempty"`
	IDs          IDs                     `yaml:"ids,omitempty"`
	Transforms   map[string]TransformRef `yaml:"transforms,omitempty"`
	TargetFields []TargetField           `yaml:"target_fields,omitempty"`
	Strategies   map[string]StrategyRef  `yaml:"strategies,omitempty"`
	Metadata     []MetadataRoute         `yaml:"metadata,omitempty"`
	Conflict     *Conflict               `yaml:"conflict,omitempty"`
}

// Load reads and parses a mapping.yaml file from path.
func Load(path string) (Mapping, error) {
	b, err := fsx.ReadFile(path)
	if err != nil {
		return Mapping{}, fmt.Errorf("mapping: reading %s: %w", path, err)
	}
	var m Mapping
	if err := yaml.Unmarshal(b, &m); err != nil {
		return Mapping{}, fmt.Errorf("mapping: parsing %s: %w", path, err)
	}
	return m, nil
}

// Save writes m to path as YAML.
func Save(path string, m Mapping) error {
	b, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("mapping: encoding: %w", err)
	}
	if err := fsx.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("mapping: writing %s: %w", path, err)
	}
	return nil
}

// CMFDestination returns the CMF field a given source field maps to, and
// whether a mapping was found.
func (m Mapping) CMFDestination(sourceField string) (string, bool) {
	for _, f := range m.Fields {
		if f.Source == sourceField {
			return f.CMF, true
		}
	}
	return "", false
}
