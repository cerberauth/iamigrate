// Package mapping implements the mapping.yaml schema and the engine that
// applies it: source field -> CMF field on export, CMF field -> target
// field on import.
package mapping

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// FieldMapping pairs one source field with the CMF field it was written to
// (or, on the import side, one CMF field with the target field it maps to),
// plus any transform applied along the way.
type FieldMapping struct {
	Source    string `yaml:"source"`
	CMF       string `yaml:"cmf"`
	Transform string `yaml:"transform,omitempty"`
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

// Mapping is the parsed form of mapping.yaml.
type Mapping struct {
	Target       string              `yaml:"target"`
	ConnectionID string              `yaml:"connection_id,omitempty"`
	Fields       []FieldMapping      `yaml:"fields,omitempty"`
	AppMetadata  []MetadataPlacement `yaml:"app_metadata,omitempty"`
	UserMetadata []MetadataPlacement `yaml:"user_metadata,omitempty"`
	ManualSteps  []ManualStep        `yaml:"manual_steps,omitempty"`
}

// Load reads and parses a mapping.yaml file from path.
func Load(path string) (Mapping, error) {
	b, err := os.ReadFile(path)
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
	if err := os.WriteFile(path, b, 0o600); err != nil {
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
