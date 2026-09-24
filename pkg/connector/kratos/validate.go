package kratos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// identitySchemaURL is a placeholder resource ID used to compile a
// --schema-file with jsonschema.Compiler; it's never dereferenced over the
// network.
const identitySchemaURL = "iamigrate://kratos-identity-schema"

// fieldTraits is the Problem.Field value for trait-related rules.
const fieldTraits = "traits"

// IdentitySchema wraps a compiled Kratos identity schema (--schema-file)
// plus the trait names it marks as a credentials identifier, so
// ValidateUser can check a CMF user's traits offline against it.
type IdentitySchema struct {
	compiled    *jsonschema.Schema
	identifiers []string
}

// LoadIdentitySchema reads and compiles a Kratos identity schema JSON file
// (--schema-file), and extracts which traits it marks as an identifier:
// any trait with an "ory.sh/kratos".credentials.<method>.identifier ==
// true extension.
func LoadIdentitySchema(path string) (*IdentitySchema, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kratos: reading identity schema %s: %w", path, err)
	}

	c := jsonschema.NewCompiler()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("kratos: parsing identity schema %s: %w", path, err)
	}
	if err := c.AddResource(identitySchemaURL, doc); err != nil {
		return nil, fmt.Errorf("kratos: adding identity schema %s: %w", path, err)
	}
	compiled, err := c.Compile(identitySchemaURL)
	if err != nil {
		return nil, fmt.Errorf("kratos: compiling identity schema %s: %w", path, err)
	}

	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("kratos: parsing identity schema %s: %w", path, err)
	}

	return &IdentitySchema{compiled: compiled, identifiers: identifierTraits(raw)}, nil
}

// identifierTraits returns the names of every trait under
// properties.traits.properties that schema marks as a credentials
// identifier.
func identifierTraits(schema map[string]any) []string {
	traits, ok := digMap(schema, "properties", "traits", "properties")
	if !ok {
		return nil
	}
	var names []string
	for name, def := range traits {
		defMap, ok := def.(map[string]any)
		if ok && isIdentifierTrait(defMap) {
			names = append(names, name)
		}
	}
	return names
}

// isIdentifierTrait reports whether a trait's schema definition marks it
// as a Kratos credentials identifier via the "ory.sh/kratos" extension,
// e.g. `"ory.sh/kratos": {"credentials": {"password": {"identifier":
// true}}}}`.
func isIdentifierTrait(def map[string]any) bool {
	creds, ok := digMap(def, "ory.sh/kratos", "credentials")
	if !ok {
		return false
	}
	for _, v := range creds {
		if m, ok := v.(map[string]any); ok && m["identifier"] == true {
			return true
		}
	}
	return false
}

// digMap walks m through a chain of nested map keys, returning ok=false
// as soon as one is missing or isn't itself a map.
func digMap(m map[string]any, keys ...string) (map[string]any, bool) {
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// ValidateUser checks u's traits against c.IdentitySchema (--schema-file),
// offline: required fields, formats, and additionalProperties come from
// the schema itself; ValidateUser also flags a user with no value set for
// any trait the schema marks as a credentials identifier, since Kratos
// can't create a usable identity without one. Without a --schema-file,
// ValidateUser has nothing to check and returns no problems.
func (c *Connector) ValidateUser(u cmf.User) []connector.Problem {
	if c.IdentitySchema == nil {
		return nil
	}

	var problems []connector.Problem
	traits := buildTraits(u)

	doc := map[string]any{fieldTraits: traits}
	b, err := json.Marshal(doc)
	if err == nil {
		var v any
		if err := json.Unmarshal(b, &v); err == nil {
			if err := c.IdentitySchema.compiled.Validate(v); err != nil {
				problems = append(problems, connector.Problem{
					SourceID: u.SourceID, Field: fieldTraits,
					Rule: "fails identity schema", Value: err.Error(),
				})
			}
		}
	}

	if len(c.IdentitySchema.identifiers) > 0 && !hasIdentifierTrait(traits, c.IdentitySchema.identifiers) {
		problems = append(problems, connector.Problem{
			SourceID: u.SourceID, Field: fieldTraits,
			Rule: fmt.Sprintf("no value set for an identifier trait (%s)", strings.Join(c.IdentitySchema.identifiers, ", ")),
		})
	}

	return problems
}

// hasIdentifierTrait reports whether traits has a non-empty string value
// for at least one of names.
func hasIdentifierTrait(traits map[string]any, names []string) bool {
	for _, n := range names {
		if s, ok := traits[n].(string); ok && s != "" {
			return true
		}
	}
	return false
}
