package cmf

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema/user.schema.json
var userSchemaJSON []byte

var userSchema *jsonschema.Schema

func init() {
	c := jsonschema.NewCompiler()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(userSchemaJSON))
	if err != nil {
		panic(fmt.Sprintf("cmf: parsing embedded user schema: %v", err))
	}
	const schemaURL = "https://cerberauth.com/iamigrate/schema/user-1.0.json"
	if err := c.AddResource(schemaURL, doc); err != nil {
		panic(fmt.Sprintf("cmf: adding embedded user schema: %v", err))
	}
	userSchema, err = c.Compile(schemaURL)
	if err != nil {
		panic(fmt.Sprintf("cmf: compiling embedded user schema: %v", err))
	}
}

// ValidateVersion reports an error if v is not a CMF version this package
// understands. It's checked before any other decode step, per the design
// doc: every consumer checks cmf_version first.
func ValidateVersion(v string) error {
	if v == "" {
		return fmt.Errorf("cmf: missing cmf_version")
	}
	if v != Version {
		return fmt.Errorf("cmf: unsupported cmf_version %q (this build understands %q)", v, Version)
	}
	return nil
}

// ValidateUser checks u against the CMF user JSON Schema and cmf_version.
func ValidateUser(u User) error {
	if err := ValidateVersion(u.CMFVersion); err != nil {
		return err
	}
	b, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("cmf: marshaling user for validation: %w", err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("cmf: unmarshaling user for validation: %w", err)
	}
	if err := userSchema.Validate(v); err != nil {
		return fmt.Errorf("cmf: schema validation failed for source_id %q: %w", u.SourceID, err)
	}
	return nil
}
