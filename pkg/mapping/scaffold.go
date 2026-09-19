package mapping

import "fmt"

// Scaffold generates a starting mapping.yaml for target from an export
// manifest's known app_metadata/user_metadata keys, per `iamigrate map`.
// Keys not recognized as standard CMF fields are flagged as manual steps
// rather than guessed at, per DESIGN.md's note that custom claims
// need a human decision.
func Scaffold(target, connectionID string, appMetadataKeys, userMetadataKeys []string) Mapping {
	m := Mapping{Target: target, ConnectionID: connectionID}
	for _, k := range appMetadataKeys {
		m.AppMetadata = append(m.AppMetadata, MetadataPlacement{Key: k, Destination: "app_metadata"})
		m.ManualSteps = append(m.ManualSteps, ManualStep{
			Field:  "app_metadata." + k,
			Reason: fmt.Sprintf("confirm %s should map to %s's app_metadata rather than user_metadata, or be dropped", k, target),
		})
	}
	for _, k := range userMetadataKeys {
		m.UserMetadata = append(m.UserMetadata, MetadataPlacement{Key: k, Destination: "user_metadata"})
	}
	return m
}

// Validate checks m for internal consistency: a target and connection ID
// are set, and every manual step has a field name.
func (m Mapping) Validate() error {
	if m.Target == "" {
		return fmt.Errorf("mapping: target is required")
	}
	for _, s := range m.ManualSteps {
		if s.Field == "" {
			return fmt.Errorf("mapping: manual_steps entry missing a field name")
		}
	}
	return nil
}
