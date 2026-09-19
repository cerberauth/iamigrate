// Package connector defines the SourceConnector and TargetConnector
// interfaces every provider implements, per DESIGN.md's Architecture
// section, plus the supporting types those interfaces exchange.
package connector

import (
	"context"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// ExportOptions is a marker interface for connector-specific export
// configuration (e.g. fixture's count/hash/mfa/locale/seed, flatfile's
// input path and format). Each connector defines its own concrete options
// type embedding BaseExportOptions, then type-asserts back to it in
// Export.
type ExportOptions interface {
	isExportOptions()
}

// BaseExportOptions is embedded by every connector's concrete
// ExportOptions type to satisfy the ExportOptions interface, since its
// marker method is unexported and can otherwise only be implemented from
// within this package.
type BaseExportOptions struct{}

func (BaseExportOptions) isExportOptions() {}

// ImportOptions configures a TargetConnector.Import call.
type ImportOptions struct {
	ConnectionID string
	Upsert       bool
	// Organizations and Roles are populated by the caller (cmd/iamigrate)
	// when organizations.cmf.jsonl / roles.cmf.jsonl sit alongside the
	// users file, so a target that supports them (Capabilities().
	// SupportsOrgs / SupportsRoles) can run its second phase without a
	// second CLI invocation, per DESIGN.md's CLI reference.
	Organizations []cmf.Organization
	Roles         []cmf.Role
}

// Capabilities declares what a TargetConnector accepts, so validate can
// fail fast, before any API call, on a CMF file containing a hash
// algorithm or MFA type the target can't import.
type Capabilities struct {
	HashAlgorithms []cmf.Algorithm
	MFATypes       []cmf.MFAType
	SupportsOrgs   bool
	SupportsRoles  bool
}

// SupportsAlgorithm reports whether alg is in the capability set.
func (c Capabilities) SupportsAlgorithm(alg cmf.Algorithm) bool {
	for _, a := range c.HashAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// SupportsMFAType reports whether t is in the capability set.
func (c Capabilities) SupportsMFAType(t cmf.MFAType) bool {
	for _, m := range c.MFATypes {
		if m == t {
			return true
		}
	}
	return false
}

// SkippedRecord notes a source record an exporter couldn't fully translate.
type SkippedRecord struct {
	SourceID string `json:"source_id"`
	Reason   string `json:"reason"`
}

// Manifest summarizes an export run: record counts, per-algorithm hash
// counts, non-portable MFA counts, and any skipped records.
type Manifest struct {
	RecordCount          int                   `json:"record_count"`
	HashAlgorithmCounts  map[cmf.Algorithm]int `json:"hash_algorithm_counts,omitempty"`
	NonPortableMFACounts map[cmf.MFAType]int   `json:"non_portable_mfa_counts,omitempty"`
	SkippedRecords       []SkippedRecord       `json:"skipped_records,omitempty"`
}

// ImportError is a single user's failure during a target import.
type ImportError struct {
	SourceID string `json:"source_id"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// ImportReport summarizes a target import run.
type ImportReport struct {
	Succeeded                 []string          `json:"succeeded"`
	Failed                    []ImportError     `json:"failed"`
	OrgIDMap                  map[string]string `json:"org_id_map,omitempty"`
	RoleIDMap                 map[string]string `json:"role_id_map,omitempty"`
	RequiresPasswordReset     []string          `json:"requires_password_reset,omitempty"`
	RequiresReenrollment      []string          `json:"requires_reenrollment,omitempty"`
	RequiresRecoveryCodeRegen []string          `json:"requires_recovery_code_regen,omitempty"`
}

// DriftEntry is one attribute mismatch found by Verify.
type DriftEntry struct {
	SourceID string   `json:"source_id"`
	Fields   []string `json:"fields"`
}

// DiffReport summarizes a reconciliation between CMF and a live target.
type DiffReport struct {
	MissingInTarget []string     `json:"missing_in_target"`
	AttributeDrift  []DriftEntry `json:"attribute_drift,omitempty"`
}

// SourceConnector exports identities from a provider into CMF.
type SourceConnector interface {
	Name() string
	Export(ctx context.Context, w *cmf.Writer, opts ExportOptions) (Manifest, error)
}

// TargetConnector imports CMF identities into a provider.
type TargetConnector interface {
	Name() string
	Capabilities() Capabilities
	Import(ctx context.Context, r *cmf.Reader, m mapping.Mapping, opts ImportOptions) (ImportReport, error)
	Verify(ctx context.Context, r *cmf.Reader) (DiffReport, error)
}
