// Package fixture implements a synthetic SourceConnector: the test-data
// generator behind `iamigrate testdata generate`. It also writes
// answer-key.json, pairing each generated user's source_id with the
// cleartext password (and TOTP secret, where enrolled) used to produce
// their CMF record, so the live integration test can prove a translated
// hash actually verifies.
package fixture

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
)

// HashSpec is one parsed --hash <algo>:<params> flag.
type HashSpec struct {
	Algorithm cmf.Algorithm
	Params    map[string]string
}

// ParseHashSpec parses "algo:k=v,k=v,..." into a HashSpec.
func ParseHashSpec(s string) (HashSpec, error) {
	algo, paramStr, _ := strings.Cut(s, ":")
	if algo == "" {
		return HashSpec{}, fmt.Errorf("fixture: empty --hash algorithm in %q", s)
	}
	spec := HashSpec{Algorithm: cmf.Algorithm(algo), Params: map[string]string{}}
	if paramStr == "" {
		return spec, nil
	}
	for _, kv := range strings.Split(paramStr, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return HashSpec{}, fmt.Errorf("fixture: malformed param %q in --hash %q", kv, s)
		}
		spec.Params[k] = v
	}
	return spec, nil
}

func (s HashSpec) intParam(key string, def int) int {
	v, ok := s.Params[key]
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// MFASpec is one parsed --mfa <type>:rate=<0-1> flag.
type MFASpec struct {
	Type cmf.MFAType
	Rate float64
}

// ParseMFASpec parses "type:rate=<0-1>" into an MFASpec.
func ParseMFASpec(s string) (MFASpec, error) {
	typ, paramStr, ok := strings.Cut(s, ":")
	if !ok {
		return MFASpec{}, fmt.Errorf("fixture: --mfa %q missing rate=<0-1>", s)
	}
	rateStr, ok := strings.CutPrefix(paramStr, "rate=")
	if !ok {
		return MFASpec{}, fmt.Errorf("fixture: --mfa %q missing rate=<0-1>", s)
	}
	rate, err := strconv.ParseFloat(rateStr, 64)
	if err != nil || rate < 0 || rate > 1 {
		return MFASpec{}, fmt.Errorf("fixture: --mfa %q has an invalid rate (must be 0-1)", s)
	}
	return MFASpec{Type: cmf.MFAType(typ), Rate: rate}, nil
}

// ExportOptions configures the fixture generator.
type ExportOptions struct {
	connector.BaseExportOptions
	Count         int
	Hashes        []HashSpec
	MFAs          []MFASpec
	Locale        string
	Seed          int64
	AnswerKeyPath string // if set, answer-key.json is written here
}
