package flatfile

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// transforms are the value transforms a mapping's `transform` can name, run
// left to right when several are joined with "|" (e.g. "trim|lowercase").
// Empty stays empty, so a default or a missing value is never turned into
// something else.
var transforms = map[string]func(string) (string, error){
	"trim":      func(s string) (string, error) { return strings.TrimSpace(s), nil },
	"lowercase": func(s string) (string, error) { return strings.ToLower(s), nil },
	"uppercase": func(s string) (string, error) { return strings.ToUpper(s), nil },
	// bool turns true/false, yes/no, y/n, on/off, t/f and 1/0 (any case)
	// into "true" or "false".
	"bool": func(s string) (string, error) {
		if s == "" {
			return "", nil
		}
		b, err := parseTruthy(s)
		return strconv.FormatBool(b), err
	},
	// not is bool, inverted: a source's `active` or `enabled` column becomes
	// the CMF `blocked`.
	"not": func(s string) (string, error) {
		if s == "" {
			return "", nil
		}
		b, err := parseTruthy(s)
		return strconv.FormatBool(!b), err
	},
}

func parseTruthy(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "t", "1", "yes", "y", "on":
		return true, nil
	case "false", "f", "0", "no", "n", "off":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a boolean (true/false, yes/no, 1/0)", s)
}

// rule is one validated mapping.FieldMapping.
type rule struct {
	source, dest, def string
	pattern           *regexp.Regexp
	values            map[string]string
	steps             []func(string) (string, error)
}

// validDestination reports whether dest is a column rowToUser reads, or an
// explicit metadata key.
func validDestination(dest string) bool {
	for _, c := range conventionalColumns {
		if dest == c {
			return true
		}
	}
	for _, p := range []string{appMetadataPrefix, userMetadataPrefix} {
		if strings.HasPrefix(dest, p) && len(dest) > len(p) {
			return true
		}
	}
	return false
}

func compileRules(m mapping.Mapping) ([]rule, error) {
	rules := make([]rule, 0, len(m.Fields))
	for i, f := range m.Fields {
		if !validDestination(f.CMF) {
			return nil, fmt.Errorf("mapping: fields[%d]: unknown cmf field %q (one of %s, or %s<key>, %s<key>)",
				i, f.CMF, strings.Join(conventionalColumns, ", "), appMetadataPrefix, userMetadataPrefix)
		}
		if f.Source == "" && f.Default == "" {
			return nil, fmt.Errorf("mapping: fields[%d] (%s): needs a source, a default, or both", i, f.CMF)
		}
		r := rule{source: f.Source, dest: f.CMF, def: f.Default, values: f.Values}
		if f.Pattern != "" {
			re, err := regexp.Compile(f.Pattern)
			if err != nil {
				return nil, fmt.Errorf("mapping: fields[%d] (%s): pattern: %w", i, f.CMF, err)
			}
			if re.NumSubexp() < 1 {
				return nil, fmt.Errorf("mapping: fields[%d] (%s): pattern %q needs a capture group, e.g. ^[^$]*\\$(.*)$", i, f.CMF, f.Pattern)
			}
			r.pattern = re
		}
		if f.Transform != "" {
			for _, name := range strings.Split(f.Transform, "|") {
				step, ok := transforms[strings.TrimSpace(name)]
				if !ok {
					return nil, fmt.Errorf("mapping: fields[%d] (%s): unknown transform %q", i, f.CMF, name)
				}
				r.steps = append(r.steps, step)
			}
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// Normalize rewrites rows into the column convention rowToUser reads, as
// directed by m.Fields. Each field takes the value of its source column (or
// its default when that is missing or empty), runs its transforms, and lands
// in its cmf column. A value goes through, in order: its pattern (keeping the
// first capture group, or nothing when it doesn't match), its values table
// (unlisted values are kept), its default (if it is empty by now) and its
// transforms. When several fields share a cmf column the first one
// with a value wins, which makes fallbacks easy (id, else email).
//
// A column named as a source is consumed: it only exists under the cmf
// fields it is mapped to. Every other column is kept as it is, so a mapping
// only needs to cover what differs from the convention. With no fields the
// rows are returned untouched.
func Normalize(rows []map[string]string, m mapping.Mapping) ([]map[string]string, error) {
	if len(m.Fields) == 0 {
		return rows, nil
	}
	rules, err := compileRules(m)
	if err != nil {
		return nil, err
	}
	consumed := map[string]bool{}
	for _, r := range rules {
		if r.source != "" {
			consumed[r.source] = true
		}
	}

	out := make([]map[string]string, len(rows))
	for i, row := range rows {
		n := make(map[string]string, len(row))
		for k, v := range row {
			if !consumed[k] {
				n[k] = v
			}
		}
		written := map[string]bool{}
		for _, r := range rules {
			if written[r.dest] {
				continue
			}
			var v string
			if r.source != "" {
				v = row[r.source]
			}
			if r.pattern != nil {
				v = ""
				if m := r.pattern.FindStringSubmatch(row[r.source]); m != nil {
					v = m[1]
				}
			}
			if t, ok := r.values[v]; ok {
				v = t
			}
			if v == "" {
				v = r.def
			}
			for _, step := range r.steps {
				if v, err = step(v); err != nil {
					return nil, fmt.Errorf("record %d: %s -> %s: %w", i+1, r.source, r.dest, err)
				}
			}
			if v != "" {
				n[r.dest] = v
				written[r.dest] = true
			}
		}
		// rowToUser reads these leniently (anything but "true" is false);
		// settle them here so a stray "yes" can't silently become false.
		for _, c := range []string{colBlocked, colEmailVerified} {
			if v := n[c]; v != "" {
				b, err := parseTruthy(v)
				if err != nil {
					return nil, fmt.Errorf("record %d: %s: %w", i+1, c, err)
				}
				n[c] = strconv.FormatBool(b)
			}
		}
		if err := settlePasswordColumns(n); err != nil {
			return nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		out[i] = n
	}
	return out, nil
}

// settlePasswordColumns writes the password columns in their canonical
// spelling ("SHA-256" -> sha256, "HEX" -> hex), so a typo stops the run here
// instead of surfacing as an unusable hash at import time.
func settlePasswordColumns(n map[string]string) error {
	if v := n[colPasswordAlgorithm]; v != "" {
		a, err := iamhash.ParseAlgorithm(v)
		if err != nil {
			return fmt.Errorf("%s: %w", colPasswordAlgorithm, err)
		}
		n[colPasswordAlgorithm] = string(a)
	}
	for col, allowed := range map[string][]cmf.Encoding{
		colPasswordEncoding:     {cmf.EncodingHex, cmf.EncodingBase64},
		colPasswordSaltEncoding: {cmf.EncodingHex, cmf.EncodingBase64, cmf.EncodingUTF8},
	} {
		if v := n[col]; v != "" {
			e, err := parseEncoding(v, allowed...)
			if err != nil {
				return fmt.Errorf("%s: %w", col, err)
			}
			n[col] = string(e)
		}
	}
	if v := n[colPasswordSaltPosition]; v != "" {
		p := strings.ToLower(strings.TrimSpace(v))
		if p != string(cmf.SaltPrefix) && p != string(cmf.SaltSuffix) {
			return fmt.Errorf("%s: %q is neither prefix nor suffix", colPasswordSaltPosition, v)
		}
		n[colPasswordSaltPosition] = p
	}
	return nil
}
