package flatfile

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/transform"
)

// rule is one validated mapping.FieldMapping.
type rule struct {
	source, dest, def string
	pattern           *regexp.Regexp
	values            map[string]string
	pipeline          *transform.Pipeline
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

func compileRules(m mapping.Mapping, reg *transform.Registry) ([]rule, error) {
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
		p, err := reg.Compile(f.Transform)
		if err != nil {
			return nil, fmt.Errorf("mapping: fields[%d] (%s): %w", i, f.CMF, err)
		}
		r.pipeline = p
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
	return normalize(context.Background(), rows, m, nil)
}

// normalize is Normalize, with custom transforms sent to their handlers
// through d. Each field runs over every row before the next field does, so a
// custom transform is one batched call per field, not one per row; the
// result is the same as field by field within each row.
func normalize(ctx context.Context, rows []map[string]string, m mapping.Mapping, d *hooks.Dispatcher) ([]map[string]string, error) {
	if len(m.Fields) == 0 {
		return rows, nil
	}
	reg, err := transform.New(m, transform.ExportHook, d)
	if err != nil {
		return nil, err
	}
	rules, err := compileRules(m, reg)
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
	written := make([]map[string]bool, len(rows))
	for i, row := range rows {
		n := make(map[string]string, len(row))
		for k, v := range row {
			if !consumed[k] {
				n[k] = v
			}
		}
		out[i], written[i] = n, map[string]bool{}
	}
	for _, r := range rules {
		var idx []int
		var keys, vals []string
		for i, row := range rows {
			if written[i][r.dest] {
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
			idx, keys, vals = append(idx, i), append(keys, strconv.Itoa(i+1)), append(vals, v)
		}
		if err := r.pipeline.Apply(ctx, r.dest, keys, vals); err != nil {
			var ve *transform.ValueError
			if errors.As(err, &ve) {
				return nil, fmt.Errorf("record %d: %s -> %s: %w", idx[ve.Index]+1, r.source, r.dest, ve.Err)
			}
			return nil, fmt.Errorf("%s -> %s: %w", r.source, r.dest, err)
		}
		for k, i := range idx {
			if vals[k] != "" {
				out[i][r.dest] = vals[k]
				written[i][r.dest] = true
			}
		}
	}
	for i, n := range out {
		// rowToUser reads these leniently (anything but "true" is false);
		// settle them here so a stray "yes" can't silently become false.
		for _, c := range []string{colBlocked, colEmailVerified} {
			if v := n[c]; v != "" {
				b, err := transform.ParseBool(v)
				if err != nil {
					return nil, fmt.Errorf("record %d: %s: %w", i+1, c, err)
				}
				n[c] = strconv.FormatBool(b)
			}
		}
		if err := settlePasswordColumns(n); err != nil {
			return nil, fmt.Errorf("record %d: %w", i+1, err)
		}
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
