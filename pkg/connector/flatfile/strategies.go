package flatfile

import (
	"context"
	"fmt"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/strategy"
)

// idSource hands the raw rows, after export.record and before any
// mapping, to the mapping's id.source handler, if any, which answers the
// source_id of each. A row it answers none for keeps the one it has.
// positions are the record numbers of rows (nil: their own), which key the
// items as they do for export.record.
func idSource(ctx context.Context, rows []map[string]string, positions []int, m mapping.Mapping) ([]map[string]string, error) {
	if m.Strategies[strategy.IDSource].Handler == "" {
		return rows, nil
	}
	set, err := strategy.New(strategy.Only(m, strategy.IDSource), hooks.FromContext(ctx))
	if err != nil {
		return nil, err
	}
	key := func(i int) string {
		if positions != nil {
			return recordKey(positions[i] - 1)
		}
		return recordKey(i)
	}
	items := make([]hooks.Item, len(rows))
	for i, row := range rows {
		items[i] = hooks.Item{Key: key(i), Data: map[string]any{"record": row}}
	}
	res, err := set.Resolve(ctx, strategy.IDSource, items)
	if err != nil || res == nil {
		return rows, err
	}
	out := make([]map[string]string, len(rows))
	for i, row := range rows {
		var a struct {
			SourceID string `json:"source_id"`
		}
		if err := strategy.Decode(strategy.IDSource, key(i), res[key(i)], &a); err != nil {
			return nil, err
		}
		n := make(map[string]string, len(row)+1)
		for k, v := range row {
			n[k] = v
		}
		if a.SourceID != "" {
			n[colSourceID] = a.SourceID
		}
		out[i] = n
	}
	return out, nil
}

// detection is what the hash.detect handler decided of one row's password:
// the password to use, or why the record is skipped.
type detection struct {
	password *cmf.Password
	skip     string
}

// detectHashes hands the mapping's hash.detect handler the password of each
// row whose password columns don't settle it (rows is normalized, so those
// are the columns rowToUser reads), and returns what it decided by row
// index. Rows the handler has no say on, or doesn't answer for, are left
// to rowToUser, which skips them with its own reason; a password the handler
// answers with that iamhash rejects skips the record.
func detectHashes(ctx context.Context, rows []map[string]string, hints map[string]cmf.Algorithm, m mapping.Mapping) (map[int]detection, error) {
	if m.Strategies[strategy.HashDetect].Handler == "" {
		return nil, nil
	}
	set, err := strategy.New(strategy.Only(m, strategy.HashDetect), hooks.FromContext(ctx))
	if err != nil {
		return nil, err
	}
	var idx []int
	var items []hooks.Item
	seen := map[string]bool{}
	for i, row := range rows {
		id := row[colSourceID]
		if id == "" || row[colPassword] == "" {
			continue
		}
		_, reason := readPassword(row, hints)
		if reason == "" {
			continue
		}
		if seen[id] {
			return nil, fmt.Errorf("%s: more than one record needing a decision has source_id %q", strategy.HashDetect, id)
		}
		seen[id] = true
		columns := map[string]string{}
		for _, c := range []string{colPasswordAlgorithm, colPasswordEncoding, colPasswordSalt, colPasswordSaltEncoding, colPasswordSaltPosition} {
			if row[c] != "" {
				columns[c] = row[c]
			}
		}
		idx = append(idx, i)
		items = append(items, hooks.Item{Key: id, Data: map[string]any{
			"source_id": id,
			"password":  row[colPassword],
			"columns":   columns,
			"reason":    reason,
		}})
	}
	res, err := set.Resolve(ctx, strategy.HashDetect, items)
	if err != nil || res == nil {
		return nil, err
	}
	out := map[int]detection{}
	for n, i := range idx {
		a := struct {
			cmf.Password
			Skip string `json:"skip"`
		}{Password: cmf.Password{Portable: true}}
		if err := strategy.Decode(strategy.HashDetect, items[n].Key, res[items[n].Key], &a); err != nil {
			return nil, err
		}
		switch {
		case strings.TrimSpace(a.Skip) != "":
			out[i] = detection{skip: a.Skip}
		case a.Algorithm == "":
			// {}: no decision, the row is skipped for the reason it was sent.
		default:
			if err := iamhash.Validate(a.Password); err != nil {
				out[i] = detection{skip: fmt.Sprintf("%s: %v", strategy.HashDetect, err)}
				continue
			}
			pw := a.Password
			out[i] = detection{password: &pw}
		}
	}
	return out, nil
}
