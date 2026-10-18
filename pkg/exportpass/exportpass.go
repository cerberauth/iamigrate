// Package exportpass rewrites a freshly exported CMF users file through the
// export-side strategies that see whole CMF users: export.user (keep, drop
// or replace each user) and then id.target. It runs as a second pass over
// the file so it works the same whatever the source connector, and only
// when one of them is configured, leaving an export without them untouched.
package exportpass

import (
	"context"
	"fmt"
	"io"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/ids"
	"github.com/cerberauth/iamigrate/pkg/strategy"
)

// Pass is the export-side strategies of one export.
type Pass struct {
	set *strategy.Set
	ids *ids.Assigner
}

// New returns the Pass of set's export.user and of a, either possibly nil,
// or nil when neither has anything to do.
func New(set *strategy.Set, a *ids.Assigner) *Pass {
	if !set.Delegated(strategy.ExportUser) && a == nil {
		return nil
	}
	return &Pass{set: set, ids: a}
}

func (p *Pass) batchSize() int {
	n := p.set.BatchSize(strategy.ExportUser)
	if p.ids != nil {
		n = max(n, p.ids.BatchSize())
	}
	return n
}

// Rewrite copies the users of r to w through the strategies, and updates
// manifest to describe what was written: the dropped users become skipped
// records, and the counts are those of the users kept, as replaced.
func (p *Pass) Rewrite(ctx context.Context, r *cmf.Reader, w *cmf.Writer, manifest *connector.Manifest) error {
	manifest.RecordCount = 0
	manifest.HashAlgorithmCounts = map[cmf.Algorithm]int{}
	manifest.NonPortableMFACounts = map[cmf.MFAType]int{}
	batch := make([]cmf.User, 0, p.batchSize())
	flush := func() error {
		kept, err := p.exportUser(ctx, batch, manifest)
		if err != nil {
			return err
		}
		if p.ids != nil {
			if err := p.ids.Assign(ctx, kept); err != nil {
				return err
			}
		}
		for _, u := range kept {
			if err := w.WriteUser(u); err != nil {
				return err
			}
			count(manifest, u)
		}
		batch = batch[:0]
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		batch = append(batch, u)
		if len(batch) == cap(batch) {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// exportUser applies export.user to users, returning those kept.
func (p *Pass) exportUser(ctx context.Context, users []cmf.User, manifest *connector.Manifest) ([]cmf.User, error) {
	items := make([]hooks.Item, len(users))
	for i, u := range users {
		items[i] = hooks.Item{Key: u.SourceID, Data: strategy.UserView(u)}
	}
	res, err := p.set.Resolve(ctx, strategy.ExportUser, items)
	if err != nil || res == nil {
		return users, err
	}
	kept := users[:0:0]
	for _, u := range users {
		var a strategy.UserAnswer
		if err := strategy.Decode(strategy.ExportUser, u.SourceID, res[u.SourceID], &a); err != nil {
			return nil, err
		}
		nu, keep, err := a.Apply(u)
		if err != nil {
			return nil, fmt.Errorf("%s: user %s: %w", strategy.ExportUser, u.SourceID, err)
		}
		if !keep {
			reason := a.Reason
			if reason == "" {
				reason = "dropped by the " + strategy.ExportUser + " hook"
			}
			manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{SourceID: u.SourceID, Reason: reason})
			continue
		}
		kept = append(kept, nu)
	}
	return kept, nil
}

// count adds u to the manifest's counts, as the source connectors count
// the users they write.
func count(m *connector.Manifest, u cmf.User) {
	m.RecordCount++
	if u.Password != nil {
		m.HashAlgorithmCounts[u.Password.Algorithm]++
	}
	for _, f := range u.MFAFactors {
		if !f.Portable {
			m.NonPortableMFACounts[f.Type]++
		}
	}
}
