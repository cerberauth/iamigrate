package importprep

import (
	"context"
	"fmt"
	"maps"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/strategy"
)

// Placement is one metadata key metadata.place's handler places for a user:
// where the key is read from and the target field it goes to, or "drop".
type Placement struct {
	Key         string `json:"key"`
	From        string `json:"from"`
	Destination string `json:"destination"`
}

// metadataOf returns the metadata map of u named from (app_metadata or
// user_metadata).
func metadataOf(u *cmf.User, from string) map[string]any {
	if from == metadataApp {
		return u.AppMetadata
	}
	return u.UserMetadata
}

// place takes the metadata keys metadata.place's handler places out of each
// user, and returns them as fields at their destination (none for a dropped
// key), like route does for the static routes, which then only see the keys
// left. Users without metadata aren't sent. A destination the target can't
// set, a key the user doesn't have, or a key placed twice fails the import.
func (a *Applier) place(ctx context.Context, users []cmf.User) ([][]Field, error) {
	out := make([][]Field, len(users))
	if !a.set.Delegated(strategy.MetadataPlace) {
		return out, nil
	}
	var items []hooks.Item
	for _, u := range users {
		if len(u.AppMetadata) > 0 || len(u.UserMetadata) > 0 {
			items = append(items, hooks.Item{Key: u.SourceID, Data: strategy.UserView(u)})
		}
	}
	res, err := a.set.Resolve(ctx, strategy.MetadataPlace, items)
	if err != nil || res == nil {
		return out, err
	}
	for i := range users {
		u := &users[i]
		raw, ok := res[u.SourceID]
		if !ok {
			continue
		}
		var placements []Placement
		if err := strategy.Decode(strategy.MetadataPlace, u.SourceID, raw, &placements); err != nil {
			return nil, err
		}
		u.AppMetadata, u.UserMetadata = maps.Clone(u.AppMetadata), maps.Clone(u.UserMetadata)
		placed := map[Placement]bool{}
		for j, p := range placements {
			fail := func(format string, args ...any) error {
				return fmt.Errorf("%s: user %s: placement[%d] (%s): %s", strategy.MetadataPlace, u.SourceID, j, p.Key, fmt.Sprintf(format, args...))
			}
			switch {
			case p.Key == "" || p.Destination == "":
				return nil, fail("key and destination are required")
			case p.From != metadataApp && p.From != metadataUser:
				return nil, fail("from must be %s or %s", metadataApp, metadataUser)
			}
			if p.Destination != routeDrop {
				if err := a.check(p.Destination); err != nil {
					return nil, fail("%v", err)
				}
			}
			from := metadataOf(u, p.From)
			v, ok := from[p.Key]
			switch {
			case placed[Placement{Key: p.Key, From: p.From}]:
				return nil, fail("placed twice")
			case !ok:
				return nil, fail("the user has no %s key %q", p.From, p.Key)
			}
			placed[Placement{Key: p.Key, From: p.From}] = true
			delete(from, p.Key)
			if p.Destination != routeDrop && !empty(v) {
				out[i] = append(out[i], Field{Path: p.Destination, Value: v})
			}
		}
	}
	return out, nil
}
