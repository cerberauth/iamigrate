// Package ids applies a mapping's id.target strategy: the user ID each
// user is to get on the target.
//
// IDs are assigned once, into the CMF users file's target_ids, rather than
// computed at import time: the file stays the single record of what is
// imported, so a resumed import (and its chunk fingerprints), the
// orgs/roles phase and verify all see the same IDs, even when a webhook
// decided them.
package ids

import (
	"context"
	"crypto/sha1" //nolint:gosec // RFC 9562 UUIDv5 is defined over SHA-1
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/strategy"
)

// Hook is the strategy hook point a handler-delegated id.target is sent
// to.
const Hook = "id.target"

// builtinBatch is how many users Rewrite reads at a time when no handler
// sets a batch size.
const builtinBatch = 100

// Assigner assigns target IDs to users with one id.target strategy.
type Assigner struct {
	target  string
	builtin func(u cmf.User) (string, error)
	batcher *hooks.Batcher
}

// NewAssigner returns the Assigner of s for target, whose capabilities are
// caps, or nil when s gives users their source ID, so there is nothing to
// assign. A handler is looked up in d's hooks file.
func NewAssigner(s *mapping.IDStrategy, target string, caps connector.Capabilities, d *hooks.Dispatcher) (*Assigner, error) {
	if !s.Assigns() {
		return nil, nil
	}
	if target == "" {
		return nil, errors.New("ids: id.target needs a target connector")
	}
	if !caps.SupportsCustomID {
		return nil, fmt.Errorf("ids: %s generates its own user IDs: ids.target can't choose them", target)
	}
	a := &Assigner{target: target}
	if s.Handler != "" {
		ref := hooks.Ref{Handler: s.Handler, OnFailure: hooks.OnFailure(s.OnFailure)}
		if err := d.Config().CheckRef(ref); err != nil {
			return nil, fmt.Errorf("ids: ids.target: %w", err)
		}
		if ref.OnFailure == hooks.Ignore {
			// Ignoring a failure would give some users their source ID
			// and others the handler's, with no way to tell which.
			return nil, errors.New("ids: ids.target: on_failure: ignore isn't supported, a failed call must stop the assignment")
		}
		a.batcher = d.Batcher(Hook, ref)
		return a, nil
	}
	switch s.Strategy {
	case mapping.IDPrefix:
		a.builtin = func(u cmf.User) (string, error) { return s.Prefix + u.SourceID, nil }
	case mapping.IDUUIDv5:
		ns, err := parseUUID(s.Namespace)
		if err != nil {
			return nil, fmt.Errorf("ids: ids.target namespace: %w", err)
		}
		a.builtin = func(u cmf.User) (string, error) { return uuidV5(ns, u.SourceID), nil }
	case mapping.IDTemplate:
		t, err := template.New("id").Option("missingkey=error").Parse(s.Template)
		if err != nil {
			return nil, fmt.Errorf("ids: ids.target template: %w", err)
		}
		a.builtin = func(u cmf.User) (string, error) {
			var b strings.Builder
			if err := t.Execute(&b, templateData(u)); err != nil {
				return "", err
			}
			return b.String(), nil
		}
	default:
		return nil, fmt.Errorf("ids: unknown ids.target strategy %q", s.Strategy)
	}
	return a, nil
}

// Target is the target connector name IDs are assigned for.
func (a *Assigner) Target() string { return a.target }

// Assign sets the target ID of every user in users that hasn't one yet: an
// ID, once assigned, is kept.
func (a *Assigner) Assign(ctx context.Context, users []cmf.User) error {
	var pending []int
	for i, u := range users {
		if u.TargetIDs[a.target] == "" {
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if a.batcher != nil {
		return a.assignWithHandler(ctx, users, pending)
	}
	for _, i := range pending {
		id, err := a.builtin(users[i])
		if err != nil {
			return fmt.Errorf("ids: user %s: %w", users[i].SourceID, err)
		}
		if err := set(&users[i], a.target, id); err != nil {
			return err
		}
	}
	return nil
}

func (a *Assigner) assignWithHandler(ctx context.Context, users []cmf.User, pending []int) error {
	items := make([]hooks.Item, len(pending))
	for k, i := range pending {
		items[k] = hooks.Item{Key: users[i].SourceID, Data: handlerView(users[i], a.target)}
	}
	res, err := a.batcher.Resolve(ctx, items)
	if err != nil {
		return err
	}
	for _, i := range pending {
		var ans struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(res[users[i].SourceID], &ans); err != nil {
			return fmt.Errorf("ids: %s answer for user %s: %w", Hook, users[i].SourceID, err)
		}
		if err := set(&users[i], a.target, ans.ID); err != nil {
			return err
		}
	}
	return nil
}

func set(u *cmf.User, target, id string) error {
	if id == "" {
		return fmt.Errorf("ids: user %s: id.target gave an empty ID", u.SourceID)
	}
	if u.TargetIDs == nil {
		u.TargetIDs = map[string]string{}
	}
	u.TargetIDs[target] = id
	return nil
}

// BatchSize is how many users to hand Assign at a time.
func (a *Assigner) BatchSize() int {
	if a.batcher != nil {
		return a.batcher.Size()
	}
	return builtinBatch
}

// Rewrite copies the users of r to w, assigning their target IDs on the
// way, a batch at a time.
func (a *Assigner) Rewrite(ctx context.Context, r *cmf.Reader, w *cmf.Writer) (int, error) {
	n := 0
	batch := make([]cmf.User, 0, a.BatchSize())
	flush := func() error {
		if err := a.Assign(ctx, batch); err != nil {
			return err
		}
		for _, u := range batch {
			if err := w.WriteUser(u); err != nil {
				return err
			}
		}
		n += len(batch)
		batch = batch[:0]
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		batch = append(batch, u)
		if len(batch) == cap(batch) {
			if err := flush(); err != nil {
				return n, err
			}
		}
	}
	return n, flush()
}

// handlerView is what an id.target handler is told of a user.
func handlerView(u cmf.User, target string) map[string]any {
	v := strategy.UserView(u)
	v["target"] = target
	return v
}

// templateData is what an ids.target template can use.
func templateData(u cmf.User) map[string]string {
	d := map[string]string{"SourceID": u.SourceID, "Username": u.Username, "Email": "", "Phone": ""}
	if len(u.Emails) > 0 {
		d["Email"] = u.Emails[0].Value
	}
	if len(u.Phones) > 0 {
		d["Phone"] = u.Phones[0].Value
	}
	return d
}

func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	h := strings.ReplaceAll(s, "-", "")
	if len(h) != 32 || len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("%q is not a UUID", s)
	}
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return u, fmt.Errorf("%q is not a UUID", s)
	}
	return u, nil
}

// uuidV5 is the name-based (SHA-1) UUID of name in namespace ns, per RFC
// 9562 section 5.5.
func uuidV5(ns [16]byte, name string) string {
	h := sha1.New() //nolint:gosec // RFC 9562 UUIDv5 is defined over SHA-1
	h.Write(ns[:])
	h.Write([]byte(name))
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = u[6]&0x0f | 0x50
	u[8] = u[8]&0x3f | 0x80
	b := hex.EncodeToString(u[:])
	return b[0:8] + "-" + b[8:12] + "-" + b[12:16] + "-" + b[16:20] + "-" + b[20:32]
}
