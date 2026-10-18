package hooks

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Dispatcher fires the hooks of one hooks.yaml. The zero of *Dispatcher,
// nil, fires nothing: every call is a no-op that lets the built-in
// behavior apply.
//
// ForJob and InState return copies scoped to a job and a state, which the
// envelopes and recorded Results carry, so one Dispatcher can serve every
// job of `iamigrate serve`.
type Dispatcher struct {
	cfg      *Config
	handlers map[string]Handler
	sizes    map[string]int

	// scope keys event IDs: the job ID, or a random ID per standalone run.
	scope  string
	jobID  string
	state  string
	record func(Result)
	now    func() time.Time
}

// New returns the Dispatcher of cfg, building its handlers (and so reading
// their secrets) up front, so a missing secret stops a run before any step
// rather than at its first hook call.
func New(cfg *Config) (*Dispatcher, error) {
	d := &Dispatcher{cfg: cfg, handlers: map[string]Handler{}, sizes: map[string]int{}, now: time.Now}
	for _, name := range sortedKeys(cfg.Handlers) {
		wc := cfg.Handlers[name].Webhook
		w, err := NewWebhook(*wc)
		if err != nil {
			return nil, fmt.Errorf("hooks: handler %q: %w", name, err)
		}
		d.handlers[name] = w
		d.sizes[name] = defaultBatchSize
		if wc.BatchSize > 0 {
			d.sizes[name] = wc.BatchSize
		}
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	d.scope = "run-" + hex.EncodeToString(b[:])
	return d, nil
}

// SetHandler replaces (or adds) the handler named name, for tests and for
// handler kinds built outside this package.
func (d *Dispatcher) SetHandler(name string, h Handler, batchSize int) {
	d.handlers[name] = h
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	d.sizes[name] = batchSize
}

// Config returns the configuration d was built from, nil for a nil d.
func (d *Dispatcher) Config() *Config {
	if d == nil {
		return nil
	}
	return d.cfg
}

// ForJob returns d scoped to job id, recording its Results with record.
func (d *Dispatcher) ForJob(id string, record func(Result)) *Dispatcher {
	if d == nil {
		return nil
	}
	c := *d
	c.scope, c.jobID, c.record = id, id, record
	return &c
}

// InState returns d scoped to a job state.
func (d *Dispatcher) InState(state string) *Dispatcher {
	if d == nil {
		return nil
	}
	c := *d
	c.state = state
	return &c
}

type dispatcherKey struct{}

// WithDispatcher returns a context carrying d, for steps and connectors to
// fire hooks through without their signatures changing.
func WithDispatcher(ctx context.Context, d *Dispatcher) context.Context {
	return context.WithValue(ctx, dispatcherKey{}, d)
}

// FromContext returns the Dispatcher in ctx, or nil if there is none.
func FromContext(ctx context.Context) *Dispatcher {
	d, _ := ctx.Value(dispatcherKey{}).(*Dispatcher)
	return d
}

// VetoError is a veto event's handler answering {"allow": false}.
type VetoError struct {
	Hook, Reason string
}

func (e *VetoError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("hook %s vetoed", e.Hook)
	}
	return fmt.Sprintf("hook %s vetoed: %s", e.Hook, e.Reason)
}

// Answer is a handler's answer to an event. Allow is false only for a veto.
type Answer struct {
	Allow bool
	// Raw is the answer to a decide event, for the step to interpret; nil
	// when there was no answer, or the hook isn't configured.
	Raw json.RawMessage
}

// Configured reports whether the event hook is configured, so a step can
// skip building an expensive payload for nobody.
func (d *Dispatcher) Configured(hook string) bool {
	if d == nil {
		return false
	}
	_, ok := d.cfg.Events[hook]
	return ok
}

// Event fires the event hook with data. It returns a *VetoError for a veto
// event its handler vetoed, and the handler's error when it failed and its
// on_failure is fail. Otherwise the step goes on, Answer.Raw holding the
// answer of a decide event.
func (d *Dispatcher) Event(ctx context.Context, hook string, data any) (Answer, error) {
	return d.event(ctx, hook, nil, data)
}

// EventAt fires the event hook for one of several parts of a step, the
// index-th (from 1) of a chunked import say, so each gets its own event ID.
func (d *Dispatcher) EventAt(ctx context.Context, hook string, index, size int, data any) (Answer, error) {
	return d.event(ctx, hook, &BatchInfo{Index: index, Size: size}, data)
}

// Notify fires the notify event hook with items, in batches of the
// handler's batch size rather than one call per item. The handler's answers
// are ignored.
func (d *Dispatcher) Notify(ctx context.Context, hook string, items []any) error {
	if events[hook] != notify {
		return fmt.Errorf("hooks: %s isn't a notify event", hook)
	}
	if !d.Configured(hook) || len(items) == 0 {
		return nil
	}
	size := d.sizes[d.cfg.Events[hook].Handler]
	for i, start := 1, 0; start < len(items); i, start = i+1, start+size {
		batch := items[start:min(start+size, len(items))]
		if _, err := d.event(ctx, hook, &BatchInfo{Index: i, Size: len(batch)}, map[string]any{"items": batch}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dispatcher) event(ctx context.Context, hook string, batch *BatchInfo, data any) (Answer, error) {
	kind, known := events[hook]
	if !known {
		return Answer{}, fmt.Errorf("hooks: unknown event %q", hook)
	}
	if !d.Configured(hook) {
		return Answer{Allow: true}, nil
	}
	ref := d.cfg.Events[hook]
	env := d.envelope(hook, batch, data)
	raw, err := d.call(ctx, ref, env)
	if err == nil && kind == veto {
		var a struct {
			Allow  *bool  `json:"allow"`
			Reason string `json:"reason"`
		}
		if len(raw) > 0 {
			err = json.Unmarshal(raw, &a)
		}
		if err == nil && a.Allow != nil && !*a.Allow {
			d.add(Result{Hook: hook, EventID: env.EventID, Outcome: Vetoed, Reason: a.Reason})
			return Answer{}, &VetoError{Hook: hook, Reason: a.Reason}
		}
	}
	if err != nil {
		return d.failed(hook, env.EventID, ref.onFailure(kind != notify), err)
	}
	return Answer{Allow: true, Raw: raw}, nil
}

func (d *Dispatcher) failed(hook, eventID string, onFailure OnFailure, err error) (Answer, error) {
	if onFailure == Ignore {
		d.add(Result{Hook: hook, EventID: eventID, Outcome: Ignored, Reason: err.Error()})
		return Answer{Allow: true}, nil
	}
	d.add(Result{Hook: hook, EventID: eventID, Outcome: Failed, Reason: err.Error()})
	return Answer{}, fmt.Errorf("hook %s: %w", hook, err)
}

// onFailure resolves r's on_failure, defaulting to fail when the hook's
// answer matters and to ignore when it doesn't.
func (r Ref) onFailure(answerMatters bool) OnFailure {
	if r.OnFailure != "" {
		return r.OnFailure
	}
	if answerMatters {
		return Fail
	}
	return Ignore
}

// Item is one user (or organization, role, ...) in a strategy batch, keyed
// by its source ID, which the handler's answer is keyed by too.
type Item struct {
	Key  string
	Data any
}

// Batcher sends the items of one strategy in batches of the handler's
// batch size, numbering the batches in the order they're sent so their
// event IDs are the same on every run over the same input. Feed it in input
// order.
type Batcher struct {
	d    *Dispatcher
	hook string
	ref  Ref

	mu   sync.Mutex
	next int
}

// Batcher returns a Batcher for the strategy hook delegated to ref.
func (d *Dispatcher) Batcher(hook string, ref Ref) *Batcher {
	return &Batcher{d: d, hook: hook, ref: ref}
}

// Size is how many items the caller should gather before calling Resolve.
func (b *Batcher) Size() int {
	if b.d == nil {
		return defaultBatchSize
	}
	if n, ok := b.d.sizes[b.ref.Handler]; ok {
		return n
	}
	return defaultBatchSize
}

// Resolve sends items, in as many calls as the batch size requires, and
// returns the handler's answer for each, by key. When the handler failed and
// its on_failure is ignore, it returns nil and no error, for the caller to
// fall back to the built-in behavior.
func (b *Batcher) Resolve(ctx context.Context, items []Item) (map[string]json.RawMessage, error) {
	if b.d == nil {
		return nil, errors.New("hooks: strategy " + b.hook + " is delegated to a handler but no hooks file is loaded")
	}
	if !IsStrategy(b.hook) {
		return nil, fmt.Errorf("hooks: unknown strategy %q", b.hook)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]json.RawMessage, len(items))
	size := b.Size()
	for start := 0; start < len(items); start += size {
		batch := items[start:min(start+size, len(items))]
		b.next++
		res, err := b.d.strategy(ctx, b.hook, b.ref, b.next, batch)
		if err != nil || res == nil {
			return nil, err
		}
		for k, v := range res {
			out[k] = v
		}
	}
	return out, nil
}

func (d *Dispatcher) strategy(ctx context.Context, hook string, ref Ref, index int, items []Item) (map[string]json.RawMessage, error) {
	data := make(map[string]any, len(items))
	for _, it := range items {
		if _, dup := data[it.Key]; dup {
			return nil, fmt.Errorf("hooks: %s: duplicate item key %q in one batch", hook, it.Key)
		}
		data[it.Key] = it.Data
	}
	env := d.envelope(hook, &BatchInfo{Index: index, Size: len(items)}, map[string]any{"items": data})
	raw, err := d.call(ctx, ref, env)
	var res struct {
		Results map[string]json.RawMessage `json:"results"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &res)
	}
	if err == nil {
		err = checkKeys(data, res.Results)
	}
	if err != nil {
		_, err = d.failed(hook, env.EventID, ref.onFailure(true), err)
		return nil, err
	}
	return res.Results, nil
}

// checkKeys reports an answer that doesn't hold exactly one result per item:
// a missing one would silently apply the built-in behavior to that user, an
// extra one means the handler answered some other batch.
func checkKeys(sent map[string]any, got map[string]json.RawMessage) error {
	for k := range sent {
		if _, ok := got[k]; !ok {
			return fmt.Errorf("answer has no result for %q", k)
		}
	}
	for k := range got {
		if _, ok := sent[k]; !ok {
			return fmt.Errorf("answer has a result for %q, which wasn't sent", k)
		}
	}
	return nil
}

func (d *Dispatcher) call(ctx context.Context, ref Ref, env Envelope) (json.RawMessage, error) {
	h, ok := d.handlers[ref.Handler]
	if !ok {
		return nil, fmt.Errorf("handler %q is not declared", ref.Handler)
	}
	return h.Call(ctx, env)
}

func (d *Dispatcher) envelope(hook string, batch *BatchInfo, data any) Envelope {
	index := 0
	if batch != nil {
		index = batch.Index
	}
	return Envelope{
		Version: Version,
		Hook:    hook,
		EventID: EventID(d.scope, hook, d.state, index),
		JobID:   d.jobID,
		State:   d.state,
		Batch:   batch,
		Data:    data,
	}
}

// EventID is the deterministic ID of a hook call: the same scope (job),
// hook, state and batch index (0 for an event) give the same ID.
func EventID(scope, hook, state string, index int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%s\x00%d", scope, hook, state, index))
	return hex.EncodeToString(sum[:16])
}

func (d *Dispatcher) add(r Result) {
	if d.record == nil {
		return
	}
	r.State = d.state
	r.At = d.now().UTC()
	d.record(r)
}
