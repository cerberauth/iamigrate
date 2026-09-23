// Package progress renders a live, single-line progress indicator on a
// terminal while a long-running export, import, or diff is in flight.
//
// A *Bar travels to connectors through the context (see NewContext and
// FromContext), so SourceConnector/TargetConnector signatures stay
// unchanged. Every method is safe on a nil *Bar, so connectors can report
// progress unconditionally. On a terminal the line is redrawn in place;
// anywhere else (pipes, CI logs, IDE consoles) a plain line is printed
// every few seconds instead, so there's still a sign of life.
package progress

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// refreshInterval is how often the line is redrawn on a terminal, so the
// spinner and elapsed time keep moving while a call (e.g. polling an Auth0
// job) blocks. plainInterval is how often a fresh line is printed when the
// output isn't a terminal and can't be redrawn in place.
const (
	refreshInterval = 100 * time.Millisecond
	plainInterval   = 2 * time.Second
)

// barWidth is the number of cells in the bar itself; defaultLineWidth caps
// the rendered line when the terminal's width can't be read, since a
// wrapped line breaks \r redraws.
const (
	barWidth         = 20
	defaultLineWidth = 79
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Bar tracks one stage at a time (a label, a done count, and an optional
// total) and redraws it in place until Done.
type Bar struct {
	w         io.Writer
	enabled   bool
	tty       bool
	lineWidth func() int

	mu      sync.Mutex
	label   string
	total   int
	current int
	status  string
	started time.Time
	frame   int
	active  bool

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New returns a Bar drawing to w, redrawn in place if w is a terminal and
// printed as periodic plain lines otherwise.
func New(w io.Writer) *Bar {
	b := &Bar{w: w, enabled: true, tty: isTerminal(w), lineWidth: terminalWidth(w), stop: make(chan struct{})}
	b.wg.Add(1)
	go b.loop()
	return b
}

// Enabled reports whether b renders anything, so callers can skip work
// (like pre-counting a file for its total) that only feeds the display.
func (b *Bar) Enabled() bool {
	return b != nil && b.enabled
}

// Stage finishes the current stage, if any, leaving its final state on
// its own line, then starts a new one. A total <= 0 means unknown: the
// count is shown without a bar or percentage.
func (b *Bar) Stage(label string, total int) {
	if !b.Enabled() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.finishLocked()
	b.label = label
	b.total = total
	b.current = 0
	b.status = ""
	b.started = time.Now()
	b.active = true
	if b.tty {
		b.renderLocked()
	} else {
		fmt.Fprint(b.w, b.lineLocked("…")+"\n")
	}
}

// SetTotal sets the current stage's total once it becomes known, e.g.
// after a connector has read its whole input.
func (b *Bar) SetTotal(total int) {
	if !b.Enabled() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total = total
	b.renderLocked()
}

// Add advances the current stage by n.
func (b *Bar) Add(n int) {
	if !b.Enabled() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.current += n
	b.renderLocked()
}

// Status sets a short note shown after the counters, describing what the
// stage is waiting on right now. An empty string clears it.
func (b *Bar) Status(format string, args ...any) {
	if !b.Enabled() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.status = fmt.Sprintf(format, args...)
	b.renderLocked()
}

// Done finishes the current stage and stops redrawing. Callers should call
// it before printing their own summary so the two don't interleave. It's
// safe to call more than once.
func (b *Bar) Done() {
	if !b.Enabled() {
		return
	}
	b.stopOnce.Do(func() { close(b.stop) })
	b.wg.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.finishLocked()
}

func (b *Bar) loop() {
	defer b.wg.Done()
	interval := plainInterval
	if b.tty {
		interval = refreshInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			b.mu.Lock()
			b.frame++
			b.tickLocked()
			b.mu.Unlock()
		}
	}
}

func (b *Bar) finishLocked() {
	if !b.active {
		return
	}
	b.status = ""
	if b.tty {
		fmt.Fprint(b.w, "\r\x1b[2K")
	}
	fmt.Fprint(b.w, b.lineLocked("✓")+"\n")
	b.active = false
}

// renderLocked redraws the line after a change. Without a terminal it does
// nothing: plain lines are only printed on Stage and on each tick, so a
// fast-moving counter can't flood a log.
func (b *Bar) renderLocked() {
	if !b.active || !b.tty {
		return
	}
	fmt.Fprint(b.w, "\r\x1b[2K"+b.lineLocked(spinnerFrames[b.frame%len(spinnerFrames)]))
}

func (b *Bar) tickLocked() {
	if !b.active {
		return
	}
	if b.tty {
		b.renderLocked()
		return
	}
	fmt.Fprint(b.w, b.lineLocked("…")+"\n")
}

func (b *Bar) lineLocked(prefix string) string {
	elapsed := time.Since(b.started)
	head := prefix + " " + b.label
	var parts []string
	if b.total > 0 {
		current := min(b.current, b.total)
		filled := current * barWidth / b.total
		parts = append(parts, fmt.Sprintf("%s [%s%s] %3d%% %d/%d", head,
			strings.Repeat("█", filled), strings.Repeat("░", barWidth-filled),
			current*100/b.total, current, b.total))
	} else {
		parts = append(parts, fmt.Sprintf("%s %d", head, b.current))
	}
	parts = append(parts, formatDuration(elapsed))
	if b.total > 0 && b.current > 0 && b.current < b.total {
		remaining := time.Duration(float64(elapsed) * float64(b.total-b.current) / float64(b.current))
		parts = append(parts, "ETA "+formatDuration(remaining))
	}
	if b.status != "" {
		parts = append(parts, b.status)
	}
	return truncate(strings.Join(parts, " · "), b.lineWidth())
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(f.Fd())) //nolint:gosec // fd fits in int
}

// terminalWidth returns a func reading w's current width on every redraw,
// so resizing the terminal mid-run is picked up.
func terminalWidth(w io.Writer) func() int {
	return func() int {
		if f, ok := w.(*os.File); ok {
			if width, _, err := term.GetSize(int(f.Fd())); err == nil && width > 1 { //nolint:gosec // fd fits in int
				return width - 1
			}
		}
		return defaultLineWidth
	}
}

type ctxKey struct{}

// NewContext returns a copy of ctx carrying b.
func NewContext(ctx context.Context, b *Bar) context.Context {
	return context.WithValue(ctx, ctxKey{}, b)
}

// FromContext returns the Bar carried by ctx, or nil (a valid no-op Bar)
// if there is none.
func FromContext(ctx context.Context) *Bar {
	b, _ := ctx.Value(ctxKey{}).(*Bar)
	return b
}
