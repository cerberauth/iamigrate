package progress

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestBar returns an enabled terminal Bar drawing to buf, without the
// redraw goroutine, so output is deterministic.
func newTestBar(buf *bytes.Buffer) *Bar {
	return &Bar{w: buf, enabled: true, tty: true, lineWidth: func() int { return 100 }, stop: make(chan struct{})}
}

func TestNilBarIsNoOp(t *testing.T) {
	var b *Bar
	require.False(t, b.Enabled())
	b.Stage("x", 10)
	b.SetTotal(5)
	b.Add(1)
	b.Status("s")
	b.Done()
	require.Nil(t, FromContext(context.Background()))
}

func TestNonTerminalPrintsPlainLines(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf)
	require.True(t, b.Enabled())
	b.Stage("importing users", 10)
	b.Add(3)
	b.mu.Lock()
	b.tickLocked()
	b.mu.Unlock()
	b.Add(7)
	b.Done()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, 3, buf.String())
	require.True(t, strings.HasPrefix(lines[0], "… importing users ["), lines[0])
	require.Contains(t, lines[0], "0/10")
	require.Contains(t, lines[1], "3/10")
	require.True(t, strings.HasPrefix(lines[2], "✓ importing users ["), lines[2])
	require.Contains(t, lines[2], "10/10")
	require.NotContains(t, buf.String(), "\r")
	require.NotContains(t, buf.String(), "\x1b")
}

func TestContextRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf)
	require.Same(t, b, FromContext(NewContext(context.Background(), b)))
}

func TestLineWithTotal(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf)
	b.Stage("importing users", 200)
	b.Add(50)
	b.Status("waiting for job")

	line := b.lineLocked("*")
	require.True(t, strings.HasPrefix(line, "* importing users [█████░░░░░░░░░░░░░░░]  25% 50/200 · 0s"), line)
	require.Contains(t, line, "ETA ")
	require.True(t, strings.HasSuffix(line, " · waiting for job"), line)
}

func TestLineWithoutTotal(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf)
	b.Stage("exporting users", 0)
	b.Add(42)
	require.Equal(t, "* exporting users 42 · 0s", b.lineLocked("*"))
}

func TestStageFinishesPreviousLine(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf)
	b.Stage("importing users", 2)
	b.Add(2)
	b.Stage("assigning roles", 1)
	b.Done()
	b.Done()

	out := buf.String()
	require.Contains(t, out, "✓ importing users [████████████████████] 100% 2/2 · 0s\n")
	require.True(t, strings.HasSuffix(out, "✓ assigning roles [░░░░░░░░░░░░░░░░░░░░]   0% 0/1 · 0s\n"), out)
}

func TestLineIsTruncated(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf)
	b.Stage("importing users", 10)
	b.Status("%s", strings.Repeat("x", 200))
	line := b.lineLocked("*")
	require.Len(t, []rune(line), 100)
	require.True(t, strings.HasSuffix(line, "…"))
}

func TestFormatDuration(t *testing.T) {
	require.Equal(t, "7s", formatDuration(7*time.Second))
	require.Equal(t, "2m05s", formatDuration(125*time.Second))
	require.Equal(t, "1h01m", formatDuration(61*time.Minute))
}
