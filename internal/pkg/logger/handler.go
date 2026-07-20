package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
)

type SystemdHandler struct {
	mu     *sync.Mutex
	w      io.Writer
	opts   slog.HandlerOptions
	attrs  []slog.Attr // accumulated via WithAttrs
	groups []string    // accumulated via WithGroup, outermost first
}

func NewSystemdHandler(w io.Writer, opts *slog.HandlerOptions) *SystemdHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &SystemdHandler{
		mu:   &sync.Mutex{},
		w:    w,
		opts: *opts,
	}
}

func (h *SystemdHandler) Enabled(_ context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

func (h *SystemdHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	b.WriteByte('<')
	b.WriteString(strconv.Itoa(priority(r.Level)))
	b.WriteString("> ")
	b.WriteString(r.Message)

	// Attrs accumulated via WithAttrs/WithGroup come first, in the same
	// order they were added, then attrs attached directly to the record.
	for _, a := range h.attrs {
		writeAttr(&b, h.groups, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, h.groups, a)
		return true
	})

	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *SystemdHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	newAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	newAttrs = append(newAttrs, h.attrs...)
	// Attrs added while groups are open belong under those groups.
	for _, a := range attrs {
		newAttrs = append(newAttrs, prefixAttr(h.groups, a))
	}
	return &SystemdHandler{
		mu:     h.mu,
		w:      h.w,
		opts:   h.opts,
		attrs:  newAttrs,
		groups: h.groups,
	}
}

func (h *SystemdHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	newGroups := make([]string, len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups[len(h.groups)] = name
	return &SystemdHandler{
		mu:     h.mu,
		w:      h.w,
		opts:   h.opts,
		attrs:  h.attrs,
		groups: newGroups,
	}
}

// priority maps slog levels to syslog priority numbers.
func priority(level slog.Level) int {
	switch {
	case level >= slog.LevelError:
		return 3 // LOG_ERR
	case level >= slog.LevelWarn:
		return 4 // LOG_WARNING
	case level >= slog.LevelInfo:
		return 6 // LOG_INFO
	default:
		return 7 // LOG_DEBUG
	}
}

// prefixAttr applies pending group names to an attr recorded via WithAttrs,
// so it carries the right dotted key once flattened later.
func prefixAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		return a
	}
	key := strings.Join(groups, ".") + "." + a.Key
	return slog.Attr{Key: key, Value: a.Value}
}

// writeAttr flattens an attr (recursing into groups) and writes it as
// KEY=VALUE, space-separated, quoting the value if needed.
func writeAttr(b *strings.Builder, groups []string, a slog.Attr) {
	// Resolve LogValuer values.
	a.Value = a.Value.Resolve()

	if a.Value.Kind() == slog.KindGroup {
		subGroups := groups
		if a.Key != "" {
			subGroups = append(append([]string{}, groups...), a.Key)
		}
		for _, sub := range a.Value.Group() {
			writeAttr(b, subGroups, sub)
		}
		return
	}

	if a.Equal(slog.Attr{}) {
		return
	}

	key := a.Key
	if len(groups) > 0 {
		key = strings.Join(groups, ".") + "." + key
	}

	b.WriteByte(' ')
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(formatValue(a.Value))
}

// formatValue renders a slog.Value, quoting it if it contains spaces,
// quotes, or is empty.
func formatValue(v slog.Value) string {
	s := v.String()
	if s == "" || strings.ContainsAny(s, " \t\"=") {
		return strconv.Quote(s)
	}
	return s
}

var _ slog.Handler = (*SystemdHandler)(nil)
var _ fmt.Stringer // silence unused import if fmt trimmed later
