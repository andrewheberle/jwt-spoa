package logger

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type LoggerTypeVar struct {
	val string
}

type LoggerType string

const (
	LoggerTypeAuto    LoggerType = "auto"
	LoggerTypeJson    LoggerType = "json"
	LoggerTypeSystemd LoggerType = "systemd"
	LoggerTypeText    LoggerType = "text"
	LoggerTypeDiscard LoggerType = "discard"
)

func (lt *LoggerTypeVar) String() string {
	switch lt.val {
	case string(LoggerTypeAuto), "":
		return "auto"
	case string(LoggerTypeDiscard):
		return "discard"
	case string(LoggerTypeJson):
		return "json"
	case string(LoggerTypeSystemd):
		return "systemd"
	case string(LoggerTypeText):
		return "text"
	}

	return "unknown"
}

func (lt *LoggerTypeVar) Set(s string) error {
	switch s {
	case "auto", "":
		lt.val = string(LoggerTypeAuto)
	case "discard":
		lt.val = string(LoggerTypeDiscard)
	case "json":
		lt.val = string(LoggerTypeJson)
	case "systemd":
		lt.val = string(LoggerTypeSystemd)
	case "text":
		lt.val = string(LoggerTypeText)
	default:
		return ErrUnhandledLoggerType
	}

	return nil
}

func (lt LoggerTypeVar) Type() string {
	return "string"
}

var (
	ErrUnhandledLoggerType = errors.New("unhandled logger type")
)

type logger struct {
	lt LoggerType
	w  io.Writer
}

func NewLogger(leveler slog.Leveler, opts ...LoggerOption) (*slog.Logger, error) {
	l := &logger{
		lt: LoggerTypeAuto,
		w:  os.Stderr,
	}

	for _, o := range opts {
		o(l)
	}

	if l.lt == LoggerTypeAuto || l.lt == "" {
		if isSystemd() {
			l.lt = LoggerTypeSystemd
		} else {
			l.lt = LoggerTypeText
		}
	}

	switch l.lt {
	case LoggerTypeSystemd:
		// output as <LEVEL> message key=value... under systemd
		h := NewSystemdHandler(l.w, &slog.HandlerOptions{Level: leveler})
		return slog.New(h), nil
	case LoggerTypeText:
		// standard text handler
		return slog.New(slog.NewTextHandler(l.w, &slog.HandlerOptions{Level: leveler})), nil
	case LoggerTypeJson:
		// standard JSON handler
		return slog.New(slog.NewJSONHandler(l.w, &slog.HandlerOptions{Level: leveler})), nil
	case LoggerTypeDiscard:
		// discard handler
		return slog.New(slog.DiscardHandler), nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnhandledLoggerType, l.lt)
}

type LoggerOption func(*logger)

func WithLoggerType(lt LoggerType) LoggerOption {
	return func(l *logger) {
		l.lt = lt
	}
}

func WithWriter(w io.Writer) LoggerOption {
	return func(l *logger) {
		l.w = w
	}
}

func isSystemd() bool {
	ppid := os.Getppid()

	return commIs(ppid, "systemd")
}

func commIs(pid int, name string) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == name
}
