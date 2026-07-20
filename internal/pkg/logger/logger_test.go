package logger

import (
	"log/slog"
	"testing"
)

func TestLoggerTypeVar_String(t *testing.T) {
	tests := []struct {
		name string
		lt   *LoggerTypeVar
		want string
	}{
		{"zero value", &LoggerTypeVar{}, "auto"},
		{"auto", &LoggerTypeVar{"auto"}, "auto"},
		{"discard", &LoggerTypeVar{"discard"}, "discard"},
		{"json", &LoggerTypeVar{"json"}, "json"},
		{"systemd", &LoggerTypeVar{"systemd"}, "systemd"},
		{"text", &LoggerTypeVar{"text"}, "text"},
		{"invalid", &LoggerTypeVar{"foo"}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.lt.String()
			if tt.want != got {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoggerTypeVar_Set(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		want    string
		wantErr bool
	}{
		{"blank", "", "auto", false},
		{"auto", "auto", "auto", false},
		{"discard", "discard", "discard", false},
		{"json", "json", "json", false},
		{"systemd", "systemd", "systemd", false},
		{"text", "text", "text", false},
		{"invalid", "invalid", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			var lt LoggerTypeVar
			gotErr := lt.Set(tt.s)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Set() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Set() succeeded unexpectedly")
			}
			got := lt.String()
			if tt.want != got {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		leveler slog.Leveler
		opts    []LoggerOption
		wantErr bool
	}{
		{"no options", new(slog.LevelVar), nil, false},
		{"valid logger type", new(slog.LevelVar), []LoggerOption{WithLoggerType(LoggerTypeAuto)}, false},
		{"invalid logger type", new(slog.LevelVar), []LoggerOption{WithLoggerType("foo")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := NewLogger(tt.leveler, tt.opts...)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewLogger() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("NewLogger() succeeded unexpectedly")
			}
		})
	}
}

func TestLoggerTypeVar_Type(t *testing.T) {
	got := (LoggerTypeVar{}).Type()
	if got != "string" {
		t.Errorf("Type() = %v, want %v", got, "string")
	}
}
