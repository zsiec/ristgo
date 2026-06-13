package ristgo

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level LogLevel
		want  string
	}{
		{LogDebug, "DEBUG"},
		{LogNote, "NOTE"},
		{LogWarning, "WARN"},
		{LogError, "ERROR"},
		{LogLevel(99), "LogLevel(99)"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("LogLevel(%d).String() = %q, want %q", int(tt.level), got, tt.want)
		}
	}
}

func TestLogCategories(t *testing.T) {
	tests := []struct {
		category LogCategory
		want     string
	}{
		{LogGeneral, "general"},
		{LogConfig, "config"},
		{LogSession, "session"},
		{LogFlow, "flow"},
		{LogRTCP, "rtcp"},
		{LogSocket, "socket"},
		{LogCrypto, "crypto"},
		{LogBonding, "bonding"},
	}
	for _, tt := range tests {
		if string(tt.category) != tt.want {
			t.Errorf("category = %q, want %q", string(tt.category), tt.want)
		}
	}
}

func TestLogfNilLogger(t *testing.T) {
	// Must not panic or allocate when logger is nil
	logf(nil, LogDebug, LogGeneral, "test %d %s", 42, "hello")
}

func TestLogfWithLogger(t *testing.T) {
	var calls []string
	logger := &testLogger{fn: func(level LogLevel, cat LogCategory, msg string) {
		calls = append(calls, msg)
	}}

	logf(logger, LogNote, LogSession, "connected to %s", "peer")

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0] != "connected to peer" {
		t.Errorf("got msg %q, want %q", calls[0], "connected to peer")
	}
}

func TestLogfPassesLevelAndCategory(t *testing.T) {
	var gotLevel LogLevel
	var gotCat LogCategory
	logger := &testLogger{fn: func(level LogLevel, cat LogCategory, msg string) {
		gotLevel = level
		gotCat = cat
	}}

	logf(logger, LogWarning, LogCrypto, "key rotation")

	if gotLevel != LogWarning {
		t.Errorf("level = %v, want %v", gotLevel, LogWarning)
	}
	if gotCat != LogCrypto {
		t.Errorf("category = %v, want %v", gotCat, LogCrypto)
	}
}

func TestStdLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := StdLogger(&buf)

	logger.Log(LogWarning, LogCrypto, "key rotation started")

	output := buf.String()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("output missing level: %q", output)
	}
	if !strings.Contains(output, "crypto") {
		t.Errorf("output missing category: %q", output)
	}
	if !strings.Contains(output, "key rotation started") {
		t.Errorf("output missing message: %q", output)
	}
	if !strings.HasSuffix(output, "\n") {
		t.Errorf("output missing trailing newline: %q", output)
	}
}

func TestSlogLogger(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := SlogLogger(slog.New(handler))

	tests := []struct {
		level     LogLevel
		wantLevel string
	}{
		{LogDebug, "level=DEBUG"},
		{LogNote, "level=INFO"},
		{LogWarning, "level=WARN"},
		{LogError, "level=ERROR"},
	}
	for _, tt := range tests {
		buf.Reset()
		logger.Log(tt.level, LogFlow, "buffer state")

		output := buf.String()
		if !strings.Contains(output, tt.wantLevel) {
			t.Errorf("output missing %q: %q", tt.wantLevel, output)
		}
		if !strings.Contains(output, "category=flow") {
			t.Errorf("output missing category attribute: %q", output)
		}
		if !strings.Contains(output, "buffer state") {
			t.Errorf("output missing message: %q", output)
		}
	}
}

func TestSlogLoggerUnknownLevel(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := SlogLogger(slog.New(handler))

	// Out-of-range levels map to Error.
	logger.Log(LogLevel(99), LogGeneral, "mystery")

	if output := buf.String(); !strings.Contains(output, "level=ERROR") {
		t.Errorf("unknown level should map to ERROR: %q", output)
	}
}

func BenchmarkLogfNilLogger(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		logf(nil, LogDebug, LogGeneral, "msg %d %s %v", 42, "hello", true)
	}
}

func BenchmarkLogfWithLogger(b *testing.B) {
	logger := &testLogger{fn: func(LogLevel, LogCategory, string) {}}
	b.ReportAllocs()
	for b.Loop() {
		logf(logger, LogDebug, LogGeneral, "msg %d %s %v", 42, "hello", true)
	}
}

// testLogger is a Logger that delegates to a function.
type testLogger struct {
	fn func(level LogLevel, cat LogCategory, msg string)
}

func (l *testLogger) Log(level LogLevel, cat LogCategory, msg string) {
	l.fn(level, cat, msg)
}
