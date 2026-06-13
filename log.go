package ristgo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	// LogDebug is for detailed diagnostic information.
	LogDebug LogLevel = iota
	// LogNote is for notable but normal events.
	LogNote
	// LogWarning is for unexpected but recoverable conditions.
	LogWarning
	// LogError is for error conditions that affect operation.
	LogError
)

// String returns a human-readable name for the log level.
func (l LogLevel) String() string {
	switch l {
	case LogDebug:
		return "DEBUG"
	case LogNote:
		return "NOTE"
	case LogWarning:
		return "WARN"
	case LogError:
		return "ERROR"
	default:
		return fmt.Sprintf("LogLevel(%d)", int(l))
	}
}

// LogCategory identifies the subsystem that generated a log message.
type LogCategory string

const (
	// LogGeneral covers messages not tied to a specific subsystem.
	LogGeneral LogCategory = "general"
	// LogConfig covers configuration parsing and validation.
	LogConfig LogCategory = "config"
	// LogSession covers session formation, keepalive, and teardown.
	LogSession LogCategory = "session"
	// LogFlow covers the ARQ core: buffering, NACKs, and playout.
	LogFlow LogCategory = "flow"
	// LogRTCP covers RTCP send/receive (SR/RR/SDES/NACK/echo).
	LogRTCP LogCategory = "rtcp"
	// LogSocket covers UDP socket I/O and demultiplexing.
	LogSocket LogCategory = "socket"
	// LogCrypto covers PSK encryption, key rotation, and SRP.
	LogCrypto LogCategory = "crypto"
	// LogBonding covers SMPTE 2022-7 multipath and path liveness.
	LogBonding LogCategory = "bonding"
)

// Logger is the interface for RIST diagnostic log output.
// Implementations must be safe for concurrent use from multiple goroutines.
//
// When Config.Logger is nil (the default), no logging occurs and there is
// zero performance overhead — the logf() helper returns immediately without
// formatting the message.
type Logger interface {
	// Log emits a log message.
	// Implementations should not block or perform expensive operations.
	Log(level LogLevel, category LogCategory, msg string)
}

// logf formats and emits a log message if logger is non-nil.
// The format string and args are only evaluated when the logger is present,
// ensuring zero allocation when logging is disabled.
func logf(logger Logger, level LogLevel, category LogCategory, format string, args ...any) {
	if logger == nil {
		return
	}
	logger.Log(level, category, fmt.Sprintf(format, args...))
}

// StdLogger returns a Logger that writes timestamped messages to w.
// Output format: "2006-01-02T15:04:05.000Z07:00 [LEVEL] category message\n"
//
// Example:
//
//	cfg := ristgo.DefaultConfig()
//	cfg.Logger = ristgo.StdLogger(os.Stderr)
func StdLogger(w io.Writer) Logger {
	return &stdLogger{w: w}
}

type stdLogger struct {
	w  io.Writer
	mu sync.Mutex
}

func (l *stdLogger) Log(level LogLevel, category LogCategory, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s [%s] %s %s\n",
		time.Now().Format("2006-01-02T15:04:05.000Z07:00"), level, category, msg)
}

// SlogLogger returns a Logger that emits messages through a [slog.Logger].
// Log levels are mapped as: LogDebug→Debug, LogNote→Info, LogWarning→Warn,
// LogError→Error. The category is included as a structured attribute.
//
// Example:
//
//	cfg := ristgo.DefaultConfig()
//	cfg.Logger = ristgo.SlogLogger(slog.Default())
func SlogLogger(l *slog.Logger) Logger {
	return &slogAdapter{l: l}
}

type slogAdapter struct {
	l *slog.Logger
}

func (a *slogAdapter) Log(level LogLevel, category LogCategory, msg string) {
	var lvl slog.Level
	switch level {
	case LogDebug:
		lvl = slog.LevelDebug
	case LogNote:
		lvl = slog.LevelInfo
	case LogWarning:
		lvl = slog.LevelWarn
	default:
		lvl = slog.LevelError
	}
	a.l.LogAttrs(context.Background(), lvl, msg,
		slog.String("category", string(category)),
	)
}
