package ristgo

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/session"
)

// wrapInvalid wraps a validation error so callers can match it with
// errors.Is(err, ErrInvalidConfig), per the WP4 binding. The redundant
// "rist: " prefix the inner message carries is trimmed.
func wrapInvalid(err error) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, strings.TrimPrefix(err.Error(), "rist: "))
}

// resolveMediaPort splits a "host:port" address and requires an even media
// port (TR-06-1: RTP on the even port, RTCP on the adjacent odd port).
func resolveMediaPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil || port <= 0 || port > 65534 {
		return "", 0, fmt.Errorf("%w: port %q out of range", ErrInvalidConfig, p)
	}
	if port%2 != 0 {
		return "", 0, fmt.Errorf("%w: media port %d must be even (RTCP uses port+1)", ErrInvalidConfig, port)
	}
	return h, port, nil
}

// toFlowConfig maps the public Config to the deterministic core's config.
func toFlowConfig(cfg Config) flow.Config {
	return flow.Config{
		RecoveryBufferMin: clock.FromDuration(cfg.BufferMin),
		RecoveryBufferMax: clock.FromDuration(cfg.BufferMax),
		ReorderBuffer:     clock.FromDuration(cfg.ReorderBuffer),
		RTTMin:            clock.FromDuration(cfg.RTTMin),
		RTTMax:            clock.FromDuration(cfg.RTTMax),
		MinRetries:        cfg.MinRetries,
		MaxRetries:        cfg.MaxRetries,
	}
}

// toSessionConfig assembles the host config, supplying the public sentinel
// errors so the session can return them directly.
func toSessionConfig(cfg Config, fc flow.Config, ssrc uint32) session.Config {
	var logf func(string, ...any)
	if cfg.Logger != nil {
		logger := cfg.Logger
		logf = func(format string, args ...any) {
			logger.Log(LogDebug, LogSession, fmt.Sprintf(format, args...))
		}
	}
	cname := cfg.CNAME
	if cname == "" {
		cname = "ristgo"
	}
	return session.Config{
		Flow:              fc,
		SSRC:              ssrc,
		CNAME:             cname,
		Bitmask:           cfg.NACKType == NACKBitmask,
		KeepaliveInterval: clock.FromDuration(cfg.KeepaliveInterval),
		SessionTimeout:    clock.FromDuration(cfg.SessionTimeout),
		Logf:              logf,
		ErrClosed:         ErrClosed,
		ErrTimeout:        ErrTimeout,
		ErrSessionTimeout: ErrSessionTimeout,
		ErrBufferOverflow: ErrBufferOverflow,
	}
}

// randomEvenSSRC returns a random even 32-bit flow SSRC. The LSB is reserved
// as the retransmit marker, so the base SSRC must be even (libRIST
// src/rist.c:570).
func randomEvenSSRC() uint32 { return rand.Uint32() &^ 1 }

// randomStartSeq returns a random initial RTP sequence number (RFC 3550
// recommends randomizing it), kept in the low 16 bits since the wire sequence
// is 16-bit.
func randomStartSeq() uint32 { return uint32(rand.Uint32() & 0xFFFF) }
