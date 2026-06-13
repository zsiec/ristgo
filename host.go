package ristgo

import (
	crand "crypto/rand"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/eap"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/srp"
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

// resolveSinglePort splits a "host:port" address for the Main profile, which
// tunnels everything over one port (not the Simple even/odd pair), so any port
// in 1-65535 is valid.
func resolveSinglePort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("%w: port %q out of range", ErrInvalidConfig, p)
	}
	return h, port, nil
}

// buildMainParams derives the session Main-profile parameters from cfg,
// constructing the PSK keys when a Secret is configured (cfg must already be
// validated, so AESKeyBits is 128 or 256 — defaulted to 256 when Secret is
// set). With no Secret the Main flow runs in cleartext.
func buildMainParams(cfg Config) (*session.MainParams, error) {
	mp := &session.MainParams{
		VirtSrcPort: cfg.VirtSrcPort,
		VirtDstPort: cfg.VirtDstPort,
	}
	if cfg.Secret == "" {
		return mp, nil
	}
	sendKey, err := crypto.NewKey([]byte(cfg.Secret), cfg.AESKeyBits, cfg.KeyRotation, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	recvKey, err := crypto.NewDecryptor([]byte(cfg.Secret), cfg.AESKeyBits)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	mp.SendKey = sendKey
	mp.RecvKey = recvKey
	mp.KeySize256 = cfg.AESKeyBits == crypto.KeySize256
	return mp, nil
}

// buildEAPClient builds the EAP-SRP authenticatee for a Main sender when
// credentials are configured (the sender authenticates to the receiver); it
// returns (nil, nil) when no Username is set.
func buildEAPClient(cfg Config) (*eap.Authenticatee, error) {
	if cfg.Username == "" {
		return nil, nil
	}
	a, err := eap.NewAuthenticatee(cfg.Username, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return a, nil
}

// buildEAPServer builds the EAP-SRP authenticator for a Main receiver when
// credentials are configured (the receiver authenticates the sender). It
// provisions a fresh random salt and the verifier derived from the configured
// username/password, served by a single-user lookup. Returns (nil, nil) when no
// Username is set.
func buildEAPServer(cfg Config) (*eap.Authenticator, error) {
	if cfg.Username == "" {
		return nil, nil
	}
	salt := make([]byte, 32)
	if _, err := crand.Read(salt); err != nil {
		return nil, fmt.Errorf("%w: SRP salt: %v", ErrInvalidConfig, err)
	}
	verifier := srp.MakeVerifier(srp.DefaultGroup(), cfg.Username, cfg.Password, salt)
	lookup := func(user string) ([]byte, []byte, bool) {
		if user == cfg.Username {
			return verifier, salt, true
		}
		return nil, nil, false
	}
	a, err := eap.NewAuthenticator(lookup)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return a, nil
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
		ErrAuth:           ErrAuth,
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
