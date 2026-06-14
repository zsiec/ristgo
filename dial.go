package ristgo

import (
	"context"
	"io"
	"sync"
	"time"
)

// This file is the ergonomic constructor surface: net-style Dial/Listen that
// take a context.Context and functional Options, layered over the Config-based
// NewSender/NewReceiver. The common knobs have dedicated With* options; WithConfig
// is the escape hatch for the full Config (and any field without a dedicated
// option). Cancelling the context closes the returned Sender/Receiver — which
// aborts a pending Main/DTLS handshake and unblocks Read/Write — so the value is
// in tying a session's lifetime to a parent context.

// Option configures a Config before a Dial/Listen builds the session. Options are
// applied in order over DefaultConfig; WithConfig replaces the whole Config, so
// it is normally given first.
type Option func(*Config)

// applyOptions builds the effective Config from DefaultConfig and the options.
func applyOptions(opts []Option) Config {
	cfg := DefaultConfig()
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return cfg
}

// WithConfig sets the entire Config at once, for callers who prefer the struct or
// need a field without a dedicated option. Give it before other options, which
// then override individual fields.
func WithConfig(cfg Config) Option { return func(c *Config) { *c = cfg } }

// WithProfile selects the RIST wire profile (default ProfileSimple).
func WithProfile(p Profile) Option { return func(c *Config) { c.Profile = p } }

// WithSecret enables PSK encryption (Main/Advanced) with the given passphrase.
func WithSecret(secret string) Option { return func(c *Config) { c.Secret = secret } }

// WithAESKeyBits sets the PSK AES key size (128 or 256); meaningful only with a
// secret.
func WithAESKeyBits(bits int) Option { return func(c *Config) { c.AESKeyBits = bits } }

// WithCredentials sets the Main-profile EAP-SRP username and password.
func WithCredentials(username, password string) Option {
	return func(c *Config) { c.Username, c.Password = username, password }
}

// WithDTLS enables DTLS 1.2 transport security for the Main profile (a copy of d
// is taken).
func WithDTLS(d DTLSConfig) Option {
	return func(c *Config) { dc := d; c.DTLS = &dc }
}

// WithBuffer sets both the minimum and maximum recovery buffer to d (the simple
// "fixed latency" case). Use WithBufferRange for distinct bounds.
func WithBuffer(d time.Duration) Option {
	return func(c *Config) { c.BufferMin, c.BufferMax = d, d }
}

// WithBufferRange sets the minimum and maximum recovery buffer lengths.
func WithBufferRange(min, max time.Duration) Option {
	return func(c *Config) { c.BufferMin, c.BufferMax = min, max }
}

// WithReorderBuffer sets how long the receiver holds out-of-order packets before
// declaring them missing.
func WithReorderBuffer(d time.Duration) Option { return func(c *Config) { c.ReorderBuffer = d } }

// WithNACKType selects the retransmission-request wire encoding.
func WithNACKType(t NACKType) Option { return func(c *Config) { c.NACKType = t } }

// WithRTT sets the lower and upper clamps applied to the measured round-trip time.
func WithRTT(min, max time.Duration) Option {
	return func(c *Config) { c.RTTMin, c.RTTMax = min, max }
}

// WithRetries sets the minimum and maximum retransmission attempts per packet.
func WithRetries(min, max int) Option {
	return func(c *Config) { c.MinRetries, c.MaxRetries = min, max }
}

// WithKeepalive sets the keepalive transmission interval.
func WithKeepalive(d time.Duration) Option { return func(c *Config) { c.KeepaliveInterval = d } }

// WithSessionTimeout sets how long a peer may be silent before the session is
// torn down.
func WithSessionTimeout(d time.Duration) Option { return func(c *Config) { c.SessionTimeout = d } }

// WithMaxBitrate sets the maximum recovery bandwidth in kbps.
func WithMaxBitrate(kbps int) Option { return func(c *Config) { c.MaxBitrate = kbps } }

// WithCNAME sets the canonical name advertised in RTCP SDES.
func WithCNAME(name string) Option { return func(c *Config) { c.CNAME = name } }

// WithCompression enables Advanced-profile payload compression (LZ4).
func WithCompression() Option { return func(c *Config) { c.Compression = true } }

// WithWeight sets this peer's load-balancing weight (0 = SMPTE 2022-7 duplicate).
func WithWeight(w int) Option { return func(c *Config) { c.Weight = w } }

// WithSourceAdaptation makes a receiver emit Link Quality Messages for source
// adaptation (TR-06-4 Part 1).
func WithSourceAdaptation() Option { return func(c *Config) { c.SourceAdaptation = true } }

// WithRateAdapt enables sender-side source-adaptation rate control: fn is called
// with each new encoder bit-rate target (kbps). It runs on the session event
// loop, so it must not block.
func WithRateAdapt(fn func(targetKbps int)) Option {
	return func(c *Config) { c.OnRateAdapt = fn }
}

// WithLogger sets the diagnostic logger (nil disables logging at zero cost).
func WithLogger(l Logger) Option { return func(c *Config) { c.Logger = l } }

// Dial connects a Sender to a RIST receiver at addr ("host:port" or a rist://
// URL) with the given options. Cancelling ctx closes the Sender (aborting a
// pending Main/DTLS handshake and unblocking Write).
func Dial(ctx context.Context, addr string, opts ...Option) (*Sender, error) {
	s, err := NewSender(addr, applyOptions(opts))
	if err != nil {
		return nil, err
	}
	s.ctxStop = watchContext(ctx, s)
	return s, nil
}

// Listen binds a Receiver at addr ("host:port" or a rist:// URL) with the given
// options. Cancelling ctx closes the Receiver (aborting a pending handshake and
// unblocking Read).
func Listen(ctx context.Context, addr string, opts ...Option) (*Receiver, error) {
	r, err := NewReceiver(addr, applyOptions(opts))
	if err != nil {
		return nil, err
	}
	r.ctxStop = watchContext(ctx, r)
	return r, nil
}

// DialBonded connects a SMPTE 2022-7 bonded Sender across several receiver
// addresses with the given options. Cancelling ctx closes the Sender.
func DialBonded(ctx context.Context, addrs []string, opts ...Option) (*BondedSender, error) {
	s, err := NewBondedSender(addrs, applyOptions(opts))
	if err != nil {
		return nil, err
	}
	s.ctxStop = watchContext(ctx, s)
	return s, nil
}

// ListenBonded binds a SMPTE 2022-7 bonded Receiver across several local
// addresses with the given options. Cancelling ctx closes the Receiver.
func ListenBonded(ctx context.Context, addrs []string, opts ...Option) (*BondedReceiver, error) {
	r, err := NewBondedReceiver(addrs, applyOptions(opts))
	if err != nil {
		return nil, err
	}
	r.ctxStop = watchContext(ctx, r)
	return r, nil
}

// watchContext closes c when ctx is cancelled, returning a stop function (called
// from Close) that ends the watcher so it never outlives the session. A nil or
// non-cancellable ctx yields a no-op.
func watchContext(ctx context.Context, c io.Closer) func() {
	if ctx == nil || ctx.Done() == nil {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-stop:
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop) }) }
}
