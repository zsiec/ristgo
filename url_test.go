package ristgo

import (
	"errors"
	"testing"
	"time"
)

func TestParseURLPlainAddr(t *testing.T) {
	addr, cfg, err := ParseURL("127.0.0.1:5000", DefaultConfig())
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if addr != "127.0.0.1:5000" {
		t.Fatalf("addr = %q, want 127.0.0.1:5000", addr)
	}
	if cfg.BufferMin != DefaultBufferMin {
		t.Fatalf("plain addr should not alter cfg; BufferMin = %v", cfg.BufferMin)
	}
}

func TestParseURLParams(t *testing.T) {
	raw := "rist://host.example:5000?buffer=1200&rtt-min=20&rtt-max=80&reorder-buffer=10" +
		"&cname=cam1&weight=3&profile=0&session-timeout=3000&keepalive=250&bandwidth=8000"
	addr, cfg, err := ParseURL(raw, DefaultConfig())
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if addr != "host.example:5000" {
		t.Fatalf("addr = %q", addr)
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"BufferMin", cfg.BufferMin, 1200 * time.Millisecond},
		{"BufferMax", cfg.BufferMax, 1200 * time.Millisecond},
		{"RTTMin", cfg.RTTMin, 20 * time.Millisecond},
		{"RTTMax", cfg.RTTMax, 80 * time.Millisecond},
		{"ReorderBuffer", cfg.ReorderBuffer, 10 * time.Millisecond},
		{"CNAME", cfg.CNAME, "cam1"},
		{"Weight", cfg.Weight, 3},
		{"Profile", cfg.Profile, ProfileSimple},
		{"SessionTimeout", cfg.SessionTimeout, 3000 * time.Millisecond},
		{"KeepaliveInterval", cfg.KeepaliveInterval, 250 * time.Millisecond},
		{"MaxBitrate", cfg.MaxBitrate, 8000},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	// The resulting config must still validate.
	if err := cfg.validate(); err != nil {
		t.Fatalf("parsed config failed validation: %v", err)
	}
}

func TestParseURLBufferOverridesMinMax(t *testing.T) {
	// buffer-min/buffer-max take precedence over buffer regardless of URL
	// order (net/url discards order — a documented simplification).
	cases := []string{
		"rist://h:5000?buffer=1000&buffer-min=200&buffer-max=400",
		"rist://h:5000?buffer-min=200&buffer-max=400&buffer=1000", // reversed order
	}
	for _, raw := range cases {
		_, cfg, err := ParseURL(raw, DefaultConfig())
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		if cfg.BufferMin != 200*time.Millisecond || cfg.BufferMax != 400*time.Millisecond {
			t.Fatalf("%q: buffer-min/max = %v/%v, want 200ms/400ms", raw, cfg.BufferMin, cfg.BufferMax)
		}
	}
}

func TestParseURLKeepaliveAliasAndRetries(t *testing.T) {
	// libRIST's canonical "keepalive-interval" and the retry/rtt params parse.
	_, cfg, err := ParseURL("rist://h:5000?keepalive-interval=300&min-retries=8&max-retries=40&rtt=33&virt-src-port=1971", DefaultConfig())
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if cfg.KeepaliveInterval != 300*time.Millisecond {
		t.Errorf("KeepaliveInterval = %v, want 300ms", cfg.KeepaliveInterval)
	}
	if cfg.MinRetries != 8 || cfg.MaxRetries != 40 {
		t.Errorf("retries = %d/%d, want 8/40", cfg.MinRetries, cfg.MaxRetries)
	}
	if cfg.RTTMin != 33*time.Millisecond || cfg.RTTMax != 33*time.Millisecond {
		t.Errorf("rtt = %v/%v, want 33ms/33ms", cfg.RTTMin, cfg.RTTMax)
	}
	if cfg.VirtSrcPort != 1971 {
		t.Errorf("VirtSrcPort = %d, want 1971", cfg.VirtSrcPort)
	}
}

func TestParseURLErrors(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"bad scheme", "srt://h:5000"},
		{"no port", "rist://h"},
		{"non-integer buffer", "rist://h:5000?buffer=abc"},
		{"non-integer rtt-min", "rist://h:5000?rtt-min=fast"},
		{"bad virt-dst-port", "rist://h:5000?virt-dst-port=99999"},
		{"unknown parameter typo", "rist://h:5000?reoder-buffer=5"},
		{"underscore not hyphen", "rist://h:5000?aes_type=128"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ParseURL(tt.url, DefaultConfig()); err == nil {
				t.Fatalf("ParseURL(%q) = nil error, want error", tt.url)
			} else if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error %v does not wrap ErrInvalidConfig", err)
			}
		})
	}
}

// TestParseURLAcceptsUnimplementedLibristParams verifies that parameters libRIST
// honors but ristgo does not yet implement are accepted and ignored (not
// rejected), so a URL authored for libRIST still parses.
func TestParseURLAcceptsUnimplementedLibristParams(t *testing.T) {
	// Each is a libRIST URL parameter ristgo does not implement but accepts and
	// ignores so a libRIST-authored URL still parses: recovery-priority (set via
	// BondedPeer), reflector (Main one-to-many fan-out), local-port (caller fixed
	// source port).
	for _, raw := range []string{
		"rist://h:5000?buffer=1000&recovery-priority=5",
		"rist://h:5000?reflector=1",
		"rist://h:5000?local-port=5004",
		"rist://h:5000?reflector=1&local-port=5004&recovery-priority=2",
	} {
		if _, _, err := ParseURL(raw, DefaultConfig()); err != nil {
			t.Fatalf("ParseURL(%q) = %v, want nil (unimplemented libRIST params should be ignored)", raw, err)
		}
	}
}

// TestParseURLReturnBandwidth verifies return-bandwidth maps onto
// Config.ReturnBandwidth (kbps).
func TestParseURLReturnBandwidth(t *testing.T) {
	_, cfg, err := ParseURL("rist://h:5000?return-bandwidth=2000", DefaultConfig())
	if err != nil {
		t.Fatalf("return-bandwidth: %v", err)
	}
	if cfg.ReturnBandwidth != 2000 {
		t.Errorf("ReturnBandwidth = %d, want 2000", cfg.ReturnBandwidth)
	}
}

// TestParseURLTimingMode verifies timing-mode maps libRIST's numbering
// (0=source, 1=arrival, 2=rtc→arrival) onto Config.TimingMode and rejects an
// out-of-range value.
func TestParseURLTimingMode(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want TimingMode
	}{
		{"0", TimingSource},
		{"1", TimingArrival},
		{"2", TimingArrival}, // RTC maps to arrival
	} {
		_, cfg, err := ParseURL("rist://h:5000?timing-mode="+tc.v, DefaultConfig())
		if err != nil {
			t.Fatalf("timing-mode=%s: %v", tc.v, err)
		}
		if cfg.TimingMode != tc.want {
			t.Errorf("timing-mode=%s → %v, want %v", tc.v, cfg.TimingMode, tc.want)
		}
	}
	if _, _, err := ParseURL("rist://h:5000?timing-mode=9", DefaultConfig()); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("timing-mode=9 error = %v, want ErrInvalidConfig", err)
	}
}

// TestParseURLSRPCompat verifies srp-compat=1 sets Config.SRPCompat.
func TestParseURLSRPCompat(t *testing.T) {
	_, cfg, err := ParseURL("rist://h:5000?srp-compat=1", DefaultConfig())
	if err != nil {
		t.Fatalf("srp-compat=1: %v", err)
	}
	if !cfg.SRPCompat {
		t.Error("srp-compat=1 did not set Config.SRPCompat")
	}
	if _, cfg, _ := ParseURL("rist://h:5000?srp-compat=0", DefaultConfig()); cfg.SRPCompat {
		t.Error("srp-compat=0 set Config.SRPCompat")
	}
}

// TestParseURLCongestionControl verifies congestion-control maps libRIST's
// numbering (0=off, 1=normal, 2=aggressive) onto Config.CongestionControl, and
// rejects an out-of-range value.
func TestParseURLCongestionControl(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want CongestionControl
	}{
		{"0", CongestionOff},
		{"1", CongestionNormal},
		{"2", CongestionAggressive},
	} {
		raw := "rist://h:5000?congestion-control=" + tc.v
		_, cfg, err := ParseURL(raw, DefaultConfig())
		if err != nil {
			t.Fatalf("ParseURL(%q) = %v, want nil", raw, err)
		}
		if cfg.CongestionControl != tc.want {
			t.Errorf("congestion-control=%s → %v, want %v", tc.v, cfg.CongestionControl, tc.want)
		}
	}
	for _, raw := range []string{"rist://h:5000?congestion-control=3", "rist://h:5000?congestion-control=x"} {
		if _, _, err := ParseURL(raw, DefaultConfig()); err == nil {
			t.Errorf("ParseURL(%q) = nil error, want error", raw)
		} else if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ParseURL(%q) error %v does not wrap ErrInvalidConfig", raw, err)
		}
	}
}

// TestParseURLMulticastParams verifies the multicast query parameters miface,
// ttl, and source map onto Config.Interface, MulticastTTL, and MulticastSource.
func TestParseURLMulticastParams(t *testing.T) {
	raw := "rist://239.1.2.3:5000?miface=eth0&ttl=32&source=10.0.0.1"
	_, cfg, err := ParseURL(raw, DefaultConfig())
	if err != nil {
		t.Fatalf("ParseURL(%q) = %v, want nil", raw, err)
	}
	if cfg.Interface != "eth0" {
		t.Errorf("Interface = %q, want eth0", cfg.Interface)
	}
	if cfg.MulticastTTL != 32 {
		t.Errorf("MulticastTTL = %d, want 32", cfg.MulticastTTL)
	}
	if cfg.MulticastSource != "10.0.0.1" {
		t.Errorf("MulticastSource = %q, want 10.0.0.1", cfg.MulticastSource)
	}
}

// TestParseURLBadTTL verifies an out-of-range or non-integer ttl is rejected.
func TestParseURLBadTTL(t *testing.T) {
	for _, raw := range []string{
		"rist://239.1.2.3:5000?ttl=256",
		"rist://239.1.2.3:5000?ttl=-1",
		"rist://239.1.2.3:5000?ttl=high",
	} {
		if _, _, err := ParseURL(raw, DefaultConfig()); err == nil {
			t.Errorf("ParseURL(%q) = nil error, want error", raw)
		} else if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ParseURL(%q) error %v does not wrap ErrInvalidConfig", raw, err)
		}
	}
}

func TestNewSenderInvalidConfigWrapsSentinel(t *testing.T) {
	// The WP4 binding: constructor validation errors must satisfy
	// errors.Is(err, ErrInvalidConfig).
	cfg := DefaultConfig()
	cfg.BufferMin = 10 * time.Millisecond // below MinBuffer
	cfg.BufferMax = 10 * time.Millisecond
	if _, err := NewSender("127.0.0.1:5000", cfg); err == nil {
		t.Fatal("NewSender accepted an out-of-range buffer")
	} else if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error %v does not wrap ErrInvalidConfig", err)
	}
}

func TestNewSenderOddPortRejected(t *testing.T) {
	if _, err := NewSender("127.0.0.1:5001", DefaultConfig()); err == nil {
		t.Fatal("NewSender accepted an odd media port")
	} else if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error %v does not wrap ErrInvalidConfig", err)
	}
}
