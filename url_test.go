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
