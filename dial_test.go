package ristgo

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestApplyOptions(t *testing.T) {
	cfg := applyOptions([]Option{
		WithProfile(ProfileMain),
		WithSecret("passphrase"),
		WithAESKeyBits(256),
		WithCredentials("user", "pass"),
		WithBuffer(800 * time.Millisecond),
		WithReorderBuffer(20 * time.Millisecond),
		WithNACKType(NACKBitmask),
		WithRTT(3*time.Millisecond, 400*time.Millisecond),
		WithRetries(4, 16),
		WithKeepalive(500 * time.Millisecond),
		WithSessionTimeout(3 * time.Second),
		WithMaxBitrate(50000),
		WithCNAME("cam-1"),
		WithCompression(),
		WithFragmentSize(1200),
		WithWeight(3),
		WithSourceAdaptation(),
	})

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"Profile", cfg.Profile, ProfileMain},
		{"Secret", cfg.Secret, "passphrase"},
		{"AESKeyBits", cfg.AESKeyBits, 256},
		{"Username", cfg.Username, "user"},
		{"Password", cfg.Password, "pass"},
		{"BufferMin", cfg.BufferMin, 800 * time.Millisecond},
		{"BufferMax", cfg.BufferMax, 800 * time.Millisecond},
		{"ReorderBuffer", cfg.ReorderBuffer, 20 * time.Millisecond},
		{"NACKType", cfg.NACKType, NACKBitmask},
		{"RTTMin", cfg.RTTMin, 3 * time.Millisecond},
		{"RTTMax", cfg.RTTMax, 400 * time.Millisecond},
		{"MinRetries", cfg.MinRetries, 4},
		{"MaxRetries", cfg.MaxRetries, 16},
		{"KeepaliveInterval", cfg.KeepaliveInterval, 500 * time.Millisecond},
		{"SessionTimeout", cfg.SessionTimeout, 3 * time.Second},
		{"MaxBitrate", cfg.MaxBitrate, 50000},
		{"CNAME", cfg.CNAME, "cam-1"},
		{"Compression", cfg.Compression, true},
		{"FragmentSize", cfg.FragmentSize, 1200},
		{"Weight", cfg.Weight, 3},
		{"SourceAdaptation", cfg.SourceAdaptation, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestWithBufferRange(t *testing.T) {
	cfg := applyOptions([]Option{WithBufferRange(200*time.Millisecond, 900*time.Millisecond)})
	if cfg.BufferMin != 200*time.Millisecond || cfg.BufferMax != 900*time.Millisecond {
		t.Errorf("buffer range = %v/%v, want 200ms/900ms", cfg.BufferMin, cfg.BufferMax)
	}
}

// TestWithConfigBaseThenOverride verifies WithConfig sets the whole struct and a
// later option overrides one field.
func TestWithConfigBaseThenOverride(t *testing.T) {
	base := DefaultConfig()
	base.Secret = "base-secret"
	base.MaxBitrate = 12345

	cfg := applyOptions([]Option{WithConfig(base), WithProfile(ProfileAdvanced)})
	if cfg.Secret != "base-secret" {
		t.Errorf("Secret = %q, want base-secret (from WithConfig)", cfg.Secret)
	}
	if cfg.MaxBitrate != 12345 {
		t.Errorf("MaxBitrate = %d, want 12345 (from WithConfig)", cfg.MaxBitrate)
	}
	if cfg.Profile != ProfileAdvanced {
		t.Errorf("Profile = %v, want advanced (later option overrides)", cfg.Profile)
	}
}

func TestWithDTLSAndRateAdapt(t *testing.T) {
	called := false
	cfg := applyOptions([]Option{
		WithDTLS(DTLSConfig{PSK: []byte("dtls-key")}),
		WithRateAdapt(func(int) { called = true }),
	})
	if cfg.DTLS == nil || string(cfg.DTLS.PSK) != "dtls-key" {
		t.Fatalf("WithDTLS did not set the DTLS PSK: %+v", cfg.DTLS)
	}
	if cfg.OnRateAdapt == nil {
		t.Fatal("WithRateAdapt did not set OnRateAdapt")
	}
	cfg.OnRateAdapt(1)
	if !called {
		t.Error("OnRateAdapt callback was not the one provided")
	}
}

// TestDialContextCancelCloses verifies that cancelling the context passed to Dial
// closes the session, so a subsequent Write returns ErrClosed.
func TestDialContextCancelCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tx, err := Dial(ctx, "127.0.0.1:5000")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tx.Close()

	// A Simple sender has no handshake, so Write works before cancellation.
	if _, err := tx.Write([]byte("hello")); err != nil {
		t.Fatalf("Write before cancel: %v", err)
	}

	cancel() // the context watcher closes the sender asynchronously

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := tx.Write([]byte("x")); errors.Is(err, ErrClosed) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Write did not return ErrClosed within 2s of context cancel")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
