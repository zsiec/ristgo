package conformance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClean: with no loss the receiver delivers every packet, in order, with no
// recovery and no invariant violation.
func TestClean(t *testing.T) {
	r := Run(Options{Packets: 64, RequireContiguous: true}, nil)
	if len(r.Invariants) != 0 {
		t.Fatalf("clean run invariants: %v", r.Invariants)
	}
	if r.Delivered != 64 || r.Lost != 0 || r.Recovered != 0 || r.ForwardDropped != 0 {
		t.Fatalf("clean: delivered=%d lost=%d recovered=%d dropped=%d, want 64/0/0/0",
			r.Delivered, r.Lost, r.Recovered, r.ForwardDropped)
	}
}

// TestRecoverable: dropping the ORIGINAL of a set of interior sequences (letting
// the retransmit through) must be fully recovered by ARQ — every packet
// delivered, in order, no gaps, nothing lost. This is the white-box ARQ
// conformance: the core recovers all recoverable loss.
func TestRecoverable(t *testing.T) {
	drop := func(seq uint32, firstTx bool) bool { return firstTx && seq%7 == 3 }
	r := Run(Options{Packets: 64, RequireContiguous: true}, drop)
	if len(r.Invariants) != 0 {
		t.Fatalf("recoverable invariants: %v", r.Invariants)
	}
	if r.Delivered != 64 || r.Lost != 0 {
		t.Fatalf("recoverable: delivered=%d lost=%d, want 64/0 (recovered=%d dropped=%d)",
			r.Delivered, r.Lost, r.Recovered, r.ForwardDropped)
	}
	if r.Recovered == 0 || r.ForwardDropped == 0 {
		t.Fatalf("recoverable should have exercised ARQ: recovered=%d dropped=%d", r.Recovered, r.ForwardDropped)
	}
}

// TestUnrecoverable: dropping BOTH the original and the retransmit of two
// sequences leaves them permanently lost — a graceful-degradation outcome. The
// no-duplicate / in-order / deadline invariants still hold (RequireContiguous
// off), but the stream has a real gap and Lost reflects it.
func TestUnrecoverable(t *testing.T) {
	drop := func(seq uint32, firstTx bool) bool { return seq == 20 || seq == 21 }
	r := Run(Options{Packets: 64, RequireContiguous: false}, drop)
	if len(r.Invariants) != 0 {
		t.Fatalf("unrecoverable should still satisfy no-dup/in-order/deadline: %v", r.Invariants)
	}
	if r.Delivered != 62 || r.Lost != 2 {
		t.Fatalf("unrecoverable: delivered=%d lost=%d, want 62/2", r.Delivered, r.Lost)
	}
	for _, s := range r.DeliveredSeqs {
		if s == 20 || s == 21 {
			t.Fatalf("seq %d was unrecoverable but appeared in the delivered stream", s)
		}
	}
}

// TestDeterministic: identical inputs produce a byte-identical Result, run to
// run — the Tier-1 reproducibility property.
func TestDeterministic(t *testing.T) {
	drop := func(seq uint32, firstTx bool) bool { return firstTx && (seq%5 == 2 || seq%11 == 0) }
	a := transcript(Run(Options{Packets: 100, RequireContiguous: true}, drop))
	b := transcript(Run(Options{Packets: 100, RequireContiguous: true}, drop))
	if a != b {
		t.Fatalf("conformance run is not deterministic:\n--- a ---\n%s\n--- b ---\n%s", a, b)
	}
}

// TestGolden pins the transcript of canonical runs — a regression in the flow
// core (recovery timing, NACK cadence, playout) surfaces as a golden diff. Set
// UPDATE_GOLDEN=1 to regenerate after an intentional change.
func TestGolden(t *testing.T) {
	var b strings.Builder
	b.WriteString("rist-conformance v1\n")
	b.WriteString("clean: " + transcript(Run(Options{Packets: 64, RequireContiguous: true}, nil)) + "\n")
	rec := func(seq uint32, firstTx bool) bool { return firstTx && seq%7 == 3 }
	b.WriteString("recoverable: " + transcript(Run(Options{Packets: 64, RequireContiguous: true}, rec)) + "\n")
	unrec := func(seq uint32, firstTx bool) bool { return seq == 20 || seq == 21 }
	b.WriteString("unrecoverable: " + transcript(Run(Options{Packets: 64}, unrec)) + "\n")
	got := b.String()

	path := filepath.Join("testdata", "golden_conformance.txt")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden updated")
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run `UPDATE_GOLDEN=1 go test ./conformance/`): %v", err)
	}
	if got != string(want) {
		t.Fatalf("conformance transcript drifted from golden %s — flow-core regression or intentional change (UPDATE_GOLDEN=1)\n--- got ---\n%s", path, got)
	}
}

// transcript renders a Result deterministically for golden comparison.
func transcript(r Result) string {
	return fmt.Sprintf("sent=%d delivered=%d fwdDropped=%d recovered=%d recoveredOneRTT=%d lost=%d disc=%d invariants=%d seqs=%v",
		r.Sent, r.Delivered, r.ForwardDropped, r.Recovered, r.RecoveredOneRTT, r.Lost, r.Discontinuities, len(r.Invariants), r.DeliveredSeqs)
}
