package clock

import (
	"testing"
	"time"
)

func TestMicroseconds(t *testing.T) {
	t.Run("Duration", func(t *testing.T) {
		d := Microseconds(1500000)
		if got := d.Duration(); got != 1500*time.Millisecond {
			t.Errorf("Duration() = %v, want %v", got, 1500*time.Millisecond)
		}
	})

	t.Run("FromDuration", func(t *testing.T) {
		d := FromDuration(2 * time.Second)
		if d != 2*Second {
			t.Errorf("FromDuration(2s) = %d, want %d", d, 2*Second)
		}
	})

	t.Run("Abs", func(t *testing.T) {
		if Microseconds(-100).Abs() != 100 {
			t.Error("Abs(-100) should be 100")
		}
		if Microseconds(100).Abs() != 100 {
			t.Error("Abs(100) should be 100")
		}
		if Microseconds(0).Abs() != 0 {
			t.Error("Abs(0) should be 0")
		}
	})

	t.Run("Constants", func(t *testing.T) {
		if Millisecond != 1000 {
			t.Errorf("Millisecond = %d, want 1000", Millisecond)
		}
		if Second != 1_000_000 {
			t.Errorf("Second = %d, want 1000000", Second)
		}
		if Minute != 60_000_000 {
			t.Errorf("Minute = %d, want 60000000", Minute)
		}
	})
}

func TestTimestamp(t *testing.T) {
	t.Run("AddSub", func(t *testing.T) {
		ts := Timestamp(1000000)
		ts2 := ts.Add(500000)
		if ts2 != 1500000 {
			t.Errorf("Add: got %d, want 1500000", ts2)
		}
		if ts2.Sub(ts) != 500000 {
			t.Errorf("Sub: got %d, want 500000", ts2.Sub(ts))
		}
	})

	t.Run("Comparison", func(t *testing.T) {
		a := Timestamp(100)
		b := Timestamp(200)
		if !a.Before(b) {
			t.Error("100 should be before 200")
		}
		if !b.After(a) {
			t.Error("200 should be after 100")
		}
		if a.After(b) {
			t.Error("100 should not be after 200")
		}
	})

	t.Run("IsZero", func(t *testing.T) {
		if !Timestamp(0).IsZero() {
			t.Error("Timestamp(0).IsZero() should be true")
		}
		if Timestamp(1).IsZero() {
			t.Error("Timestamp(1).IsZero() should be false")
		}
	})
}

func TestLow32(t *testing.T) {
	t.Run("Lower32bits", func(t *testing.T) {
		ts := Timestamp(0x1_FFFFFFFF) // 33 bits set
		got := ts.Low32()
		if got != 0xFFFFFFFF {
			t.Errorf("Low32() = 0x%X, want 0xFFFFFFFF", got)
		}
	})

	t.Run("WrapPeriod", func(t *testing.T) {
		period := Wrap32Period()
		// 2^32 microseconds ≈ 4294.967296 seconds ≈ 71.58 minutes
		if period != 1<<32 {
			t.Errorf("WrapPeriod = %d, want %d", period, Microseconds(1<<32))
		}
	})
}

func TestFrom32BitTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		ts32      uint32
		reference Timestamp
		expected  Timestamp
	}{
		{
			name:      "same epoch, no wrap",
			ts32:      1000,
			reference: Timestamp(500),
			expected:  Timestamp(1000),
		},
		{
			name:      "same epoch, before reference",
			ts32:      500,
			reference: Timestamp(1000),
			expected:  Timestamp(500),
		},
		{
			name:      "second epoch, no wrap",
			ts32:      1000,
			reference: Timestamp(int64(wrap32Period) + 500),
			expected:  Timestamp(int64(wrap32Period) + 1000),
		},
		{
			name:      "wrap forward: ts32 near 0, reference near max",
			ts32:      100,
			reference: Timestamp(int64(wrap32Period) - 100),
			expected:  Timestamp(int64(wrap32Period) + 100),
		},
		{
			name:      "wrap backward: ts32 near max, reference near 0 of next epoch",
			ts32:      0xFFFFFF00,
			reference: Timestamp(int64(wrap32Period) + 100),
			expected:  Timestamp(0xFFFFFF00),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := From32BitTimestamp(tt.ts32, tt.reference)
			if got != tt.expected {
				t.Errorf("From32BitTimestamp(0x%X, %d) = %d, want %d",
					tt.ts32, tt.reference, got, tt.expected)
			}
		})
	}
}

func TestFrom32BitTimestampRoundTrip(t *testing.T) {
	// A full timestamp must survive Low32 + reconstruction against any
	// reference within half a wrap period.
	for _, full := range []Timestamp{
		0,
		1,
		Timestamp(int64(wrap32Period) - 1),
		Timestamp(int64(wrap32Period)),
		Timestamp(int64(wrap32Period) + 1),
		Timestamp(3*int64(wrap32Period) + 12345),
	} {
		for _, skew := range []Microseconds{
			0, 1, -1, Second, -Second,
			wrap32Period/2 - 1, -(wrap32Period/2 - 1),
		} {
			ref := full.Add(skew)
			if ref < 0 {
				continue
			}
			got := From32BitTimestamp(full.Low32(), ref)
			if got != full {
				t.Errorf("round trip full=%d skew=%d: got %d", full, skew, got)
			}
		}
	}
}

func TestMockClock(t *testing.T) {
	c := NewMockClock()
	if c.Now() != 0 {
		t.Errorf("initial time should be 0, got %d", c.Now())
	}

	c.Advance(1000)
	if c.Now() != 1000 {
		t.Errorf("after Advance(1000), got %d", c.Now())
	}

	c.Set(Timestamp(5000))
	if c.Now() != 5000 {
		t.Errorf("after Set(5000), got %d", c.Now())
	}

	c.Advance(Second)
	if c.Now() != Timestamp(5000+Second) {
		t.Errorf("after Advance(Second), got %d, want %d", c.Now(), Timestamp(5000+Second))
	}
}

func TestRealClock(t *testing.T) {
	c := NewRealClock()
	t1 := c.Now()
	time.Sleep(1 * time.Millisecond)
	t2 := c.Now()

	if !t2.After(t1) {
		t.Error("RealClock should advance with time")
	}

	diff := t2.Sub(t1)
	if diff < 1000 { // at least 1ms = 1000μs
		t.Errorf("expected at least 1000μs difference, got %d", diff)
	}
}

func TestClockInterface(t *testing.T) {
	// Both implementations must satisfy Clock.
	var _ Clock = NewRealClock()
	var _ Clock = NewMockClock()
}

// Benchmarks

func BenchmarkTimestampAdd(b *testing.B) {
	ts := Timestamp(1000000)
	d := Microseconds(500)
	for b.Loop() {
		ts = ts.Add(d)
	}
}

func BenchmarkLow32(b *testing.B) {
	ts := Timestamp(5_000_000_000)
	for b.Loop() {
		_ = ts.Low32()
	}
}

func BenchmarkFrom32BitTimestamp(b *testing.B) {
	ref := Timestamp(5_000_000_000)
	ts32 := uint32(1000)
	for b.Loop() {
		From32BitTimestamp(ts32, ref)
	}
}
