package adapt

import "testing"

func BenchmarkLQMMarshal(b *testing.B) {
	m := LQM{SequenceNumber: 1, ReportingPeriodMS: 1000, SourceReceived: 5000, OriginalLost: 17}
	dst := make([]byte, 0, LQMSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.AppendTo(dst[:0])
	}
}

func BenchmarkLQMParse(b *testing.B) {
	wire := (LQM{SequenceNumber: 1, ReportingPeriodMS: 1000, SourceReceived: 5000, OriginalLost: 17}).Marshal()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(wire); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkControllerObserve(b *testing.B) {
	c := NewController(DefaultControllerConfig())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Alternate clean/lossy so both AIMD branches are exercised.
		if i&1 == 0 {
			c.Observe(0)
		} else {
			c.Observe(0.05)
		}
	}
}
