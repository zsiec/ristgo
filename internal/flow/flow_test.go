package flow

import (
	"reflect"
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/wire"
)

// testConfig returns the libRIST defaults used by most tests:
// recoveryBuffer = 1s (so recoveryBuffer*1.1 = 1.1s), rtt clamp [5ms,500ms],
// max retries 20.
func testConfig() Config {
	return DefaultConfig()
}

// srcNTP converts a source-domain microsecond instant into the NTP-64 wire
// form carried in MediaPacket.SourceTime.
func srcNTP(us clock.Microseconds) uint64 {
	return uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(us)))
}

// mkPkt builds a media packet with SourceTime at srcUS microseconds.
func mkPkt(seqn uint32, srcUS clock.Microseconds, payload []byte) wire.MediaPacket {
	return wire.MediaPacket{Seq: seqn, SourceTime: srcNTP(srcUS), SSRC: 0x1234_5678, Payload: payload}
}

// drainOutputs empties the output queue.
func drainOutputs(f *Flow) []Output {
	var out []Output
	for {
		o, ok := f.PollOutput()
		if !ok {
			return out
		}
		out = append(out, o)
	}
}

// drainEvents empties the event queue.
func drainEvents(f *Flow) []Event {
	var evs []Event
	for {
		e, ok := f.PollEvent()
		if !ok {
			return evs
		}
		evs = append(evs, e)
	}
}

// deliveredSeqs extracts the sequence numbers of Deliver events.
func deliveredSeqs(evs []Event) []uint32 {
	var seqs []uint32
	for _, e := range evs {
		if d, ok := e.(Deliver); ok {
			seqs = append(seqs, d.Seq)
		}
	}
	return seqs
}

// feedbackOutputs extracts SendFeedback effects.
func feedbackOutputs(outs []Output) []SendFeedback {
	var fbs []SendFeedback
	for _, o := range outs {
		if fb, ok := o.(SendFeedback); ok {
			fbs = append(fbs, fb)
		}
	}
	return fbs
}

func TestNewRingSizing(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		ringSize int
		want     int
	}{
		{"receiver default", RoleReceiver, 0, DefaultRingSize},
		{"receiver negative pins to default", RoleReceiver, -5, DefaultRingSize},
		{"receiver rounds up to pow2", RoleReceiver, 100, 128},
		{"receiver exact pow2 kept", RoleReceiver, 256, 256},
		{"sender has no ring", RoleSender, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(tt.role, Config{RingSize: tt.ringSize})
			if got := len(f.receiver.ring); got != tt.want {
				t.Fatalf("ring size = %d, want %d", got, tt.want)
			}
			if f.Role() != tt.role {
				t.Fatalf("Role() = %v, want %v", f.Role(), tt.role)
			}
		})
	}
}

func TestRecoveryBufferFormula(t *testing.T) {
	// buffer_time = (max-min)/2 + min (librist).
	tests := []struct {
		name     string
		min, max clock.Microseconds
		want     clock.Microseconds
	}{
		{"librist defaults", 1000 * clock.Millisecond, 1000 * clock.Millisecond, 1000 * clock.Millisecond},
		{"asymmetric window", 1000 * clock.Millisecond, 3000 * clock.Millisecond, 2000 * clock.Millisecond},
		{"odd spread truncates", 50 * clock.Millisecond, 51 * clock.Millisecond, 50*clock.Millisecond + 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{RecoveryBufferMin: tt.min, RecoveryBufferMax: tt.max}
			if got := c.RecoveryBuffer(); got != tt.want {
				t.Fatalf("RecoveryBuffer() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFirstPacketLocksOffsetAndSchedules(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, []byte("a")))

	if f.receiver.offset != 10_000 {
		t.Fatalf("offset = %d, want 10000", f.receiver.offset)
	}
	if f.receiver.lastFound != 100 || f.receiver.deliverNext != 100 {
		t.Fatalf("cursors = (%d,%d), want (100,100)", f.receiver.lastFound, f.receiver.deliverNext)
	}
	s := &f.receiver.ring[100&f.receiver.mask]
	if s.state != slotFilled || s.packetTime != 10_000 || s.outputTime != 1_010_000 {
		t.Fatalf("slot = %+v, want filled with packetTime 10000, outputTime 1010000", s)
	}
	want := []Output{
		SetTimer{ID: TimerPlayout, Deadline: 1_010_000},
		SetTimer{ID: TimerRttEcho, Deadline: 110_000},
	}
	if got := drainOutputs(f); !reflect.DeepEqual(got, want) {
		t.Fatalf("outputs = %v, want %v", got, want)
	}

	// A later packet maps through the locked offset.
	f.Feed(17_500, 0, mkPkt(101, 7_000, []byte("b")))
	s2 := &f.receiver.ring[101&f.receiver.mask]
	if s2.packetTime != 17_000 || s2.outputTime != 1_017_000 {
		t.Fatalf("slot2 packetTime/outputTime = %d/%d, want 17000/1017000", s2.packetTime, s2.outputTime)
	}
	// In-order steady state: no further effects.
	if got := drainOutputs(f); got != nil {
		t.Fatalf("steady-state outputs = %v, want none", got)
	}
}

// zeroGauges blanks the fields that depend on payload size or live estimator state
// — the byte counters (ReceivedBytes/SentBytes/RetransmittedBytes) and the gauges
// (SmoothedRTTUs/DataBitrateBps/RetryBitrateBps, which Stats() fills and so are never
// zero) — so the packet-count snapshot can be compared against a literal in tests
// that assert counting logic rather than byte totals.
func zeroGauges(s Stats) Stats {
	s.ReceivedBytes, s.SentBytes, s.RetransmittedBytes = 0, 0, 0
	s.SmoothedRTTUs, s.DataBitrateBps, s.RetryBitrateBps = 0, 0, 0
	return s
}

func TestFirstPacketRetransmitIgnored(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	pkt := mkPkt(100, 0, []byte("a"))
	pkt.Retransmit = true
	f.Feed(10_000, 0, pkt) // librist
	if f.receiver.started {
		t.Fatal("flow must not start on a retransmit")
	}
	if got := zeroGauges(f.Stats()); got != (Stats{}) {
		t.Fatalf("stats = %+v, want zero", got)
	}
}

func TestFeedDedupOverwriteInsert(t *testing.T) {
	type step struct {
		now     clock.Timestamp
		path    uint8
		pkt     wire.MediaPacket
		retrans bool
	}
	tests := []struct {
		name      string
		steps     []step
		wantStats Stats
		// wantSlot checks the final slot keyed by the last step's seq.
		wantPayload string
		wantPaths   uint64
	}{
		{
			name: "exact duplicate dropped, path recorded",
			steps: []step{
				{now: 10_000, path: 0, pkt: mkPkt(100, 0, []byte("orig"))},
				{now: 10_500, path: 1, pkt: mkPkt(100, 0, []byte("copy"))},
			},
			wantStats:   Stats{Received: 1, Duplicates: 1},
			wantPayload: "orig",
			wantPaths:   0b11,
		},
		{
			name: "retransmit duplicate dropped",
			steps: []step{
				{now: 10_000, path: 0, pkt: mkPkt(100, 0, []byte("orig"))},
				{now: 12_000, path: 0, pkt: mkPkt(100, 0, []byte("orig")), retrans: true},
			},
			// The retransmit copy is counted in RetransmittedReceived before
			// the dedup test sheds it as a duplicate.
			wantStats:   Stats{Received: 1, Duplicates: 1, RetransmittedReceived: 1},
			wantPayload: "orig",
			wantPaths:   0b1,
		},
		{
			name: "same seq different sourceTime overwrites (stale slot)",
			steps: []step{
				{now: 10_000, path: 0, pkt: mkPkt(100, 0, []byte("old"))},
				{now: 20_000, path: 1, pkt: mkPkt(100, 9_000, []byte("new"))},
			},
			wantStats:   Stats{Received: 2, Overwritten: 1},
			wantPayload: "new",
			wantPaths:   0b10,
		},
		{
			name: "ring-collision seq overwrites (seq+2^16, gap guard skips marking)",
			steps: []step{
				{now: 10_000, path: 0, pkt: mkPkt(100, 0, []byte("old"))},
				{now: 20_000, path: 0, pkt: mkPkt(100+1<<16, 9_000, []byte("new"))},
			},
			wantStats:   Stats{Received: 2, Overwritten: 1},
			wantPayload: "new",
			wantPaths:   0b1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(RoleReceiver, testConfig())
			var last wire.MediaPacket
			for _, st := range tt.steps {
				pkt := st.pkt
				pkt.Retransmit = st.retrans
				f.Feed(st.now, st.path, pkt)
				last = pkt
			}
			if got := zeroGauges(f.Stats()); got != tt.wantStats {
				t.Fatalf("stats = %+v, want %+v", got, tt.wantStats)
			}
			s := &f.receiver.ring[last.Seq&f.receiver.mask]
			if string(s.payload) != tt.wantPayload {
				t.Fatalf("slot payload = %q, want %q", s.payload, tt.wantPayload)
			}
			if s.pathSeen != tt.wantPaths {
				t.Fatalf("pathSeen = %b, want %b", s.pathSeen, tt.wantPaths)
			}
		})
	}
}

func TestMissingDetectInterpolationExact(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	f.Feed(17_000, 0, mkPkt(101, 7_000, nil))
	drainOutputs(f)

	// Gap 101 -> 105: missing 102..104. packetTimeLast = pt(101) = 17000,
	// delta = 45000-17000 = 28000, interpacket = 28000/(4+1) = 5600
	// (librist: divisor is gap+1).
	f.Feed(45_000, 3, mkPkt(105, 35_000, nil))

	type entry struct {
		seq       uint32
		path      uint8
		insertion clock.Timestamp
		nextNack  clock.Timestamp
		count     int
	}
	var got []entry
	for e := f.receiver.missingHead; e != nil; e = e.next {
		got = append(got, entry{e.seq, e.path, e.insertionTime, e.nextNack, e.nackCount})
	}
	// firstNack = now + max(clamp(rtt)/2, reorder_buffer) anchored to now=45000
	// (libRIST rist_receiver_missing). Cold start: clamp(rtt)/2 = 2.5ms <
	// reorder_buffer (15ms), so the floor applies: 45000 + 15000 = 60000 for
	// every entry, regardless of its interpolated insertion time.
	want := []entry{
		{102, 3, 22_600, 60_000, 0},
		{103, 3, 28_200, 60_000, 0},
		{104, 3, 33_800, 60_000, 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing entries = %+v, want %+v", got, want)
	}
	if f.Stats().Missing != 3 {
		t.Fatalf("Stats.Missing = %d, want 3", f.Stats().Missing)
	}
	// The NACK cadence timer must be armed 5ms out (RIST_MAX_JITTER).
	outs := drainOutputs(f)
	want2 := []Output{SetTimer{ID: TimerNack, Deadline: 50_000}}
	if !reflect.DeepEqual(outs, want2) {
		t.Fatalf("outputs = %v, want %v", outs, want2)
	}
	if f.receiver.lastFound != 105 {
		t.Fatalf("lastFound = %d, want 105", f.receiver.lastFound)
	}
}

func TestMissingInsertionTimeClamped(t *testing.T) {
	// An interpolated nack time older than now-recoveryBuffer becomes now
	// (librist sets out-of-range values to now, both sides).
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	// Next in-order packet arrives 2s later (source stalled then jumped):
	// interpolated times fall below now-recoveryBuffer.
	f.Feed(2_010_000, 0, mkPkt(102, 2_000_000, nil))
	e := f.receiver.missingHead
	if e == nil || e.seq != 101 {
		t.Fatalf("missing head = %+v, want seq 101", e)
	}
	// nackTime = 10000 + (2010000-10000)/3 = 676666 < now-1s = 1010000 -> now.
	if e.insertionTime != 2_010_000 {
		t.Fatalf("insertionTime = %d, want clamped to now (2010000)", e.insertionTime)
	}
	// firstNack = now + max(clamp(rtt)/2, reorder_buffer) = 2010000 + 15000.
	if e.nextNack != 2_025_000 {
		t.Fatalf("nextNack = %d, want 2025000", e.nextNack)
	}
}

func TestMissingGapGuards(t *testing.T) {
	tests := []struct {
		name        string
		firstSeq    uint32
		nextSeq     uint32
		wantMissing uint64
	}{
		// Gap of exactly MaxGap16 is still loss (gap-1 entries).
		{"gap at MaxGap16 marks", 100, 100 + 32768, 32767},
		// Strictly greater means wraparound/reorder: mark nothing
		// (librist; ORCHESTRATION.md WP3 binding).
		{"gap above MaxGap16 ignored", 100, 100 + 32769, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Raise RecoveryMaxBitrate so missing_counter_max (which caps the
			// marked gap, tested separately) far exceeds MaxGap16 and this test
			// isolates the wraparound boundary. Pin RingSize so the high bitrate
			// does not balloon the derived ring.
			cfg := testConfig()
			cfg.RecoveryMaxBitrate = 10_000_000
			cfg.RingSize = 1 << 16
			f := New(RoleReceiver, cfg)
			f.Feed(10_000, 0, mkPkt(tt.firstSeq, 0, nil))
			f.Feed(17_000, 0, mkPkt(tt.nextSeq, 7_000, nil))
			if got := f.Stats().Missing; got != tt.wantMissing {
				t.Fatalf("Stats.Missing = %d, want %d", got, tt.wantMissing)
			}
		})
	}
}

func TestMissingSkippedForRetransmitAndOutOfOrder(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	f.Feed(38_000, 0, mkPkt(104, 28_000, nil)) // marks 101..103
	if got := f.Stats().Missing; got != 3 {
		t.Fatalf("Stats.Missing = %d, want 3", got)
	}

	// A retransmit filling a hole must not re-run detection or move
	// lastFound (librist `if (!retry)`).
	rt := mkPkt(102, 14_000, nil)
	rt.Retransmit = true
	f.Feed(40_000, 0, rt)
	if got := f.Stats().Missing; got != 3 {
		t.Fatalf("after retransmit, Stats.Missing = %d, want 3", got)
	}
	if f.receiver.lastFound != 104 {
		t.Fatalf("lastFound = %d, want 104", f.receiver.lastFound)
	}

	// An out-of-order original fills its hole without moving lastFound.
	f.Feed(41_000, 0, mkPkt(101, 7_000, nil))
	st := f.Stats()
	if st.Missing != 3 || st.Reordered != 1 || f.receiver.lastFound != 104 {
		t.Fatalf("missing/reordered/lastFound = %d/%d/%d, want 3/1/104",
			st.Missing, st.Reordered, f.receiver.lastFound)
	}
}

func TestNackPassBatchAndRetryTiming(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	f.Feed(17_000, 0, mkPkt(101, 7_000, nil))
	f.Feed(45_000, 0, mkPkt(105, 35_000, nil)) // missing 102..104
	drainOutputs(f)

	// Every entry's first nack is scheduled at now+reorder_buffer =
	// 45000+15000 = 60000. The 5ms cadence timer fires at 50000 and 55000 with
	// nothing yet due, re-arming each time.
	f.HandleTimer(50_000, TimerNack)
	outs := drainOutputs(f)
	if fbs := feedbackOutputs(outs); len(fbs) != 0 {
		t.Fatalf("unexpected feedback at 50000: %v", fbs)
	}
	if want := []Output{SetTimer{ID: TimerNack, Deadline: 55_000}}; !reflect.DeepEqual(outs, want) {
		t.Fatalf("outputs at 50000 = %v, want re-arm to 55000", outs)
	}
	f.HandleTimer(55_000, TimerNack)
	if fbs := feedbackOutputs(drainOutputs(f)); len(fbs) != 0 {
		t.Fatalf("unexpected feedback at 55000")
	}

	// 60000: every entry's first nack is due -> one grouped NackRequest, each
	// re-scheduled at now + 1.1*clamp(rtt) = 60000 + 5500.
	f.HandleTimer(60_000, TimerNack)
	outs = drainOutputs(f)
	fbs := feedbackOutputs(outs)
	if len(fbs) != 1 {
		t.Fatalf("feedback outputs = %d, want 1 (%v)", len(fbs), outs)
	}
	nack, ok := fbs[0].FB.(wire.NackRequest)
	if !ok {
		t.Fatalf("feedback = %T, want NackRequest", fbs[0].FB)
	}
	if want := []uint32{102, 103, 104}; !reflect.DeepEqual(nack.Missing, want) {
		t.Fatalf("nack.Missing = %v, want %v", nack.Missing, want)
	}
	if nack.SSRC != 0x1234_5678 {
		t.Fatalf("nack.SSRC = %#x, want 0x12345678", nack.SSRC)
	}
	// Re-armed on the 5ms cadence.
	if want := (SetTimer{ID: TimerNack, Deadline: 65_000}); outs[len(outs)-1] != want {
		t.Fatalf("rearm = %v, want %v", outs[len(outs)-1], want)
	}
	for e := f.receiver.missingHead; e != nil; e = e.next {
		// next_nack = now + (uint64)(rtt*1.1) = 60000 + 5500 (librist).
		if e.nextNack != 65_500 || e.nackCount != 1 {
			t.Fatalf("entry %d nextNack/count = %d/%d, want 65500/1", e.seq, e.nextNack, e.nackCount)
		}
	}
	if got := f.Stats().NacksSent; got != 3 {
		t.Fatalf("NacksSent = %d, want 3", got)
	}

	// 65000: nothing due (65500 > 65000) -> no feedback, just the re-arm.
	f.HandleTimer(65_000, TimerNack)
	outs = drainOutputs(f)
	if fbs := feedbackOutputs(outs); len(fbs) != 0 {
		t.Fatalf("unexpected feedback at 65000: %v", fbs)
	}
	if want := []Output{SetTimer{ID: TimerNack, Deadline: 70_000}}; !reflect.DeepEqual(outs, want) {
		t.Fatalf("outputs = %v, want %v", outs, want)
	}

	// 70000: due again (65500 <= 70000).
	f.HandleTimer(70_000, TimerNack)
	if fbs := feedbackOutputs(drainOutputs(f)); len(fbs) != 1 {
		t.Fatalf("second retry batch missing")
	}
	if got := f.Stats().NacksSent; got != 6 {
		t.Fatalf("NacksSent = %d, want 6", got)
	}
}

func TestNackAbandonMaxRetries(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRetries = 2
	f := New(RoleReceiver, cfg)
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	f.Feed(24_000, 0, mkPkt(102, 14_000, nil)) // missing 101
	drainOutputs(f)

	// First nack is due at 24000 + reorder_buffer(15000) = 39000.
	f.processNacks(40_000) // nack #1 (due at 39000)
	f.processNacks(50_000) // nack #2 (nextNack was 40000+5500=45500)
	if got := f.Stats().NacksSent; got != 2 {
		t.Fatalf("NacksSent = %d, want 2", got)
	}
	// Third pass: nackCount(2) >= MaxRetries(2) -> abandon
	// (librist).
	f.processNacks(60_000)
	st := f.Stats()
	if st.Abandoned != 1 || st.NacksSent != 2 || f.receiver.missingCount != 0 {
		t.Fatalf("abandoned/nacks/pending = %d/%d/%d, want 1/2/0",
			st.Abandoned, st.NacksSent, f.receiver.missingCount)
	}
}

func TestNackAbandonAgeExact(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRetries = 1 << 30 // never trip the retry limit
	f := New(RoleReceiver, cfg)
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	f.Feed(24_000, 0, mkPkt(102, 14_000, nil)) // missing 101, insertion 14666
	drainOutputs(f)

	e := f.receiver.missingHead
	if e.insertionTime != 14_666 {
		t.Fatalf("insertionTime = %d, want 14666", e.insertionTime)
	}
	// Abandon strictly after insertion + recoveryBuffer*1.1
	// (librist `>` comparison).
	deadline := e.insertionTime.Add(1_100_000)
	f.processNacks(deadline) // age == threshold: NOT abandoned (sends a nack)
	if got := f.Stats().Abandoned; got != 0 {
		t.Fatalf("abandoned at age==threshold, want not")
	}
	f.processNacks(deadline.Add(1)) // age > threshold: abandoned
	st := f.Stats()
	if st.Abandoned != 1 || f.receiver.missingCount != 0 {
		t.Fatalf("abandoned/pending = %d/%d, want 1/0", st.Abandoned, f.receiver.missingCount)
	}
}

func TestNackRecoveredRemoval(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	f.Feed(24_000, 0, mkPkt(102, 14_000, nil)) // missing 101
	drainOutputs(f)

	// Recovered before any NACK went out: removed silently
	// (librist: recovered only counts nack_count>0).
	f.Feed(25_000, 0, mkPkt(101, 7_000, nil))
	f.processNacks(26_000)
	st := f.Stats()
	if f.receiver.missingCount != 0 || st.Recovered != 0 || st.NacksSent != 0 {
		t.Fatalf("pending/recovered/nacks = %d/%d/%d, want 0/0/0",
			f.receiver.missingCount, st.Recovered, st.NacksSent)
	}

	// Now a hole that is NACKed once, then recovered: counts Recovered.
	f.Feed(45_000, 0, mkPkt(104, 35_000, nil)) // missing 103
	f.processNacks(60_000)                     // sends nack #1
	rt := mkPkt(103, 28_000, nil)
	rt.Retransmit = true
	f.Feed(61_000, 0, rt)
	f.processNacks(62_000)
	st = f.Stats()
	if st.Recovered != 1 || f.receiver.missingCount != 0 {
		t.Fatalf("recovered/pending = %d/%d, want 1/0", st.Recovered, f.receiver.missingCount)
	}
}

func TestTooLateDropOnFeed(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	f.Feed(2_010_000, 0, mkPkt(200, 2_000_000, nil))
	drainOutputs(f)
	base := f.Stats()

	// packetTime 510000 < lastPacketTime, seq != successor, and
	// now > packetTime + 1.1*recoveryBuffer (= 1610000) -> shed
	// (librist).
	f.Feed(2_011_000, 0, mkPkt(150, 500_000, nil))
	st := f.Stats()
	if st.TooLate != base.TooLate+1 || st.Received != base.Received {
		t.Fatalf("tooLate/received = %d/%d, want %d/%d",
			st.TooLate, st.Received, base.TooLate+1, base.Received)
	}

	// Same shape but within the window: accepted as a reordered packet.
	f.Feed(2_011_500, 0, mkPkt(151, 1_500_000, nil))
	st = f.Stats()
	if st.Received != base.Received+1 || st.Reordered != base.Reordered+1 {
		t.Fatalf("received/reordered = %d/%d, want %d/%d",
			st.Received, st.Reordered, base.Received+1, base.Reordered+1)
	}
}

func TestDeliveryInOrderTimeDriven(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	for i := uint32(0); i < 3; i++ {
		f.Feed(clock.Timestamp(10_000+7_000*int64(i)), 0, mkPkt(100+i, clock.Microseconds(7_000*int64(i)), []byte{byte(i)}))
	}
	drainOutputs(f)

	// Before the first outputTime nothing may be delivered.
	f.Tick(1_009_999)
	if evs := drainEvents(f); evs != nil {
		t.Fatalf("early delivery: %v", evs)
	}

	// At exactly outputTime (now >= outputTime) the packet is delivered.
	f.HandleTimer(1_010_000, TimerPlayout)
	evs := drainEvents(f)
	if want := []uint32{100}; !reflect.DeepEqual(deliveredSeqs(evs), want) {
		t.Fatalf("delivered = %v, want %v", deliveredSeqs(evs), want)
	}
	d := evs[0].(Deliver)
	if d.Discontinuity || string(d.Payload) != "\x00" {
		t.Fatalf("deliver = %+v, want continuous payload [0]", d)
	}
	// The next deadline is re-armed at packet 101's outputTime.
	outs := drainOutputs(f)
	if want := []Output{SetTimer{ID: TimerPlayout, Deadline: 1_017_000}}; !reflect.DeepEqual(outs, want) {
		t.Fatalf("outputs = %v, want %v", outs, want)
	}

	// A late tick delivers everything due, in order.
	f.Tick(1_030_000)
	if want := []uint32{101, 102}; !reflect.DeepEqual(deliveredSeqs(drainEvents(f)), want) {
		t.Fatalf("delivered remainder mismatch")
	}
	st := f.Stats()
	if st.Delivered != 3 || st.Lost != 0 || st.Discontinuities != 0 {
		t.Fatalf("delivered/lost/disc = %d/%d/%d, want 3/0/0", st.Delivered, st.Lost, st.Discontinuities)
	}
	// Ring drained: the playout timer is released.
	outs = drainOutputs(f)
	if want := Output(ClearTimer{ID: TimerPlayout}); len(outs) == 0 || outs[len(outs)-1] != want {
		t.Fatalf("outputs = %v, want trailing %v", outs, want)
	}
}

func TestDeliverySkipsAbandonedWithDiscontinuity(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, []byte("a")))
	f.Feed(24_000, 0, mkPkt(102, 14_000, []byte("c"))) // 101 never arrives
	drainOutputs(f)

	// 100 due at 1010000; 102 due at 1024000; the hole holds delivery.
	f.HandleTimer(1_010_000, TimerPlayout)
	if want := []uint32{100}; !reflect.DeepEqual(deliveredSeqs(drainEvents(f)), want) {
		t.Fatalf("first delivery mismatch")
	}
	// While 102 is not yet due the hole may still heal: wake at 1024000.
	outs := drainOutputs(f)
	if want := []Output{SetTimer{ID: TimerPlayout, Deadline: 1_024_000}}; !reflect.DeepEqual(outs, want) {
		t.Fatalf("outputs = %v, want %v", outs, want)
	}

	// Once 102 is due, 101 is abandoned and delivery advances.
	f.HandleTimer(1_024_000, TimerPlayout)
	evs := drainEvents(f)
	if want := []uint32{102}; !reflect.DeepEqual(deliveredSeqs(evs), want) {
		t.Fatalf("skip delivery = %v, want %v", deliveredSeqs(evs), want)
	}
	if d := evs[0].(Deliver); !d.Discontinuity {
		t.Fatalf("delivery after skip must flag a discontinuity")
	}
	st := f.Stats()
	if st.Lost != 1 || st.Discontinuities != 1 || st.Delivered != 2 {
		t.Fatalf("lost/disc/delivered = %d/%d/%d, want 1/1/2", st.Lost, st.Discontinuities, st.Delivered)
	}
}

func TestLateRetransmitBehindCursorShed(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, []byte("a")))
	f.Tick(1_010_000)
	if got := f.Stats().Delivered; got != 1 {
		t.Fatalf("Delivered = %d, want 1", got)
	}
	drainEvents(f)
	drainOutputs(f)

	// Any copy behind the playout cursor — retransmit or duplicate — can
	// never be delivered and is shed as too late, not re-buffered.
	rt := mkPkt(100, 0, []byte("a"))
	rt.Retransmit = true
	f.Feed(1_011_000, 0, rt)
	st := f.Stats()
	if st.TooLate != 1 || st.Received != 1 || st.Duplicates != 0 {
		t.Fatalf("tooLate/received/dup = %d/%d/%d, want 1/1/0", st.TooLate, st.Received, st.Duplicates)
	}
}

func TestRttEchoRequestAnsweredAndResponseObserved(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 2, mkPkt(100, 0, nil))
	drainOutputs(f)

	// Inbound request: answered verbatim with zero processing delay on
	// the most recent media path.
	f.FeedFeedback(20_000, wire.RttEchoRequest{Timestamp: 0xDEAD_BEEF})
	outs := drainOutputs(f)
	want := []Output{SendFeedback{Path: 2, FB: wire.RttEchoResponse{Timestamp: 0xDEAD_BEEF, ProcessingDelay: 0}}}
	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("outputs = %v, want %v", outs, want)
	}

	// Inbound response: sample = (now - sent) - processingDelay folded
	// into eight_times_rtt: 40000 - 40000/8 + 8000 = 43000 -> 5375.
	f.FeedFeedback(20_000, wire.RttEchoResponse{
		Timestamp:       uint64(clock.NTPTimeFromTimestamp(10_000)),
		ProcessingDelay: 2_000,
	})
	if got := f.est.Smoothed(); got != 5_375 {
		t.Fatalf("Smoothed = %d, want 5375", got)
	}
}

func TestRttEchoTimerCadence(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 1, mkPkt(100, 0, nil))
	drainOutputs(f)

	// RIST_PING_INTERVAL = 100ms (librist).
	f.HandleTimer(110_000, TimerRttEcho)
	outs := drainOutputs(f)
	want := []Output{
		SendFeedback{Path: 1, FB: wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(110_000))}},
		SetTimer{ID: TimerRttEcho, Deadline: 210_000},
	}
	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("outputs = %v, want %v", outs, want)
	}
}

func TestReceiverIgnoresSenderOnlyEntryPoints(t *testing.T) {
	// PushApp and a NackRequest are sender-half inputs; a receiver-role Flow
	// ignores PushApp entirely and counts the NackRequest as unhandled.
	f := New(RoleReceiver, testConfig())
	f.PushApp(1_000, []byte("payload"))
	if outs := drainOutputs(f); outs != nil {
		t.Fatalf("receiver PushApp emitted %v", outs)
	}
	f.FeedFeedback(3_000, wire.NackRequest{SSRC: 1, Missing: []uint32{1}})
	if outs := drainOutputs(f); outs != nil {
		t.Fatalf("receiver NackRequest emitted %v", outs)
	}
	if got := zeroGauges(f.Stats()); got != (Stats{IgnoredFeedback: 1}) {
		t.Fatalf("stats = %+v, want IgnoredFeedback 1", got)
	}
}

func TestFeedbackWithoutHandlerCounted(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.FeedFeedback(1_000, wire.SenderReport{NTP: 1, RTPTime: 2}) // WP4
	f.FeedFeedback(2_000, wire.Keepalive{})                      // host liveness
	f.FeedFeedback(3_000, wire.NackRequest{SSRC: 1})             // sender-half input
	if got := f.Stats().IgnoredFeedback; got != 3 {
		t.Fatalf("IgnoredFeedback = %d, want 3", got)
	}
	if outs := drainOutputs(f); outs != nil {
		t.Fatalf("unexpected outputs %v", outs)
	}
}

// TestEchoResponseEchoesRequesterSSRC verifies that an inbound RTT echo request
// produces a response carrying the requester's SSRC (not the responder's). A
// libRIST requester drops any echo response whose SSRC differs from its own
// peer_ssrc, so echoing the wrong SSRC silently breaks RTT measurement.
func TestEchoResponseEchoesRequesterSSRC(t *testing.T) {
	for _, role := range []Role{RoleReceiver, RoleSender} {
		f := New(role, testConfig())
		const requesterSSRC = 0xABCD_1234
		f.FeedFeedback(clock.Timestamp(clock.Second), wire.RttEchoRequest{SSRC: requesterSSRC, Timestamp: 0x1111_2222_3333_4444})
		fbs := feedbackOutputs(drainOutputs(f))
		var resp *wire.RttEchoResponse
		for _, fb := range fbs {
			if r, ok := fb.FB.(wire.RttEchoResponse); ok {
				resp = &r
			}
		}
		if resp == nil {
			t.Fatalf("role %v: no RttEchoResponse emitted", role)
		}
		if resp.SSRC != requesterSSRC {
			t.Errorf("role %v: response SSRC = %#x, want requester %#x", role, resp.SSRC, requesterSSRC)
		}
		if resp.Timestamp != 0x1111_2222_3333_4444 {
			t.Errorf("role %v: response did not echo the request timestamp", role)
		}
	}
}

// TestSourceClockNoReanchorOnAnomalousTimestamp verifies the receiver does NOT
// re-anchor on a single anomalous-but-not-wrapped timestamp. libRIST re-anchors
// only on a true backward 32-bit wrap (source time falling by more than half the
// 32-bit space); a modest backward step is ordinary jitter/reordering and must
// never resync the clock — even once the dwell window has elapsed.
func TestSourceClockNoReanchorOnAnomalousTimestamp(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	// Run a steady in-order flow with source advancing in lockstep with now for
	// longer than the dwell window (3*recoveryBuffer = 3s), so the dwell guard
	// alone would not block a re-anchor — only the backward-wrap test does.
	base := clock.Microseconds(10_000_000)
	for i := 0; i < 5; i++ {
		src := base + clock.Microseconds(i)*1_000_000
		f.Feed(clock.Timestamp(src), 0, mkPkt(uint32(100+i), src, []byte{1}))
	}
	drainOutputs(f)
	drainEvents(f)
	before := f.Stats()

	// A successor whose source time steps modestly backward (100 ms below the
	// newest source time of 4 s): a wrong reading, not a wrap. The backward
	// delta is far below the ~6.6h half-span, so no resync. now stays within the
	// recovery window of the mapped time, so the packet is also not shed.
	now := clock.Timestamp(int64(base) + 4_100_000)
	f.Feed(now, 0, mkPkt(105, base+3_900_000, []byte{2}))
	if got := f.Stats().ClockResync; got != before.ClockResync {
		t.Fatalf("ClockResync = %d, want %d (anomalous timestamp must not resync)", got, before.ClockResync)
	}
}

// TestSourceClockWrapReanchor verifies the receiver re-anchors its clock offset
// on a GENUINE backward 32-bit wrap of the source counter, bumping the offset by
// one wrap period so playout continues, instead of shedding every subsequent
// packet as too-late and stalling the stream permanently.
func TestSourceClockWrapReanchor(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	// One full 32-bit RTP-counter wrap spans srcWrapPeriodMicros of media time.
	// Run the flow up to the wrap boundary with source == now (so the offset is
	// ~0), advancing past the 3s dwell window, then feed the first post-wrap
	// packet whose source time has dropped by one wrap period.
	wrap := srcWrapPeriodMicros
	step := clock.Microseconds(1_000_000)
	startSrc := wrap - 4*step // start 4 s of media before the wrap boundary
	f.Feed(clock.Timestamp(startSrc), 0, mkPkt(100, startSrc, []byte{0}))
	for i := 1; i <= 4; i++ {
		src := startSrc + clock.Microseconds(i)*step
		f.Feed(clock.Timestamp(src), 0, mkPkt(uint32(100+i), src, []byte{byte(i)}))
	}
	drainOutputs(f)
	drainEvents(f)
	before := f.Stats()

	// seq 105: now advances one step; the source counter wraps, so its source
	// time is (previous source + step) - wrap, a small positive value. The
	// offset bump of one wrap period maps it back onto ~now.
	now := clock.Timestamp(startSrc + 5*step)
	wrappedSrc := startSrc + 5*step - wrap
	f.Feed(now, 0, mkPkt(105, wrappedSrc, []byte{5}))
	after := f.Stats()
	if after.ClockResync != before.ClockResync+1 {
		t.Fatalf("ClockResync = %d, want %d (genuine wrap must re-anchor)", after.ClockResync, before.ClockResync+1)
	}
	if after.TooLate != before.TooLate {
		t.Fatalf("wrapped packet shed as too-late (%d) instead of re-anchoring", after.TooLate)
	}
	if after.Received != before.Received+1 {
		t.Fatalf("wrapped packet not accepted (Received %d -> %d)", before.Received, after.Received)
	}

	// The stream keeps flowing after the wrap (no permanent stall).
	now = clock.Timestamp(startSrc + 6*step)
	f.Feed(now, 0, mkPkt(106, wrappedSrc+step, []byte{6}))
	if f.Stats().Received != after.Received+1 {
		t.Fatalf("post-wrap packet not accepted; stream stalled")
	}
}

// TestMissingCounterMaxCaps verifies the receiver stops queuing new missing
// entries once the missing queue exceeds missing_counter_max (libRIST's
// buffer-bloat / overflow guard), so a large gap cannot fill the ring.
func TestMissingCounterMaxCaps(t *testing.T) {
	cfg := testConfig() // default 100 Mbps / 1000 ms -> missing_counter_max = 3571
	f := New(RoleReceiver, cfg)
	f.Feed(10_000, 0, mkPkt(100, 0, nil))
	// A gap of 20000 (< MaxGap16) would mark ~20000 entries without the cap.
	f.Feed(17_000, 0, mkPkt(100+20000, 7_000, nil))
	if got := f.Stats().Missing; got > uint64(deriveMissingCounterMax(cfg))+1 {
		t.Fatalf("Stats.Missing = %d, want <= missing_counter_max+1 (%d)", got, deriveMissingCounterMax(cfg)+1)
	}
	if f.Stats().Missing < 1000 {
		t.Fatalf("Stats.Missing = %d, want a substantial (capped) count", f.Stats().Missing)
	}
}

// TestDerivedCongestionConstants checks the libRIST-matching defaults.
func TestDerivedCongestionConstants(t *testing.T) {
	cfg := DefaultConfig()
	// missing_counter_max = recovery_buffer_ms * max(1, maxbitrate/1000) / 28
	//                     = 1000 * 100 / 28 = 3571 (librist init_peer_settings,
	//                     struct rist_gre_seq is 12 bytes -> divisor 28).
	if got := deriveMissingCounterMax(cfg); got != 3571 {
		t.Errorf("missing_counter_max = %d, want 3571", got)
	}
	if got := deriveMaxNacksPerLoop(cfg); got != 88 {
		t.Errorf("max_nacksperloop = %d, want 88", got)
	}
}
