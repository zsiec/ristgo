package fec

import "github.com/zsiec/ristgo/internal/seq"

// Variant selects the FEC wire format: SMPTE ST 2022-1 (the default) or the high
// bit rate ST 2022-5. The XOR matrix is identical; only the FEC header layout and
// the base-sequence width differ (see [Header] and [Header5]).
type Variant uint8

const (
	// Variant20221 is SMPTE ST 2022-1 (24-bit base, 8-bit Offset/NA).
	Variant20221 Variant = iota
	// Variant20225 is SMPTE ST 2022-5 (16-bit base, 10-bit Offset/NA).
	Variant20225
)

// Config sizes the FEC matrix: Cols (L) columns by Rows (D) rows. ColumnOnly
// suppresses the row (horizontal) FEC, keeping only column (vertical) FEC. Variant
// selects the ST 2022-1 or ST 2022-5 wire format.
type Config struct {
	Cols       int // L: number of columns (>= 1)
	Rows       int // D: number of rows (>= 1)
	ColumnOnly bool
	Variant    Variant
}

func (c Config) matrixSize() int { return c.Cols * c.Rows }

// Packet is one FEC packet ready for transmission: a SMPTE ST 2022-1 header
// followed by the XOR of the group's payloads, tagged with its dimension.
type Packet struct {
	Direction Direction
	Data      []byte
}

// Recovered is a media packet reconstructed by FEC, ready to feed into the flow
// like an ARQ retransmit.
type Recovered struct {
	Seq         uint32
	Timestamp   uint32
	PayloadType uint8
	SSRC        uint32 // SSRC of the group the loss belonged to (its members all share it)
	Payload     []byte
}

func seqAdd(base uint32, off int) uint32 { return seq.Num32(base).Add(int64(off)).Value() }
func seqDiff(base, s uint32) int         { return int(seq.Num32(base).Distance(seq.Num32(s))) }

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// fecGroup accumulates the XOR of one row or column's packets. lengthClip,
// ptClip, and tsClip recover the missing packet's payload length, RTP payload
// type, and timestamp; payloadClip recovers its payload.
type fecGroup struct {
	base        uint32
	collected   int
	lengthClip  uint16
	ptClip      uint8
	tsClip      uint32
	payloadClip []byte
}

func newGroup(base uint32, payloadSize int) fecGroup {
	return fecGroup{base: base, payloadClip: make([]byte, payloadSize)}
}

func (g *fecGroup) reset(base uint32) {
	g.base = base
	g.collected = 0
	g.lengthClip = 0
	g.ptClip = 0
	g.tsClip = 0
	clear(g.payloadClip)
}

// clip XORs one packet's recoverable fields into the accumulator. A short
// payload is implicitly zero-padded to the matrix payload size.
func (g *fecGroup) clip(length uint16, pt uint8, ts uint32, payload []byte) {
	g.lengthClip ^= length
	g.ptClip ^= pt & 0x7f
	g.tsClip ^= ts
	for i := 0; i < len(payload) && i < len(g.payloadClip); i++ {
		g.payloadClip[i] ^= payload[i]
	}
}

// ---------------- Encoder (sender) ----------------

// Encoder clips each media packet into its row and column groups and emits a FEC
// packet whenever a group fills. It is deterministic and allocation-light: it
// reuses its group buffers across matrices.
type Encoder struct {
	cfg         Config
	payloadSize int

	row     fecGroup
	cols    []fecGroup
	rowBase uint32 // base sequence of the current row group
}

// NewEncoder builds an Encoder for the matrix in cfg. payloadSize is the largest
// protected payload (FEC payloads are this size); isn is the first sequence
// number, which must be the seq of the first media packet pushed.
func NewEncoder(cfg Config, payloadSize int, isn uint32) *Encoder {
	e := &Encoder{cfg: cfg, payloadSize: payloadSize, rowBase: isn}
	e.row = newGroup(isn, payloadSize)
	if cfg.Rows > 1 {
		e.cols = make([]fecGroup, cfg.Cols)
		for i := range e.cols {
			e.cols[i] = newGroup(seqAdd(isn, i), payloadSize)
		}
	}
	return e
}

// Push clips one media packet (in sequence order) and returns any FEC packets the
// completed groups produced (zero, one, or both a column and a row packet).
func (e *Encoder) Push(s, ts uint32, pt uint8, payload []byte) []Packet {
	var out []Packet
	L := e.cfg.Cols

	// Advance the row group if this packet starts a new row.
	if seqDiff(e.rowBase, s) >= L {
		e.rowBase = seqAdd(e.rowBase, L)
		e.row.reset(e.rowBase)
	}
	pos := seqDiff(e.rowBase, s) // column index within the current row

	e.row.clip(uint16(len(payload)), pt, ts, payload)
	e.row.collected++

	if e.cfg.Rows > 1 && pos >= 0 && pos < len(e.cols) {
		col := &e.cols[pos]
		if seqDiff(col.base, s) >= e.cfg.matrixSize() {
			col.reset(seqAdd(col.base, e.cfg.matrixSize()))
		}
		col.clip(uint16(len(payload)), pt, ts, payload)
		col.collected++
		if col.collected >= e.cfg.Rows {
			out = append(out, e.emit(col, Column))
			col.reset(seqAdd(col.base, e.cfg.matrixSize()))
		}
	}

	if e.row.collected >= L {
		if !e.cfg.ColumnOnly {
			out = append(out, e.emit(&e.row, Row))
		}
		e.rowBase = seqAdd(e.rowBase, L)
		e.row.reset(e.rowBase)
	}
	return out
}

// emit builds a FEC packet (header + XOR payload) from a completed group, encoding
// the ST 2022-1 or ST 2022-5 header per the configured variant.
func (e *Encoder) emit(g *fecGroup, dir Direction) Packet {
	offset, na := e.cfg.Cols, e.cfg.Rows // column: stride L over D members
	if dir == Row {
		offset, na = 1, e.cfg.Cols // row: stride 1 over L members
	}
	data := make([]byte, 0, HeaderSize+e.payloadSize)
	if e.cfg.Variant == Variant20225 {
		h := Header5{
			LengthRecovery: g.lengthClip,
			PTRecovery:     g.ptClip,
			TSRecovery:     g.tsClip,
			SNBase:         uint16(g.base),
			Offset:         uint16(offset),
			NA:             uint16(na),
		}
		data = h.AppendTo(data)
	} else {
		h := Header{
			LengthRecovery: g.lengthClip,
			PTRecovery:     g.ptClip,
			TSRecovery:     g.tsClip,
			Direction:      dir,
			Offset:         uint8(offset),
			NA:             uint8(na),
		}
		h.setBase24(g.base)
		data = h.AppendTo(data)
	}
	data = append(data, g.payloadClip...)
	return Packet{Direction: dir, Data: data}
}

// ---------------- Decoder (receiver) ----------------

// Decoder reconstructs lost media from FEC packets. It is driven entirely by the
// FEC packets' own SNBase and geometry (Offset/NA) rather than any assumed matrix
// alignment, so it recovers correctly even when the first media packet of a stream
// is lost: a FEC packet defines its group's exact sequence numbers, the decoder
// checks them against the media it has stored in a sliding window, and rebuilds
// the single missing member by XOR. Recovered packets re-enter the window, so a
// 2-D loss recovered along one dimension cascades into the other.
type Decoder struct {
	cfg         Config
	payloadSize int
	window      int
	maxFECs     int // cap on stored FEC packets (FEC-flood DoS guard)

	media   map[uint32]storedMedia // received and recovered media in the window
	fecs    []storedFEC            // FEC packets in the window not yet fully resolved
	lastSeq uint32                 // highest media sequence seen (window anchor)
	haveSeq bool

	out []Recovered
}

// storedMedia holds the recoverable fields of one media packet in the window.
type storedMedia struct {
	ts      uint32
	pt      uint8
	ssrc    uint32
	payload []byte
}

// storedFEC holds one received FEC packet: the group it protects (base, stride,
// count) and the recovery fields/payload to XOR.
type storedFEC struct {
	base          uint32
	stride, count int
	lengthRec     uint16
	ptRec         uint8
	tsRec         uint32
	payload       []byte
	done          bool // group fully resolved (recovered or complete)
}

// NewDecoder builds a Decoder for the matrix in cfg. isn seeds the window anchor;
// it need not be exact (the window self-corrects from the first media packet).
func NewDecoder(cfg Config, payloadSize int, isn uint32) *Decoder {
	return &Decoder{
		cfg:         cfg,
		payloadSize: payloadSize,
		window:      cfg.matrixSize()*3 + cfg.Cols + 8, // a few matrices, enough for column FEC
		// Bound the stored FEC set to a few matrices' worth of column + row packets, so
		// a flood of forged/duplicate FEC packets whose bases hug the window front (and
		// so never age out via evict) cannot grow memory/CPU without limit.
		maxFECs: (cfg.Cols+cfg.Rows)*4 + 16,
		media:   make(map[uint32]storedMedia, cfg.matrixSize()*2),
		lastSeq: isn,
	}
}

// PushMedia stores one received media packet and returns any packets its arrival
// allowed FEC to recover. ssrc is stamped onto any recovery from a group this packet
// belongs to (a FEC matrix is per-source, so its members share one SSRC).
func (d *Decoder) PushMedia(s, ts uint32, pt uint8, ssrc uint32, payload []byte) []Recovered {
	d.out = d.out[:0]
	d.advance(s)
	if _, ok := d.media[s]; ok {
		return nil // duplicate (ARQ/2022-7 already delivered it)
	}
	d.store(s, ts, pt, ssrc, payload)
	d.recoverAll()
	d.evict()
	return d.out
}

// PushFEC parses a FEC packet (already stripped of its carriage framing) in the
// configured variant and returns any packets it allowed FEC to recover.
func (d *Decoder) PushFEC(fec []byte) []Recovered {
	d.out = d.out[:0]
	var (
		base               uint32
		stride, count, off int
		lengthRec          uint16
		ptRec              uint8
		tsRec              uint32
	)
	if d.cfg.Variant == Variant20225 {
		h, o, err := ParseHeader5(fec)
		if err != nil {
			return nil
		}
		base, stride, count, off = d.widen(uint32(h.SNBase)), int(h.Offset), int(h.NA), o
		lengthRec, ptRec, tsRec = h.LengthRecovery, h.PTRecovery&0x7f, h.TSRecovery
	} else {
		h, o, err := ParseHeader(fec)
		if err != nil {
			return nil
		}
		base, stride, count, off = d.widen(h.base24()), int(h.Offset), int(h.NA), o
		lengthRec, ptRec, tsRec = h.LengthRecovery, h.PTRecovery&0x7f, h.TSRecovery
	}
	if stride <= 0 || count <= 1 || count > na10Max {
		return nil // malformed geometry; ignore
	}
	// Constrain the recovery group to the configured matrix: a legitimate ST 2022-x FEC
	// packet is a column (Offset=L, NA=D) or a 2-D row (Offset=1, NA=L). Trusting the
	// packet's own stride/count would let a forged or corrupt header define an arbitrary
	// group spanning sequences the sender has not transmitted, fabricating a media packet
	// out of attacker/corruption-controlled bytes (the bases may still stagger within the
	// matrix, which the staggered-column interop relies on — only stride and count are
	// fixed by L and D).
	if !d.geometryOK(stride, count) {
		return nil
	}
	// Dedup by (base, stride, count): a bonded sender duplicates every FEC packet to each
	// path and a flood/forgery repeats it; an identical group carries an identical XOR
	// payload, so one copy suffices and the rest would only cost memory and rescans.
	for i := range d.fecs {
		if d.fecs[i].base == base && d.fecs[i].stride == stride && d.fecs[i].count == count {
			return nil
		}
	}
	// Cap the stored FEC set (FEC-flood DoS guard): evict aged groups first, then drop the
	// oldest stored group if still over the bound (it is closest to the eviction floor).
	if len(d.fecs) >= d.maxFECs {
		d.evict()
		if len(d.fecs) >= d.maxFECs {
			copy(d.fecs, d.fecs[1:])
			d.fecs = d.fecs[:len(d.fecs)-1]
		}
	}
	d.fecs = append(d.fecs, storedFEC{
		base:      base,
		stride:    stride,
		count:     count,
		lengthRec: lengthRec,
		ptRec:     ptRec,
		tsRec:     tsRec,
		payload:   append([]byte(nil), fec[off:]...),
	})
	d.recoverAll()
	d.evict()
	return d.out
}

// geometryOK reports whether a FEC packet's (stride, count) matches the configured
// matrix: a column is (Offset=Cols, NA=Rows); a 2-D row is (Offset=1, NA=Cols). The
// bases may stagger (non-block-aligned), but stride and count are fixed by L and D.
func (d *Decoder) geometryOK(stride, count int) bool {
	if stride == d.cfg.Cols && count == d.cfg.Rows {
		return true // column FEC
	}
	if !d.cfg.ColumnOnly && stride == 1 && count == d.cfg.Cols {
		return true // 2-D row FEC
	}
	return false
}

func (d *Decoder) store(s, ts uint32, pt uint8, ssrc uint32, payload []byte) {
	d.media[s] = storedMedia{ts: ts, pt: pt, ssrc: ssrc, payload: append([]byte(nil), payload...)}
}

func (d *Decoder) advance(s uint32) {
	if !d.haveSeq || seqDiff(d.lastSeq, s) > 0 {
		d.lastSeq = s
		d.haveSeq = true
	}
}

// widen maps a truncated FEC base sequence to the full 32-bit space using the latest
// media sequence as context (a FEC packet always protects sequences near the current
// window). ST 2022-1 truncates to 24 bits, ST 2022-5 to 16; the window is always far
// smaller than either span, so the nearest candidate is unambiguous.
func (d *Decoder) widen(base uint32) uint32 {
	mask, span := uint32(0xFFFFFF), uint32(1<<24)
	if d.cfg.Variant == Variant20225 {
		mask, span = 0xFFFF, 1<<16
	}
	cand := (d.lastSeq &^ mask) | (base & mask)
	best := cand
	for _, c := range [2]uint32{cand + span, cand - span} {
		if abs(seqDiff(d.lastSeq, c)) < abs(seqDiff(d.lastSeq, best)) {
			best = c
		}
	}
	return best
}

// recoverAll repeatedly scans the stored FEC packets, recovering every group that
// has exactly one missing member, until a full pass recovers nothing — so a packet
// recovered in one dimension cascades into the FEC of the other.
func (d *Decoder) recoverAll() {
	for {
		recovered := false
		for i := range d.fecs {
			if d.tryRecover(&d.fecs[i]) {
				recovered = true
			}
		}
		if !recovered {
			return
		}
	}
}

// tryRecover rebuilds the single missing member of sf's group, if exactly one is
// missing, and stores it back into the window (so the opposite dimension can use
// it). It returns true only when it recovers a packet.
func (d *Decoder) tryRecover(sf *storedFEC) bool {
	if sf.done {
		return false
	}
	// Only recover while the whole group is inside the window. sf.base is the oldest
	// member (stride > 0), so once it ages below the floor a member may have been
	// evicted, and treating an evicted (but received) member as missing would
	// "recover" a packet that was never lost. Give the group to ARQ instead.
	if seqDiff(seqAdd(d.lastSeq, -d.window), sf.base) < 0 {
		sf.done = true
		return false
	}
	// Refuse to recover a member the sender cannot yet have transmitted. A legitimate FEC
	// group is emitted only after all its members were sent, so every real member is
	// <= lastSeq (the highest sequence seen). If the newest member is still ahead of the
	// window front, the "missing" member is a not-yet-sent (future) sequence, not a loss,
	// and fabricating it would preempt the real packet when it arrives. Leave the group
	// active (no done) so it can recover once a later media packet advances lastSeq past it.
	if newest := seqAdd(sf.base, (sf.count-1)*sf.stride); seqDiff(d.lastSeq, newest) > 0 {
		return false
	}
	var missing uint32
	missingCount := 0
	for i := 0; i < sf.count; i++ {
		s := seqAdd(sf.base, i*sf.stride)
		if _, ok := d.media[s]; !ok {
			missingCount++
			if missingCount > 1 {
				return false // more than one missing: not recoverable yet
			}
			missing = s
		}
	}
	if missingCount == 0 {
		sf.done = true
		return false
	}
	length := sf.lengthRec
	pt := sf.ptRec
	ts := sf.tsRec
	var ssrc uint32 // the group's SSRC, taken from any present member (all members share it)
	payload := make([]byte, d.payloadSize)
	copy(payload, sf.payload)
	for i := 0; i < sf.count; i++ {
		m, ok := d.media[seqAdd(sf.base, i*sf.stride)]
		if !ok {
			continue
		}
		ssrc = m.ssrc
		length ^= uint16(len(m.payload))
		pt ^= m.pt & 0x7f
		ts ^= m.ts
		for j := 0; j < len(m.payload) && j < len(payload); j++ {
			payload[j] ^= m.payload[j]
		}
	}
	if int(length) > d.payloadSize {
		sf.done = true // implausible recovered length: this group can never recover, stop rescanning it
		return false
	}
	rp := Recovered{Seq: missing, Timestamp: ts, PayloadType: pt, SSRC: ssrc, Payload: append([]byte(nil), payload[:length]...)}
	d.out = append(d.out, rp)
	d.media[missing] = storedMedia{ts: ts, pt: pt, ssrc: ssrc, payload: rp.Payload}
	sf.done = true
	return true
}

// evict drops media and FEC packets older than the window, bounding memory.
func (d *Decoder) evict() {
	lo := seqAdd(d.lastSeq, -d.window)
	for s := range d.media {
		if seqDiff(lo, s) < 0 {
			delete(d.media, s)
		}
	}
	keep := d.fecs[:0]
	for _, f := range d.fecs {
		if seqDiff(lo, f.base) >= 0 {
			keep = append(keep, f)
		}
	}
	d.fecs = keep
}
