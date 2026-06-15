package fec

import "github.com/zsiec/ristgo/internal/seq"

// Config sizes the FEC matrix: Cols (L) columns by Rows (D) rows. ColumnOnly
// suppresses the row (horizontal) FEC, keeping only column (vertical) FEC.
type Config struct {
	Cols       int // L: number of columns (>= 1)
	Rows       int // D: number of rows (>= 1)
	ColumnOnly bool
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

// emit builds a FEC packet (header + XOR payload) from a completed group.
func (e *Encoder) emit(g *fecGroup, dir Direction) Packet {
	h := Header{
		LengthRecovery: g.lengthClip,
		PTRecovery:     g.ptClip,
		TSRecovery:     g.tsClip,
		Direction:      dir,
	}
	h.setBase24(g.base)
	if dir == Column {
		h.Offset, h.NA = uint8(e.cfg.Cols), uint8(e.cfg.Rows)
	} else {
		h.Offset, h.NA = 1, uint8(e.cfg.Cols)
	}
	data := h.AppendTo(make([]byte, 0, HeaderSize+e.payloadSize))
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
		media:       make(map[uint32]storedMedia, cfg.matrixSize()*2),
		lastSeq:     isn,
	}
}

// PushMedia stores one received media packet and returns any packets its arrival
// allowed FEC to recover.
func (d *Decoder) PushMedia(s, ts uint32, pt uint8, payload []byte) []Recovered {
	d.out = d.out[:0]
	d.advance(s)
	if _, ok := d.media[s]; ok {
		return nil // duplicate (ARQ/2022-7 already delivered it)
	}
	d.store(s, ts, pt, payload)
	d.recoverAll()
	d.evict()
	return d.out
}

// PushFEC parses a FEC packet (already stripped of its carriage framing) and
// returns any packets it allowed FEC to recover.
func (d *Decoder) PushFEC(fec []byte) []Recovered {
	d.out = d.out[:0]
	h, off, err := ParseHeader(fec)
	if err != nil {
		return nil
	}
	stride, count := int(h.Offset), int(h.NA)
	if stride <= 0 || count <= 1 || count > 256 {
		return nil // malformed geometry; ignore
	}
	d.fecs = append(d.fecs, storedFEC{
		base:      d.widen(h.base24()),
		stride:    stride,
		count:     count,
		lengthRec: h.LengthRecovery,
		ptRec:     h.PTRecovery & 0x7f,
		tsRec:     h.TSRecovery,
		payload:   append([]byte(nil), fec[off:]...),
	})
	d.recoverAll()
	d.evict()
	return d.out
}

func (d *Decoder) store(s, ts uint32, pt uint8, payload []byte) {
	d.media[s] = storedMedia{ts: ts, pt: pt, payload: append([]byte(nil), payload...)}
}

func (d *Decoder) advance(s uint32) {
	if !d.haveSeq || seqDiff(d.lastSeq, s) > 0 {
		d.lastSeq = s
		d.haveSeq = true
	}
}

// widen maps a 24-bit FEC base sequence to the full 32-bit space using the latest
// media sequence as context (a FEC packet always protects sequences near the
// current window).
func (d *Decoder) widen(base24 uint32) uint32 {
	cand := (d.lastSeq &^ 0xFFFFFF) | (base24 & 0xFFFFFF)
	best := cand
	for _, c := range [2]uint32{cand + (1 << 24), cand - (1 << 24)} {
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
	payload := make([]byte, d.payloadSize)
	copy(payload, sf.payload)
	for i := 0; i < sf.count; i++ {
		m, ok := d.media[seqAdd(sf.base, i*sf.stride)]
		if !ok {
			continue
		}
		length ^= uint16(len(m.payload))
		pt ^= m.pt & 0x7f
		ts ^= m.ts
		for j := 0; j < len(m.payload) && j < len(payload); j++ {
			payload[j] ^= m.payload[j]
		}
	}
	if int(length) > d.payloadSize {
		return false // implausible recovered length: leave the loss to ARQ
	}
	rp := Recovered{Seq: missing, Timestamp: ts, PayloadType: pt, Payload: append([]byte(nil), payload[:length]...)}
	d.out = append(d.out, rp)
	d.media[missing] = storedMedia{ts: ts, pt: pt, payload: rp.Payload}
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
