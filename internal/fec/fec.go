package fec

import "github.com/zsiec/ristgo/internal/seq"

// maxRcvHistory bounds how many matrix series the decoder tracks before dropping
// the oldest, so a long run or a large sequence jump cannot grow state without
// bound.
const maxRcvHistory = 10

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

// fecGroup accumulates the XOR of one row or column's packets. lengthClip,
// ptClip, and tsClip recover the missing packet's payload length, RTP payload
// type, and timestamp; payloadClip recovers its payload.
type fecGroup struct {
	base        uint32
	collected   int
	hasFEC      bool
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
	g.hasFEC = false
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

// clipFEC XORs a received FEC packet's recovery fields into the accumulator, so
// the group holds the XOR of (FEC packet) ^ (all received members) — which is the
// single missing member.
func (g *fecGroup) clipFEC(h Header, fecPayload []byte) {
	g.lengthClip ^= h.LengthRecovery
	g.ptClip ^= h.PTRecovery & 0x7f
	g.tsClip ^= h.TSRecovery
	for i := 0; i < len(fecPayload) && i < len(g.payloadClip); i++ {
		g.payloadClip[i] ^= fecPayload[i]
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

// Decoder collects media and FEC packets and rebuilds any single packet missing
// from a row or column, recursively recovering across dimensions. Recovered
// packets are returned for the host to feed into the flow.
type Decoder struct {
	cfg         Config
	payloadSize int

	rows       []fecGroup // sliding window of row groups
	cols       []fecGroup // column groups across the tracked matrix series
	colSeries  int
	colBaseISN uint32

	cells map[uint32]bool // seqs known received (media or recovered)

	out []Recovered
}

// NewDecoder builds a Decoder for the matrix in cfg. isn is the first expected
// media sequence number.
func NewDecoder(cfg Config, payloadSize int, isn uint32) *Decoder {
	d := &Decoder{
		cfg:         cfg,
		payloadSize: payloadSize,
		colBaseISN:  isn,
		cells:       make(map[uint32]bool, cfg.matrixSize()),
	}
	initRows := 2
	if cfg.Rows > 1 {
		initRows = cfg.Rows + 1
	}
	for i := 0; i < initRows; i++ {
		d.rows = append(d.rows, newGroup(seqAdd(isn, i*cfg.Cols), payloadSize))
	}
	if cfg.Rows > 1 {
		d.extendColumns(isn)
	}
	return d
}

func (d *Decoder) extendColumns(base uint32) {
	for i := 0; i < d.cfg.Cols; i++ {
		d.cols = append(d.cols, newGroup(seqAdd(base, i), d.payloadSize))
	}
	d.colSeries++
}

// PushMedia clips one received media packet and returns any packets its arrival
// allowed FEC to recover.
func (d *Decoder) PushMedia(s, ts uint32, pt uint8, payload []byte) []Recovered {
	d.out = d.out[:0]
	d.trim(s)
	if d.cells[s] {
		return nil // duplicate (ARQ/2022-7 already delivered it)
	}
	d.cells[s] = true
	d.hangRowData(s, ts, pt, payload)
	if d.cfg.Rows > 1 {
		d.hangColData(s, ts, pt, payload)
	}
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
	payload := fec[off:]
	if h.Direction == Row {
		d.hangRowFEC(h, payload)
	} else if d.cfg.Rows > 1 {
		d.hangColFEC(h, payload)
	}
	return d.out
}

// rowIndex returns the row-group slot for seq, growing the window as needed, or
// -1 if seq is behind the window or too far ahead.
func (d *Decoder) rowIndex(s uint32) int {
	if len(d.rows) == 0 {
		return -1
	}
	off := seqDiff(d.rows[0].base, s)
	if off < 0 {
		return -1
	}
	idx := off / d.cfg.Cols
	if idx >= maxRcvHistory*max(d.cfg.Rows, 1) {
		return -1
	}
	for idx >= len(d.rows) {
		d.rows = append(d.rows, newGroup(seqAdd(d.rows[len(d.rows)-1].base, d.cfg.Cols), d.payloadSize))
	}
	return idx
}

// colIndex returns the column-group slot for seq, extending the series deque as
// needed, or -1.
func (d *Decoder) colIndex(s uint32) int {
	if len(d.cols) == 0 {
		return -1
	}
	off := seqDiff(d.colBaseISN, s)
	if off < 0 {
		return -1
	}
	colx := off % d.cfg.Cols
	series := off / d.cfg.matrixSize()
	maxSeries := d.colSeries - 1
	if series > maxSeries {
		need := series - maxSeries
		if d.colSeries+need > maxRcvHistory {
			return -1
		}
		for i := 0; i < need; i++ {
			d.extendColumns(seqAdd(d.colBaseISN, d.colSeries*d.cfg.matrixSize()))
		}
	}
	firstSeries := seqDiff(d.colBaseISN, d.cols[0].base) / d.cfg.matrixSize()
	local := series - firstSeries
	if local < 0 {
		return -1
	}
	idx := local*d.cfg.Cols + colx
	if idx < 0 || idx >= len(d.cols) {
		return -1
	}
	return idx
}

func (d *Decoder) hangRowData(s, ts uint32, pt uint8, payload []byte) {
	i := d.rowIndex(s)
	if i < 0 {
		return
	}
	g := &d.rows[i]
	g.clip(uint16(len(payload)), pt, ts, payload)
	g.collected++
	if g.hasFEC && g.collected == d.cfg.Cols-1 {
		d.recoverRow(g)
	}
}

func (d *Decoder) hangRowFEC(h Header, payload []byte) {
	i := d.rowIndexForBase(h.base24())
	if i < 0 {
		return
	}
	g := &d.rows[i]
	if g.hasFEC {
		return
	}
	g.hasFEC = true
	g.clipFEC(h, payload)
	if g.collected == d.cfg.Cols-1 {
		d.recoverRow(g)
	}
}

// rowIndexForBase maps a FEC header's base seq (which may carry only 24 bits) to
// a row slot by widening it against the current window.
func (d *Decoder) rowIndexForBase(base24 uint32) int {
	if len(d.rows) == 0 {
		return -1
	}
	return d.rowIndex(d.widen(base24))
}

func (d *Decoder) hangColData(s, ts uint32, pt uint8, payload []byte) {
	i := d.colIndex(s)
	if i < 0 {
		return
	}
	g := &d.cols[i]
	g.clip(uint16(len(payload)), pt, ts, payload)
	g.collected++
	if g.hasFEC && g.collected == d.cfg.Rows-1 {
		d.recoverCol(g)
	}
}

func (d *Decoder) hangColFEC(h Header, payload []byte) {
	i := d.colIndex(d.widen(h.base24()))
	if i < 0 {
		return
	}
	g := &d.cols[i]
	if g.hasFEC {
		return
	}
	g.hasFEC = true
	g.clipFEC(h, payload)
	if g.collected == d.cfg.Rows-1 {
		d.recoverCol(g)
	}
}

// widen maps a 24-bit FEC base sequence to the full 32-bit space using the most
// recent row base as context (the base is always within the active window).
func (d *Decoder) widen(base24 uint32) uint32 {
	if len(d.rows) == 0 {
		return base24
	}
	ref := d.rows[0].base
	hi := ref &^ 0xFFFFFF
	cand := hi | (base24 & 0xFFFFFF)
	// Resolve the 24-bit wrap by picking the candidate closest to ref.
	for _, c := range [3]uint32{cand, cand + (1 << 24), cand - (1 << 24)} {
		if abs(seqDiff(ref, c)) <= abs(seqDiff(ref, cand)) {
			cand = c
		}
	}
	return cand
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (d *Decoder) recoverRow(g *fecGroup) {
	lost := d.findLost(g.base, 1, d.cfg.Cols)
	if lost < 0 {
		return
	}
	d.rebuild(g, uint32(lost), Row)
}

func (d *Decoder) recoverCol(g *fecGroup) {
	lost := d.findLost(g.base, d.cfg.Cols, d.cfg.Rows)
	if lost < 0 {
		return
	}
	d.rebuild(g, uint32(lost), Column)
}

// findLost returns the single missing sequence in a group (base, stride, count),
// or -1 if zero or more than one are missing.
func (d *Decoder) findLost(base uint32, stride, count int) int {
	lost := -1
	for i := 0; i < count; i++ {
		s := seqAdd(base, i*stride)
		if !d.cells[s] {
			if lost >= 0 {
				return -1 // more than one missing: unrecoverable in this dimension
			}
			lost = int(s)
		}
	}
	return lost
}

// rebuild reconstructs the lost packet from the group accumulator and, for a 2-D
// matrix, feeds it into the opposite dimension to cascade further recovery.
func (d *Decoder) rebuild(g *fecGroup, s uint32, dir Direction) {
	length := int(g.lengthClip)
	if length > d.payloadSize || length < 0 {
		return
	}
	rp := Recovered{
		Seq:         s,
		Timestamp:   g.tsClip,
		PayloadType: g.ptClip,
		Payload:     append([]byte(nil), g.payloadClip[:length]...),
	}
	d.out = append(d.out, rp)
	d.cells[s] = true

	if d.cfg.Rows <= 1 {
		return
	}
	if dir == Row {
		d.crossCol(rp)
	} else {
		d.crossRow(rp)
	}
}

func (d *Decoder) crossRow(rp Recovered) {
	i := d.rowIndex(rp.Seq)
	if i < 0 {
		return
	}
	g := &d.rows[i]
	g.clip(uint16(len(rp.Payload)), rp.PayloadType, rp.Timestamp, rp.Payload)
	g.collected++
	if g.hasFEC && g.collected == d.cfg.Cols-1 {
		d.recoverRow(g)
	}
}

func (d *Decoder) crossCol(rp Recovered) {
	i := d.colIndex(rp.Seq)
	if i < 0 {
		return
	}
	g := &d.cols[i]
	g.clip(uint16(len(rp.Payload)), rp.PayloadType, rp.Timestamp, rp.Payload)
	g.collected++
	if g.hasFEC && g.collected == d.cfg.Rows-1 {
		d.recoverCol(g)
	}
}

// trim drops groups and cells the sliding window has passed, bounding memory.
func (d *Decoder) trim(s uint32) {
	if len(d.rows) == 0 {
		return
	}
	off := seqDiff(d.rows[0].base, s)
	matSz := d.cfg.matrixSize()
	if matSz > 0 && off/matSz >= maxRcvHistory {
		d.fullReset(s)
		return
	}
	threshold := matSz * 2
	if d.cfg.Rows <= 1 {
		threshold = d.cfg.Cols * 2
	}
	for off >= threshold && len(d.rows) > 1 {
		d.rows = d.rows[1:]
		off = seqDiff(d.rows[0].base, s)
		d.cleanCells()
	}
	if d.cfg.Rows > 1 {
		for d.colSeries > 2 && len(d.cols) > d.cfg.Cols {
			d.cols = d.cols[d.cfg.Cols:]
			d.colSeries--
		}
	}
}

func (d *Decoder) fullReset(s uint32) {
	base := seqAdd(s, -(seqDiff(0, s) % max(d.cfg.Cols, 1)))
	d.rows = d.rows[:0]
	d.rows = append(d.rows, newGroup(base, d.payloadSize))
	d.cols = d.cols[:0]
	d.colSeries = 0
	d.colBaseISN = base
	if d.cfg.Rows > 1 {
		d.extendColumns(base)
	}
	clear(d.cells)
}

func (d *Decoder) cleanCells() {
	if len(d.rows) == 0 {
		return
	}
	base := d.rows[0].base
	for s := range d.cells {
		if seqDiff(base, s) < 0 {
			delete(d.cells, s)
		}
	}
}
