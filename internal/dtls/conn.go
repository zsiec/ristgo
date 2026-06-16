package dtls

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

// Transport is the carrier DTLS runs over: a datagram conn delivering whole
// records to one peer (a *net.UDPConn filtered to one address, or an in-memory
// pipe in tests). DTLS needs read deadlines to drive flight retransmission
// (RFC 6347 §4.2.4); a zero deadline means block indefinitely.
type Transport interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// Config configures a DTLS endpoint. The zero value is invalid; at least one of
// PSK or Certificate must be set (they select the offered cipher suite(s)).
type Config struct {
	// PSK, when non-nil, enables TLS_PSK_WITH_AES_128_GCM_SHA256. PSKIdentity is
	// the identity the client sends and the server expects (informational for a
	// single shared key).
	PSK         []byte
	PSKIdentity []byte

	// Certificate, when non-nil, enables the certificate-authenticated suites. An
	// ECDSA P-256 certificate enables the ECDHE_ECDSA suites; an RSA certificate
	// enables the ECDHE_RSA suites and RSA_WITH_NULL_SHA256 (integrity only). A
	// server in cert mode must supply one (and the suite it can serve follows the
	// certificate's key type); a client supplies one only for mutual authentication.
	Certificate *Certificate

	// DisabledSuites lists cipher suites (by their IANA id) the user has turned
	// off, satisfying TR-06-2 §6.2's requirement that a device "provide a means for
	// the user to disable individual cipher suites." A disabled suite is neither
	// offered (client) nor selected (server). Disabling every suite a config could
	// otherwise use fails the handshake (no common suite), which is the intended
	// effect of an operator turning everything off.
	DisabledSuites []uint16

	// AllowNullCipher opts in to the integrity-only TLS_RSA_WITH_NULL_SHA256 suite,
	// which authenticates but does NOT encrypt. It is OFF by default: even though a
	// remote peer cannot downgrade to it (the Finished MAC binds the negotiated
	// suite), a confidentiality-free suite must not be reachable just because a
	// certificate was configured. Set it only when an unencrypted-but-authenticated
	// transport is a deliberate requirement.
	AllowNullCipher bool

	// RequireClientCert makes a server send a CertificateRequest and reject a
	// client that does not authenticate with a certificate.
	RequireClientCert bool

	// RequireExtendedMasterSecret, when set on a client, aborts the handshake
	// with a fatal alert if the server's ServerHello omits the
	// extended_master_secret extension (RFC 7627). It defends against a
	// downgrade in which an attacker strips the extension to force the legacy
	// master-secret derivation. The client always offers EMS; this only changes
	// whether a stripped ServerHello is tolerated. Default off (a non-EMS server
	// is accepted, preserving interop with peers that lack RFC 7627).
	RequireExtendedMasterSecret bool

	// Peer-certificate verification (cert mode). Checked in this order:
	// InsecureSkipVerify accepts any; a non-zero PeerCertFingerprint pins the
	// peer's leaf SHA-256; otherwise the chain is verified against RootCAs.
	InsecureSkipVerify  bool
	RootCAs             *x509.CertPool
	PeerCertFingerprint [32]byte
	pinnedFingerprint   bool

	// PeerName, when non-empty, additionally requires the peer's leaf
	// certificate to be valid for this DNS name or IP (matched against the
	// certificate's Subject Alternative Names via the standard x509 hostname
	// check). It applies only on the RootCAs chain-verification path: without it,
	// RootCAs authenticates "some certificate issued under this CA," not a
	// specific peer — any leaf the CA signed is accepted. Empty preserves that
	// chain-of-trust-only behavior. It is ignored on the InsecureSkipVerify and
	// PeerCertFingerprint paths (a fingerprint pin already authenticates the
	// exact key).
	PeerName string

	// Rand supplies randomness (randoms, ECDHE keys, cookies); defaults to
	// crypto/rand.Reader.
	Rand io.Reader

	// HandshakeTimeout bounds the whole handshake; zero means a 30 s default.
	HandshakeTimeout time.Duration

	// RetransmitTimeout is the initial flight retransmission timer (RFC 6347
	// §4.2.4.1); zero means 1 s. It doubles per retransmission up to 60 s.
	RetransmitTimeout time.Duration
}

func (c *Config) normalize() *Config {
	cp := *c
	if cp.Rand == nil {
		cp.Rand = rand.Reader
	}
	if cp.HandshakeTimeout == 0 {
		cp.HandshakeTimeout = 30 * time.Second
	}
	if cp.RetransmitTimeout == 0 {
		cp.RetransmitTimeout = time.Second
	}
	cp.pinnedFingerprint = cp.PeerCertFingerprint != [32]byte{}
	return &cp
}

// offersPSK reports whether a PSK is configured (either role).
func (c *Config) offersPSK() bool { return c.PSK != nil }

// offersCert reports whether this endpoint can PRESENT a certificate — required
// for a server to accept a certificate suite, and for a client to satisfy a
// CertificateRequest (mutual auth).
func (c *Config) offersCert() bool { return c.Certificate != nil }

// canVerifyCert reports whether this endpoint can VERIFY a peer certificate, the
// condition for a client to offer a certificate suite (the certificate it
// verifies is the server's, so the client needs none of its own).
func (c *Config) canVerifyCert() bool {
	return c.InsecureSkipVerify || c.pinnedFingerprint || c.RootCAs != nil
}

// suiteDisabled reports whether the user turned suite id off (§6.2 disable knob).
func (c *Config) suiteDisabled(id uint16) bool {
	return slices.Contains(c.DisabledSuites, id)
}

// suiteUsable reports the gates common to both roles, independent of key-exchange:
// the suite is not disabled, and a confidentiality-free suite is allowed only on
// explicit opt-in. RSA_WITH_NULL_SHA256 provides integrity but NO encryption, so it
// must NEVER be offered or selected by default — otherwise a config that supplied a
// certificate merely for the encrypted ECDHE_RSA suites would silently also permit a
// cleartext media session. It is reachable only when AllowNullCipher is set (a
// remote peer still cannot downgrade to it — the Finished MAC binds the suite — but
// off-by-default removes the misconfiguration footgun).
func (c *Config) suiteUsable(s cipherSuiteInfo) bool {
	if c.suiteDisabled(s.id) {
		return false
	}
	if !s.aead && !c.AllowNullCipher {
		return false
	}
	return true
}

// clientCanOffer reports whether the client may offer suite s: it is usable (not
// disabled, NULL only on opt-in) and the config can run its key exchange — a PSK for
// the PSK suite, or the ability to verify the server's certificate for a certificate
// suite (the client needs no certificate of its own to verify the server's).
func (c *Config) clientCanOffer(s cipherSuiteInfo) bool {
	if !c.suiteUsable(s) {
		return false
	}
	if s.kx == kxPSK {
		return c.offersPSK()
	}
	return c.canVerifyCert()
}

// serverCanSelect reports whether the server may select suite s: it is usable (not
// disabled, NULL only on opt-in) and the config can serve it — a PSK for the PSK
// suite, or a certificate whose key type (ECDSA/RSA) matches the suite's
// authentication method.
func (c *Config) serverCanSelect(s cipherSuiteInfo) bool {
	if !c.suiteUsable(s) {
		return false
	}
	if s.kx == kxPSK {
		return c.offersPSK()
	}
	if !c.offersCert() {
		return false
	}
	at, ok := c.Certificate.keyType()
	return ok && at == s.auth
}

// clientSuites returns the cipher suites the client offers, in the table's
// preference order, filtered by what the config can do and what is disabled.
func (c *Config) clientSuites() []uint16 {
	var out []uint16
	for _, s := range suiteTable {
		if c.clientCanOffer(s) {
			out = append(out, s.id)
		}
	}
	return out
}

// maxDatagram bounds an outbound DTLS datagram to stay under a conservative path
// MTU and avoid IP fragmentation (RFC 6347 §4.1.1.1).
const maxDatagram = 1200

// readBufSize bounds an inbound datagram read.
const readBufSize = 1 << 16

// Conn is a DTLS 1.2 connection over a datagram transport.
//
// Concurrency (post-handshake): one goroutine may Read while another Writes.
// The two directions decrypt/encrypt with independent halfConns, and ALL
// outbound record emission — application-data Writes and the Read path's
// RFC 6347 §4.2.4 last-flight resend — is serialized by sendMu so the shared
// epoch-1 record sequence (c.sendSeq[1]) is never advanced concurrently. That
// serialization is mandatory, not merely tidy: the AES-GCM nonce is
// salt||epoch<<48|seq, so two epoch-1 records sharing a sequence number would
// reuse a nonce under one key — a catastrophic AEAD failure (keystream XOR
// disclosure plus GHASH authentication-key recovery). The handshake itself must
// still run on a single goroutine; sendMu only governs post-handshake emission.
type Conn struct {
	transport Transport
	cfg       *Config
	isClient  bool

	// sendMu serializes all outbound record emission after the handshake: it
	// guards each (allocate record seq, seal, transport.Write) unit so the
	// concurrent post-handshake Read and Write goroutines cannot interleave two
	// epoch-1 records onto the same sequence number (and thus the same GCM
	// nonce). It is uncontended during the single-goroutine handshake.
	sendMu sync.Mutex

	sendEpoch uint16
	sendSeq   [2]uint64 // per-epoch outgoing record sequence
	recvEpoch uint16
	replay    [2]replayWindow

	keys      connKeys
	keysReady bool

	cipherSuite uint16
	suite       cipherSuiteInfo // descriptor for cipherSuite, set once negotiated
	peerLeaf    *x509.Certificate

	handshakeDone bool

	// inbound app-data records buffered across Reads (a datagram may hold
	// several records, or a record more than one Read's worth).
	appData [][]byte

	// records left over from the last datagram read during the handshake.
	pendingRecords []record

	// handshake-only state.
	transcript []byte        // running transcript hash input (RFC 6347 §4.2.6)
	reasm      *reassembler  // inbound handshake fragment reassembly
	peerCCS    bool          // a ChangeCipherSpec from the peer has been seen
	lastFlight *flight       // our last outgoing flight, for retransmission
	curRetrans time.Duration // current retransmission timer (doubles per resend)
	sendMsgSeq uint16        // our next outgoing handshake message_seq

	// finalFlightResends counts post-handshake retransmissions of the server's
	// final flight (RFC 6347 §4.2.4), bounded by maxFinalFlightResends so a
	// misbehaving peer cannot make the server resend forever.
	finalFlightResends int
}

// maxFinalFlightResends bounds how many times the server resends its final
// flight (CCS + Finished) in response to a retransmitted client flight after the
// handshake has completed (RFC 6347 §4.2.4 last-flight handling).
const maxFinalFlightResends = 8

// Client wraps transport as the DTLS client side. The handshake runs on the
// first Read/Write or an explicit Handshake call.
func Client(transport Transport, cfg *Config) *Conn {
	return &Conn{transport: transport, cfg: cfg.normalize(), isClient: true}
}

// Server wraps transport as the DTLS server side.
func Server(transport Transport, cfg *Config) *Conn {
	return &Conn{transport: transport, cfg: cfg.normalize(), isClient: false}
}

// Handshake runs the DTLS handshake to completion. It is idempotent.
func (c *Conn) Handshake() error {
	if c.handshakeDone {
		return nil
	}
	var err error
	if c.isClient {
		err = c.clientHandshake()
	} else {
		err = c.serverHandshake()
	}
	if err != nil {
		return err
	}
	c.handshakeDone = true
	return nil
}

// ConnectionState reports the negotiated suite and the verified peer leaf (nil
// in PSK mode or when the peer sent no certificate).
func (c *Conn) ConnectionState() (cipherSuite uint16, peer *x509.Certificate) {
	return c.cipherSuite, c.peerLeaf
}

// Write sends one application-data datagram (one DTLS record). It runs the
// handshake first if needed.
func (c *Conn) Write(p []byte) (int, error) {
	if !c.handshakeDone {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	// Serialize with the Read path's last-flight resend: both emit epoch-1
	// records and must not share an epoch-1 record sequence (GCM nonce).
	c.sendMu.Lock()
	err := c.writeRecord(recordApplicationData, c.sendEpoch, p)
	c.sendMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read returns the next application-data payload. It runs the handshake first if
// needed. A record larger than p is truncated to len(p); callers pass a buffer
// at least as large as the peer's largest record (the RIST host uses 64 KiB).
func (c *Conn) Read(p []byte) (int, error) {
	if !c.handshakeDone {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	for len(c.appData) == 0 {
		if err := c.readAppRecords(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.appData[0])
	c.appData = c.appData[1:]
	return n, nil
}

// Close closes the underlying transport. (A close_notify alert is best-effort
// and omitted: RIST tears the UDP flow down at the session layer.)
func (c *Conn) Close() error { return c.transport.Close() }

// nextSeq returns and advances the outgoing record sequence for an epoch.
func (c *Conn) nextSeq(epoch uint16) uint64 {
	s := c.sendSeq[epoch]
	c.sendSeq[epoch]++
	return s
}

// writeRecord builds and sends a single record (one per datagram) at the given
// epoch, encrypting when epoch > 0.
func (c *Conn) writeRecord(typ contentType, epoch uint16, payload []byte) error {
	seq := c.nextSeq(epoch)
	fragment := payload
	if epoch > 0 {
		if !c.keysReady {
			return errors.New("rist: dtls: encrypt before key derivation")
		}
		fragment = c.sealHalf(epoch).seal(epoch, seq, typ, versionDTLS12, payload)
	}
	rec := record{typ: typ, version: versionDTLS12, epoch: epoch, seq: seq, fragment: fragment}
	_, err := c.transport.Write(rec.marshal(nil))
	return err
}

// sealHalf / openHalf return the halfConn used to protect/parse a record in the
// given direction. The client encrypts with clientWrite and decrypts with
// serverWrite; the server does the reverse.
func (c *Conn) sealHalf(uint16) halfConn {
	if c.isClient {
		return c.keys.clientWrite
	}
	return c.keys.serverWrite
}

func (c *Conn) openHalf(uint16) halfConn {
	if c.isClient {
		return c.keys.serverWrite
	}
	return c.keys.clientWrite
}

// readAppRecords reads one datagram and queues its application-data records,
// decrypting them. It blocks indefinitely (zero read deadline): post-handshake
// idle is normal for a media stream, and session-level liveness/timeout is the
// host's concern, not DTLS's. Non-app records (a retransmitted peer Finished, an
// alert) are handled or ignored.
func (c *Conn) readAppRecords() error {
	recs, err := c.readDatagram(time.Time{})
	if err != nil {
		return err
	}
	for _, r := range recs {
		switch r.typ {
		case recordApplicationData:
			pt, ok := c.decryptRecord(r)
			if !ok {
				continue
			}
			c.appData = append(c.appData, pt)
		case recordAlert:
			// A close_notify (or any fatal alert) ends the stream.
			return io.EOF
		default:
			// RFC 6347 §4.2.4 last-flight handling: a retransmitted peer
			// handshake or CCS record after we finished means our final flight
			// was lost in transit. The server MUST resend its last flight (CCS +
			// Finished) — without this, a single dropped server-Finished datagram
			// permanently fails the handshake under loss instead of recovering.
			// The client has no post-Finished flight to lose, so it does not
			// resend. Bounded by maxFinalFlightResends.
			if !c.isClient && c.lastFlight != nil &&
				(r.typ == recordHandshake || r.typ == recordChangeCipherSpec) &&
				c.finalFlightResends < maxFinalFlightResends {
				c.finalFlightResends++
				// The final flight carries an epoch-1 Finished. Serialize with a
				// concurrent application-data Write so the two cannot allocate the
				// same epoch-1 record sequence (and thus reuse a GCM nonce).
				c.sendMu.Lock()
				err := c.transmit(c.lastFlight)
				c.sendMu.Unlock()
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// decryptRecord opens an encrypted record subject to the anti-replay window,
// returning the plaintext and whether it was accepted.
func (c *Conn) decryptRecord(r record) ([]byte, bool) {
	if r.epoch == 0 || !c.keysReady {
		return nil, false
	}
	w := &c.replay[r.epoch&1]
	if !w.check(r.seq) {
		return nil, false // replay or too old
	}
	pt, err := c.openHalf(r.epoch).open(r)
	if err != nil {
		return nil, false
	}
	w.mark(r.seq)
	return pt, true
}

// readDatagram reads one UDP datagram before the deadline and splits it into
// records, returning a timeout error verbatim so the handshake loop can
// retransmit.
func (c *Conn) readDatagram(deadline time.Time) ([]record, error) {
	if err := c.transport.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	buf := make([]byte, readBufSize)
	n, err := c.transport.Read(buf)
	if err != nil {
		return nil, err
	}
	return splitRecords(buf[:n])
}

// isTimeout reports whether err is a deadline timeout (so the handshake loop
// retransmits rather than failing).
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// fingerprintOf returns the SHA-256 fingerprint of a DER certificate.
func fingerprintOf(der []byte) [32]byte { return sha256.Sum256(der) }

// selectSuite picks the cipher suite both sides can do given cfg and the peer's
// offered list, walking suiteTable in server-preference order (forward-secret and
// stronger suites first; the integrity-only NULL suite last) and returning the
// first the server can serve that the client offered.
func selectSuite(cfg *Config, offered []uint16) (cipherSuiteInfo, error) {
	for _, s := range suiteTable {
		if cfg.serverCanSelect(s) && slices.Contains(offered, s.id) {
			return s, nil
		}
	}
	return cipherSuiteInfo{}, fmt.Errorf("rist: dtls: no common cipher suite")
}
