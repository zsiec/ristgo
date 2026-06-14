package ristgo

import (
	"errors"
	"net"
	"net/netip"
	"time"
)

// Default configuration values. Each mirrors the corresponding
// RIST_DEFAULT_* macro in libRIST; matching them
// exactly is required for interoperability.
const (
	DefaultBufferMin         = 1000 * time.Millisecond // RIST_DEFAULT_RECOVERY_LENGTH_MIN (ms)
	DefaultBufferMax         = 1000 * time.Millisecond // RIST_DEFAULT_RECOVERY_LENGTH_MAX (ms)
	DefaultReorderBuffer     = 15 * time.Millisecond   // RIST_DEFAULT_RECOVERY_REORDER_BUFFER (ms)
	DefaultRTTMin            = 5 * time.Millisecond    // RIST_DEFAULT_RECOVERY_RTT_MIN (ms)
	DefaultRTTMax            = 500 * time.Millisecond  // RIST_DEFAULT_RECOVERY_RTT_MAX (ms)
	DefaultRTTMultiplier     = 7                       // libRIST recovery_rtt_multiplier
	DefaultMinRetries        = 6                       // RIST_DEFAULT_MIN_RETRIES
	DefaultMaxRetries        = 20                      // RIST_DEFAULT_MAX_RETRIES
	DefaultSessionTimeout    = 2000 * time.Millisecond // RIST_DEFAULT_SESSION_TIMEOUT (ms)
	DefaultKeepaliveInterval = 1000 * time.Millisecond // RIST_DEFAULT_KEEPALIVE_INTERVAL (ms)
	DefaultMaxBitrate        = 100000                  // RIST_DEFAULT_RECOVERY_MAXBITRATE (kbps)
	DefaultVirtSrcPort       = 1971                    // RIST_DEFAULT_VIRT_SRC_PORT
	DefaultVirtDstPort       = 1968                    // RIST_DEFAULT_VIRT_DST_PORT

	// MinBuffer and MaxBuffer bound BufferMin and BufferMax.
	MinBuffer = 50 * time.Millisecond
	MaxBuffer = 30 * time.Second

	// MinRTT and MaxRTT bound RTTMin and RTTMax.
	MinRTT = 1 * time.Millisecond
	MaxRTT = 1 * time.Second

	// MaxRetriesLimit is the upper bound for MinRetries and MaxRetries.
	MaxRetriesLimit = 100

	// MaxRTTMultiplier is the upper bound for RTTMultiplier.
	MaxRTTMultiplier = 100

	// String length limits, matching libRIST's RIST_MAX_STRING_SHORT (128)
	// and RIST_MAX_STRING_LONG (256) minus the C NUL terminator.
	maxShortString = 127
	maxLongString  = 255
)

// Config contains RIST sender/receiver configuration.
//
// The zero value of every field means "use the default"; validation fills
// defaults in place before checking ranges, so Config{} behaves like
// DefaultConfig().
type Config struct {
	// Profile selects the RIST wire profile.
	// Default: ProfileSimple.
	//
	// NOTE: this deviates from libRIST, whose default profile is Main. ristgo
	// defaults to ProfileSimple — the simplest interoperable profile — so a
	// zero-value Config needs no tunnelling or keys; set ProfileMain or
	// ProfileAdvanced explicitly for those profiles.
	Profile Profile

	// BufferMin is the minimum recovery (retransmission) buffer length
	// (libRIST recovery_length_min). The effective playout delay is
	// derived as (BufferMax-BufferMin)/2 + BufferMin.
	// Default: 1000ms. Range: 50ms-30s.
	BufferMin time.Duration

	// BufferMax is the maximum recovery buffer length
	// (libRIST recovery_length_max). Must be >= BufferMin.
	// Default: 1000ms. Range: 50ms-30s.
	BufferMax time.Duration

	// ReorderBuffer is how long the receiver holds out-of-order packets
	// before declaring them missing and requesting retransmission
	// (libRIST recovery_reorder_buffer).
	// Default: 15ms. Range: 0-BufferMin. Zero means "use the default";
	// it cannot express "no reorder hold".
	ReorderBuffer time.Duration

	// RTTMin is the lower clamp applied to the measured round-trip time
	// when scheduling NACK retries (libRIST recovery_rtt_min).
	// Default: 5ms. Range: 1ms-1s.
	RTTMin time.Duration

	// RTTMax is the upper clamp applied to the measured round-trip time
	// (libRIST recovery_rtt_max). Must be >= RTTMin.
	// Default: 500ms. Range: 1ms-1s.
	RTTMax time.Duration

	// RTTMultiplier scales the measured RTT when sizing the recovery
	// buffer (libRIST recovery_rtt_multiplier, "default 7, per RIST
	// spec"). Default: 7. Range: 1-100.
	RTTMultiplier int

	// MinRetries is the minimum number of retransmission requests sent
	// for a missing packet before giving up, regardless of timing
	// (libRIST min_retries). Must be <= MaxRetries.
	// Default: 6. Range: 0-100. Zero means "use the default".
	MinRetries int

	// MaxRetries is the maximum number of retransmission requests sent
	// for a missing packet (libRIST max_retries).
	// Default: 20. Range: 0-100. Zero means "use the default".
	MaxRetries int

	// SessionTimeout is how long a peer may stay silent (no data, RTCP,
	// or keepalive) before the session is torn down
	// (libRIST session_timeout).
	// Default: 2000ms. Must be >= KeepaliveInterval.
	SessionTimeout time.Duration

	// KeepaliveInterval is the period between keepalive transmissions
	// (libRIST keepalive_interval).
	// Default: 1000ms. Must be positive.
	KeepaliveInterval time.Duration

	// MaxBitrate is the maximum recovery bandwidth in kilobits per second
	// (libRIST recovery_maxbitrate, kbps).
	// Default: 100000 (100 Mbps). Must be positive.
	MaxBitrate int

	// ReturnBandwidth caps a receiver's outbound NACK channel in kbps (libRIST
	// return-bandwidth), so its retransmission requests stay within an upstream
	// budget on an asymmetric link. 0 (the default) means unlimited. Receiver-
	// side only; must be >= 0. NOTE: libRIST v0.2.18 stores but does not enforce
	// this value — ristgo enforces it as an interop-safe enhancement (the sender
	// merely receives fewer NACKs, never a protocol violation); over-throttling
	// only slows recovery, it never drops a still-recoverable packet.
	ReturnBandwidth int

	// MinBitrate is the floor, in kbps, below which source-adaptation rate
	// control (OnRateAdapt) will not drive the encoder target. TR-06-4 Part 1
	// §7 notes that for a given codec, resolution, and frame rate there is a
	// minimum supportable bit rate below which operation is not guaranteed, so
	// an application should set this to its encoder's viable floor. 0 (the
	// default) means the controller's built-in 500 kbps floor. When set it must
	// satisfy 0 < MinBitrate <= MaxBitrate. Only meaningful with OnRateAdapt.
	MinBitrate int

	// VirtSrcPort is the virtual source port carried in the reduced
	// overhead header (libRIST virt_src_port). Not used by the Simple
	// profile. Default: 1971.
	VirtSrcPort uint16

	// VirtDstPort is the virtual destination port (libRIST
	// virt_dst_port). Not used by the Simple profile. Default: 1968.
	VirtDstPort uint16

	// CNAME is the canonical name advertised in RTCP SDES packets.
	// When empty, a host-derived name is generated.
	// Maximum 127 bytes (libRIST RIST_MAX_STRING_SHORT).
	CNAME string

	// NACKType selects the retransmission-request wire encoding.
	// Default: NACKRange (the RIST and libRIST default).
	NACKType NACKType

	// CongestionControl selects how the sender paces retransmissions against
	// MaxBitrate (libRIST congestion_control). The zero value is
	// CongestionNormal, the libRIST default. Set via the rist:// URL with
	// congestion-control=0|1|2 (off|normal|aggressive, libRIST's numbering).
	CongestionControl CongestionControl

	// TimingMode selects how a receiver schedules playout (libRIST timing_mode).
	// The zero value is TimingSource, the libRIST default. Receiver-side; ignored
	// on a sender. Set via the rist:// URL with timing-mode=0|1|2
	// (source|arrival|rtc; rtc maps to arrival).
	TimingMode TimingMode

	// Secret is the pre-shared passphrase enabling PSK encryption
	// (Main and Advanced profiles). Empty disables encryption.
	// Maximum 127 bytes (libRIST RIST_MAX_STRING_SHORT).
	Secret string

	// AESKeyBits is the AES key size in bits: 128 or 256.
	// Only meaningful when Secret is set; when Secret is set and
	// AESKeyBits is 0, it defaults to 128.
	//
	// 128 matches the libRIST command-line tools (ristsender/ristreceiver),
	// which pre-set a 128-bit key when -e/--secret is given without an explicit
	// size — so an omitted aes-type interoperates with the most common libRIST
	// CLI invocation. (The libRIST *library* default is 256, but its tools
	// override it to 128 before the library default applies.) The GRE H bit
	// signals 128 vs 256 on the wire and both ends must agree, so set AESKeyBits
	// explicitly when interoperating with a peer configured for 256.
	// Setting AESKeyBits without Secret is an error.
	AESKeyBits int

	// KeyRotation is the number of packets encrypted with one key before
	// the nonce is rotated and the key re-derived (libRIST key_rotation).
	// 0 means the library default (rotate only when the counter would
	// otherwise be exhausted). Must be >= 0.
	KeyRotation int

	// Username is the SRP authentication username (Main profile).
	// Must be set together with Password.
	// Maximum 255 bytes (libRIST RIST_MAX_STRING_LONG).
	Username string

	// Password is the SRP authentication password (Main profile).
	// Must be set together with Username.
	// Maximum 255 bytes (libRIST RIST_MAX_STRING_LONG).
	Password string

	// SRPCompat selects the legacy pre-0.2.16 SRP hashing mode (libRIST
	// srp-compat=1: unpadded k/u, EAPOL version 2) for interop with old peers.
	// It only affects a RECEIVER acting as the EAP authenticator (which then
	// advertises legacy); a sender's authenticatee already auto-negotiates the
	// peer's advertised version, so SRPCompat is a no-op on a sender. Default
	// false (RFC-5054 PAD, the libRIST 0.2.16+ default).
	SRPCompat bool

	// Compression enables payload compression (Advanced profile only;
	// libRIST compression). Receivers auto-detect. Default: false.
	Compression bool

	// Weight is the load-balancing weight of this peer when a sender
	// feeds multiple peers (libRIST weight). 0 (the default, libRIST
	// RIST_PEER_WEIGHT_DUPLICATE) duplicates every packet to this peer —
	// the SMPTE 2022-7 mode — instead of joining the weighted rotation.
	// Must be >= 0.
	Weight int

	// SourceAdaptation, set on a Receiver, makes it send periodic Link Quality
	// Messages back to the sender (VSF TR-06-4 Part 1). Default: false. Supported
	// on all three profiles: the LQM is carried as an RR profile-specific
	// extension on Simple (§5.2), the same RR tunnelled over GRE on Main (§5.3),
	// and a native Type=Control message (Control Index 0x0002) on Advanced (§5.4).
	SourceAdaptation bool

	// OnRateAdapt, set on a Sender, enables source-adaptation rate control: the
	// sender feeds each inbound Link Quality Message to an AIMD controller and
	// calls this function with the new encoder bit-rate target in kbps. The
	// application should retune its encoder toward that target. nil (the default)
	// disables rate adaptation. The callback runs on the session's event loop, so
	// it must not block. Supported on all three profiles (see SourceAdaptation).
	OnRateAdapt func(targetKbps int)

	// Interface is the name of the network interface used for multicast
	// (libRIST "miface"): a sender's outbound multicast egress interface and a
	// receiver's group-membership interface. Empty (the default) lets the OS
	// choose the system default interface. It is consulted only when the
	// destination (sender) or bind (receiver) address is a multicast group;
	// unicast ignores it. When set it must resolve via net.InterfaceByName.
	Interface string

	// MulticastTTL is the IP multicast hop limit (TTL for IPv4, hop limit for
	// IPv6) stamped on a sender's outbound multicast datagrams. 0 (the default)
	// uses the OS default of 1, which restricts the traffic to the local link
	// (it is never forwarded by a router). Real multicast distribution across
	// router hops needs a higher value (e.g. 16, 32, or more, sized to the
	// network diameter). Range: 0-255. It is consulted only when the destination
	// is a multicast group; unicast ignores it.
	MulticastTTL int

	// MulticastSource, set on a Receiver whose bind address is a multicast group,
	// selects source-specific multicast (SSM, RFC 4607): the receiver joins the
	// group filtered to datagrams from this exact source IP, ignoring any other
	// sender on the group. Empty (the default) is any-source multicast (ASM): the
	// receiver accepts the group from any source. When set it must parse as an IP
	// literal, and the bind address must be a multicast group (it is rejected on a
	// unicast destination).
	MulticastSource string

	// MulticastLoopback controls whether a sender transmitting to a multicast
	// group also receives its own datagrams on the same host (IP multicast
	// loopback). false (the default) disables loopback, matching the common
	// production case where the source host is not also a subscriber. It is
	// consulted only when the destination is a multicast group; unicast ignores
	// it. Multicast loopback is also what the multicast e2e test relies on.
	MulticastLoopback bool

	// DTLS, when non-nil, enables DTLS 1.2 transport security for the Main
	// profile (VSF TR-06-2 §6), protecting the whole GRE tunnel. It is an
	// alternative to the GRE PSK-AES-CTR encryption — setting both Secret and
	// DTLS is rejected by validation. The RIST sender is the DTLS client and the
	// receiver is the DTLS server. Requires Profile == ProfileMain.
	//
	// DTLS adds ~37 bytes of per-packet overhead (record header, explicit nonce,
	// GCM tag); leave headroom in the media payload to avoid IP fragmentation of
	// the resulting datagram.
	DTLS *DTLSConfig

	// Logger receives diagnostic log messages. When nil (the default),
	// no logging occurs and there is zero performance overhead.
	Logger Logger
}

// DTLSConfig selects the DTLS 1.2 mode and credentials for Main-profile
// transport security. Set exactly one of PSK or the certificate fields.
type DTLSConfig struct {
	// PSK enables TLS_PSK_WITH_AES_128_GCM_SHA256: a shared secret on both ends.
	// PSKIdentity is the identity hint exchanged (informational).
	PSK         []byte
	PSKIdentity string

	// CertPEM and KeyPEM enable TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 with a
	// supplied ECDSA P-256 certificate and key (PEM). On a receiver they are the
	// presented server certificate; if omitted on a receiver, a self-signed
	// certificate is generated. On a sender they are sent only for mutual auth.
	CertPEM []byte
	KeyPEM  []byte

	// PeerFingerprint, when non-zero, pins the peer leaf certificate's SHA-256
	// (the recommended way to authenticate a self-signed RIST peer). On a sender
	// it pins the receiver's certificate.
	PeerFingerprint [32]byte

	// InsecureSkipVerify disables peer-certificate verification (cert mode). Use
	// only for testing; prefer PeerFingerprint.
	InsecureSkipVerify bool
}

// DefaultConfig returns a Config with default values matching libRIST's
// RIST_DEFAULT_* macros, except Profile: libRIST
// defaults to the Main profile, while ristgo defaults to ProfileSimple
// until Main is implemented (see Config.Profile).
func DefaultConfig() Config {
	return Config{
		Profile:           ProfileSimple,
		BufferMin:         DefaultBufferMin,
		BufferMax:         DefaultBufferMax,
		ReorderBuffer:     DefaultReorderBuffer,
		RTTMin:            DefaultRTTMin,
		RTTMax:            DefaultRTTMax,
		RTTMultiplier:     DefaultRTTMultiplier,
		MinRetries:        DefaultMinRetries,
		MaxRetries:        DefaultMaxRetries,
		SessionTimeout:    DefaultSessionTimeout,
		KeepaliveInterval: DefaultKeepaliveInterval,
		MaxBitrate:        DefaultMaxBitrate,
		VirtSrcPort:       DefaultVirtSrcPort,
		VirtDstPort:       DefaultVirtDstPort,
		NACKType:          NACKRange,
		CongestionControl: CongestionNormal,
	}
}

// validate applies defaults to zero fields and checks constraints.
func (cfg *Config) validate() error {
	if cfg.Profile < ProfileSimple || cfg.Profile > ProfileAdvanced {
		return errors.New("rist: Profile must be ProfileSimple (0), ProfileMain (1), or ProfileAdvanced (2)")
	}

	// Profile-capability gate: fail closed when a security- or feature-bearing
	// field is set on a profile that does not consume it, instead of silently
	// dropping it on the floor. The Simple profile (TR-06-1) has no encryption,
	// no SRP authentication, and no compression; EAP-SRP is Main-only; payload
	// compression is Advanced-only. A caller who sets Secret but forgets
	// ProfileMain/Advanced must get an error rather than a cleartext stream.
	if cfg.Profile == ProfileSimple {
		switch {
		case cfg.Secret != "":
			return errors.New("rist: Secret (PSK encryption) requires ProfileMain or ProfileAdvanced; the Simple profile transmits in the clear")
		case cfg.AESKeyBits != 0:
			return errors.New("rist: AESKeyBits requires ProfileMain or ProfileAdvanced")
		case cfg.KeyRotation != 0:
			return errors.New("rist: KeyRotation requires ProfileMain or ProfileAdvanced")
		}
	}
	if cfg.Username != "" && cfg.Profile != ProfileMain {
		return errors.New("rist: Username/Password (EAP-SRP authentication) requires ProfileMain")
	}
	if cfg.Compression && cfg.Profile != ProfileAdvanced {
		return errors.New("rist: Compression requires ProfileAdvanced")
	}

	if cfg.DTLS != nil {
		if cfg.Profile != ProfileMain {
			return errors.New("rist: DTLS transport security requires ProfileMain")
		}
		if cfg.Secret != "" {
			return errors.New("rist: DTLS and Secret (GRE PSK encryption) are mutually exclusive; DTLS already protects the whole tunnel")
		}
		if cfg.DTLS.PSK == nil && len(cfg.DTLS.CertPEM) == 0 && !cfg.DTLS.InsecureSkipVerify && cfg.DTLS.PeerFingerprint == [32]byte{} {
			return errors.New("rist: DTLS requires a PSK, a certificate, or peer verification")
		}
		// Bound the PSK well below the 16-bit length prefix in the RFC 4279
		// pre-master construction (a >64 KiB PSK would silently truncate); a DTLS
		// PSK is a short shared secret, so 512 bytes is generous.
		if len(cfg.DTLS.PSK) > 512 {
			return errors.New("rist: DTLS PSK must be at most 512 bytes")
		}
	}

	if cfg.BufferMin == 0 {
		cfg.BufferMin = DefaultBufferMin
	}
	if cfg.BufferMax == 0 {
		cfg.BufferMax = DefaultBufferMax
	}
	if cfg.BufferMin < MinBuffer || cfg.BufferMin > MaxBuffer {
		return errors.New("rist: BufferMin must be between 50ms and 30s")
	}
	if cfg.BufferMax < MinBuffer || cfg.BufferMax > MaxBuffer {
		return errors.New("rist: BufferMax must be between 50ms and 30s")
	}
	if cfg.BufferMin > cfg.BufferMax {
		return errors.New("rist: BufferMin must not exceed BufferMax")
	}

	if cfg.ReorderBuffer == 0 {
		cfg.ReorderBuffer = DefaultReorderBuffer
	}
	if cfg.ReorderBuffer < 0 || cfg.ReorderBuffer > cfg.BufferMin {
		return errors.New("rist: ReorderBuffer must be between 0 and BufferMin")
	}

	if cfg.RTTMin == 0 {
		cfg.RTTMin = DefaultRTTMin
	}
	if cfg.RTTMax == 0 {
		cfg.RTTMax = DefaultRTTMax
	}
	if cfg.RTTMin < MinRTT || cfg.RTTMin > MaxRTT {
		return errors.New("rist: RTTMin must be between 1ms and 1s")
	}
	if cfg.RTTMax < MinRTT || cfg.RTTMax > MaxRTT {
		return errors.New("rist: RTTMax must be between 1ms and 1s")
	}
	if cfg.RTTMin > cfg.RTTMax {
		return errors.New("rist: RTTMin must not exceed RTTMax")
	}

	if cfg.RTTMultiplier == 0 {
		cfg.RTTMultiplier = DefaultRTTMultiplier
	}
	if cfg.RTTMultiplier < 1 || cfg.RTTMultiplier > MaxRTTMultiplier {
		return errors.New("rist: RTTMultiplier must be between 1 and 100")
	}

	if cfg.MinRetries == 0 {
		cfg.MinRetries = DefaultMinRetries
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.MinRetries < 0 || cfg.MinRetries > MaxRetriesLimit {
		return errors.New("rist: MinRetries must be between 0 and 100")
	}
	if cfg.MaxRetries < 0 || cfg.MaxRetries > MaxRetriesLimit {
		return errors.New("rist: MaxRetries must be between 0 and 100")
	}
	if cfg.MinRetries > cfg.MaxRetries {
		return errors.New("rist: MinRetries must not exceed MaxRetries")
	}

	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = DefaultSessionTimeout
	}
	if cfg.SessionTimeout < 0 {
		return errors.New("rist: SessionTimeout must be positive")
	}
	if cfg.KeepaliveInterval == 0 {
		cfg.KeepaliveInterval = DefaultKeepaliveInterval
	}
	if cfg.KeepaliveInterval < 0 {
		return errors.New("rist: KeepaliveInterval must be positive")
	}
	if cfg.KeepaliveInterval > cfg.SessionTimeout {
		return errors.New("rist: KeepaliveInterval must not exceed SessionTimeout")
	}

	if cfg.MaxBitrate == 0 {
		cfg.MaxBitrate = DefaultMaxBitrate
	}
	if cfg.MaxBitrate < 0 {
		return errors.New("rist: MaxBitrate must be positive (kbps)")
	}
	if cfg.MinBitrate < 0 {
		return errors.New("rist: MinBitrate must be at least 0 (kbps; 0 = library floor)")
	}
	if cfg.ReturnBandwidth < 0 {
		return errors.New("rist: ReturnBandwidth must be at least 0 (kbps; 0 = unlimited)")
	}
	if cfg.MinBitrate > cfg.MaxBitrate {
		return errors.New("rist: MinBitrate must not exceed MaxBitrate")
	}

	if cfg.VirtSrcPort == 0 {
		cfg.VirtSrcPort = DefaultVirtSrcPort
	}
	if cfg.VirtDstPort == 0 {
		cfg.VirtDstPort = DefaultVirtDstPort
	}

	if len(cfg.CNAME) > maxShortString {
		return errors.New("rist: CNAME must be at most 127 bytes")
	}

	if cfg.NACKType != NACKRange && cfg.NACKType != NACKBitmask {
		return errors.New("rist: NACKType must be NACKRange (0) or NACKBitmask (1)")
	}

	if cfg.CongestionControl != CongestionNormal && cfg.CongestionControl != CongestionAggressive && cfg.CongestionControl != CongestionOff {
		return errors.New("rist: CongestionControl must be CongestionNormal, CongestionAggressive, or CongestionOff")
	}

	if cfg.TimingMode != TimingSource && cfg.TimingMode != TimingArrival {
		return errors.New("rist: TimingMode must be TimingSource or TimingArrival")
	}

	if len(cfg.Secret) > maxShortString {
		return errors.New("rist: Secret must be at most 127 bytes")
	}
	if cfg.Secret != "" && cfg.AESKeyBits == 0 {
		// Match the libRIST CLI tools, which set a 128-bit key when a secret is
		// given without an explicit aes-type; the library's own 256 default never
		// fires there. Set AESKeyBits explicitly to interoperate with a 256 peer.
		cfg.AESKeyBits = 128
	} else if cfg.Secret == "" && cfg.Username != "" && cfg.AESKeyBits == 0 {
		// SRP without a Secret = use_key_as_passphrase: the media key is derived
		// from the SRP session key K. libRIST's _librist_crypto_psk_set_passphrase
		// defaults key_size to 256 when it is unset (which it is when the tools are
		// given no aes-type), so default to 256 here to interoperate.
		cfg.AESKeyBits = 256
	}
	switch cfg.AESKeyBits {
	case 0, 128, 256:
	default:
		return errors.New("rist: AESKeyBits must be 0, 128, or 256")
	}
	// AESKeyBits requires either a Secret (PSK keying) or SRP credentials
	// (use_key_as_passphrase keying from K). It is meaningless without a key.
	if cfg.AESKeyBits != 0 && cfg.Secret == "" && cfg.Username == "" {
		return errors.New("rist: AESKeyBits requires a Secret or SRP credentials")
	}
	if cfg.KeyRotation < 0 {
		return errors.New("rist: KeyRotation must be at least 0 (packets per key)")
	}

	if (cfg.Username == "") != (cfg.Password == "") {
		return errors.New("rist: Username and Password must be set together")
	}
	if len(cfg.Username) > maxLongString {
		return errors.New("rist: Username must be at most 255 bytes")
	}
	if len(cfg.Password) > maxLongString {
		return errors.New("rist: Password must be at most 255 bytes")
	}
	// SRP credentials WITHOUT a pre-shared Secret select libRIST's
	// use_key_as_passphrase mode: the media AES key is derived from the SRP
	// session key K on a successful handshake (so the channel is still encrypted,
	// keyed by the mutually-authenticated K — no confidentiality downgrade), and
	// both GRE directions key from K. This is valid and interoperates with a
	// libRIST peer given username/password and no secret. SRP WITH an explicit
	// Secret keeps using the Secret-derived PSK (SRP only gates the channel).
	// Both forms are accepted here; no rejection.
	//
	// AESKeyBits without a Secret is the use_key_as_passphrase key size (128/256);
	// the AESKeyBits-requires-Secret check above would have rejected it, so allow
	// it here when SRP credentials are present (see the AESKeyBits block below,
	// which now permits it under SRP).

	if cfg.Weight < 0 {
		return errors.New("rist: Weight must be at least 0 (0 = duplicate)")
	}

	if err := cfg.validateMulticast(); err != nil {
		return err
	}

	return nil
}

// validateMulticast checks the IP-multicast configuration fields (Interface,
// MulticastTTL, MulticastSource, MulticastLoopback). The destination-address
// dependent checks (e.g. rejecting MulticastSource on a unicast bind) happen in
// the constructor, where the address is known; these are the field-level
// constraints that hold regardless of address.
func (cfg *Config) validateMulticast() error {
	if cfg.MulticastTTL < 0 || cfg.MulticastTTL > 255 {
		return errors.New("rist: MulticastTTL must be between 0 and 255 (0 = OS default of 1)")
	}
	if cfg.Interface != "" {
		if _, err := net.InterfaceByName(cfg.Interface); err != nil {
			return errors.New("rist: Interface " + cfg.Interface + " not found: " + err.Error())
		}
	}
	if cfg.MulticastSource != "" {
		if _, err := netip.ParseAddr(cfg.MulticastSource); err != nil {
			return errors.New("rist: MulticastSource must be an IP address: " + err.Error())
		}
	}
	return nil
}

// recoveryBufferTime returns the derived recovery (playout) buffer
// duration: (BufferMax-BufferMin)/2 + BufferMin, matching libRIST's
// buffer-time computation. With the default 1000ms/1000ms window this is
// 1000ms.
func (cfg *Config) recoveryBufferTime() time.Duration {
	return (cfg.BufferMax-cfg.BufferMin)/2 + cfg.BufferMin
}
