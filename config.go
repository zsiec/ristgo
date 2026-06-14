package ristgo

import (
	"errors"
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

	// Secret is the pre-shared passphrase enabling PSK encryption
	// (Main and Advanced profiles). Empty disables encryption.
	// Maximum 127 bytes (libRIST RIST_MAX_STRING_SHORT).
	Secret string

	// AESKeyBits is the AES key size in bits: 128 or 256.
	// Only meaningful when Secret is set; when Secret is set and
	// AESKeyBits is 0, it defaults to 256 (matching libRIST, which
	// assumes the maximum security level when aes-type is omitted).
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
	}
}

// validate applies defaults to zero fields and checks constraints.
func (cfg *Config) validate() error {
	if cfg.Profile < ProfileSimple || cfg.Profile > ProfileAdvanced {
		return errors.New("rist: Profile must be ProfileSimple (0), ProfileMain (1), or ProfileAdvanced (2)")
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

	if len(cfg.Secret) > maxShortString {
		return errors.New("rist: Secret must be at most 127 bytes")
	}
	if cfg.Secret != "" && cfg.AESKeyBits == 0 {
		cfg.AESKeyBits = 256 // libRIST: maximum security level when aes-type omitted
	}
	switch cfg.AESKeyBits {
	case 0, 128, 256:
	default:
		return errors.New("rist: AESKeyBits must be 0, 128, or 256")
	}
	if cfg.AESKeyBits != 0 && cfg.Secret == "" {
		return errors.New("rist: AESKeyBits requires a Secret")
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

	if cfg.Weight < 0 {
		return errors.New("rist: Weight must be at least 0 (0 = duplicate)")
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
