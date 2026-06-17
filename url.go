package ristgo

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ParseURL parses a rist:// URL into a dial/listen address ("host:port") and a
// Config. Query parameters override the corresponding cfg fields, so callers
// typically pass DefaultConfig() as the base. The accepted parameter names
// match libRIST's (parse_url_options) so the same URL works against
// ffmpeg/libRIST:
//
//	buffer, buffer-min, buffer-max, rtt, rtt-min, rtt-max, reorder-buffer,
//	session-timeout, keepalive-interval   (all milliseconds)
//	rtt-multiplier, min-retries, max-retries, weight, key-rotation
//	bandwidth, return-bandwidth   (kbps)        aes-type   (128/256)
//	cname, secret, username, password, compression, profile,
//	virt-src-port, virt-dst-port
//	miface (multicast interface), ttl (multicast TTL, 0..255),
//	source (source-specific-multicast source IP)
//	congestion-control (0=off, 1=normal, 2=aggressive, libRIST's numbering)
//	timing-mode (0=source, 1=arrival, 2=rtc→arrival), srp-compat (legacy SRP)
//
// "keepalive" is also accepted as a ristgo alias for "keepalive-interval".
// "buffer" sets both buffer-min and buffer-max, and "rtt" sets both rtt-min
// and rtt-max; an explicit -min/-max always wins regardless of URL order
// (net/url discards order — a deliberate simplification of libRIST's
// order-dependent parsing). A bare "host:port" (no scheme) is accepted and
// returned unchanged.
//
// An unrecognized query parameter (e.g. a typo) is REJECTED with ErrInvalidConfig,
// matching libRIST's parse_url_options (which fails on an unknown key) rather
// than silently running with a default. recovery-priority is accepted and
// ignored here — it is a per-peer NACK priority set via the BondedPeer API
// ([NewBondedReceiverPeers]), not a single per-session URL value — so a URL
// written for libRIST still parses.
func ParseURL(rawURL string, cfg Config) (addr string, out Config, err error) {
	if !strings.Contains(rawURL, "://") {
		return rawURL, cfg, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", cfg, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if u.Scheme != "rist" {
		return "", cfg, fmt.Errorf("%w: unsupported scheme %q (want rist)", ErrInvalidConfig, u.Scheme)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		return "", cfg, fmt.Errorf("%w: rist URL must include a port", ErrInvalidConfig)
	}
	if err := applyQuery(&cfg, u.Query()); err != nil {
		return "", cfg, err
	}
	return net.JoinHostPort(host, port), cfg, nil
}

// applyQuery folds URL query parameters into cfg.
func applyQuery(cfg *Config, q url.Values) error {
	// maxURLMillis bounds a millisecond-valued query parameter. It is far above
	// any sane RIST timing value (one week) yet far below the point where
	// n*time.Millisecond would overflow int64 nanoseconds (~9.2e12 ms) and wrap
	// to a value that could slip past the range checks in validate().
	const maxURLMillis = 7 * 24 * 3600 * 1000
	parseMillis := func(key, v string) (time.Duration, error) {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%w: %s=%q is not an integer", ErrInvalidConfig, key, v)
		}
		if n < 0 || n > maxURLMillis {
			return 0, fmt.Errorf("%w: %s=%q out of range (0..%d ms)", ErrInvalidConfig, key, v, maxURLMillis)
		}
		return time.Duration(n) * time.Millisecond, nil
	}
	ms := func(key string, dst *time.Duration) error {
		v := q.Get(key)
		if v == "" {
			return nil
		}
		d, err := parseMillis(key, v)
		if err != nil {
			return err
		}
		*dst = d
		return nil
	}
	intVal := func(key string, dst *int) error {
		v := q.Get(key)
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%w: %s=%q is not an integer", ErrInvalidConfig, key, v)
		}
		*dst = n
		return nil
	}

	// "buffer" and "rtt" set both the min and max; the explicit -min/-max
	// keys below then override them. (libRIST resolves these in URL order;
	// net/url discards order, so ristgo always lets the explicit -min/-max
	// win — a documented simplification.)
	if v := q.Get("buffer"); v != "" {
		d, err := parseMillis("buffer", v)
		if err != nil {
			return err
		}
		cfg.BufferMin = d
		cfg.BufferMax = d
	}
	if v := q.Get("rtt"); v != "" {
		d, err := parseMillis("rtt", v)
		if err != nil {
			return err
		}
		cfg.RTTMin = d
		cfg.RTTMax = d
	}
	for _, step := range []struct {
		key string
		dst *time.Duration
	}{
		{"buffer-min", &cfg.BufferMin},
		{"buffer-max", &cfg.BufferMax},
		{"rtt-min", &cfg.RTTMin},
		{"rtt-max", &cfg.RTTMax},
		{"reorder-buffer", &cfg.ReorderBuffer},
		{"session-timeout", &cfg.SessionTimeout},
		{"keepalive", &cfg.KeepaliveInterval},          // ristgo alias
		{"keepalive-interval", &cfg.KeepaliveInterval}, // libRIST canonical key (wins on conflict)
	} {
		if err := ms(step.key, step.dst); err != nil {
			return err
		}
	}
	for _, step := range []struct {
		key string
		dst *int
	}{
		{"rtt-multiplier", &cfg.RTTMultiplier},
		{"bandwidth", &cfg.MaxBitrate},
		{"return-bandwidth", &cfg.ReturnBandwidth},
		{"weight", &cfg.Weight},
		{"aes-type", &cfg.AESKeyBits},
		{"key-rotation", &cfg.KeyRotation},
		{"min-retries", &cfg.MinRetries},
		{"max-retries", &cfg.MaxRetries},
	} {
		if err := intVal(step.key, step.dst); err != nil {
			return err
		}
	}
	for _, step := range []struct {
		key string
		dst *uint16
	}{
		{"virt-dst-port", &cfg.VirtDstPort},
		{"virt-src-port", &cfg.VirtSrcPort},
	} {
		v := q.Get(step.key)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("%w: %s=%q is not a valid port", ErrInvalidConfig, step.key, v)
		}
		*step.dst = uint16(n)
	}
	if v := q.Get("profile"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%w: profile=%q is not an integer", ErrInvalidConfig, v)
		}
		cfg.Profile = Profile(n)
	}
	if v := q.Get("cname"); v != "" {
		cfg.CNAME = v
	}
	if v := q.Get("secret"); v != "" {
		cfg.Secret = v
	}
	if v := q.Get("username"); v != "" {
		cfg.Username = v
	}
	if v := q.Get("password"); v != "" {
		cfg.Password = v
	}
	if v := q.Get("compression"); v != "" {
		cfg.Compression = v != "0"
	}

	// Multicast options (libRIST: miface, ttl; SSM source filter: source).
	if v := q.Get("miface"); v != "" {
		cfg.Interface = v
	}
	if v := q.Get("ttl"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 255 {
			return fmt.Errorf("%w: ttl=%q must be an integer in 0..255", ErrInvalidConfig, v)
		}
		cfg.MulticastTTL = n
	}
	if v := q.Get("source"); v != "" {
		cfg.MulticastSource = v
	}

	// congestion-control uses libRIST's numbering (0=off, 1=normal, 2=aggressive),
	// mapped to ristgo's zero-is-default CongestionControl encoding.
	if v := q.Get("congestion-control"); v != "" {
		switch v {
		case "0":
			cfg.CongestionControl = CongestionOff
		case "1":
			cfg.CongestionControl = CongestionNormal
		case "2":
			cfg.CongestionControl = CongestionAggressive
		default:
			return fmt.Errorf("%w: congestion-control=%q must be 0 (off), 1 (normal), or 2 (aggressive)", ErrInvalidConfig, v)
		}
	}

	// timing-mode uses libRIST's numbering (0=source, 1=arrival, 2=rtc). ristgo
	// has no wall-clock source, so rtc maps to arrival.
	if v := q.Get("timing-mode"); v != "" {
		switch v {
		case "0":
			cfg.TimingMode = TimingSource
		case "1", "2":
			cfg.TimingMode = TimingArrival
		default:
			return fmt.Errorf("%w: timing-mode=%q must be 0 (source), 1 (arrival), or 2 (rtc)", ErrInvalidConfig, v)
		}
	}

	// srp-compat=1 selects the legacy pre-0.2.16 SRP mode (any non-zero value).
	if v := q.Get("srp-compat"); v != "" {
		cfg.SRPCompat = v != "0"
	}

	// split (sender) and merge (receiver) are libRIST's packet-split bonding modes,
	// spelled as words (not numbers): split=off|auto|half (ts is an alias for auto)
	// and merge=off|pairs|auto.
	if v := q.Get("split"); v != "" {
		switch v {
		case "off":
			cfg.SplitMode = SplitOff
		case "auto", "ts":
			cfg.SplitMode = SplitAuto
		case "half":
			cfg.SplitMode = SplitHalf
		default:
			return fmt.Errorf("%w: split=%q must be off, auto, or half", ErrInvalidConfig, v)
		}
	}
	if v := q.Get("merge"); v != "" {
		switch v {
		case "off":
			cfg.MergeMode = MergeOff
		case "pairs":
			cfg.MergeMode = MergePairs
		case "auto":
			cfg.MergeMode = MergeAuto
		default:
			return fmt.Errorf("%w: merge=%q must be off, pairs, or auto", ErrInvalidConfig, v)
		}
	}

	// Reject genuinely unknown parameters (a typo like "reoder-buffer"), matching
	// libRIST's parse_url_options which fails on an unrecognized key rather than
	// silently using a default. Keys libRIST honors but ristgo does not yet
	// implement are in recognizedURLParams (accepted and ignored), so a URL
	// written for libRIST still parses.
	for key := range q {
		if !recognizedURLParams[key] {
			return fmt.Errorf("%w: unknown parameter %q", ErrInvalidConfig, key)
		}
	}
	return nil
}

// recognizedURLParams is the set of rist:// query parameters ParseURL accepts.
// It contains every key applyQuery acts on PLUS the libRIST parameters ristgo
// does not yet implement but tolerates (accept-and-ignore) so a URL authored for
// libRIST is not rejected over an unsupported-but-valid option. Any key absent
// here is treated as a typo and rejected (see applyQuery), matching libRIST.
var recognizedURLParams = map[string]bool{
	// Handled by applyQuery.
	"buffer": true, "buffer-min": true, "buffer-max": true,
	"rtt": true, "rtt-min": true, "rtt-max": true, "rtt-multiplier": true,
	"reorder-buffer": true, "session-timeout": true,
	"keepalive": true, "keepalive-interval": true,
	"bandwidth": true, "weight": true, "aes-type": true, "key-rotation": true,
	"min-retries": true, "max-retries": true,
	"virt-src-port": true, "virt-dst-port": true,
	"profile": true, "cname": true, "secret": true,
	"username": true, "password": true, "compression": true,
	"miface": true, "ttl": true, "source": true,
	"congestion-control": true, "timing-mode": true, "srp-compat": true,
	"return-bandwidth": true, "split": true, "merge": true,
	// Recognized by libRIST but not implemented as a rist:// query parameter by
	// ristgo: recovery-priority is a PER-PEER NACK priority, only meaningful
	// across bonded peers, set via the BondedPeer API (NewBondedReceiverPeers),
	// not a single per-session URL value — so it is accepted and ignored here.
	"recovery-priority": true,
	// reflector (Main one-to-many fan-out) and local-port (caller fixed source
	// port) are libRIST URL parameters ristgo does not implement. They are
	// accepted and ignored rather than rejected so a URL authored for libRIST
	// still parses, matching the recovery-priority treatment above — the
	// alternative (a hard parse error on a valid libRIST URL) is the worse
	// failure for URL portability.
	"reflector": true, "local-port": true,
}
