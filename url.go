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
//	bandwidth   (kbps)        aes-type   (128/256)
//	cname, secret, username, password, compression, profile,
//	virt-src-port, virt-dst-port
//
// "keepalive" is also accepted as a ristgo alias for "keepalive-interval".
// "buffer" sets both buffer-min and buffer-max, and "rtt" sets both rtt-min
// and rtt-max; an explicit -min/-max always wins regardless of URL order
// (net/url discards order — a deliberate simplification of libRIST's
// order-dependent parsing). A bare "host:port" (no scheme) is accepted and
// returned unchanged. Unknown query parameters are ignored, matching libRIST.
func ParseURL(rawURL string, cfg Config) (addr string, out Config, err error) {
	if !strings.Contains(rawURL, "://") {
		return rawURL, cfg, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", cfg, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
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
	ms := func(key string, dst *time.Duration) error {
		v := q.Get(key)
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%w: %s=%q is not an integer", ErrInvalidConfig, key, v)
		}
		*dst = time.Duration(n) * time.Millisecond
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
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%w: buffer=%q is not an integer", ErrInvalidConfig, v)
		}
		cfg.BufferMin = time.Duration(n) * time.Millisecond
		cfg.BufferMax = cfg.BufferMin
	}
	if v := q.Get("rtt"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%w: rtt=%q is not an integer", ErrInvalidConfig, v)
		}
		cfg.RTTMin = time.Duration(n) * time.Millisecond
		cfg.RTTMax = cfg.RTTMin
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
	return nil
}
