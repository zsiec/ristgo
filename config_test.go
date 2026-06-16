package ristgo

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestDefaultConfig asserts every DefaultConfig field against hand-written
// values taken from libRIST. If any of these drift,
// interoperability with libRIST is at risk.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name string
		got  any
		want any
	}{
		// libRIST RIST_DEFAULT_PROFILE is RIST_PROFILE_MAIN; ristgo
		// deliberately deviates to ProfileSimple until Main exists.
		{"Profile", cfg.Profile, ProfileSimple},
		{"BufferMin", cfg.BufferMin, 1000 * time.Millisecond},                 // RIST_DEFAULT_RECOVERY_LENGTH_MIN (1000)
		{"BufferMax", cfg.BufferMax, 1000 * time.Millisecond},                 // RIST_DEFAULT_RECOVERY_LENGTH_MAX (1000)
		{"ReorderBuffer", cfg.ReorderBuffer, 15 * time.Millisecond},           // RIST_DEFAULT_RECOVERY_REORDER_BUFFER (15)
		{"RTTMin", cfg.RTTMin, 5 * time.Millisecond},                          // RIST_DEFAULT_RECOVERY_RTT_MIN (5)
		{"RTTMax", cfg.RTTMax, 500 * time.Millisecond},                        // RIST_DEFAULT_RECOVERY_RTT_MAX (500)
		{"RTTMultiplier", cfg.RTTMultiplier, 7},                               // libRIST recovery_rtt_multiplier = 7
		{"MinRetries", cfg.MinRetries, 6},                                     // RIST_DEFAULT_MIN_RETRIES (6)
		{"MaxRetries", cfg.MaxRetries, 20},                                    // RIST_DEFAULT_MAX_RETRIES (20)
		{"SessionTimeout", cfg.SessionTimeout, 2000 * time.Millisecond},       // RIST_DEFAULT_SESSION_TIMEOUT (2000)
		{"KeepaliveInterval", cfg.KeepaliveInterval, 1000 * time.Millisecond}, // RIST_DEFAULT_KEEPALIVE_INTERVAL (1000)
		{"MaxBitrate", cfg.MaxBitrate, 100000},                                // RIST_DEFAULT_RECOVERY_MAXBITRATE (100000 kbps)
		{"VirtSrcPort", cfg.VirtSrcPort, uint16(1971)},                        // RIST_DEFAULT_VIRT_SRC_PORT (1971)
		{"VirtDstPort", cfg.VirtDstPort, uint16(1968)},                        // RIST_DEFAULT_VIRT_DST_PORT (1968)
		{"NACKType", cfg.NACKType, NACKRange},                                 // default NACK type = RANGE
		{"CongestionControl", cfg.CongestionControl, CongestionNormal},        // default congestion_control = NORMAL
		{"TimingMode", cfg.TimingMode, TimingSource},                          // default timing_mode = SOURCE
		{"CNAME", cfg.CNAME, ""},
		{"Secret", cfg.Secret, ""},
		{"AESKeyBits", cfg.AESKeyBits, 0},
		{"KeyRotation", cfg.KeyRotation, 0},
		{"Username", cfg.Username, ""},
		{"Password", cfg.Password, ""},
		{"Compression", cfg.Compression, false},
		{"Weight", cfg.Weight, 0}, // RIST_PEER_WEIGHT_DUPLICATE (0)
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
		}
	}
	if cfg.Logger != nil {
		t.Errorf("Logger: got %v, want nil", cfg.Logger)
	}
}

// TestDefaultConstants pins the exported Default* constants to the
// hand-written values, independently of DefaultConfig.
func TestDefaultConstants(t *testing.T) {
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"DefaultBufferMin", DefaultBufferMin, 1000 * time.Millisecond},
		{"DefaultBufferMax", DefaultBufferMax, 1000 * time.Millisecond},
		{"DefaultReorderBuffer", DefaultReorderBuffer, 15 * time.Millisecond},
		{"DefaultRTTMin", DefaultRTTMin, 5 * time.Millisecond},
		{"DefaultRTTMax", DefaultRTTMax, 500 * time.Millisecond},
		{"DefaultRTTMultiplier", DefaultRTTMultiplier, 7},
		{"DefaultMinRetries", DefaultMinRetries, 6},
		{"DefaultMaxRetries", DefaultMaxRetries, 20},
		{"DefaultSessionTimeout", DefaultSessionTimeout, 2000 * time.Millisecond},
		{"DefaultKeepaliveInterval", DefaultKeepaliveInterval, 1000 * time.Millisecond},
		{"DefaultMaxBitrate", DefaultMaxBitrate, 100000},
		{"DefaultVirtSrcPort", DefaultVirtSrcPort, 1971},
		{"DefaultVirtDstPort", DefaultVirtDstPort, 1968},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

// TestProfileValues pins the Profile constants to libRIST's enum
// rist_profile values.
func TestProfileValues(t *testing.T) {
	if ProfileSimple != 0 {
		t.Errorf("ProfileSimple = %d, want 0", ProfileSimple)
	}
	if ProfileMain != 1 {
		t.Errorf("ProfileMain = %d, want 1", ProfileMain)
	}
	if ProfileAdvanced != 2 {
		t.Errorf("ProfileAdvanced = %d, want 2", ProfileAdvanced)
	}
}

// TestNACKTypeValues pins the NACKType constants.
func TestNACKTypeValues(t *testing.T) {
	if NACKRange != 0 {
		t.Errorf("NACKRange = %d, want 0", NACKRange)
	}
	if NACKBitmask != 1 {
		t.Errorf("NACKBitmask = %d, want 1", NACKBitmask)
	}
}

func TestProfileString(t *testing.T) {
	tests := []struct {
		profile Profile
		want    string
	}{
		{ProfileSimple, "simple"},
		{ProfileMain, "main"},
		{ProfileAdvanced, "advanced"},
		{Profile(3), "unknown"},
		{Profile(-1), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.profile.String(); got != tt.want {
			t.Errorf("Profile(%d).String() = %q, want %q", int(tt.profile), got, tt.want)
		}
	}
}

func TestNACKTypeString(t *testing.T) {
	tests := []struct {
		nack NACKType
		want string
	}{
		{NACKRange, "range"},
		{NACKBitmask, "bitmask"},
		{NACKType(2), "unknown"},
		{NACKType(-1), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.nack.String(); got != tt.want {
			t.Errorf("NACKType(%d).String() = %q, want %q", int(tt.nack), got, tt.want)
		}
	}
}

// TestDefaultConfigValidates verifies DefaultConfig passes validation and
// that validation does not alter any of its values.
func TestDefaultConfigValidates(t *testing.T) {
	cfg := DefaultConfig()
	validated := cfg
	if err := validated.validate(); err != nil {
		t.Fatalf("DefaultConfig().validate() = %v, want nil", err)
	}
	if !reflect.DeepEqual(validated, cfg) {
		t.Errorf("validate() altered DefaultConfig: got %+v, want %+v", validated, cfg)
	}
}

// TestValidateZeroConfig verifies that validating a zero Config fills in
// exactly the same values DefaultConfig returns.
func TestValidateZeroConfig(t *testing.T) {
	cfg := Config{}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate zero config: %v", err)
	}
	if want := DefaultConfig(); !reflect.DeepEqual(cfg, want) {
		t.Errorf("validated zero config = %+v, want %+v", cfg, want)
	}
}

// TestValidatePreservesExplicitValues verifies that valid non-default
// values survive validation untouched.
func TestValidatePreservesExplicitValues(t *testing.T) {
	cfg := Config{
		Profile:           ProfileMain,
		BufferMin:         200 * time.Millisecond,
		BufferMax:         400 * time.Millisecond,
		ReorderBuffer:     25 * time.Millisecond,
		RTTMin:            10 * time.Millisecond,
		RTTMax:            300 * time.Millisecond,
		RTTMultiplier:     5,
		MinRetries:        3,
		MaxRetries:        10,
		SessionTimeout:    5 * time.Second,
		KeepaliveInterval: 500 * time.Millisecond,
		MaxBitrate:        20000,
		VirtSrcPort:       4000,
		VirtDstPort:       4002,
		CNAME:             "encoder-1",
		NACKType:          NACKBitmask,
		Secret:            "opensesame",
		AESKeyBits:        128,
		KeyRotation:       4096,
		Username:          "user",
		Password:          "pass",
		Weight:            5,
	}
	want := cfg
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("validate() altered explicit values: got %+v, want %+v", cfg, want)
	}

	// Compression is Advanced-only, so it cannot coexist with the Main-profile
	// credentials above; verify it survives validation under ProfileAdvanced.
	adv := Config{Profile: ProfileAdvanced, Secret: "opensesame", AESKeyBits: 256, Compression: true}
	wantAdv := adv
	if err := adv.validate(); err != nil {
		t.Fatalf("validate advanced: %v", err)
	}
	if adv.Compression != wantAdv.Compression {
		t.Errorf("validate() altered Compression: got %v, want %v", adv.Compression, wantAdv.Compression)
	}
}

// TestConfigValidate is the accept/reject matrix. Each case mutates a zero
// Config (so untouched fields take defaults) and asserts the exact error.
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // "" means accept
	}{
		// Profile
		{"profile simple", func(c *Config) { c.Profile = ProfileSimple }, ""},
		{"profile main", func(c *Config) { c.Profile = ProfileMain }, ""},
		{"profile advanced", func(c *Config) { c.Profile = ProfileAdvanced }, ""},
		{"profile too large", func(c *Config) { c.Profile = Profile(3) },
			"rist: Profile must be ProfileSimple (0), ProfileMain (1), or ProfileAdvanced (2)"},
		{"profile negative", func(c *Config) { c.Profile = Profile(-1) },
			"rist: Profile must be ProfileSimple (0), ProfileMain (1), or ProfileAdvanced (2)"},

		// BufferMin / BufferMax
		{"buffer min boundary 50ms", func(c *Config) { c.BufferMin = 50 * time.Millisecond }, ""},
		{"buffer max boundary 30s", func(c *Config) {
			c.BufferMin = 30 * time.Second
			c.BufferMax = 30 * time.Second
		}, ""},
		{"buffer min too small", func(c *Config) { c.BufferMin = 49 * time.Millisecond },
			"rist: BufferMin must be between 50ms and 30s"},
		{"buffer min too large", func(c *Config) {
			c.BufferMin = 31 * time.Second
			c.BufferMax = 31 * time.Second
		}, "rist: BufferMin must be between 50ms and 30s"},
		{"buffer min negative", func(c *Config) { c.BufferMin = -time.Second },
			"rist: BufferMin must be between 50ms and 30s"},
		{"buffer max too small", func(c *Config) {
			c.BufferMin = 50 * time.Millisecond
			c.BufferMax = 49 * time.Millisecond
		}, "rist: BufferMax must be between 50ms and 30s"},
		{"buffer max too large", func(c *Config) { c.BufferMax = 31 * time.Second },
			"rist: BufferMax must be between 50ms and 30s"},
		{"buffer min above max", func(c *Config) {
			c.BufferMin = 2 * time.Second
			c.BufferMax = 1 * time.Second
		}, "rist: BufferMin must not exceed BufferMax"},
		{"asymmetric window", func(c *Config) {
			c.BufferMin = 500 * time.Millisecond
			c.BufferMax = 2 * time.Second
		}, ""},

		// ReorderBuffer
		{"reorder boundary equals BufferMin", func(c *Config) { c.ReorderBuffer = 1000 * time.Millisecond }, ""},
		{"reorder above BufferMin", func(c *Config) { c.ReorderBuffer = 1001 * time.Millisecond },
			"rist: ReorderBuffer must be between 0 and BufferMin"},
		{"reorder negative", func(c *Config) { c.ReorderBuffer = -time.Millisecond },
			"rist: ReorderBuffer must be between 0 and BufferMin"},
		{"reorder ok with small buffer", func(c *Config) {
			c.BufferMin = 50 * time.Millisecond
			c.BufferMax = 50 * time.Millisecond
			c.ReorderBuffer = 50 * time.Millisecond
		}, ""},
		{"reorder default above small buffer", func(c *Config) {
			// zero ReorderBuffer defaults to 15ms, within the 50ms floor
			c.BufferMin = 50 * time.Millisecond
			c.BufferMax = 50 * time.Millisecond
		}, ""},

		// RTTMin / RTTMax
		{"rtt min boundary 1ms", func(c *Config) { c.RTTMin = 1 * time.Millisecond }, ""},
		{"rtt max boundary 1s", func(c *Config) { c.RTTMax = 1 * time.Second }, ""},
		{"rtt min equals max", func(c *Config) {
			c.RTTMin = 100 * time.Millisecond
			c.RTTMax = 100 * time.Millisecond
		}, ""},
		{"rtt min sub-millisecond", func(c *Config) { c.RTTMin = 500 * time.Microsecond },
			"rist: RTTMin must be between 1ms and 1s"},
		{"rtt min negative", func(c *Config) { c.RTTMin = -time.Millisecond },
			"rist: RTTMin must be between 1ms and 1s"},
		{"rtt min too large", func(c *Config) { c.RTTMin = 2 * time.Second },
			"rist: RTTMin must be between 1ms and 1s"},
		{"rtt max too large", func(c *Config) { c.RTTMax = 2 * time.Second },
			"rist: RTTMax must be between 1ms and 1s"},
		{"rtt max sub-millisecond", func(c *Config) {
			c.RTTMin = 1 * time.Millisecond
			c.RTTMax = 500 * time.Microsecond
		}, "rist: RTTMax must be between 1ms and 1s"},
		{"rtt min above max", func(c *Config) {
			c.RTTMin = 600 * time.Millisecond
			c.RTTMax = 500 * time.Millisecond
		}, "rist: RTTMin must not exceed RTTMax"},
		{"rtt min above default max", func(c *Config) { c.RTTMin = 600 * time.Millisecond },
			"rist: RTTMin must not exceed RTTMax"},

		// RTTMultiplier
		{"rtt multiplier boundary 1", func(c *Config) { c.RTTMultiplier = 1 }, ""},
		{"rtt multiplier boundary 100", func(c *Config) { c.RTTMultiplier = 100 }, ""},
		{"rtt multiplier negative", func(c *Config) { c.RTTMultiplier = -1 },
			"rist: RTTMultiplier must be between 1 and 100"},
		{"rtt multiplier too large", func(c *Config) { c.RTTMultiplier = 101 },
			"rist: RTTMultiplier must be between 1 and 100"},

		// MinRetries / MaxRetries
		{"retries boundary 100/100", func(c *Config) {
			c.MinRetries = 100
			c.MaxRetries = 100
		}, ""},
		{"retries equal", func(c *Config) {
			c.MinRetries = 10
			c.MaxRetries = 10
		}, ""},
		{"min retries negative", func(c *Config) { c.MinRetries = -1 },
			"rist: MinRetries must be between 0 and 100"},
		{"min retries too large", func(c *Config) {
			c.MinRetries = 101
			c.MaxRetries = 101
		}, "rist: MinRetries must be between 0 and 100"},
		{"max retries negative", func(c *Config) { c.MaxRetries = -1 },
			"rist: MaxRetries must be between 0 and 100"},
		{"max retries too large", func(c *Config) { c.MaxRetries = 101 },
			"rist: MaxRetries must be between 0 and 100"},
		{"min retries above max", func(c *Config) {
			c.MinRetries = 10
			c.MaxRetries = 5
		}, "rist: MinRetries must not exceed MaxRetries"},
		{"min retries above default max", func(c *Config) { c.MinRetries = 21 },
			"rist: MinRetries must not exceed MaxRetries"},

		// SessionTimeout / KeepaliveInterval
		{"session timeout negative", func(c *Config) { c.SessionTimeout = -time.Second },
			"rist: SessionTimeout must be positive"},
		{"keepalive negative", func(c *Config) { c.KeepaliveInterval = -time.Second },
			"rist: KeepaliveInterval must be positive"},
		{"keepalive equals session timeout", func(c *Config) {
			c.SessionTimeout = time.Second
			c.KeepaliveInterval = time.Second
		}, ""},
		{"keepalive above session timeout", func(c *Config) {
			c.SessionTimeout = time.Second
			c.KeepaliveInterval = 2 * time.Second
		}, "rist: KeepaliveInterval must not exceed SessionTimeout"},
		{"short session timeout below default keepalive", func(c *Config) {
			// default KeepaliveInterval (1000ms) > 500ms
			c.SessionTimeout = 500 * time.Millisecond
		}, "rist: KeepaliveInterval must not exceed SessionTimeout"},
		{"long session timeout", func(c *Config) { c.SessionTimeout = time.Minute }, ""},

		// MaxBitrate
		{"bitrate 1 kbps", func(c *Config) { c.MaxBitrate = 1 }, ""},
		{"bitrate negative", func(c *Config) { c.MaxBitrate = -1 },
			"rist: MaxBitrate must be positive (kbps)"},

		// Ports (uint16: any non-zero value is valid; zero takes defaults)
		{"explicit virtual ports", func(c *Config) {
			c.VirtSrcPort = 4000
			c.VirtDstPort = 4002
		}, ""},

		// CNAME
		{"cname boundary 127 bytes", func(c *Config) { c.CNAME = strings.Repeat("a", 127) }, ""},
		{"cname too long", func(c *Config) { c.CNAME = strings.Repeat("a", 128) },
			"rist: CNAME must be at most 127 bytes"},

		// NACKType
		{"nack bitmask", func(c *Config) { c.NACKType = NACKBitmask }, ""},
		{"nack invalid", func(c *Config) { c.NACKType = NACKType(2) },
			"rist: NACKType must be NACKRange (0) or NACKBitmask (1)"},
		{"nack negative", func(c *Config) { c.NACKType = NACKType(-1) },
			"rist: NACKType must be NACKRange (0) or NACKBitmask (1)"},
		{"congestion invalid", func(c *Config) { c.CongestionControl = CongestionControl(9) },
			"rist: CongestionControl must be CongestionNormal, CongestionAggressive, or CongestionOff"},
		{"timing-mode invalid", func(c *Config) { c.TimingMode = TimingMode(9) },
			"rist: TimingMode must be TimingSource or TimingArrival"},
		{"return-bandwidth negative", func(c *Config) { c.ReturnBandwidth = -1 },
			"rist: ReturnBandwidth must be at least 0 (kbps; 0 = unlimited)"},

		// Secret / AESKeyBits / KeyRotation (require Main or Advanced)
		{"secret with aes 128", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = "opensesame"
			c.AESKeyBits = 128
		}, ""},
		{"secret with aes 256", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = "opensesame"
			c.AESKeyBits = 256
		}, ""},
		{"secret on advanced", func(c *Config) {
			c.Profile = ProfileAdvanced
			c.Secret = "opensesame"
		}, ""},
		{"secret boundary 127 bytes", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = strings.Repeat("s", 127)
		}, ""},
		{"secret too long", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = strings.Repeat("s", 128)
		}, "rist: Secret must be at most 127 bytes"},
		{"aes 192 rejected", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = "opensesame"
			c.AESKeyBits = 192
		}, "rist: AESKeyBits must be 0, 128, or 256"},
		{"aes bits without secret or srp", func(c *Config) {
			c.Profile = ProfileMain
			c.AESKeyBits = 128
		}, "rist: AESKeyBits requires a Secret or SRP credentials"},
		{"key rotation with secret", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = "opensesame"
			c.KeyRotation = 4096
		}, ""},
		{"key rotation negative", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = "opensesame"
			c.KeyRotation = -1
		}, "rist: KeyRotation must be at least 0 (packets per key)"},

		// Profile-capability gate: security/feature fields fail closed on the
		// wrong profile instead of being silently dropped (the WithSecret-on-
		// Simple cleartext footgun).
		{"secret on simple rejected", func(c *Config) { c.Secret = "opensesame" },
			"rist: Secret (PSK encryption) requires ProfileMain or ProfileAdvanced; the Simple profile transmits in the clear"},
		{"aes on simple rejected", func(c *Config) { c.AESKeyBits = 128 },
			"rist: AESKeyBits requires ProfileMain or ProfileAdvanced"},
		{"key rotation on simple rejected", func(c *Config) { c.KeyRotation = 4096 },
			"rist: KeyRotation requires ProfileMain or ProfileAdvanced"},

		// Username / Password (require Main)
		{"srp credentials", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = "opensesame"
			c.Username = "user"
			c.Password = "pass"
		}, ""},
		{"srp without secret accepted (use_key_as_passphrase)", func(c *Config) {
			c.Profile = ProfileMain
			c.Username = "user"
			c.Password = "pass"
		}, ""},
		{"username without password", func(c *Config) {
			c.Profile = ProfileMain
			c.Username = "user"
		}, "rist: Username and Password must be set together"},
		{"password without username", func(c *Config) {
			c.Profile = ProfileMain
			c.Password = "pass"
		}, "rist: Username and Password must be set together"},
		{"username boundary 255 bytes", func(c *Config) {
			c.Profile = ProfileMain
			c.Secret = "opensesame"
			c.Username = strings.Repeat("u", 255)
			c.Password = "pass"
		}, ""},
		{"username too long", func(c *Config) {
			c.Profile = ProfileMain
			c.Username = strings.Repeat("u", 256)
			c.Password = "pass"
		}, "rist: Username must be at most 255 bytes"},
		{"password too long", func(c *Config) {
			c.Profile = ProfileMain
			c.Username = "user"
			c.Password = strings.Repeat("p", 256)
		}, "rist: Password must be at most 255 bytes"},
		{"credentials on simple rejected", func(c *Config) {
			c.Username = "user"
			c.Password = "pass"
		}, "rist: Username/Password (EAP-SRP authentication) requires ProfileMain"},
		{"credentials on advanced rejected", func(c *Config) {
			c.Profile = ProfileAdvanced
			c.Username = "user"
			c.Password = "pass"
		}, "rist: Username/Password (EAP-SRP authentication) requires ProfileMain"},

		// Compression / Weight
		{"compression enabled", func(c *Config) {
			c.Profile = ProfileAdvanced
			c.Compression = true
		}, ""},
		{"compression on simple rejected", func(c *Config) { c.Compression = true },
			"rist: Compression requires ProfileAdvanced"},
		{"compression on main rejected", func(c *Config) {
			c.Profile = ProfileMain
			c.Compression = true
		}, "rist: Compression requires ProfileAdvanced"},
		{"weight positive", func(c *Config) { c.Weight = 5 }, ""},
		{"weight negative", func(c *Config) { c.Weight = -1 },
			"rist: Weight must be at least 0 (0 = duplicate)"},

		// Null-packet deletion: Main profile only.
		{"npd on main", func(c *Config) {
			c.Profile = ProfileMain
			c.NullPacketDeletion = true
		}, ""},
		{"npd on simple rejected", func(c *Config) { c.NullPacketDeletion = true },
			"rist: NullPacketDeletion requires ProfileMain"},
		{"npd on advanced rejected", func(c *Config) {
			c.Profile = ProfileAdvanced
			c.NullPacketDeletion = true
		}, "rist: NullPacketDeletion requires ProfileMain"},

		// Multicast: MulticastTTL range (0..255), MulticastLoopback always OK.
		{"multicast ttl zero (OS default)", func(c *Config) { c.MulticastTTL = 0 }, ""},
		{"multicast ttl mid", func(c *Config) { c.MulticastTTL = 32 }, ""},
		{"multicast ttl max", func(c *Config) { c.MulticastTTL = 255 }, ""},
		{"multicast ttl too large", func(c *Config) { c.MulticastTTL = 256 },
			"rist: MulticastTTL must be between 0 and 255 (0 = OS default of 1)"},
		{"multicast ttl negative", func(c *Config) { c.MulticastTTL = -1 },
			"rist: MulticastTTL must be between 0 and 255 (0 = OS default of 1)"},
		{"multicast loopback set", func(c *Config) { c.MulticastLoopback = true }, ""},
		{"multicast source valid ip", func(c *Config) { c.MulticastSource = "10.0.0.1" }, ""},
		{"multicast source valid ipv6", func(c *Config) { c.MulticastSource = "fe80::1" }, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{}
			tt.mutate(&cfg)
			err := cfg.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate() = nil, want %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("validate() = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestValidateMulticastInterfaceAndSource verifies the multicast field checks
// whose error text is OS/input-dependent: a non-existent Interface name and a
// MulticastSource that is not a valid IP are both rejected with a "rist: "-
// prefixed error.
func TestValidateMulticastInterfaceAndSource(t *testing.T) {
	t.Run("bad interface", func(t *testing.T) {
		cfg := Config{Interface: "no-such-iface-xyz-12345"}
		err := cfg.validate()
		if err == nil {
			t.Fatal("validate() = nil, want an interface-not-found error")
		}
		if !strings.HasPrefix(err.Error(), "rist: Interface ") {
			t.Fatalf("validate() = %q, want a \"rist: Interface \" error", err.Error())
		}
	})
	t.Run("bad multicast source", func(t *testing.T) {
		cfg := Config{MulticastSource: "not-an-ip"}
		err := cfg.validate()
		if err == nil {
			t.Fatal("validate() = nil, want a MulticastSource parse error")
		}
		if !strings.HasPrefix(err.Error(), "rist: MulticastSource must be an IP address") {
			t.Fatalf("validate() = %q, want a \"rist: MulticastSource...\" error", err.Error())
		}
	})
}

// TestValidateErrorPrefix verifies every validation error carries the
// "rist: " prefix.
func TestValidateErrorPrefix(t *testing.T) {
	bad := []func(*Config){
		func(c *Config) { c.Profile = Profile(9) },
		func(c *Config) { c.BufferMin = time.Millisecond },
		func(c *Config) { c.ReorderBuffer = -1 },
		func(c *Config) { c.RTTMin = 2 * time.Second },
		func(c *Config) { c.RTTMultiplier = -1 },
		func(c *Config) { c.MinRetries = -1 },
		func(c *Config) { c.SessionTimeout = -1 },
		func(c *Config) { c.MaxBitrate = -1 },
		func(c *Config) { c.NACKType = NACKType(7) },
		func(c *Config) { c.AESKeyBits = 64 },
		func(c *Config) { c.Weight = -1 },
	}
	for i, mutate := range bad {
		cfg := Config{}
		mutate(&cfg)
		err := cfg.validate()
		if err == nil {
			t.Errorf("case %d: expected error", i)
			continue
		}
		if !strings.HasPrefix(err.Error(), "rist: ") {
			t.Errorf("case %d: error %q missing \"rist: \" prefix", i, err.Error())
		}
	}
}

// TestSecretDefaultsAESKeyBits verifies that a secret without an explicit
// aes-type defaults to 128, matching the libRIST CLI tools (which override the
// library's 256 default to 128 when -e is given without a size).
func TestSecretDefaultsAESKeyBits(t *testing.T) {
	cfg := Config{Profile: ProfileMain, Secret: "opensesame"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.AESKeyBits != 128 {
		t.Errorf("AESKeyBits: got %d, want 128 (libRIST CLI default when aes-type omitted)", cfg.AESKeyBits)
	}

	// An explicit value must be preserved.
	cfg = Config{Profile: ProfileMain, Secret: "opensesame", AESKeyBits: 128}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.AESKeyBits != 128 {
		t.Errorf("AESKeyBits: got %d, want 128 (explicit value)", cfg.AESKeyBits)
	}

	// No secret: stays disabled.
	cfg = Config{}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.AESKeyBits != 0 {
		t.Errorf("AESKeyBits: got %d, want 0 (no secret)", cfg.AESKeyBits)
	}
}

// TestRecoveryBufferTime verifies the derived buffer-time formula
// (BufferMax-BufferMin)/2 + BufferMin against hand-computed values.
func TestRecoveryBufferTime(t *testing.T) {
	tests := []struct {
		name     string
		min, max time.Duration
		want     time.Duration
	}{
		{"librist defaults", 1000 * time.Millisecond, 1000 * time.Millisecond, 1000 * time.Millisecond},
		{"asymmetric", 50 * time.Millisecond, 250 * time.Millisecond, 150 * time.Millisecond},
		{"wide window", 500 * time.Millisecond, 2 * time.Second, 1250 * time.Millisecond},
		{"floor", 50 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{BufferMin: tt.min, BufferMax: tt.max}
			if got := cfg.recoveryBufferTime(); got != tt.want {
				t.Errorf("recoveryBufferTime(%v, %v) = %v, want %v", tt.min, tt.max, got, tt.want)
			}
		})
	}
}

// TestSentinelErrors verifies the sentinel errors exist, are distinct, and
// carry the "rist: " prefix.
func TestSentinelErrors(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrClosed", ErrClosed},
		{"ErrTimeout", ErrTimeout},
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrSessionTimeout", ErrSessionTimeout},
		{"ErrBufferOverflow", ErrBufferOverflow},
	}
	seen := make(map[string]bool)
	for _, s := range sentinels {
		if s.err == nil {
			t.Errorf("%s is nil", s.name)
			continue
		}
		msg := s.err.Error()
		if !strings.HasPrefix(msg, "rist: ") {
			t.Errorf("%s = %q, missing \"rist: \" prefix", s.name, msg)
		}
		if seen[msg] {
			t.Errorf("%s duplicates another sentinel message %q", s.name, msg)
		}
		seen[msg] = true
	}
}

// TestVersion verifies the library version constant is populated.
func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version is empty")
	}
}
