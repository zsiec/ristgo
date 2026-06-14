package adapt

// Controller turns Link Quality Messages into encoder bit-rate targets. It is a
// deterministic AIMD (additive-increase / multiplicative-decrease) loop, the
// shape of the algorithm examples in TR-06-4 Part 1 §6 (informative): when the
// reported original-loss rate is at or below a small target it probes the rate
// up by a fixed step; above the target it cuts the rate multiplicatively, by an
// amount that GROWS with the loss — so the next target is monotonically
// non-increasing in the observed loss. Clamped to [MinKbps, MaxKbps].
//
// It owns no clock and no I/O: the host calls Observe once per received LQM and
// hands the returned target to the application's encoder-rate callback. That
// keeps the policy exhaustively testable, including the closed-loop behaviour
// against a simulated link.
type Controller struct {
	cfg     ControllerConfig
	current int
}

// ControllerConfig parameterizes the AIMD loop. The zero value is not valid;
// use DefaultControllerConfig and adjust.
type ControllerConfig struct {
	// MinKbps and MaxKbps bound the target. MaxKbps defaults to the libRIST
	// recovery_maxbitrate (100000 kbps = 100 Mbps).
	MinKbps int
	MaxKbps int
	// InitialKbps is the starting target.
	InitialKbps int
	// TargetLoss is the original-loss fraction at or below which the controller
	// probes the rate up; above it the controller backs off.
	TargetLoss float64
	// IncreaseKbps is the additive step taken per at-or-below-target report.
	IncreaseKbps int
	// DecreaseGain scales the multiplicative cut with the loss above target:
	// cut = DecreaseGain * (loss - TargetLoss), capped at maxCut.
	DecreaseGain float64
}

// maxCut bounds a single multiplicative decrease so one bad report cannot
// collapse the rate straight to the floor.
const maxCut = 0.90

// DefaultControllerConfig returns sensible defaults: probe up by 1% of the
// 100 Mbps ceiling per clean report, back off multiplicatively above a 0.5%
// loss target, with a 500 kbps floor.
func DefaultControllerConfig() ControllerConfig {
	const maxKbps = 100_000 // recovery_maxbitrate (libRIST default)
	return ControllerConfig{
		MinKbps:      500,
		MaxKbps:      maxKbps,
		InitialKbps:  maxKbps,
		TargetLoss:   0.005,
		IncreaseKbps: maxKbps / 100,
		DecreaseGain: 8.0,
	}
}

// NewController builds a Controller. It normalizes a misconfigured config so the
// target bounds are always sane (no panics, matching the library style): a
// negative floor becomes 0, a ceiling below the floor is raised to the floor (a
// fixed-rate degenerate case), and a negative increase step becomes 0. The
// initial target is clamped into range.
func NewController(cfg ControllerConfig) *Controller {
	if cfg.MinKbps < 0 {
		cfg.MinKbps = 0
	}
	if cfg.MaxKbps < cfg.MinKbps {
		cfg.MaxKbps = cfg.MinKbps
	}
	if cfg.IncreaseKbps < 0 {
		cfg.IncreaseKbps = 0
	}
	c := &Controller{cfg: cfg, current: clampKbps(cfg.InitialKbps, cfg.MinKbps, cfg.MaxKbps)}
	return c
}

// Target returns the current rate target in kbps.
func (c *Controller) Target() int { return c.current }

// Observe folds one reported loss fraction into the target and returns the new
// target. It is monotonically non-increasing in loss: for any current rate, a
// larger loss yields a target no greater than a smaller loss would.
func (c *Controller) Observe(lossFraction float64) int {
	if lossFraction < 0 {
		lossFraction = 0
	}
	if lossFraction <= c.cfg.TargetLoss {
		c.current = clampKbps(c.current+c.cfg.IncreaseKbps, c.cfg.MinKbps, c.cfg.MaxKbps)
		return c.current
	}
	cut := c.cfg.DecreaseGain * (lossFraction - c.cfg.TargetLoss)
	if cut > maxCut {
		cut = maxCut
	}
	c.current = clampKbps(int(float64(c.current)*(1-cut)), c.cfg.MinKbps, c.cfg.MaxKbps)
	return c.current
}

// ObserveLQM folds one Link Quality Message into the target using the two-signal
// rule of the TR-06-4 Part 1 §6.1 encoder rate-adaptation example: probe the
// rate UP only when "the number of unrecovered packets is zero AND the number
// of lost packets is less than a certain level", and back OFF when "the number
// of unrecovered packets is non-zero OR the number of lost packets is higher
// than a certain level". Adapting on raw original loss alone (as a single-signal
// Observe(LossFraction) would) is wrong: it lets the encoder climb while the
// receiver is dropping unrecoverable packets whenever the loss is spread thinly
// enough to stay under the target.
//
// A report that accounts for no packets at all (a total stall/blackout) carries
// no information about the link, so the target is held rather than probed up —
// otherwise a dead link reads as "clean" and the controller ratchets the rate
// toward the ceiling, the worst possible reaction.
func (c *Controller) ObserveLQM(m LQM) int {
	if m.SourceReceived == 0 && m.OriginalLost == 0 && m.Unrecovered == 0 {
		return c.current // no accounting this period: no information, hold
	}
	origLoss := m.LossFraction()
	if m.Unrecovered == 0 && origLoss <= c.cfg.TargetLoss {
		c.current = clampKbps(c.current+c.cfg.IncreaseKbps, c.cfg.MinKbps, c.cfg.MaxKbps)
		return c.current
	}
	// Back off, scaling the multiplicative cut by the worse of the residual
	// (unrecovered) loss and the original loss above target, so a link dropping
	// unrecoverable packets cuts even when raw loss is thin.
	severity := m.ResidualLossFraction()
	if over := origLoss - c.cfg.TargetLoss; over > severity {
		severity = over
	}
	cut := c.cfg.DecreaseGain * severity
	if cut > maxCut {
		cut = maxCut
	}
	if cut < 0 {
		cut = 0
	}
	c.current = clampKbps(int(float64(c.current)*(1-cut)), c.cfg.MinKbps, c.cfg.MaxKbps)
	return c.current
}

func clampKbps(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
