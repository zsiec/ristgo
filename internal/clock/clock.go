// Package clock provides type-safe time abstractions for RIST.
//
// RIST timing is microsecond-precision internally. On the wire, RTP
// timestamps are 32-bit unsigned integers that wrap, and RTCP Sender
// Reports plus RIST RTT Echo messages carry 64-bit NTP timestamps.
// This package provides a Clock interface to enable deterministic
// testing, the internal Timestamp/Microseconds types, 32-bit wrap
// reconstruction, and NTP-64 conversions.
package clock

import "time"

// Clock provides the current time. Use RealClock for production and
// MockClock for testing.
type Clock interface {
	Now() Timestamp
}

// RealClock uses the system clock. Because the epoch is captured with
// time.Now, readings use the monotonic clock and are immune to
// wall-clock adjustments.
type RealClock struct {
	epoch time.Time
}

// NewRealClock returns a Clock based on the system clock.
// The epoch is set to the time of creation; all timestamps are
// relative to this epoch.
func NewRealClock() *RealClock {
	return &RealClock{epoch: time.Now()}
}

// Now returns the elapsed time since the epoch in microseconds.
func (c *RealClock) Now() Timestamp {
	return Timestamp(time.Since(c.epoch).Microseconds())
}

// MockClock is a clock for testing that advances only when told to.
type MockClock struct {
	now Timestamp
}

// NewMockClock returns a mock clock starting at time 0.
func NewMockClock() *MockClock {
	return &MockClock{}
}

// Now returns the mock clock's current timestamp.
func (c *MockClock) Now() Timestamp {
	return c.now
}

// Set sets the mock clock to the given timestamp.
func (c *MockClock) Set(t Timestamp) {
	c.now = t
}

// Advance moves the mock clock forward by d microseconds.
func (c *MockClock) Advance(d Microseconds) {
	c.now = c.now.Add(d)
}
