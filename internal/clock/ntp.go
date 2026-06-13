package clock

import "time"

// NTPTime is a 64-bit NTP-format timestamp as carried in RTCP Sender
// Reports and RIST RTT Echo messages: the upper 32 bits count seconds
// since the NTP epoch (1900-01-01 00:00:00 UTC) and the lower 32 bits
// hold the fraction of a second in units of 1/2^32 s (~233 ps
// resolution).
//
// Conversions round to nearest, so a round trip through the coarser
// unit (nanoseconds or microseconds) is exact, and a round trip
// through NTPTime loses at most half an ulp of the coarser unit.
// Seconds outside the 32-bit range wrap, per NTP era semantics.
type NTPTime uint64

// ntpEpochOffset is the number of seconds between the NTP epoch
// (1900-01-01) and the Unix epoch (1970-01-01): 70 years, 17 of them
// leap years.
const ntpEpochOffset = 2208988800

const (
	nsPerSecond = 1_000_000_000
	usPerSecond = 1_000_000
)

// NTPTimeFromTime converts a wall-clock time to NTP-64 format.
// The fraction is rounded to nearest, so nanosecond precision
// round-trips exactly through Time.
func NTPTimeFromTime(t time.Time) NTPTime {
	sec := uint64(t.Unix() + ntpEpochOffset)
	frac := (uint64(t.Nanosecond())<<32 + nsPerSecond/2) / nsPerSecond
	return NTPTime(sec<<32 | frac)
}

// Time converts the NTP timestamp to a wall-clock time in UTC,
// rounded to the nearest nanosecond.
func (n NTPTime) Time() time.Time {
	sec := int64(n>>32) - ntpEpochOffset
	ns := (uint64(uint32(n))*nsPerSecond + 1<<31) >> 32
	return time.Unix(sec, int64(ns)).UTC()
}

// NTPTimeFromTimestamp converts a Timestamp (microseconds since an
// arbitrary epoch) into NTP-64 format relative to that same epoch.
// This is the form RIST RTT Echo requests carry: the peer echoes the
// 64-bit value back verbatim, so the epoch cancels when computing RTT.
// Negative timestamps are clamped to zero.
func NTPTimeFromTimestamp(ts Timestamp) NTPTime {
	if ts < 0 {
		return 0
	}
	sec := uint64(ts) / usPerSecond
	us := uint64(ts) % usPerSecond
	frac := (us<<32 + usPerSecond/2) / usPerSecond
	return NTPTime(sec<<32 | frac)
}

// Timestamp converts the NTP value back into a Timestamp
// (microseconds since the epoch the value was built against),
// rounded to the nearest microsecond.
func (n NTPTime) Timestamp() Timestamp {
	sec := uint64(n >> 32)
	us := (uint64(uint32(n))*usPerSecond + 1<<31) >> 32
	return Timestamp(sec*usPerSecond + us)
}

// Seconds returns the integer-seconds field (upper 32 bits).
func (n NTPTime) Seconds() uint32 {
	return uint32(n >> 32)
}

// Fraction returns the fractional-second field (lower 32 bits),
// in units of 1/2^32 s.
func (n NTPTime) Fraction() uint32 {
	return uint32(n)
}

// Middle32 returns the middle 32 bits of the NTP timestamp: the low
// 16 bits of the seconds field and the high 16 bits of the fraction.
// This is the compact form used by the RTCP LSR and DLSR fields,
// with a resolution of 1/65536 s and a range of ~18.2 hours.
func (n NTPTime) Middle32() uint32 {
	return uint32(n >> 16)
}
