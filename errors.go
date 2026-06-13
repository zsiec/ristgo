package ristgo

import "errors"

// Sentinel errors for common conditions. Callers should test for them
// with errors.Is, as returned errors may wrap these with additional
// context.
var (
	// ErrClosed is returned when operating on a closed Sender or Receiver.
	ErrClosed = errors.New("rist: use of closed connection")

	// ErrTimeout is returned when a blocking operation exceeds its
	// deadline.
	ErrTimeout = errors.New("rist: operation timed out")

	// ErrInvalidConfig is returned by constructors when the supplied
	// Config fails validation. The wrapped message names the offending
	// field and its valid range.
	ErrInvalidConfig = errors.New("rist: invalid configuration")

	// ErrSessionTimeout is returned when no traffic (data, RTCP, or
	// keepalive) has been received from the peer within
	// Config.SessionTimeout and the session is torn down.
	ErrSessionTimeout = errors.New("rist: session timed out")

	// ErrBufferOverflow is returned when an internal buffer cannot accept
	// more data, e.g. the sender's retransmission history or the
	// receiver's recovery buffer is full because the consumer is too slow.
	ErrBufferOverflow = errors.New("rist: buffer overflow")
)
