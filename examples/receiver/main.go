// Command receiver is a minimal RIST receiver example: it receives a stream and
// writes the recovered, in-order media to stdout. Ctrl-C shuts it down cleanly.
//
// Usage:
//
//	receiver ':5000' > out.ts
//	receiver 'rist://:5000?profile=1&secret=passphrase' | ffplay -
//
// The address is the even media port (RTCP binds on port+1) for the Simple
// profile, or the single port for Main/Advanced. Query parameters on a rist://
// URL override the defaults.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	ristgo "github.com/zsiec/ristgo"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <addr|rist://url>\n", os.Args[0])
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rx, err := ristgo.Listen(ctx, os.Args[1], ristgo.WithLogger(ristgo.StdLogger(os.Stderr)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "receiver: %v\n", err)
		os.Exit(1)
	}
	defer rx.Close()

	// Cancelling ctx (Ctrl-C) closes rx, which ends the stream with io.EOF, so
	// io.Copy returns nil — a clean stop. A non-nil error is an abnormal teardown
	// (session timeout, buffer overflow, or auth failure).
	if _, err := io.Copy(os.Stdout, rx); err != nil {
		fmt.Fprintf(os.Stderr, "receiver: %v\n", err)
		os.Exit(1)
	}
}
