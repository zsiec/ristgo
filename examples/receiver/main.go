// Command receiver is a minimal RIST receiver example: it receives a stream
// and writes the recovered, in-order media to stdout.
//
// Usage:
//
//	receiver 'rist://@:5000?profile=0&buffer=1000' > out.ts
//	receiver 127.0.0.1:5000 | ffplay -
//
// The address is the even media port; RTCP is bound on port+1.
package main

import (
	"fmt"
	"io"
	"os"

	ristgo "github.com/zsiec/ristgo"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <addr|rist://url>\n", os.Args[0])
		os.Exit(2)
	}
	cfg := ristgo.DefaultConfig()
	cfg.Logger = ristgo.StdLogger(os.Stderr)

	rx, err := ristgo.NewReceiver(os.Args[1], cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "receiver: %v\n", err)
		os.Exit(1)
	}
	defer rx.Close()

	if _, err := io.Copy(os.Stdout, rx); err != nil {
		fmt.Fprintf(os.Stderr, "receiver: %v\n", err)
		os.Exit(1)
	}
}
