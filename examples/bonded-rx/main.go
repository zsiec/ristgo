// Command bonded-rx is a URL-configurable SMPTE 2022-7 bonded RIST receiver used by
// the ristrust differential interop suite. Each argument is a rist:// URL or a bare
// host:port; the first URL's query parameters configure the whole bonded session
// (profile, secret, username/password, …) and every argument contributes one bonded
// path. The recovered, deduplicated, in-order media is written to stdout.
//
// Usage:
//
//	bonded-rx 'rist://:5000?profile=1' ':6000' > out.ts
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
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <url> [url...]\n", os.Args[0])
		os.Exit(2)
	}
	cfg := ristgo.DefaultConfig()
	var addrs []string
	for i, raw := range os.Args[1:] {
		addr, c, err := ristgo.ParseURL(raw, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bonded-rx: %v\n", err)
			os.Exit(2)
		}
		if i == 0 {
			cfg = c // the first URL's params configure the whole bonded session
		}
		addrs = append(addrs, addr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rx, err := ristgo.ListenBonded(ctx, addrs,
		ristgo.WithConfig(cfg), ristgo.WithLogger(ristgo.StdLogger(os.Stderr)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "bonded-rx: %v\n", err)
		os.Exit(1)
	}
	defer rx.Close()

	if _, err := io.Copy(os.Stdout, rx); err != nil {
		fmt.Fprintf(os.Stderr, "bonded-rx: %v\n", err)
		os.Exit(1)
	}
}
