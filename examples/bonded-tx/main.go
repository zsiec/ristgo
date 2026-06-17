// Command bonded-tx is a URL-configurable SMPTE 2022-7 bonded RIST sender used by
// the ristrust differential interop suite (it complements the stock bonded-sender,
// which is fixed to the default Simple-profile config). Each argument is a rist://
// URL or a bare host:port; the first URL's query parameters configure the whole
// bonded session (profile, secret, username/password, …) and every argument
// contributes one bonded path. Media is read from stdin in RTP-sized chunks.
//
// Usage:
//
//	bonded-tx 'rist://127.0.0.1:5000?profile=1' '127.0.0.1:6000' < in.ts
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	ristgo "github.com/zsiec/ristgo"
)

const chunk = 1316

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
			fmt.Fprintf(os.Stderr, "bonded-tx: %v\n", err)
			os.Exit(2)
		}
		if i == 0 {
			cfg = c // the first URL's params configure the whole bonded session
		}
		addrs = append(addrs, addr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tx, err := ristgo.DialBonded(ctx, addrs,
		ristgo.WithConfig(cfg), ristgo.WithLogger(ristgo.StdLogger(os.Stderr)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "bonded-tx: %v\n", err)
		os.Exit(1)
	}
	defer tx.Close()

	buf := make([]byte, chunk)
	for {
		n, rerr := io.ReadFull(os.Stdin, buf)
		if n > 0 {
			if _, werr := tx.Write(buf[:n]); werr != nil {
				if errors.Is(werr, ristgo.ErrClosed) {
					return // Ctrl-C closed the sender
				}
				fmt.Fprintf(os.Stderr, "bonded-tx: %v\n", werr)
				os.Exit(1)
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return
		}
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "bonded-tx: %v\n", rerr)
			os.Exit(1)
		}
	}
}
