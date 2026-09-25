// Command rpslq writes router prefix lists and AS lists from IRR data, as
// bgpq4 does, with the rpsl expansion engine: its mbrs-by-ref checks, range
// operators and limits, over IRRd, whois or an offline dump.
//
//	go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslq@latest
//	rpslq -h whois.radb.net -S RADB -b AS-EXAMPLE
//
// Run rpslq with no arguments for its flags.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/rkolesnichenko/rpsl/resolve/internal/rpslq"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := rpslq.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
