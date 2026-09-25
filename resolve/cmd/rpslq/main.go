// Command rpslq writes router filters — prefix lists, route-filters, as-path
// lists, AS sets — from IRR data, taking bgpq4's command line and writing
// bgpq4's output, but expanding with the rpsl engine: its mbrs-by-ref checks,
// range operators and limits, over IRRd, whois or an offline dump.
//
//	go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslq@latest
//	rpslq -h whois.radb.net -S RADB -b AS-EXAMPLE
//
// Run rpslq with no arguments for its options.
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
