// Command rpslcheck checks whether neighbouring networks' routing policies
// in IRR data agree — what one network's export permits announcing against
// what its neighbour's import accepts — and lints one network's policies,
// on the rpsl engine.
//
//	go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslcheck@latest
//	rpslcheck -h whois.radb.net AS65001
//	rpslcheck -dump ripe.db.aut-num.gz -dump ripe.db.route.gz -sweep
//
// Run rpslcheck -help for its options; docs/rpslcheck.md has the rest.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/rkolesnichenko/rpsl/resolve/internal/rpslcheck"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := rpslcheck.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
