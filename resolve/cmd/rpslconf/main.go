// Command rpslconf evaluates the routing policy in IRR data, as IRRToolSet's
// peval and rtconfig do, on the rpsl engine. It has both modes: template mode
// (the default), which reads an IRRToolSet-style @RtConfig template from
// stdin and writes router configuration, and peval mode (-e), which prints
// one filter's normal form.
//
//	go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslconf@latest
//	rpslconf -h whois.radb.net -config junos < router.tmpl > router.conf
//	rpslconf -h whois.radb.net -e 'AS-EXAMPLE AND NOT {0.0.0.0/0^25-32}'
//
// Run rpslconf -help for its options.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/rkolesnichenko/rpsl/resolve/internal/rpslconf"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := rpslconf.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
