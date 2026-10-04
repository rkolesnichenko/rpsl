// Command rpsld is an IRRd-compatible mirror: it keeps registries in memory
// — from dumps, NRTMv4 mirrors and RPKI VRPs — and answers IRRd's query
// protocol and RIPE-style whois on one port, as IRRd 4.5.3 answers, so
// bgpq4, IRRToolSet and rpslq run against it unchanged.
//
//	go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpsld@latest
//	rpsld -source RIPE=nrtm4:https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose,key=ripe.pem \
//	      -source RADB=dump:radb.db.gz -rpki https://…/vrps.json -keep-route-text
//
// SIGHUP re-reads every dump registry; SIGTERM and SIGINT stop it, giving
// open connections -grace to finish, and a second one ends it at once. Run
// rpsld -help for its options and exit statuses; docs/rpsld.md has the rest.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rkolesnichenko/rpsl/resolve/internal/rpsld"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal the default behaviour returns: a second one
	// ends rpsld at once, without waiting out -grace.
	go func() {
		<-ctx.Done()
		stop()
	}()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	// One pending reload stands for every SIGHUP that arrives before rpsld
	// takes it: a send never waits.
	reload := make(chan struct{}, 1)
	go func() {
		for range hup {
			select {
			case reload <- struct{}{}:
			default:
			}
		}
	}()
	code := rpsld.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, reload)
	stop()
	os.Exit(code)
}
