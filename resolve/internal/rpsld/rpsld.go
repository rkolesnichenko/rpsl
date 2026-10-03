// Package rpsld is the rpsld command's logic: it holds registries from
// dumps, NRTMv4 mirrors and RPKI VRPs, keeps them current, and serves them
// over the IRRd query protocol and RIPE-style whois with resolve/irrdserver.
// resolve/cmd/rpsld is its shim; docs/rpsld.md is its page.
package rpsld

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/internal/buildinfo"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/irrdserver"
	"github.com/rkolesnichenko/rpsl/resolve/nrtm4"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
)

// The exit statuses, as rpslq, rpslconf and rpslcheck use them.
const (
	exitClean  = 0 // stopped as asked (SIGTERM, SIGINT), or -v
	exitUsage  = 2 // a command line rpsld cannot use
	exitFailed = 3 // could not complete: an input failed to load at startup, or serving failed
)

// env is what a run takes from outside its command line; tests set it.
type env struct {
	// http fetches everything: VRPs and the mirrors' files. nil: a client
	// with a 10-minute timeout for VRPs, nrtm4's own for the mirrors.
	http *http.Client
	// listen opens the query port; nil is net.Listen.
	listen func(network, addr string) (net.Listener, error)
}

type sourceFlags []SourceSpec

func (f *sourceFlags) String() string { return fmt.Sprint(*f) }
func (f *sourceFlags) Set(v string) error {
	s, err := ParseSourceSpec(v)
	if err != nil {
		return err
	}
	for _, o := range *f {
		if o.Name == s.Name {
			return fmt.Errorf("two -source %s", s.Name)
		}
	}
	*f = append(*f, s)
	return nil
}

// state is what the run publishes from: the registries in order and the
// snapshot options, guarded by mu; cur is what the server reads.
type state struct {
	mu   sync.Mutex
	regs []*irrdq.Registry
	opts irrdq.SnapshotOptions
	cur  atomic.Pointer[irrdq.Snapshot]
	log  *slog.Logger
}

// publish replaces the registry of r's name (or, for a nil r, keeps them)
// and the VRPs when v is non-nil, then stores the next snapshot: one atomic
// store, so an answer reads the old snapshot or the new one, never a mixture.
func (st *state) publish(r *irrdq.Registry, v *rpki.VRPs) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	regs := slices.Clone(st.regs)
	if r != nil {
		for i := range regs {
			if regs[i].Name() == r.Name() {
				regs[i] = r
			}
		}
	}
	opts := st.opts
	if v != nil {
		opts.VRPs = v
	}
	snap, err := irrdq.NewSnapshot(regs, opts)
	if err != nil {
		return err
	}
	st.regs, st.opts = regs, opts
	st.cur.Store(snap)
	if r != nil {
		st.log.Info("swapped", "registry", r.Name(), "serial", r.Serial())
	}
	return nil
}

// Run is rpsld. It returns the exit status: 0 after a clean stop (ctx's
// end: SIGTERM, SIGINT), 2 for a bad command line, 3 when an input fails to
// load at startup or serving fails. reload, when not nil, re-reads every
// dump registry each time it receives (SIGHUP).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, reload <-chan struct{}) int {
	return run(ctx, args, stdout, stderr, reload, env{})
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, reload <-chan struct{}, e env) int {
	fs := flag.NewFlagSet("rpsld", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: rpsld -source NAME=SPEC [-source NAME=SPEC …] [flags]

rpsld serves the registries it is given over IRRd's query protocol and
RIPE-style whois, on one port, keeping them current. SPEC is
dump:FILE[,FILE…] (dump files, gzip or plain, re-read when they change or
on SIGHUP) or nrtm4:URL,key=PEMFILE (an NRTMv4 mirror).

`)
		fs.PrintDefaults()
		fmt.Fprint(stderr, `
Exit status:
  0  stopped as asked (SIGTERM or SIGINT), or -v
  2  a command line rpsld cannot use
  3  could not complete: an input failed to load at startup, or serving failed
`)
	}
	var sources sourceFlags
	fs.Var(&sources, "source", "a registry: NAME=dump:FILE[,FILE…] or NAME=nrtm4:URL,key=PEMFILE (repeatable; the order is precedence)")
	rpkiSrc := fs.String("rpki", "", "VRPs (rpki-client/Routinator JSON): a `file` or an https:// URL; serves the registry RPKI and hides RPKI-invalid routes")
	rpkiRefresh := fs.Duration("rpki-refresh", 10*time.Minute, "how often -rpki is re-read")
	slurm := fs.String("slurm", "", "an RFC 8416 SLURM `file` applied to -rpki")
	rpkiDefault := fs.Bool("rpki-default", true, "select the RPKI registry by default, last, as RADB does")
	listen := fs.String("listen", ":43", "the `address` of the IRRd and whois query port")
	rfc := fs.Bool("rfc", false, "RFC 2622 answers for !i…,1 and !a (resolve.Expander), not IRRd's")
	keepText := fs.Bool("keep-route-text", false, "keep every route's text, for !m route, !r and -i origin")
	stateDir := fs.String("state-dir", "", "a `directory` for each NRTMv4 mirror's current signing key")
	checkDumps := fs.Duration("check-dumps", time.Minute, "how often dump files' modification times are checked")
	nrtmInterval := fs.Duration("nrtm-interval", time.Minute, "how often each NRTMv4 mirror polls")
	var lim irrdserver.Limits
	fs.IntVar(&lim.MaxConns, "max-conns", 256, "connections served at once")
	fs.DurationVar(&lim.IdleTimeout, "idle-timeout", 30*time.Second, "how long a connection may wait between commands (IRRd's default; !t overrides it)")
	fs.IntVar(&lim.MaxLine, "max-line", 1<<20, "bytes in one command line")
	fs.Int64Var(&lim.MaxReply, "max-reply", 256<<20, "bytes in one answer")
	fs.DurationVar(&lim.QueryTime, "query-time", time.Minute, "how long one command may evaluate")
	grace := fs.Duration("grace", 10*time.Second, "how long open connections get to finish at shutdown")
	logQueries := fs.Bool("log-queries", false, "log every command")
	version := fs.Bool("v", false, "print rpsld's version and exit")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *version {
		fmt.Fprintf(stdout, "rpsld %s\n", buildinfo.Version())
		return exitClean
	}
	usage := func(msg string) int {
		fmt.Fprintf(stderr, "rpsld: %s\n", msg)
		fs.Usage()
		return exitUsage
	}
	switch {
	case len(sources) == 0:
		return usage("at least one -source")
	case fs.NArg() > 0:
		return usage(fmt.Sprintf("an argument that is no flag: %q", fs.Arg(0)))
	case lim.MaxConns < 1 || lim.MaxLine < 1 || lim.MaxReply < 1 || lim.IdleTimeout <= 0 || lim.QueryTime <= 0:
		return usage("every limit positive")
	case *rpkiRefresh <= 0 || *checkDumps <= 0 || *nrtmInterval <= 0:
		return usage("every interval positive")
	case *grace < 0:
		return usage("-grace not negative")
	case *slurm != "" && *rpkiSrc == "":
		return usage("-slurm applies to -rpki, which is not given")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := slog.New(slog.NewTextHandler(stderr, nil))
	vrpClient := e.http
	if vrpClient == nil {
		vrpClient = &http.Client{Timeout: 10 * time.Minute}
	}
	listenFn := e.listen
	if listenFn == nil {
		listenFn = net.Listen
	}
	// failed ends the run when an input fails at startup: status 3, unless
	// ctx ended first — a stop asked for during startup is a clean one.
	failed := func(registry string, err error) int {
		if ctx.Err() != nil {
			log.Info("stopped before serving")
			return exitClean
		}
		log.Error("load failed", "registry", registry, "err", err)
		return exitFailed
	}

	// Load every input before listening.
	if *stateDir != "" {
		if err := os.MkdirAll(*stateDir, 0o700); err != nil {
			log.Error("state-dir", "err", err)
			return exitFailed
		}
	}
	st := &state{log: log}
	mirrors := map[string]*nrtm4.Client{}
	dumpTimes := map[string][]time.Time{}
	for _, s := range sources {
		begin := time.Now()
		if s.Kind == "dump" {
			dumpTimes[s.Name], _ = mtimes(s) // before reading: a change while it is read is seen
			r, ds, err := loadDump(ctx, s, *keepText, 1)
			if err != nil {
				return failed(s.Name, err)
			}
			log.Info("loaded", "registry", s.Name, "serial", r.Serial(), "objects", ds.objects,
				"other_sources", ds.other, "took", time.Since(begin).Round(time.Millisecond))
			st.regs = append(st.regs, r)
		} else {
			c, keyFile, err := newMirror(s, *keepText, *stateDir, e.http)
			if err != nil {
				return failed(s.Name, err)
			}
			u, err := c.Sync(ctx)
			if err != nil {
				return failed(s.Name, err)
			}
			r, err := mirrorRegistry(c, s.Name, *keepText)
			if err != nil {
				return failed(s.Name, err)
			}
			mirrors[s.Name] = c
			if *stateDir != "" {
				if err := saveKey(*stateDir, s.Name, c.Status().CurrentKey); err != nil {
					log.Warn("could not save the signing key", "registry", s.Name, "err", err)
				}
			}
			log.Info("loaded", "registry", s.Name, "serial", r.Serial(), "session", c.Status().SessionID,
				"objects", c.Status().Objects, "key", keyFile, "took", time.Since(begin).Round(time.Millisecond))
			if u.Stale {
				log.Warn("stale notification file", "registry", s.Name)
			}
			st.regs = append(st.regs, r)
		}
		st.opts.Default = append(st.opts.Default, s.Name)
	}
	var vrps *rpki.VRPs
	if *rpkiSrc != "" {
		begin := time.Now()
		v, err := loadVRPs(ctx, *rpkiSrc, *slurm, vrpClient)
		if err != nil {
			return failed(rpki.PseudoSource, err)
		}
		r, err := rpkiRegistry(v, 1)
		if err != nil {
			return failed(rpki.PseudoSource, err)
		}
		vrps = v
		st.regs = append(st.regs, r)
		if *rpkiDefault {
			st.opts.Default = append(st.opts.Default, rpki.PseudoSource)
		}
		log.Info("loaded", "registry", rpki.PseudoSource, "serial", r.Serial(), "vrps", v.Len(), "took", time.Since(begin).Round(time.Millisecond))
	}
	st.opts.VRPs, st.opts.RFC, st.opts.Version = vrps, *rfc, buildinfo.Version()
	if err := st.publish(nil, nil); err != nil {
		log.Error("snapshot", "err", err)
		return exitFailed
	}

	// Serve.
	ln, err := listenFn("tcp", *listen)
	if err != nil {
		log.Error("listen", "err", err)
		return exitFailed
	}
	srv := &irrdserver.Server{Snapshot: st.cur.Load, Limits: lim, Log: log, LogQueries: *logQueries}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String())

	// Refresh, each input on its own goroutine.
	var wg sync.WaitGroup
	var dumpReload []chan struct{} // one per dump registry: a SIGHUP reaches every one (R11)
	for _, s := range sources {
		wg.Add(1)
		if s.Kind == "dump" {
			ch := make(chan struct{}, 1)
			dumpReload = append(dumpReload, ch)
			go func() {
				defer wg.Done()
				st.watchDump(ctx, s, *keepText, dumpTimes[s.Name], *checkDumps, ch)
			}()
		} else {
			go func() {
				defer wg.Done()
				st.follow(ctx, s, mirrors[s.Name], *keepText, *stateDir, *nrtmInterval)
			}()
		}
	}
	if reload != nil && len(dumpReload) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fanOut(ctx, reload, dumpReload, log)
		}()
	}
	if vrps != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.refreshVRPs(ctx, *rpkiSrc, *slurm, vrpClient, *rpkiRefresh)
		}()
	}

	// Stop: on ctx's end, cleanly; when serving fails, with status 3.
	code, serving := exitClean, true
	select {
	case <-ctx.Done():
		log.Info("stopping")
	case err := <-served:
		log.Error("serving failed", "err", err)
		code, serving = exitFailed, false
	}
	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), *grace)
	defer scancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Warn("shutdown: connections cut at the end of -grace", "err", err)
	}
	if serving {
		<-served // ErrServerClosed, now that Shutdown closed the listener
	}
	wg.Wait()
	log.Info("stopped")
	return code
}

// fanOut passes each reload on to every dump watcher. A watcher's channel
// holds one reload, and a send never waits: reloads asked for while one is
// pending are that one.
func fanOut(ctx context.Context, reload <-chan struct{}, to []chan struct{}, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-reload:
			if !ok {
				return
			}
			log.Info("reload: re-reading every dump registry", "registries", len(to))
			for _, ch := range to {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
}

// watchDump re-reads s when its files' modification times change, or on
// reload. last is the times its first load began with.
func (st *state) watchDump(ctx context.Context, s SourceSpec, keepText bool, last []time.Time, every time.Duration, reload <-chan struct{}) {
	serial := uint64(1)
	tick := time.NewTicker(every)
	defer tick.Stop()
	statFailed := false
	for {
		forced := false
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-reload:
			forced = true
		}
		now, err := mtimes(s)
		if !forced {
			if err != nil {
				if !statFailed { // once, not every tick
					st.log.Warn("cannot check a dump file; keeping the previous data", "registry", s.Name, "err", err)
				}
				statFailed = true
				continue
			}
			statFailed = false
			if slices.EqualFunc(now, last, time.Time.Equal) {
				continue
			}
		}
		begin := time.Now()
		r, ds, err := loadDump(ctx, s, keepText, serial+1)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			st.log.Error("reload failed: keeping the previous data", "registry", s.Name, "serial", serial, "err", err)
			continue
		}
		st.log.Info("reloaded", "registry", s.Name, "serial", serial+1, "objects", ds.objects,
			"other_sources", ds.other, "took", time.Since(begin).Round(time.Millisecond))
		if err := st.publish(r, nil); err != nil {
			st.log.Error("snapshot failed: keeping the previous data", "registry", s.Name, "err", err)
			continue
		}
		serial, last = serial+1, now
	}
}

// follow syncs the mirror every interval and publishes each new version.
// A Sync publishes in the client what it reached even when a later file
// fails, a version at a time, so the registry is rebuilt whenever the
// version moved; when it did not, the registry stays as it was.
func (st *state) follow(ctx context.Context, s SourceSpec, c *nrtm4.Client, keepText bool, stateDir string, every time.Duration) {
	savedKey := c.Status().CurrentKey
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		begin := time.Now()
		u, err := c.Sync(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			st.log.Error("sync failed", "registry", s.Name, "serial", c.Status().Version, "err", err)
		}
		if u.Stale {
			st.log.Warn("stale notification file", "registry", s.Name)
		}
		if k := c.Status().CurrentKey; stateDir != "" && k != savedKey {
			if err := saveKey(stateDir, s.Name, k); err != nil {
				st.log.Warn("could not save the signing key", "registry", s.Name, "err", err)
			} else {
				savedKey = k
				st.log.Info("saved the signing key", "registry", s.Name)
			}
		}
		if u.To == u.From && !u.Snapshot {
			continue
		}
		r, err := mirrorRegistry(c, s.Name, keepText)
		if err != nil {
			st.log.Error("rebuild failed", "registry", s.Name, "err", err)
			continue
		}
		st.log.Info("synced", "registry", s.Name, "from", u.From, "to", u.To, "snapshot", u.Snapshot,
			"deltas", u.Deltas, "took", time.Since(begin).Round(time.Millisecond))
		if err := st.publish(r, nil); err != nil {
			st.log.Error("snapshot failed: keeping the previous version", "registry", s.Name, "err", err)
		}
	}
}

// refreshVRPs re-reads the VRPs every interval and publishes them with a
// new RPKI registry.
func (st *state) refreshVRPs(ctx context.Context, src, slurm string, hc *http.Client, every time.Duration) {
	serial := uint64(1)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		begin := time.Now()
		v, err := loadVRPs(ctx, src, slurm, hc)
		var r *irrdq.Registry
		if err == nil {
			r, err = rpkiRegistry(v, serial+1)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			st.log.Error("VRP refresh failed: keeping the previous VRPs", "registry", rpki.PseudoSource, "serial", serial, "err", err)
			continue
		}
		st.log.Info("reloaded", "registry", rpki.PseudoSource, "serial", serial+1, "vrps", v.Len(), "took", time.Since(begin).Round(time.Millisecond))
		if err := st.publish(r, v); err != nil {
			st.log.Error("snapshot failed: keeping the previous VRPs", "registry", rpki.PseudoSource, "err", err)
			continue
		}
		serial++
	}
}
