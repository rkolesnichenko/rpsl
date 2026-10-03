package rpsld

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/internal/buildinfo"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrdoracle"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/nrtmtest"
)

// lockedBuffer is a bytes.Buffer safe for the run's logger and the test.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

var listening = regexp.MustCompile(`msg=listening addr=(\S+)`)

// start runs rpsld with args (plus -listen 127.0.0.1:0) until the test
// ends, which must find it exiting 0; it returns the address once the log
// says it is listening, the reload channel, and the log.
func start(t *testing.T, hc *http.Client, args ...string) (addr string, reload chan struct{}, log *lockedBuffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	reload, code, log := make(chan struct{}), make(chan int, 1), &lockedBuffer{}
	go func() {
		code <- run(ctx, append(args, "-listen", "127.0.0.1:0"), io.Discard, log, reload, env{http: hc})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case c := <-code:
			if c != 0 {
				t.Errorf("exit %d; log:\n%s", c, log.String())
			}
		case <-time.After(15 * time.Second):
			t.Error("rpsld did not stop")
		}
	})
	for i := 0; i < 1000; i++ {
		if m := listening.FindStringSubmatch(log.String()); m != nil {
			return m[1], reload, log
		}
		select {
		case c := <-code:
			code <- c // for the cleanup
			t.Fatalf("exited %d before listening; log:\n%s", c, log.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not listening; log:\n%s", log.String())
	return
}

func query(t *testing.T, addr, send string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, send)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

// eventually polls query until it returns want, for up to 10 s.
func eventually(t *testing.T, addr, send, want string) {
	t.Helper()
	var got string
	for i := 0; i < 200; i++ {
		if got = query(t, addr, send); got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%q: %q, want %q", send, got, want)
}

// logged waits, for up to 10 s, until the log has n lines matching re.
func logged(t *testing.T, log *lockedBuffer, re string, n int) {
	t.Helper()
	r := regexp.MustCompile(re)
	for i := 0; i < 1000; i++ {
		if len(r.FindAllString(log.String(), -1)) >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %d lines matching %s; log:\n%s", n, re, log.String())
}

func writeFile(t *testing.T, name, text string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBadCommandLines(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-source", "RIPE"},
		{"-nosuchflag"},
		{"-source", "RIPE=dump:x", "-max-conns", "-1"},
		{"-source", "RIPE=dump:x", "-source", "ripe=dump:y"}, // one registry twice
		{"-source", "RIPE=dump:x", "-slurm", "s.json"},       // -slurm without -rpki
		{"-source", "RIPE=dump:x", "-grace", "-1s"},
		{"-source", "RIPE=dump:x", "-nrtm-interval", "0"},
		{"-source", "RIPE=dump:x", "extra"},
	} {
		var stderr bytes.Buffer
		if c := Run(context.Background(), args, io.Discard, &stderr, nil); c != 2 {
			t.Errorf("%q: exit %d, want 2", args, c)
		}
	}
}

func TestVersion(t *testing.T) {
	var stdout bytes.Buffer
	if c := Run(context.Background(), []string{"-v"}, &stdout, io.Discard, nil); c != 0 || stdout.String() != "rpsld "+buildinfo.Version()+"\n" {
		t.Errorf("exit %d, %q", c, stdout.String())
	}
}

// TestUsageNamesExitStatuses: -help documents every exit status.
func TestUsageNamesExitStatuses(t *testing.T) {
	var stderr bytes.Buffer
	Run(context.Background(), []string{"-help"}, io.Discard, &stderr, nil)
	for _, want := range []string{"-source", "0 ", "2 ", "3 "} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("usage lacks %q:\n%s", want, stderr.String())
		}
	}
}

func TestStartupLoadFails(t *testing.T) {
	dir := t.TempDir()
	dump := filepath.Join(dir, "ripe.db")
	writeFile(t, dump, "as-set: AS-X\nmembers: AS1\nsource: RIPE\n")
	notKey := filepath.Join(dir, "key.pem")
	writeFile(t, notKey, "not a key")
	s := nrtmtest.New(t, "TEST")
	s.SetTime(time.Now().UTC())
	for _, args := range [][]string{
		{"-source", "RIPE=dump:/no/such/file"},
		{"-source", "RIPE=dump:" + dump + ",/no/such/file"},             // every file of a registry must load
		{"-source", "RIPE=dump:" + dump, "-rpki", "/no/such/vrps.json"}, // VRPs are an input too
		{"-source", "RIPE=dump:" + dump, "-rpki", dump},                 // not VRPs
		{"-source", "TEST=nrtm4:" + s.URL() + ",key=/no/such/key.pem"},
		{"-source", "TEST=nrtm4:" + s.URL() + ",key=" + notKey},
	} {
		var stderr bytes.Buffer
		c := run(context.Background(), append(args, "-listen", "127.0.0.1:0"), io.Discard, &stderr, nil, env{http: s.HTTPClient()})
		if c != 3 || !strings.Contains(stderr.String(), "load failed") || strings.Contains(stderr.String(), "msg=listening") {
			t.Errorf("%q: exit %d, want 3 before listening; log %s", args, c, stderr.String())
		}
	}
}

// TestStartupStaleNotificationFails: a notification file over 24 hours old
// is refused at startup (Client.MaxAge), as IRRd refuses it.
func TestStartupStaleNotificationFails(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.SetTime(time.Now().UTC().Add(-25 * time.Hour))
	key := filepath.Join(t.TempDir(), "key.pem")
	writeFile(t, key, s.PublicKey())
	var stderr bytes.Buffer
	c := run(context.Background(), []string{"-source", "TEST=nrtm4:" + s.URL() + ",key=" + key, "-listen", "127.0.0.1:0"},
		io.Discard, &stderr, nil, env{http: s.HTTPClient()})
	if c != 3 || !strings.Contains(stderr.String(), "MaxAge") {
		t.Errorf("exit %d, want 3; log %s", c, stderr.String())
	}
}

// TestListenFails (R12): an address in use is exit 3, at once.
func TestListenFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dump := filepath.Join(t.TempDir(), "ripe.db")
	writeFile(t, dump, "as-set: AS-X\nmembers: AS1\nsource: RIPE\n")
	var stderr lockedBuffer
	code := make(chan int, 1)
	go func() {
		code <- Run(context.Background(), []string{"-source", "RIPE=dump:" + dump, "-listen", ln.Addr().String()}, io.Discard, &stderr, nil)
	}()
	select {
	case c := <-code:
		if c != 3 {
			t.Errorf("exit %d, want 3; log %s", c, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("rpsld did not exit; log %s", stderr.String())
	}
}

// failingListener accepts nothing; once fail is closed, Accept returns a
// permanent error, as a listener whose socket broke does.
type failingListener struct {
	net.Listener
	fail <-chan struct{}
}

func (l failingListener) Accept() (net.Conn, error) {
	<-l.fail
	return nil, errors.New("the socket broke")
}

// settled waits, for up to 10 s, until no more goroutines run than before.
func settled(t *testing.T, before int) {
	t.Helper()
	n := runtime.NumGoroutine()
	for i := 0; i < 1000 && n > before; i++ {
		time.Sleep(10 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	if n > before {
		buf := make([]byte, 1<<20)
		t.Errorf("%d goroutines, %d before:\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}

// TestServeFails (R12): when serving fails, the run cancels its refreshers,
// waits for them and exits 3, leaving no goroutine behind.
func TestServeFails(t *testing.T) {
	dir := t.TempDir()
	dump := filepath.Join(dir, "ripe.db")
	writeFile(t, dump, "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n")
	vrps := filepath.Join(dir, "vrps.json")
	writeFile(t, vrps, `{"roas": []}`)
	before := runtime.NumGoroutine()
	fail := make(chan struct{})
	e := env{listen: func(network, addr string) (net.Listener, error) {
		ln, err := net.Listen(network, addr)
		return failingListener{ln, fail}, err
	}}
	var log lockedBuffer
	code := make(chan int, 1)
	go func() {
		code <- run(context.Background(), []string{"-source", "RIPE=dump:" + dump, "-rpki", vrps, "-listen", "127.0.0.1:0",
			"-check-dumps", "10ms", "-rpki-refresh", "10ms"}, io.Discard, &log, make(chan struct{}), e)
	}()
	logged(t, &log, `msg=listening`, 1)
	logged(t, &log, `msg=reloaded registry=RPKI`, 1) // the refreshers are running
	close(fail)
	select {
	case c := <-code:
		if c != 3 || !strings.Contains(log.String(), "serving failed") {
			t.Errorf("exit %d, want 3; log %s", c, log.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("rpsld did not exit; log %s", log.String())
	}
	settled(t, before)
}

// TestCleanStopLeavesNoGoroutine: ctx's end is exit 0, and nothing the run
// started outlives it.
func TestCleanStopLeavesNoGoroutine(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "ripe.db")
	writeFile(t, dump, "as-set: AS-X\nmembers: AS1\nsource: RIPE\n")
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	var log lockedBuffer
	code := make(chan int, 1)
	go func() {
		code <- Run(ctx, []string{"-source", "RIPE=dump:" + dump, "-listen", "127.0.0.1:0", "-check-dumps", "10ms"}, io.Discard, &log, make(chan struct{}))
	}()
	logged(t, &log, `msg=listening`, 1)
	addr := listening.FindStringSubmatch(log.String())[1]
	if got := query(t, addr, "!iAS-X\n"); got != "A4\nAS1\nC\n" {
		t.Errorf("served %q", got)
	}
	cancel()
	select {
	case c := <-code:
		if c != 0 {
			t.Errorf("exit %d; log %s", c, log.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("rpsld did not stop; log %s", log.String())
	}
	settled(t, before)
}

func TestServesAndReloadsDumps(t *testing.T) {
	dir := t.TempDir()
	dump := filepath.Join(dir, "ripe.db")
	writeFile(t, dump, "as-set: AS-X\nmembers: AS1\nsource: RIPE\n\nas-set: AS-Y\nmembers: AS9\nsource: RADB\n")
	addr, reload, log := start(t, nil, "-source", "RIPE="+"dump:"+dump, "-check-dumps", "1h")
	if got := query(t, addr, "!!\n!iAS-X\n!iAS-Y\n!sRADB\n!j-*\n!q\n"); got != "A4\nAS1\nC\nD\nF One or more selected sources are unavailable.\nA11\nRIPE:N:0-1\nC\n" {
		t.Errorf("served %q", got) // AS-Y's source is RADB: not RIPE's registry, and no registry of its own
	}
	writeFile(t, dump, "as-set: AS-X\nmembers: AS1, AS2\nsource: RIPE\n")
	reload <- struct{}{}
	eventually(t, addr, "!!\n!iAS-X\n!j-*\n!q\n", "A8\nAS1 AS2\nC\nA11\nRIPE:N:0-2\nC\n")
	// A reload that fails keeps the data and the serial.
	os.Remove(dump)
	reload <- struct{}{}
	logged(t, log, `msg="reload failed: keeping the previous data" registry=RIPE`, 1)
	if got := query(t, addr, "!!\n!iAS-X\n!j-*\n!q\n"); got != "A8\nAS1 AS2\nC\nA11\nRIPE:N:0-2\nC\n" {
		t.Errorf("after a failed reload: %q", got)
	}
	// And the next one that succeeds moves the serial on by one.
	writeFile(t, dump, "as-set: AS-X\nmembers: AS3\nsource: RIPE\n")
	reload <- struct{}{}
	eventually(t, addr, "!!\n!iAS-X\n!j-*\n!q\n", "A4\nAS3\nC\nA11\nRIPE:N:0-3\nC\n")
}

// TestReloadReachesEveryDump (R11): one reload signal re-reads every dump
// registry, not just one of them.
func TestReloadReachesEveryDump(t *testing.T) {
	dir := t.TempDir()
	ripe, radb := filepath.Join(dir, "ripe.db"), filepath.Join(dir, "radb.db")
	writeFile(t, ripe, "as-set: AS-X\nmembers: AS1\nsource: RIPE\n")
	writeFile(t, radb, "as-set: AS-Y\nmembers: AS9\nsource: RADB\n")
	addr, reload, _ := start(t, nil, "-source", "RIPE=dump:"+ripe, "-source", "RADB=dump:"+radb, "-check-dumps", "1h")
	if got := query(t, addr, "!!\n!iAS-X\n!iAS-Y\n!j-*\n!q\n"); got != "A4\nAS1\nC\nA4\nAS9\nC\nA22\nRIPE:N:0-1\nRADB:N:0-1\nC\n" {
		t.Errorf("served %q", got)
	}
	writeFile(t, ripe, "as-set: AS-X\nmembers: AS2\nsource: RIPE\n")
	writeFile(t, radb, "as-set: AS-Y\nmembers: AS8\nsource: RADB\n")
	reload <- struct{}{}
	eventually(t, addr, "!!\n!iAS-X\n!iAS-Y\n!j-*\n!q\n", "A4\nAS2\nC\nA4\nAS8\nC\nA22\nRIPE:N:0-2\nRADB:N:0-2\nC\n")
}

// TestReloadsChangedDump: a dump file whose modification time changed is
// re-read without a signal; one that did not change is not.
func TestReloadsChangedDump(t *testing.T) {
	dir := t.TempDir()
	ripe, radb := filepath.Join(dir, "ripe.db"), filepath.Join(dir, "radb.db")
	writeFile(t, ripe, "as-set: AS-X\nmembers: AS1\nsource: RIPE\n")
	writeFile(t, radb, "as-set: AS-Y\nmembers: AS9\nsource: RADB\n")
	addr, _, log := start(t, nil, "-source", "RIPE=dump:"+ripe, "-source", "RADB=dump:"+radb, "-check-dumps", "20ms")
	writeFile(t, ripe, "as-set: AS-X\nmembers: AS2\nsource: RIPE\n")
	later := time.Now().Add(time.Hour) // whatever the file system's timestamp resolution
	if err := os.Chtimes(ripe, later, later); err != nil {
		t.Fatal(err)
	}
	eventually(t, addr, "!!\n!iAS-X\n!j-*\n!q\n", "A4\nAS2\nC\nA22\nRIPE:N:0-2\nRADB:N:0-1\nC\n")
	if strings.Contains(log.String(), "registry=RADB serial=2") {
		t.Errorf("RADB re-read though its file did not change:\n%s", log.String())
	}
}

func TestMirrorsNRTMv4(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	key := nrtmtest.NewKey(t) // ours, so that signing can stop and resume with it
	s.SignWith(key)
	s.SetTime(time.Now().UTC()) // rpsld refuses a notification file over 24 hours old (MaxAge), as IRRd does
	s.Publish(nrtmtest.Change{Class: "as-set", PK: "AS-X", Text: "as-set: AS-X\nmembers: AS1\nsource: TEST\n"})
	s.Snapshot()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	writeFile(t, keyFile, nrtmtest.PEM(t, key))
	state := filepath.Join(dir, "state")
	addr, _, log := start(t, s.HTTPClient(), "-source", "TEST=nrtm4:"+s.URL()+",key="+keyFile, "-nrtm-interval", "50ms", "-state-dir", state)
	if got := query(t, addr, "!!\n!iAS-X\n!jTEST\n!q\n"); got != "A4\nAS1\nC\nA11\nTEST:N:0-2\nC\n" {
		t.Errorf("served %q", got)
	}
	s.Publish(nrtmtest.Change{Class: "as-set", PK: "AS-X", Text: "as-set: AS-X\nmembers: AS1, AS2\nsource: TEST\n"})
	eventually(t, addr, "!!\n!iAS-X\n!jTEST\n!q\n", "A8\nAS1 AS2\nC\nA11\nTEST:N:0-3\nC\n")

	// A refused delta (spec §7) leaves the data and the serial where they
	// were. Signing with a key the mirror does not trust holds every poll
	// off while delta 4 is published and corrupted, so that no poll can
	// fetch it whole in between; then the server signs as before, and the
	// mirror refuses delta 4 on its hash, over and over.
	s.SignWith(nrtmtest.NewKey(t))
	logged(t, log, `msg="sync failed" registry=TEST serial=3 err=".*notification file`, 1)
	s.Publish(nrtmtest.Change{Class: "as-set", PK: "AS-X", Text: "as-set: AS-X\nmembers: AS9\nsource: TEST\n"})
	s.Corrupt(4, []byte("not the delta the hash is of"))
	s.SignWith(key)
	// Three Syncs failing on a delta make the fourth reload the snapshot
	// (version 2) and reapply delta 3: refusing delta 4 again five times
	// covers that path too.
	logged(t, log, `msg="sync failed" registry=TEST serial=3 err=".*delta 4: .*SHA-256`, 5)
	logged(t, log, `msg=synced registry=TEST from=3 to=3 snapshot=true deltas=1 `, 1)
	if got := query(t, addr, "!!\n!iAS-X\n!jTEST\n!q\n"); got != "A8\nAS1 AS2\nC\nA11\nTEST:N:0-3\nC\n" {
		t.Errorf("after refused deltas: %q", got)
	}
	saved, err := os.ReadFile(filepath.Join(state, "TEST.pem"))
	if err != nil || strings.TrimSpace(string(saved)) != strings.TrimSpace(nrtmtest.PEM(t, key)) {
		t.Errorf("state-dir key: %q, %v", saved, err)
	}
}

// TestMirrorStartsFromSavedKey: the key saved in -state-dir is the one a
// mirror starts from, so a rotation while rpsld was down still verifies.
func TestMirrorStartsFromSavedKey(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.SetTime(time.Now().UTC())
	s.Publish(nrtmtest.Change{Class: "as-set", PK: "AS-X", Text: "as-set: AS-X\nmembers: AS1\nsource: TEST\n"})
	s.Snapshot()
	dir := t.TempDir()
	oldKey := filepath.Join(dir, "old.pem")
	writeFile(t, oldKey, s.PublicKey())
	// A first run follows a key rotation and saves the new key.
	state := filepath.Join(dir, "state")
	func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var log lockedBuffer
		code := make(chan int, 1)
		go func() {
			code <- run(ctx, []string{"-source", "TEST=nrtm4:" + s.URL() + ",key=" + oldKey, "-listen", "127.0.0.1:0",
				"-nrtm-interval", "20ms", "-state-dir", state}, io.Discard, &log, nil, env{http: s.HTTPClient()})
		}()
		logged(t, &log, `msg=listening`, 1)
		// The mirror has read the announcement once a second poll began
		// after it: one Sync at a time.
		notifications := func() (n int) {
			for _, p := range s.Requests() {
				if strings.HasSuffix(p, "/update-notification-file.jose") {
					n++
				}
			}
			return n
		}
		next, seen := s.AnnounceKey(), notifications()
		for i := 0; i < 1000 && notifications() < seen+2; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		s.RotateKey()
		s.Publish(nrtmtest.Change{Class: "as-set", PK: "AS-X", Text: "as-set: AS-X\nmembers: AS2\nsource: TEST\n"})
		logged(t, &log, `msg=synced registry=TEST from=2 to=3`, 1)
		if b, err := os.ReadFile(filepath.Join(state, "TEST.pem")); err != nil || strings.TrimSpace(string(b)) != strings.TrimSpace(next) {
			t.Errorf("saved key %q, %v; want the rotated one", b, err)
		}
		cancel()
		if c := <-code; c != 0 {
			t.Errorf("first run: exit %d; log %s", c, log.String())
		}
	}()
	// The old key no longer verifies anything the server signs: a second
	// run starts only because it reads the rotated key from -state-dir.
	addr, _, _ := start(t, s.HTTPClient(), "-source", "TEST=nrtm4:"+s.URL()+",key="+oldKey, "-state-dir", state)
	if got := query(t, addr, "!iAS-X\n"); got != "A4\nAS2\nC\n" {
		t.Errorf("served %q", got)
	}
}

// TestMirrorRandomHistory (spec §7, "mirroring end to end"): nrtmtest
// publishes random histories — changes, deletes, snapshots, expired deltas,
// new sessions — and after rpsld has synced each version its answers equal
// irrtest's over the NRTMv4 server's database, for every set and AS the
// history touched.
func TestMirrorRandomHistory(t *testing.T) {
	for seed := uint64(0); seed < 8; seed++ {
		r := rand.New(rand.NewPCG(seed, 33))
		s := nrtmtest.New(t, "TEST")
		s.SetTime(time.Now().UTC())
		s.Publish(nrtmtest.Change{Class: "as-set", PK: "AS-S0", Text: "as-set: AS-S0\nmembers: AS1\nsource: TEST\n"})
		s.Snapshot()
		key := filepath.Join(t.TempDir(), "key.pem")
		writeFile(t, key, s.PublicKey())
		addr, _, _ := start(t, s.HTTPClient(), "-source", "TEST=nrtm4:"+s.URL()+",key="+key, "-nrtm-interval", "30ms", "-keep-route-text")
		live := map[int]bool{0: true} // the as-sets the server holds now
		for step := 0; step < 14; step++ {
			switch k := r.IntN(12); {
			case k < 6:
				n := r.IntN(4)
				var ms []string
				for i := 0; i < 1+r.IntN(3); i++ {
					if r.IntN(3) == 0 {
						ms = append(ms, fmt.Sprintf("AS-S%d", r.IntN(4)))
					} else {
						ms = append(ms, fmt.Sprintf("AS%d", 1+r.IntN(5)))
					}
				}
				s.Publish(nrtmtest.Change{Class: "as-set", PK: fmt.Sprintf("AS-S%d", n),
					Text: fmt.Sprintf("as-set: AS-S%d\nmembers: %s\nsource: TEST\n", n, strings.Join(ms, ", "))})
				live[n] = true
			case k < 8:
				as := 1 + r.IntN(5)
				p := fmt.Sprintf("192.0.%d.0/24", r.IntN(8))
				s.Publish(nrtmtest.Change{Class: "route", PK: fmt.Sprintf("%sAS%d", p, as),
					Text: fmt.Sprintf("route: %s\norigin: AS%d\nsource: TEST\n", p, as)})
			case k < 9:
				s.Snapshot()
			case k < 10:
				s.Expire(s.Version() - 1) // never past the snapshot: the mirror reloads it when it must
			case k < 11:
				s.NewSession()
			default:
				for n := 0; n < 4; n++ { // the lowest-numbered set the server holds: a seed replays alike
					if live[n] {
						s.Publish(nrtmtest.Change{Delete: true, Class: "as-set", PK: fmt.Sprintf("AS-S%d", n)})
						delete(live, n)
						break
					}
				}
			}
			var texts []string
			for _, text := range s.Objects() {
				texts = append(texts, text)
			}
			oracle := irrtest.New(texts...).WithSources("TEST").IRRd(t)
			var cmds []string
			for i := 0; i < 4; i++ {
				cmds = append(cmds, fmt.Sprintf("!iAS-S%d", i), fmt.Sprintf("!iAS-S%d,1", i), fmt.Sprintf("!aAS-S%d", i))
			}
			for as := 1; as <= 5; as++ {
				cmds = append(cmds, fmt.Sprintf("!gAS%d", as))
			}
			send := "!!\n" + strings.Join(cmds, "\n") + "\n!q\n"
			want := query(t, oracle, send)
			// Wait until rpsld holds the server's version and answers as
			// the oracle does: a new session restarts the versions, so the
			// version alone does not say the mirror has caught up.
			serial := fmt.Sprintf("TEST:N:0-%d\n", s.Version())
			var err error
			for i := 0; i < 400; i++ {
				if strings.Contains(query(t, addr, "!jTEST\n"), serial) {
					if err = irrdoracle.Compare(irrdoracle.Words, query(t, addr, send), want); err == nil {
						break
					}
				} else {
					err = fmt.Errorf("serial is not %q", serial)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("seed %d step %d (version %d): %v", seed, step, s.Version(), err)
			}
		}
	}
}

func TestRPKIRefresh(t *testing.T) {
	dir := t.TempDir()
	dump := filepath.Join(dir, "ripe.db")
	writeFile(t, dump, "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n")
	vrps := filepath.Join(dir, "vrps.json")
	writeFile(t, vrps, `{"roas": []}`)
	addr, _, log := start(t, nil, "-source", "RIPE=dump:"+dump, "-rpki", vrps, "-rpki-refresh", "50ms", "-keep-route-text")
	if got := query(t, addr, "!!\n!gAS1\n!j-*\n!q\n"); got != "A13\n192.0.2.0/24\nC\nA22\nRIPE:N:0-1\nRPKI:N:0-1\nC\n" {
		t.Errorf("before: %q", got)
	}
	writeFile(t, vrps, `{"roas": [{"asn": "AS2", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "t"}]}`)
	eventually(t, addr, "!gAS1\n", "D\n") // now RPKI-invalid: hidden
	eventually(t, addr, "!!\n!sRPKI\n!gAS2\n!q\n", "C\nA13\n192.0.2.0/24\nC\n")
	// A refresh that fails keeps the VRPs and the RPKI registry.
	writeFile(t, vrps, `{"roas": [`)
	logged(t, log, `msg="VRP refresh failed: keeping the previous VRPs"`, 1)
	if got := query(t, addr, "!!\n!gAS1\n!sRPKI\n!gAS2\n!q\n"); got != "D\nC\nA13\n192.0.2.0/24\nC\n" {
		t.Errorf("after a failed refresh: %q", got)
	}
}

// TestRPKIDefault: -rpki-default puts RPKI last in the default selection,
// as RADB does; false leaves it to "!s".
func TestRPKIDefault(t *testing.T) {
	dir := t.TempDir()
	dump := filepath.Join(dir, "ripe.db")
	writeFile(t, dump, "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n")
	vrps := filepath.Join(dir, "vrps.json")
	writeFile(t, vrps, `{"roas": [{"asn": "AS2", "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "t"}]}`)
	addr, _, _ := start(t, nil, "-source", "RIPE=dump:"+dump, "-rpki", vrps)
	if got := query(t, addr, "!!\n!s-lc\n!gAS2\n!q\n"); got != "A10\nRIPE,RPKI\nC\nA16\n198.51.100.0/24\nC\n" {
		t.Errorf("-rpki-default: %q", got)
	}
	addr, _, _ = start(t, nil, "-source", "RIPE=dump:"+dump, "-rpki", vrps, "-rpki-default=false")
	if got := query(t, addr, "!!\n!s-lc\n!gAS2\n!q\n"); got != "A5\nRIPE\nC\nD\n" {
		t.Errorf("-rpki-default=false: %q", got)
	}
}
