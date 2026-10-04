package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestMain runs main itself when the test binary is started as rpsld by
// TestSecondSignalEnds.
func TestMain(m *testing.M) {
	if args := os.Getenv("RPSLD_TEST_MAIN"); args != "" {
		os.Args = append([]string{"rpsld"}, strings.Split(args, "\x1f")...)
		main()
		return
	}
	os.Exit(m.Run())
}

// TestSecondSignalEnds: the first SIGTERM stops rpsld gently, giving a
// connection still being answered -grace to finish; a second one ends it
// at once, as Go's default handling does.
func TestSecondSignalEnds(t *testing.T) {
	if testing.Short() {
		t.Skip("starts rpsld in a process of its own")
	}
	// An answer far larger than the socket buffers, so that a client that
	// never reads holds its connection being answered.
	dump := filepath.Join(t.TempDir(), "ripe.db")
	var b strings.Builder
	for i := 0; i < 40000; i++ {
		fmt.Fprintf(&b, "route: 10.%d.%d.0/24\norigin: AS1\nremarks: %s\nsource: RIPE\n\n", i>>8&255, i&255, strings.Repeat("x", 500))
	}
	if err := os.WriteFile(dump, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "RPSLD_TEST_MAIN="+strings.Join([]string{
		"-source", "RIPE=dump:" + dump, "-keep-route-text", "-listen", "127.0.0.1:0", "-grace", "1m"}, "\x1f"))
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	var log strings.Builder
	var mu sync.Mutex
	lines := make(chan string, 100)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			mu.Lock()
			log.WriteString(sc.Text() + "\n")
			mu.Unlock()
			select {
			case lines <- sc.Text():
			default:
			}
		}
		io.Copy(io.Discard, stderr)
		exited <- cmd.Wait()
	}()
	t.Cleanup(func() { cmd.Process.Kill() })
	wait := func(re string) string {
		t.Helper()
		r := regexp.MustCompile(re)
		deadline := time.After(30 * time.Second)
		for {
			select {
			case l := <-lines:
				if m := r.FindStringSubmatch(l); m != nil {
					return m[len(m)-1]
				}
			case <-deadline:
				mu.Lock()
				defer mu.Unlock()
				t.Fatalf("no log line matching %s; log:\n%s", re, log.String())
			}
		}
	}
	addr := wait(`msg=listening addr=(\S+)`)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "!r0.0.0.0/0,M\n") // and never read
	time.Sleep(500 * time.Millisecond)
	cmd.Process.Signal(syscall.SIGTERM)
	wait(`msg=stopping`)
	select {
	case err := <-exited:
		t.Fatalf("rpsld ended within its grace after one signal: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-exited:
		ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
			t.Errorf("after a second SIGTERM: %v (%v), want the signal's default end", err, cmd.ProcessState)
		}
	case <-time.After(10 * time.Second):
		t.Error("a second SIGTERM did not end rpsld")
	}
}
