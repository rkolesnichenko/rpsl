package irrdoracle

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestRecord starts IRRd 4.5.3 in Docker on the fixture, once per
// configuration, asks it every case on a fresh connection and rewrites
// golden/<config>.txt. Opt-in: RPSL_IRRD_DOCKER=1 (Docker and Compose v2;
// nothing is installed on the host). About two minutes the first time (the
// image builds), a few seconds per configuration after.
func TestRecord(t *testing.T) {
	if os.Getenv("RPSL_IRRD_DOCKER") != "1" {
		t.Skip("set RPSL_IRRD_DOCKER=1 to record IRRd's answers in Docker")
	}
	dir := Fixture(t)
	run := func(args ...string) {
		cmd := exec.Command(filepath.Join(dir, "run.sh"), args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("run.sh %v: %v", args, err)
		}
	}
	t.Cleanup(func() { run("down") })
	for _, config := range []string{"plain", "rpki"} {
		run("up", config)
		var gs []Golden
		for _, c := range Cases() {
			if c.Config != config {
				continue
			}
			gs = append(gs, Golden{Case: c, Got: askStable(t, "127.0.0.1:18043", c)})
		}
		if err := Write(filepath.Join(dir, "golden", config+".txt"), gs); err != nil {
			t.Fatal(err)
		}
		run("down")
	}
}

// askStable asks c until two answers in a row agree under c.Kind, at most
// five times, and returns the later. IRRd now and then closes a fresh
// connection without a byte (2 of 741 answers in three recordings), and an
// answer in hash order that a case compares exactly fails here, not in a
// later task's comparison.
func askStable(t *testing.T, addr string, c Case) string {
	t.Helper()
	prev := ask(t, addr, c.Send)
	for range 4 {
		got := ask(t, addr, c.Send)
		if Compare(c.Kind, got, prev) == nil {
			return got
		}
		prev = got
	}
	t.Fatalf("%s %s: IRRd gave no two agreeing answers in five", c.Config, c.Name)
	return ""
}

// ask sends send on a fresh connection (Send) and returns every byte answered until
// the server closes it or two seconds pass without one.
func ask(t *testing.T, addr, send string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := Send(c, send); err != nil {
		t.Fatal(err)
	}
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return string(out)
		}
	}
}
