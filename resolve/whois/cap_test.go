package whois

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A response larger than the cap is rejected rather than read unbounded into
// memory. MaxResponse makes the limit injectable so the test need not stream
// the 256 MiB default.
func TestWhoisResponseCap(t *testing.T) {
	fw := newFakeWhois(t, map[string]string{
		"-r -T as-set,route-set AS-BIG": strings.Repeat("x", 100),
	})
	src := &Source{Addr: fw.addr(), Timeout: 2 * time.Second, MaxResponse: 10}
	_, err := src.GetSet(context.Background(), mustSet(t, "AS-BIG"))
	if err == nil {
		t.Fatal("expected response-cap error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %v, want a response-cap error", err)
	}
}

func TestWhoisSanitizeSources(t *testing.T) {
	if got := sanitizeLine("RIPE\n-i member-of EVIL"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("sanitizeLine left control chars: %q", got)
	}
}
