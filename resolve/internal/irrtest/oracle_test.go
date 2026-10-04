package irrtest

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrdoracle"
	"github.com/rkolesnichenko/rpsl/types"
)

// skipped are the recorded cases irrtest does not answer as IRRd, each with
// why; every other case must agree. Commands irrtest does not implement at
// all (!r, -x, -M) are its scope, not its bugs.
var skipped = map[string]string{
	"session/j-all":  "irrtest's serial is its object count (NAME:N:0-n); IRRd's plain load has none",
	"session/j-ripe": "as session/j-all", "session/j-mixed": "as session/j-all", "session/j-lower": "as session/j-all",
	"ripe/-x 192.0.2.0/24": "irrtest has no -x", "ripe/-M 192.0.2.0/24": "irrtest has no -M",
	"rpki/!j-*": "irrtest's serials (see session/j-all)", "rpki/!jRPKI": "as rpki/!j-*",
	"rpki/-x 192.0.2.0/25": "irrtest has no -x",
	"rpki/all-sources":     "it holds !r192.0.2.0/24,o; irrtest has no !r",
}

func TestMatchesIRRd(t *testing.T) {
	dir := irrdoracle.Fixture(t)
	for _, config := range []string{"plain", "rpki"} {
		db := New().WithSources("RIPE", "RADB")
		db.defaults = []string{"RIPE", "RADB"} // sources_default in irrd.yaml and irrd-rpki.yaml
		db.unique = true                       // radb.db's last route replaces an earlier one, as in IRRd
		for _, text := range fixtureTexts(t, dir) {
			o, _ := rpsl.ParseObject(text)
			db.Add(o, text)
		}
		if config == "rpki" {
			db = db.WithRPKI(fixtureROAs(t, dir)...)
		}
		addr := db.IRRd(t)
		for _, g := range irrdoracle.Load(t, config) {
			if strings.HasPrefix(g.Name, "r/") || strings.HasPrefix(g.Name, "rpki/!r") {
				continue // !r: not implemented by irrtest
			}
			if g.Name == "rpki/pseudo" {
				// Its !r lines are irrtest's scope; every other reply in it
				// is compared (the pseudo registry's !s, !g, and an !mroute
				// by prefix and origin, which names no pseudo route).
				var err error
				if g.Send, g.Got, err = withoutCommands(g.Send, g.Got, "!r"); err != nil {
					t.Fatalf("%s: %v", g.Name, err)
				}
			}
			if why, ok := skipped[g.Name]; ok {
				t.Logf("%s: skipped: %s", g.Name, why)
				continue
			}
			got := ask(t, addr, g.Send)
			if err := irrdoracle.Compare(g.Kind, got, g.Got); err != nil {
				t.Errorf("%s %s (%q): %v", config, g.Name, g.Send, err)
			}
		}
	}
}

// withoutCommands is a recorded exchange — send, a persistent session's
// commands, and got, IRRd's replies to them — without the commands that
// begin with prefix and their replies. "!!" and "!q" have no reply; every
// other command has one: an A frame, or a C, D or F line.
func withoutCommands(send, got, prefix string) (string, string, error) {
	var replies []string
	for rest := got; rest != ""; {
		n := strings.IndexByte(rest, '\n') + 1
		if n == 0 {
			return "", "", fmt.Errorf("a reply without its newline: %q", rest)
		}
		if rest[0] == 'A' {
			size, err := strconv.Atoi(rest[1 : n-1])
			if err != nil || n+size+2 > len(rest) || rest[n+size:n+size+2] != "C\n" {
				return "", "", fmt.Errorf("a broken frame: %q", rest)
			}
			n += size + 2
		}
		replies, rest = append(replies, rest[:n]), rest[n:]
	}
	var keptSend, keptGot strings.Builder
	i := 0
	for _, cmd := range strings.SplitAfter(send, "\n") {
		if cmd == "" {
			continue
		}
		if line := strings.TrimSuffix(cmd, "\n"); line == "!!" || line == "!q" {
			keptSend.WriteString(cmd)
			continue
		}
		if i >= len(replies) {
			return "", "", fmt.Errorf("more commands than the %d replies", len(replies))
		}
		if !strings.HasPrefix(cmd, prefix) {
			keptSend.WriteString(cmd)
			keptGot.WriteString(replies[i])
		}
		i++
	}
	if i != len(replies) {
		return "", "", fmt.Errorf("%d commands for %d replies", i, len(replies))
	}
	return keptSend.String(), keptGot.String(), nil
}

// fixtureTexts reads ripe.db and radb.db, one text per object, RIPE first.
func fixtureTexts(t *testing.T, dir string) []string {
	var texts []string
	for _, f := range []string{"ripe.db", "radb.db"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range strings.Split(string(b), "\n\n") {
			if strings.TrimSpace(o) != "" {
				texts = append(texts, strings.Trim(o, "\n")+"\n")
			}
		}
	}
	return texts
}

func fixtureROAs(t *testing.T, dir string) []ROA {
	b, err := os.ReadFile(filepath.Join(dir, "roas.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ROAs []struct {
			ASN       string `json:"asn"`
			Prefix    string `json:"prefix"`
			MaxLength int    `json:"maxLength"`
			TA        string `json:"ta"`
		} `json:"roas"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var out []ROA
	for _, r := range doc.ROAs {
		as, err := types.ParseASN(r.ASN)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ROA{Prefix: netip.MustParsePrefix(r.Prefix), ASN: as, MaxLength: r.MaxLength, TA: r.TA})
	}
	return out
}

func ask(t *testing.T, addr, send string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := irrdoracle.Send(c, send); err != nil {
		t.Fatal(err)
	}
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return string(out)
		}
	}
}
