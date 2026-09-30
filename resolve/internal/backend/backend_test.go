package backend

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

const dump = "aut-num: AS1\nas-name: ONE\nimport: from AS2 accept ANY\nsource: RIPE\n\n" +
	"route: 10.1.0.0/16\norigin: AS1\nsource: RIPE\n\n" +
	"route: 10.9.0.0/16\norigin: AS1\nsource: RADB\n"

func TestOpenDumps(t *testing.T) {
	name := filepath.Join(t.TempDir(), "d.db")
	if err := os.WriteFile(name, []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Open(Options{Dumps: []string{name}, Sources: "ripe", KeepPolicy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ps, err := b.Src.OriginatedRoutes(context.Background(), 1, types.AFIv4)
	if err != nil || len(ps) != 1 || ps[0].String() != "10.1.0.0/16" {
		t.Errorf("OriginatedRoutes(AS1) with -s RIPE = %v, %v; want [10.1.0.0/16]", ps, err)
	}
	if an, err := b.Src.AutNum(context.Background(), 1, ""); err != nil || an.AS != 1 {
		t.Errorf("AutNum(AS1) with KeepPolicy = %v, %v", an.AS, err)
	}
	all, err := b.Restrict("RADB").OriginatedRoutes(context.Background(), 1, types.AFIv4)
	if err != nil || len(all) != 1 || all[0].String() != "10.9.0.0/16" {
		t.Errorf("Restrict(RADB).OriginatedRoutes(AS1) = %v, %v", all, err)
	}
}

func TestOpenIRRd(t *testing.T) {
	db := irrtest.New("route: 10.1.0.0/16\norigin: AS1\nsource: RIPE\n").WithSources("RIPE")
	b, err := Open(Options{Host: db.IRRd(t), Sources: "RIPE", Conns: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ps, err := b.Src.OriginatedRoutes(context.Background(), 1, types.AFIv4)
	if err != nil || len(ps) != 1 {
		t.Errorf("OriginatedRoutes(AS1) over IRRd = %v, %v", ps, err)
	}
}
