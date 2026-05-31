package policy

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// action parses one import: value and returns its single PeerAction's actions.
func actions(t *testing.T, s string) []Action {
	t.Helper()
	imp, diags := ParseImport(s)
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	f := factor(t, imp.Expr)
	if len(f.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(f.Peers))
	}
	return f.Peers[0].Actions
}

func TestActionInt(t *testing.T) {
	as := actions(t, "from AS1 action pref = 100; med = 10; dpa = 5 accept ANY")
	if len(as) != 3 {
		t.Fatalf("actions = %+v, want 3", as)
	}
	for i, want := range []int{100, 10, 5} {
		if n, ok := as[i].Int(); !ok || n != want {
			t.Errorf("action[%d].Int() = %d,%v, want %d,true", i, n, ok, want)
		}
	}
}

func TestActionPrepends(t *testing.T) {
	as := actions(t, "from AS1 action aspath.prepend(AS65001, AS65001, AS65001) accept ANY")
	if len(as) != 1 {
		t.Fatalf("actions = %+v, want 1", as)
	}
	got, ok := as[0].Prepends()
	if !ok || len(got) != 3 {
		t.Fatalf("Prepends() = %v,%v, want 3 ASNs", got, ok)
	}
	for _, as := range got {
		if as != types.ASN(65001) {
			t.Errorf("prepend ASN = %v, want AS65001", as)
		}
	}
}

func TestActionCommunities(t *testing.T) {
	cases := map[string]string{
		"assign": "from AS1 action community = {65000:1, 65000:2} accept ANY",
		"append": "from AS1 action community .= {65000:1, 65000:2} accept ANY",
		"method": "from AS1 action community.append(65000:1, 65000:2) accept ANY",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			as := actions(t, s)
			if len(as) != 1 {
				t.Fatalf("actions = %+v, want 1", as)
			}
			got, ok := as[0].Communities()
			if !ok || len(got) != 2 || got[0] != "65000:1" || got[1] != "65000:2" {
				t.Errorf("Communities() = %v,%v, want [65000:1 65000:2]", got, ok)
			}
		})
	}
}

func TestActionAccessorsRejectMismatch(t *testing.T) {
	as := actions(t, "from AS1 action pref = 100 accept ANY")
	if _, ok := as[0].Prepends(); ok {
		t.Error("pref action reported as Prepends")
	}
	if _, ok := as[0].Communities(); ok {
		t.Error("pref action reported as Communities")
	}
}

func TestFilterCommunityValues(t *testing.T) {
	imp, _ := ParseImport("from AS1 accept community(65000:1, 65000:2)")
	f := factor(t, imp.Expr)
	fc, ok := f.Filter.(FilterCommunity)
	if !ok {
		t.Fatalf("filter = %T, want FilterCommunity", f.Filter)
	}
	if vs := fc.Values(); len(vs) != 2 || vs[0] != "65000:1" {
		t.Errorf("Values() = %v, want [65000:1 65000:2]", vs)
	}
}
