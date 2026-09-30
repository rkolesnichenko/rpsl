package rtconfig

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
)

// actions parses "action …" text the way an import: carries it.
func actions(t *testing.T, s string) []policy.Action {
	t.Helper()
	imp, diags := policy.ParseImport("from AS2 action " + s + " accept ANY")
	for _, d := range diags {
		if d.Severity >= ast.Error {
			t.Fatalf("%q: %v", s, d)
		}
	}
	return imp.Expr.(policy.Factor).Peers[0].Actions
}

func (o setOps) summary() string {
	var parts []string
	if o.localPref >= 0 {
		parts = append(parts, fmt.Sprintf("lp=%d", o.localPref))
	}
	if o.med >= 0 {
		parts = append(parts, fmt.Sprintf("med=%d", o.med))
	}
	if o.medIGP {
		parts = append(parts, "med=igp")
	}
	list := func(cs []community) string {
		var s []string
		for _, c := range cs {
			s = append(s, c.String())
		}
		return strings.Join(s, ",")
	}
	if o.commSetGiven {
		parts = append(parts, "set="+list(o.commSet))
	}
	if len(o.commAdd) > 0 {
		parts = append(parts, "add="+list(o.commAdd))
	}
	if len(o.commDel) > 0 {
		parts = append(parts, "del="+list(o.commDel))
	}
	if len(o.prepend) > 0 {
		parts = append(parts, fmt.Sprintf("prepend=%v", o.prepend))
	}
	if o.nextHop.IsValid() {
		parts = append(parts, "nh="+o.nextHop.String())
	}
	if o.nextHopSelf {
		parts = append(parts, "nh=self")
	}
	return strings.Join(parts, " ")
}

func TestCompileActions(t *testing.T) {
	g := &Generator{Vendor: Junos}
	for _, c := range []struct{ in, want string }{
		{"pref = 10;", "lp=990"},
		{"pref = 10; pref = 20;", "lp=980"},
		{"med = 5;", "med=5"},
		{"med = igp_cost;", "med=igp"},
		{"community.append(1:2, no_export);", "add=1:2,65535:65281"},
		{"community .= {1:3};", "add=1:3"},
		{"community = {1:4}; community.append(1:5);", "set=1:4,1:5"},
		{"community.append(1:2); community.delete(1:2);", "del=1:2"},
		{"community.delete(1:2); community.append(1:2);", "add=1:2"},
		{"aspath.prepend(AS1, AS1);", "prepend=[AS1 AS1]"},
		{"aspath.prepend(AS2); aspath.prepend(AS1);", "prepend=[AS1 AS2]"},
		{"next-hop = 192.0.2.1;", "nh=192.0.2.1"},
		{"next-hop = self;", "nh=self"},
	} {
		ops, err := g.compileActions(actions(t, c.in), c.in)
		if err != nil || ops.summary() != c.want {
			t.Errorf("compileActions(%s) = %q, %v; want %q", c.in, ops.summary(), err, c.want)
		}
	}
}

func TestCompileActionsRefuses(t *testing.T) {
	for _, c := range []struct {
		v     Vendor
		in    string
		cause string
	}{
		{Junos, "pref = 1001;", CausePref},
		{Junos, "dpa = 5;", CauseAction},
		{Junos, "community.append(1:2:3);", CauseCommunityForm},
		{Junos, "med = abc;", CauseActionValue},
		{BIRD2, "med = igp_cost;", CauseActionValue},
		{IOS, "next-hop = self;", CauseActionValue},
		{BIRD2, "next-hop = self;", CauseActionValue},
	} {
		g := &Generator{Vendor: c.v}
		_, err := g.compileActions(actions(t, c.in), c.in)
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Cause != c.cause || ue.Vendor != c.v {
			t.Errorf("%v compileActions(%s): err %v, want cause %q", c.v, c.in, err, c.cause)
		}
	}
}
