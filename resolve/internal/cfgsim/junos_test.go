package cfgsim

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// rtconfig's own Junos output means what its IOS output means (Task 7).
func TestJunosReadsRtconfig(t *testing.T) {
	text, err := os.ReadFile("../../testdata/rtconfig/golden/import-v4-junos.txt")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseJunos(string(text))
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := c.Attached(netip.MustParseAddr("10.0.0.2"), false); !ok || name != "policy_2_1" {
		t.Fatalf("Attached(10.0.0.2) = %q, %v", name, ok)
	}
	for _, x := range []struct {
		name   string
		r      Route
		accept bool
		attrs  Attrs
	}{
		{"policy_2_1", route("10.1.0.0/16", []types.ASN{2, 1}), true, Attrs{LocalPref: 990, MED: 5, Communities: []string{"1:100"}}},
		{"policy_2_1", route("10.11.0.0/16", []types.ASN{2}), true, Attrs{LocalPref: 990, MED: 5, Communities: []string{"1:100"}}},
		{"policy_2_1", route("10.10.1.0/24", []types.ASN{2}), true, Attrs{LocalPref: 990, MED: 5, Communities: []string{"1:100"}}},
		{"policy_2_1", route("10.10.2.0/24", []types.ASN{2}), false, Attrs{}},
		{"policy_2_1", route("10.1.0.0/24", []types.ASN{2}), false, Attrs{}},
		{"policy_2_1", route("192.0.2.0/24", []types.ASN{2}), true, Attrs{LocalPref: -1, MED: -1}},
		{"policy_4_3", route("10.44.0.0/16", []types.ASN{4, 10, 1}, "4:1"), true, Attrs{LocalPref: -1, MED: -1, Communities: []string{"4:1"}}},
		{"policy_4_3", route("10.44.0.0/16", []types.ASN{4, 13}, "4:1"), false, Attrs{}},
		{"policy_5_4", route("10.5.0.0/16", []types.ASN{5}), true, Attrs{LocalPref: -1, MED: -1, Prepended: []types.ASN{1, 1}}},
		{"policy_5_4", route("10.55.0.0/16", []types.ASN{5}, "5:666"), false, Attrs{}},
		{"policy_5_4", route("10.55.0.0/16", []types.ASN{5}), true, Attrs{LocalPref: -1, MED: -1, Prepended: []types.ASN{1, 1}}},
	} {
		ok, a, err := c.Policy(x.name, x.r)
		if err != nil || ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("%s(%v) = %v %+v, %v; want %v %+v", x.name, x.r, ok, a, err, x.accept, x.attrs)
		}
	}
}

// The longest-matching route-filter decides, even when a shorter one would
// have accepted; and a policy that falls off its end accepts (BGP's default
// import policy).
func TestJunosLongestMatchAndDefault(t *testing.T) {
	const text = `
policy-options {
    policy-statement P {
        term t {
            from {
                route-filter 10.0.0.0/8 upto /24;
                route-filter 10.2.0.0/16 exact;
            }
            then {
                local-preference 500;
                accept;
            }
        }
        term r {
            then reject;
        }
    }
    policy-statement OPEN {
        term t {
            from as-path NEVER;
            then reject;
        }
    }
    as-path NEVER "666";
}
`
	c, err := ParseJunos(text)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		name   string
		r      Route
		accept bool
	}{
		{"P", route("10.2.0.0/16", []types.ASN{2}), true},
		{"P", route("10.2.3.0/24", []types.ASN{2}), false},
		{"P", route("10.3.3.0/24", []types.ASN{2}), true},
		{"OPEN", route("10.3.3.0/24", []types.ASN{2}), true},
		{"OPEN", route("10.3.3.0/24", []types.ASN{666}), false},
	} {
		ok, _, err := c.Policy(x.name, x.r)
		if err != nil || ok != x.accept {
			t.Errorf("%s(%v) = %v, %v; want %v", x.name, x.r, ok, err, x.accept)
		}
	}
	if _, err := ParseJunos("policy-options { policy-statement P { term t { from { frobnicate 1; } then accept; } } }"); err == nil {
		t.Errorf("an unknown condition parsed")
	}
}

// Several "from policy" conditions are one chain, which the first subroutine
// that decides decides. A policy expression combines the results.
func TestJunosPolicyChains(t *testing.T) {
	const text = `
policy-options {
    policy-statement COMM {
        term t { from community C1; then accept; }
    }
    policy-statement COMMR {
        term t { from community C1; then accept; }
        term r { then reject; }
    }
    policy-statement PFX {
        term t { from { route-filter 10.0.0.0/8 orlonger; } then accept; }
        term r { then reject; }
    }
    policy-statement CHAIN {
        term t { from { policy COMM; policy PFX; } then accept; }
        term r { then reject; }
    }
    policy-statement AND {
        term t { from policy (COMMR && PFX); then accept; }
        term r { then reject; }
    }
    community C1 members 1:1;
}
`
	c, err := ParseJunos(text)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		name   string
		r      Route
		accept bool
	}{
		{"CHAIN", route("192.0.2.0/24", nil, "1:1"), true}, // COMM decides; PFX is never asked
		{"CHAIN", route("10.1.0.0/16", nil), true},         // COMM decides nothing; PFX accepts
		{"CHAIN", route("192.0.2.0/24", nil), false},
		{"AND", route("10.1.0.0/16", nil, "1:1"), true},
		{"AND", route("10.1.0.0/16", nil), false},
		{"AND", route("192.0.2.0/24", nil, "1:1"), false},
	} {
		ok, _, err := c.Policy(x.name, x.r)
		if err != nil || ok != x.accept {
			t.Errorf("%s(%v) = %v, %v; want %v", x.name, x.r, ok, err, x.accept)
		}
	}
}

// A route-filter's own action must be "accept", "reject", or absent; an
// unrecognized one is refused rather than silently treated as no action. An
// unknown "then" keyword is refused the same way an unknown "from" condition
// is: at parse time (fromHandlers and thenHandlers are the one place cfgsim's
// Junos reader knows each keyword, so nothing is silently accepted in one
// place and silently ignored in the other).
func TestJunosInvalidActionsRefused(t *testing.T) {
	c, err := ParseJunos(`
policy-options {
    policy-statement P {
        term t {
            from { route-filter 10.0.0.0/8 exact frobnicate; }
            then accept;
        }
    }
}
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Policy("P", route("10.0.0.0/8", nil)); err == nil {
		t.Errorf("a route-filter with an invalid action parsed")
	}
	if _, err := ParseJunos("policy-options { policy-statement P { term t { then frobnicate; } } }"); err == nil {
		t.Errorf("an unknown then keyword parsed")
	}
}

// rtconfig writes its warnings amid the configuration, here inside
// policy-options; they are its diagnostics, not configuration, and are
// skipped as ParseIOS and ParseXR skip them.
func TestJunosSkipsRtconfigWarnings(t *testing.T) {
	c, err := ParseJunos(`
policy-options {
Warning: filter "P" matches ANY/NOT ANY
  policy-statement P {
      term t { from { } then { accept; } }
   }
}
*** Error: something rtconfig could not do
`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := c.Policy("P", route("192.0.2.0/24", nil)); err != nil || !ok {
		t.Errorf("P(192.0.2.0/24) = %v, %v; want accepted", ok, err)
	}
}
