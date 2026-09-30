package rpslconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var policyTexts = append(append([]string(nil), texts...),
	"aut-num: AS1\nas-name: ONE\n"+
		"import: from AS2 10.0.0.2 at 10.0.0.1 action pref = 10; accept AS2\n"+
		"import: protocol OSPF from AS2 accept ANY\n"+
		"export: to AS2 10.0.0.2 at 10.0.0.1 announce AS1\n"+
		"default: to AS2 networks {10.9.0.0/16}\n"+
		"mp-import: afi ipv6.unicast from AS2 2001:db8::2 at 2001:db8::1 accept AS2\n"+
		"source: RIPE\n",
	"aut-num: AS3\nas-name: THREE\ndefault: to AS2 action pref = 100; networks ANY\nsource: RIPE\n",
	"route6: 2001:db8:2::/48\norigin: AS2\nsource: RIPE\n",
)

func policyDump(t *testing.T) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "irr.db")
	if err := os.WriteFile(name, []byte(strings.Join(policyTexts, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestTemplateModeCisco(t *testing.T) {
	dump := policyDump(t)
	code, out, errOut := runIn(t, "!\n"+
		"@RtConfig set sources = RIPE\n"+
		"@RtConfig set cisco_map_name = \"AS%d-IN-%d\"\n"+
		"@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n"+
		"@RtConfig default AS1 AS2\n"+
		"@RtConfig networks AS1\n"+
		"@RtConfig v6networks AS1\n"+
		"end\n", "-dump", dump)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"route-map AS2-IN-1 permit 1\n", " set local-preference 990\n",
		"ip prefix-list pl100 seq 5 permit 10.2.0.0/16\n", " neighbor 10.0.0.2 route-map AS2-IN-1 in\n",
		"ip default-network 10.9.0.0\n", "network 10.1.0.0 mask 255.255.0.0\n", "network 2001:db8:1::/48\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if !strings.HasPrefix(out, "!\n") || !strings.HasSuffix(out, "end\n") || strings.Contains(out, "@RtConfig") {
		t.Errorf("the template's own lines are not copied as they are:\n%s", out)
	}
	if !strings.Contains(errOut, "line 4") || !strings.Contains(errOut, "protocol OSPF") {
		t.Errorf("no warning for the undecided OSPF import: %q", errOut)
	}
}

func TestTemplateModeLists(t *testing.T) {
	dump := policyDump(t)
	code, out, errOut := runIn(t,
		"@RtConfig aspath_access_list filter <^AS1 AS-A*$>\n"+
			"@RtConfig printPrefixRanges \"%p/%l^%n-%m\\n\" filter AS-A\n"+
			"@RtConfig printPrefixes \"%p %k %K %L\\n\" filter {10.0.0.0/23^24}\n"+
			"@RtConfig access_list filter afi ipv6.unicast AS1\n", "-dump", dump)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	want := "!\nno ip as-path access-list 100\nip as-path access-list 100 permit ^_1(_(1|2))*$\n" +
		"10.1.0.0/16^16-16\n10.2.0.0/16^16-16\n" +
		"10.0.0.0 255.255.255.0 0.0.0.255 8\n10.0.1.0 255.255.255.0 0.0.0.255 8\n" +
		"!\nno ipv6 prefix-list pl100\nipv6 prefix-list pl100 seq 5 permit 2001:db8:1::/48\n"
	if out != want {
		t.Errorf("output\n%s\nwant\n%s", out, want)
	}
}

func TestTemplateModeVendors(t *testing.T) {
	dump := policyDump(t)
	code, out, errOut := runIn(t, "@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n@RtConfig export AS1 10.0.0.1 AS2 10.0.0.2\n",
		"-dump", dump, "-config", "bird")
	if code != 0 || strings.Count(out, "protocol bgp ") != 1 ||
		!strings.Contains(out, "import filter MyMap_2_1;\n    export filter MyMap_2_2;") {
		t.Errorf("bird: exit %d, %s\n%s", code, errOut, out)
	}
	code, out, errOut = runIn(t, "@RtConfig import AS1 2001:db8::1 AS2 2001:db8::2\n", "-dump", dump, "-config", "junos")
	if code != 0 || !strings.Contains(out, "policy-statement policy_2_1") || !strings.Contains(out, "family inet6") {
		t.Errorf("junos v6: exit %d, %s\n%s", code, errOut, out)
	}
	for _, v := range []string{"junos", "ciscoxr", "bird"} {
		code, _, errOut = runIn(t, "@RtConfig default AS1 AS2\n", "-dump", dump, "-config", v)
		if code != 1 || !strings.Contains(errOut, "a default: the vendor has no configuration for") {
			t.Errorf("%s default: exit %d, %q", v, code, errOut)
		}
	}
	// D6: rtconfig drops the pref of a default; rpslconf refuses it.
	code, _, errOut = runIn(t, "@RtConfig default AS3 AS2\n", "-dump", dump)
	if code != 1 || !strings.Contains(errOut, "a default: the vendor has no configuration for") {
		t.Errorf("cisco default with pref: exit %d, %q", code, errOut)
	}
}

func TestTemplateModeErrors(t *testing.T) {
	dump := policyDump(t)
	for _, c := range []struct{ template, inErr string }{
		{"x\n@RtConfig import AS9 10.0.0.1 AS2 10.0.0.2\n", "AS9"}, // D9: rtconfig exits 0
		{"@RtConfig configureRouter r1.example.net\n", "not supported yet"},
		{"@RtConfig frob\n", "line 1"},
		{"@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n@RtConfig set prefix_acl_no = 5\n", "prefix_acl_no"},
		{"@RtConfig printPrefixes \"%p\\n\" filter <^AS1>\n", "prefix ranges"},
		{"@RtConfig access_list filter afi ipv4.unicast, ipv6.unicast AS1\n", "one address family"},
		{"@RtConfig aspath_access_list filter <^AS1> AND <AS2$>\n", "one AS-path"},
		{"@RtConfig access_list filter PeerAS\n", "PeerAS"},
		{"@RtConfig printPrefixes \"%p\\n\" filter {10.0.0.0/8^32}\n", "more than"},
	} {
		code, _, errOut := runIn(t, c.template, "-dump", dump)
		if code != 1 || !strings.Contains(errOut, c.inErr) {
			t.Errorf("%q: exit %d, stderr %q; want 1 and %q", c.template, code, errOut, c.inErr)
		}
	}
}
