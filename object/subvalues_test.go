package object

import (
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
)

// The RFC 2622 §8.1 aggregation attributes decode into their own ASTs rather
// than staying raw text.
func TestDecodeRouteAggregation(t *testing.T) {
	r := mustDecode(t, `route:          128.8.0.0/16
origin:         AS1
pingable:       128.8.0.1
pingable:       128.8.0.2
inject:         at 1.1.1.1 action dpa = 100; upon HAVE-COMPONENTS {128.8.0.0/17, 128.8.128.0/17}
components:     protocol BGP4 {128.8.0.0/16^+}
aggr-bndry:     AS1 OR AS2
aggr-mtd:       outbound AS-ANY
export-comps:   {128.8.0.0/16^-}
mnt-by:         EXAMPLE-MNT
source:         RIPE
`).(Route)

	if len(r.Pingable) != 2 || r.Pingable[0].String() != "128.8.0.1" || r.Pingable[1].String() != "128.8.0.2" {
		t.Errorf("Pingable = %v", r.Pingable)
	}
	if len(r.Inject) != 1 {
		t.Fatalf("Inject = %+v, want one", r.Inject)
	}
	in := r.Inject[0]
	if addr, ok := in.At.(policy.RouterAddr); !ok || addr.Addr.String() != "1.1.1.1" {
		t.Errorf("Inject.At = %#v", in.At)
	}
	if len(in.Actions) != 1 || in.Actions[0].Attr != "dpa" {
		t.Errorf("Inject.Actions = %+v", in.Actions)
	}
	hc, ok := in.Upon.(policy.InjectHaveComponents)
	if !ok || len(hc.Ranges) != 2 {
		t.Fatalf("Inject.Upon = %#v", in.Upon)
	}
	if hc.Ranges[0].String() != "128.8.0.0/17" {
		t.Errorf("Upon.Ranges[0] = %s", hc.Ranges[0])
	}

	if len(r.Components.Lists) != 1 || r.Components.Lists[0].Protocol != "BGP4" {
		t.Errorf("Components = %+v", r.Components)
	}
	if r.Components.Atomic {
		t.Error("Components.Atomic = true")
	}
	if _, ok := r.AggrBndry.(policy.ASExprBinary); !ok {
		t.Errorf("AggrBndry = %#v, want a binary AS expression", r.AggrBndry)
	}
	if !r.AggrMtd.Outbound || r.AggrMtd.Inbound {
		t.Errorf("AggrMtd = %+v", r.AggrMtd)
	}
	if ref, ok := r.AggrMtd.AS.(policy.ASSetRef); !ok || ref.Name.String() != "AS-ANY" {
		t.Errorf("AggrMtd.AS = %#v", r.AggrMtd.AS)
	}
	list, ok := r.ExportComps.(policy.FilterPrefixList)
	if !ok || len(list.Ranges) != 1 || list.Ranges[0].String() != "128.8.0.0/16^-" {
		t.Errorf("ExportComps = %#v", r.ExportComps)
	}
}

// A route with none of the aggregation attributes leaves them all zero.
func TestDecodeRouteAggregationAbsent(t *testing.T) {
	r := mustDecode(t, "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: RIPE\n").(Route)
	if len(r.Pingable) != 0 || len(r.Inject) != 0 {
		t.Errorf("Pingable %v, Inject %v", r.Pingable, r.Inject)
	}
	if !r.Components.IsZero() || !r.AggrMtd.IsZero() {
		t.Errorf("Components %+v, AggrMtd %+v", r.Components, r.AggrMtd)
	}
	if r.AggrBndry != nil || r.ExportComps != nil {
		t.Errorf("AggrBndry %#v, ExportComps %#v", r.AggrBndry, r.ExportComps)
	}
}

// A bad aggregation value costs that value and nothing else, and is reported
// against its own attribute's line.
func TestDecodeRouteAggregationDiagnostics(t *testing.T) {
	o := parse("route: 192.0.2.0/24\norigin: AS1\naggr-mtd: sideways\npingable: not-an-address\nmnt-by: M\nsource: RIPE\n")
	obj, diags := Decode(o)
	if len(diags) != 2 {
		t.Fatalf("diags = %+v, want two", diags)
	}
	byRule := map[string]ast.Diagnostic{}
	for _, d := range diags {
		byRule[d.Rule] = d
	}
	if d, ok := byRule["policy/aggr-mtd"]; !ok || d.Span.StartLine != 3 {
		t.Errorf("aggr-mtd diagnostic = %+v", d)
	}
	if d, ok := byRule["object/route-pingable"]; !ok || d.Span.StartLine != 4 {
		t.Errorf("pingable diagnostic = %+v", d)
	}
	r := obj.(Route)
	if r.Origin.String() != "AS1" || r.Prefix.String() != "192.0.2.0/24" {
		t.Errorf("the rest of the object was lost: %+v", r)
	}
}

// The RFC 2622 §9 inet-rtr attributes decode into their own ASTs.
func TestDecodeInetRtrAttributes(t *testing.T) {
	r := mustDecode(t, `inet-rtr:       rtr.example.net
local-as:       AS1
ifaddr:         192.0.2.1 masklen 30 action mtu = 1500;
interface:      afi ipv6.unicast 2001:db8::1 masklen 64 tunnel 192.0.2.9,GRE
peer:           BGP4 192.0.2.2 asno(AS2), flap_damp()
mp-peer:        BGP4 2001:db8::2 asno(AS2)
mnt-by:         EXAMPLE-MNT
source:         RIPE
`).(InetRtr)

	if len(r.Ifaddr) != 1 || r.Ifaddr[0].Addr.String() != "192.0.2.1" || r.Ifaddr[0].Masklen != 30 {
		t.Fatalf("Ifaddr = %+v", r.Ifaddr)
	}
	if len(r.Ifaddr[0].Actions) != 1 || r.Ifaddr[0].Actions[0].Attr != "mtu" {
		t.Errorf("Ifaddr actions = %+v", r.Ifaddr[0].Actions)
	}
	if len(r.Interface) != 1 {
		t.Fatalf("Interface = %+v", r.Interface)
	}
	iface := r.Interface[0]
	if iface.AFI.String() != "ipv6.unicast" || iface.Masklen != 64 {
		t.Errorf("Interface = %+v", iface)
	}
	if iface.Tunnel == nil || iface.Tunnel.Remote.String() != "192.0.2.9" || iface.Tunnel.Type != "GRE" {
		t.Errorf("Interface.Tunnel = %+v", iface.Tunnel)
	}
	if len(r.Peers) != 1 || r.Peers[0].Protocol != "BGP4" || len(r.Peers[0].Options) != 2 {
		t.Fatalf("Peers = %+v", r.Peers)
	}
	if r.Peers[0].Options[0].Name != "asno" || r.Peers[0].Options[0].Args[0] != "AS2" {
		t.Errorf("peer option = %+v", r.Peers[0].Options[0])
	}
	if len(r.MpPeers) != 1 || r.MpPeers[0].Peer.(policy.RouterAddr).Addr.String() != "2001:db8::2" {
		t.Errorf("MpPeers = %+v", r.MpPeers)
	}
}

func TestDecodeAuth(t *testing.T) {
	m := mustDecode(t, `mntner:         EXAMPLE-MNT
admin-c:        EX1-RIPE
upd-to:         ex@example.net
auth:           MD5-PW $1$abc$xyz
auth:           PGPKEY-1234ABCD
auth:           SSO ex@example.net
auth:           NONE
mnt-by:         EXAMPLE-MNT
source:         RIPE
`).(Mntner)
	if len(m.Auth) != 4 {
		t.Fatalf("Auth = %+v", m.Auth)
	}
	want := []struct {
		method AuthMethod
		value  string
	}{
		{AuthMD5, "$1$abc$xyz"},
		{AuthPGPKey, "PGPKEY-1234ABCD"},
		{AuthSSO, "ex@example.net"},
		{AuthNone, ""},
	}
	for i, w := range want {
		if m.Auth[i].Method != w.method || m.Auth[i].Value != w.value {
			t.Errorf("Auth[%d] = %+v, want %v %q", i, m.Auth[i], w.method, w.value)
		}
	}
	// An unknown scheme is kept whole and warned about, never dropped.
	o := parse("mntner: M\nadmin-c: EX1-RIPE\nupd-to: e@e.net\nauth: WEIRD-PW abc\nmnt-by: M\nsource: RIPE\n")
	obj, diags := Decode(o)
	if len(diags) != 1 || diags[0].Severity != ast.Warning || diags[0].Rule != "object/mntner-auth" {
		t.Fatalf("diags = %+v, want one object/mntner-auth warning", diags)
	}
	if a := obj.(Mntner).Auth; len(a) != 1 || a[0].Method != AuthUnknown || a[0].Raw != "WEIRD-PW abc" {
		t.Errorf("Auth = %+v", a)
	}
}

func TestParseAuthErrors(t *testing.T) {
	for _, s := range []string{"", "WEIRD abc", "MD5-PW", "SSO"} {
		if _, err := ParseAuth(s); err == nil {
			t.Errorf("ParseAuth(%q) reported no error", s)
		}
	}
	// The raw text survives even when the scheme is not understood.
	a, _ := ParseAuth("  WEIRD-PW abc  ")
	if a.Raw != "WEIRD-PW abc" || a.String() != "WEIRD-PW abc" {
		t.Errorf("Auth = %+v", a)
	}
}

func TestDecodeTimestampsAndChanged(t *testing.T) {
	r := mustDecode(t, `route:          192.0.2.0/24
origin:         AS1
mnt-by:         M
changed:        ex@example.net 20200102
changed:        other@example.net
created:        2020-01-01T00:00:00Z
last-modified:  2021-06-30T12:34:56Z
source:         RIPE
`).(Route)
	if len(r.Changed) != 2 {
		t.Fatalf("Changed = %+v", r.Changed)
	}
	if r.Changed[0].Email != "ex@example.net" || !r.Changed[0].Date.Equal(time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Changed[0] = %+v", r.Changed[0])
	}
	if r.Changed[1].Email != "other@example.net" || !r.Changed[1].Date.IsZero() {
		t.Errorf("Changed[1] = %+v, want no date", r.Changed[1])
	}
	if !r.Created.Known() || r.Created.Time.Year() != 2020 || r.Created.Raw != "2020-01-01T00:00:00Z" {
		t.Errorf("Created = %+v", r.Created)
	}
	if !r.LastModified.Known() || r.LastModified.Time.Year() != 2021 {
		t.Errorf("LastModified = %+v", r.LastModified)
	}
	if r.Created.IsZero() {
		t.Error("Created.IsZero() = true on a present attribute")
	}

	// An unparsable stamp is kept and warned about: Raw still round-trips it.
	o := parse("route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\ncreated: yesterday\nsource: RIPE\n")
	obj, diags := Decode(o)
	if len(diags) != 1 || diags[0].Severity != ast.Warning || diags[0].Rule != "object/route-created" {
		t.Fatalf("diags = %+v, want one object/route-created warning", diags)
	}
	if c := obj.(Route).Created; c.Raw != "yesterday" || c.Known() {
		t.Errorf("Created = %+v", c)
	}
}

func TestDecodeMntRoutes(t *testing.T) {
	r := mustDecode(t, `route:          192.0.2.0/24
origin:         AS1
mnt-by:         M
mnt-routes:     MNT-A
mnt-routes:     MNT-B ANY
mnt-routes:     MNT-C {192.0.2.0/25^+, 192.0.2.128/25}
source:         RIPE
`).(Route)
	if len(r.MntRoutes) != 3 {
		t.Fatalf("MntRoutes = %+v", r.MntRoutes)
	}
	// No scope means the whole space, as RIPE reads it.
	if r.MntRoutes[0].Mntner != "MNT-A" || !r.MntRoutes[0].Any || len(r.MntRoutes[0].Ranges) != 0 {
		t.Errorf("MntRoutes[0] = %+v", r.MntRoutes[0])
	}
	if r.MntRoutes[1].Mntner != "MNT-B" || !r.MntRoutes[1].Any {
		t.Errorf("MntRoutes[1] = %+v", r.MntRoutes[1])
	}
	c := r.MntRoutes[2]
	if c.Mntner != "MNT-C" || c.Any || len(c.Ranges) != 2 {
		t.Fatalf("MntRoutes[2] = %+v", c)
	}
	if c.Ranges[0].String() != "192.0.2.0/25^+" || c.Ranges[1].String() != "192.0.2.128/25" {
		t.Errorf("MntRoutes[2].Ranges = %v", c.Ranges)
	}
	if got, want := c.String(), "MNT-C {192.0.2.0/25^+, 192.0.2.128/25}"; got != want {
		t.Errorf("MntRoutes[2].String() = %q, want %q", got, want)
	}
}

func TestParseRtrSetMember(t *testing.T) {
	for _, c := range []struct {
		in   string
		kind RtrMemberKind
	}{
		{"rtr1.example.net", RtrMemberRouter},
		{"192.0.2.1", RtrMemberRouter},
		{"2001:db8::1", RtrMemberRouter},
		{"RTRS-FOO", RtrMemberSet},
		{"AS1:RTRS-FOO", RtrMemberSet},
	} {
		m, err := ParseRtrSetMember(c.in)
		if err != nil {
			t.Errorf("ParseRtrSetMember(%q): %v", c.in, err)
			continue
		}
		if m.Kind != c.kind || m.Raw != c.in {
			t.Errorf("ParseRtrSetMember(%q) = %+v, want kind %v", c.in, m, c.kind)
		}
	}
	// A set of the wrong class is an error, not a silently followed member.
	for _, in := range []string{"", "AS-FOO", "RS-FOO", "not a router!", "1.2.3", "256.0.0.1"} {
		m, err := ParseRtrSetMember(in)
		if err == nil {
			t.Errorf("ParseRtrSetMember(%q) = %+v, want an error", in, m)
		}
		if m.Kind != RtrMemberInvalid {
			t.Errorf("ParseRtrSetMember(%q).Kind = %v, want invalid", in, m.Kind)
		}
	}
	if got := RtrMemberSet.String(); got != "rtr-set" {
		t.Errorf("RtrMemberSet.String() = %q", got)
	}
}

// A bad rtr-set member is an Error on its own item, and the good ones survive.
func TestDecodeRtrSetBadMember(t *testing.T) {
	o := parse("rtr-set: RTRS-X\nmembers: r1.example, AS-WRONG, r2.example\nmnt-by: M\nsource: RIPE\n")
	obj, diags := Decode(o)
	if len(diags) != 1 || diags[0].Severity != ast.Error || diags[0].Rule != "object/rtr-set-members" {
		t.Fatalf("diags = %+v, want one object/rtr-set-members error", diags)
	}
	ms := obj.(RtrSet).Members
	if len(ms) != 3 || ms[0].Kind != RtrMemberRouter || ms[1].Kind != RtrMemberInvalid || ms[2].Kind != RtrMemberRouter {
		t.Errorf("Members = %+v", ms)
	}
	if ms[1].Raw != "AS-WRONG" {
		t.Errorf("the bad member lost its text: %+v", ms[1])
	}
}
