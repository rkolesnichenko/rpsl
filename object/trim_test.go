package object

import (
	"net/netip"
	"reflect"
	"testing"
)

// A "+" (or comment-only) continuation line adds an empty line to a value, so
// "route: 91.207.181.0/24" followed by two "+" lines has the logical value
// "91.207.181.0/24\n\n" — a real RIPE object. Decoded values are trimmed at
// both ends; interior line breaks are kept.
func TestDecodedValuesAreTrimmed(t *testing.T) {
	r := mustDecode(t, "route:   91.207.181.0/24\n+\n+\norigin:  AS48275\nsource:  RIPE\n+\n").(Route)
	if r.Prefix != netip.MustParsePrefix("91.207.181.0/24") || r.Source != "RIPE" {
		t.Errorf("route = %s, source %q; want 91.207.181.0/24, RIPE", r.Prefix, r.Source)
	}
	r6 := mustDecode(t, "route6: 2001:db8::/32\n+\norigin: AS1\n").(Route6)
	if r6.Prefix != netip.MustParsePrefix("2001:db8::/32") {
		t.Errorf("route6 = %s, want 2001:db8::/32", r6.Prefix)
	}
	in6 := mustDecode(t, "inet6num: 2001:db8::/32\n+\nnetname: NET\n+\nstatus: ASSIGNED PA\n+\n").(Inet6num)
	if in6.Prefix != netip.MustParsePrefix("2001:db8::/32") || in6.Netname != "NET" || in6.Status != "ASSIGNED PA" {
		t.Errorf("inet6num = %s %q %q", in6.Prefix, in6.Netname, in6.Status)
	}
	in := mustDecode(t, "inetnum: 192.0.2.0 - 192.0.2.255\n+\n").(Inetnum)
	if in.Lo != netip.MustParseAddr("192.0.2.0") || in.Hi != netip.MustParseAddr("192.0.2.255") {
		t.Errorf("inetnum = %s - %s", in.Lo, in.Hi)
	}
	an := mustDecode(t, "aut-num: AS1\nas-name: ONE\n+\ndescr: first\n+\n+\nremarks: a\n+\n b\n").(AutNum)
	if an.AsName != "ONE" || !reflect.DeepEqual(an.Descr, []string{"first"}) ||
		!reflect.DeepEqual(an.Remarks, []string{"a\n\nb"}) {
		t.Errorf("aut-num as-name %q, descr %q, remarks %q", an.AsName, an.Descr, an.Remarks)
	}
	mn := mustDecode(t, "mntner: MNT-X\n+\n").(Mntner)
	if mn.Handle != "MNT-X" {
		t.Errorf("mntner handle = %q, want MNT-X", mn.Handle)
	}
}
