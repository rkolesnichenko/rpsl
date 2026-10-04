package irrdoracle

import "strings"

// Cases is every exchange recorded from IRRd, in recording order.
func Cases() []Case {
	var cs []Case
	add := func(config string, k Kind, name, send string) {
		cs = append(cs, Case{Name: name, Config: config, Send: send, Kind: k})
	}
	line := func(s string) string { return s + "\n" }

	// Session commands (plain).
	for _, c := range []struct{ name, send string }{
		{"v", "!v"},
		{"pipeline", "!!\n!v\n!gAS65001\n!6AS65001\n!iAS-FOO\n!q"},
		{"not-persistent", "!v\n!gAS65001"},
		{"s-ripe", "!sRIPE"}, {"s-ripe-lower", "!sripe"}, {"s-lc", "!s-lc"}, {"s-star", "!s-*"},
		{"s-nosuch", "!sNOSUCH"}, {"s-ripe-nosuch", "!sRIPE,NOSUCH"}, {"s-empty", "!s"},
		{"s-session", "!!\n!sRIPE\n!s-lc\n!iAS-FOO\n!q"},
		{"s-radb", "!!\n!sRADB\n!s-lc\n!iAS-FOO\n!iAS-FOO,1\n!aAS-FOO\n!q"},
		{"s-star-keeps", "!!\n!sRIPE\n!s-*\n!s-lc\n!q"},
		{"s-refused-keeps", "!!\n!sRIPE\n!sNOSUCH\n!s-lc\n!q"},
		{"s-order", "!!\n!sradb,ripe\n!s-lc\n!iAS-FOO\n!q"},
		{"j-all", "!j-*"}, {"j-ripe", "!jRIPE"}, {"j-nosuch", "!jNOSUCH"}, {"j-mixed", "!jRIPE,NOSUCH"},
		{"j-lower", "!jripe"}, {"j-empty", "!j"}, {"j-rpki", "!jRPKI"},
		{"n-space", "!n test"}, {"n", "!ntest"}, {"n-empty", "!n"},
		{"t", "!t600"}, {"t-zero", "!t0"}, {"t-big", "!t1001"}, {"t-word", "!tfoo"}, {"t-empty", "!t"},
		{"unknown", "!x"}, {"unknown-upper", "!X"}, {"bang", "!"},
		{"q", "!q"}, {"q-upper", "!Q"}, {"q-bare", "q"},
		{"blank-first", "\n!v"}, {"crlf", "\r\n!v\r"}, {"spaces-first", "   \n!v"},
		{"blank-in-session", "!!\n\n\n!v\n!q"}, {"nul", "!iAS-FOO\x00"},
	} {
		k := Exact
		if c.name == "pipeline" {
			k = Words // it holds !gAS65001, whose prefixes IRRd answers in hash order
		}
		add("plain", k, "session/"+c.name, line(c.send))
	}

	sets := []string{"AS-FOO", "as-foo", "AS-BAR", "RS-FOO", "RS-INNER", "AS-REF", "AS-EMPTY",
		"AS-MISSING", "AS-ANY", "RS-ANY", "AS-RADBONLY", "FLTR-FOO", "RTRS-FOO", "PRNG-FOO",
		"AS65001", "AS-NORM", "RS-NOLEN", "RS-LOWER", "AS-LOWER"}
	for _, s := range sets {
		add("plain", Exact, "i/"+s, line("!i"+s))
		add("plain", Exact, "i1/"+s, line("!i"+s+",1"))
	}
	add("plain", Exact, "i/empty", line("!i"))
	add("plain", Exact, "i1/depth-2", line("!iAS-FOO,2"))
	add("plain", Exact, "i1/space", line("!iAS-FOO, 1"))

	for _, s := range []string{"!aAS-FOO", "!a4AS-FOO", "!a6AS-FOO", "!aAS-BAR", "!aRS-FOO", "!a4RS-FOO",
		"!aAS-MISSING", "!aAS-EMPTY", "!aAS-RADBONLY", "!aAS-ANY", "!a", "!a4", "!a6", "!aas-foo", "!aAS-REF", "!aRS-LOWER", "!aAS-LOWER"} {
		add("plain", Words, "a/"+strings.TrimPrefix(s, "!"), line(s))
	}
	for _, s := range []string{"!gAS65001", "!gAS65002", "!gAS65003", "!gAS65005", "!gAS65099",
		"!gas65001", "!g65001", "!gAS1.10", "!gFOO", "!gAS", "!g", "!6AS65001", "!6AS65002",
		"!6AS65003", "!6AS65099", "!6FOO", "!gAS4294967296", "!gAS65007"} {
		add("plain", Words, "g/"+strings.TrimPrefix(s, "!"), line(s))
	}
	for _, s := range []string{"192.0.2.0/24", "192.0.2.0/24,o", "192.0.2.0/24,l", "192.0.2.0/24,L",
		"192.0.2.0/24,M", "192.0.2.0/25", "192.0.2.0/25,o", "192.0.2.0/25,l", "192.0.2.0/25,L",
		"192.0.2.64/26", "192.0.2.64/26,o", "192.0.2.64/26,l", "192.0.2.64/26,L", "10.0.0.0/8",
		"10.0.0.0/8,o", "10.0.0.0/8,M", "10.0.0.0/8,L", "foo", "192.0.2.0/33", "192.0.2.1/24",
		"192.0.2.0/24,x", "192.0.2.1", "2001:db8::/32", "2001:db8::/32,o", "2001:db8::/32,M",
		"2001:DB8::/32,o", "0.0.0.0/0,M", "198.51.100.0/24,o", "64.6.160.0/19"} {
		k := Objects
		if strings.HasSuffix(s, ",o") {
			k = Words
		}
		add("plain", k, "r/"+s, line("!r"+s))
	}
	for _, s := range []string{"aut-num,AS65001", "aut-num,as65001", "AUT-NUM,AS65001", "as-set,AS-FOO",
		"as-set,as-foo", "route-set,RS-FOO", "route,192.0.2.0/24AS65001", "route,192.0.2.0/24 AS65001",
		"route,192.0.2.0/24-AS65001", "route,192.0.2.0/24as65001", "route,192.0.2.0/24",
		"route6,2001:db8::/32AS65001", "route6,2001:DB8::/32AS65001", "route6,2001:0db8::/32AS65001",
		"mntner,MNT-A", "person,JD1-RIPE", "filter-set,FLTR-FOO", "peering-set,PRNG-FOO", "rtr-set,RTRS-FOO",
		"inet-rtr,rtr1.example.net", "inet-rtr,RTR1.EXAMPLE.NET", "foo,BAR", "aut-num,AS65999",
		"an,AS65001", "rt,192.0.2.0/24-AS65001", "mntner", "", "as-set,", "as-set,AS-NORM",
		"route-set,RS-NOLEN", "route,64.6.160.0/19AS65007", "route,064.006.160.000/19AS65007"} {
		add("plain", Objects, "m/"+s, line("!m"+s))
	}

	// RIPE-style queries, one per connection, and inside a session.
	for _, s := range []string{"-s RIPE -T as-set AS-FOO", "-T as-set AS-FOO", "-s RADB -T as-set AS-FOO",
		"-i origin AS65001", "-i member-of AS-FOO", "-i member-of AS-REF", "-K -i origin AS65001",
		"-K -T as-set AS-FOO", "-K -T route-set RS-FOO", "-r -T aut-num AS65001", "AS65001", "as65001",
		"AS-NOSUCH", "-s NOSUCH AS65001", "-i foo bar", "-i origin", "-T route 192.0.2.0/24",
		"192.0.2.0/24", "-x 192.0.2.0/24", "-M 192.0.2.0/24", "-T route6 2001:db8::/32", "MNT-A",
		"-i mnt-by MNT-B", "-T mntner MNT-A", "-B AS65001", "-G AS65001", "-s ripe AS-FOO",
		"-T foo AS65001", "-Z AS65001", "AS65001 AS65002", "-i origin as65001", "-i member-of as-ref",
		"rtr1.example.net", "JD1-RIPE", "-K AS-NORM", "-s RADB AS-NORM", "-K -T route-set RS-LOWER",
		"-K -T as-set AS-LOWER", "-i members rs-inner", "-i members RS-INNER", "-i members as-bar", "-i members AS-BAR",
		"-T route-set RS-LOWER", "-i mp-members 2001:db8:1::/48", "-i mp-members 2001:DB8:1::/48",
		"-i mp-members 2001:db8::/32", "-i members 192.0.2.0/24", "-i members as65003",
		"-i members 192.0.2.1", "-i members 192.0.2.1/32", "-i members rtr1.example.net",
		"-i members RTR1.EXAMPLE.NET", "-K -T rtr-set RTRS-FOO"} {
		k := Objects
		if s == "-i foo bar" {
			// IRRd lists the attributes it can search in Python set order,
			// which changes from one IRRd run to the next.
			k = Words
		}
		add("plain", k, "ripe/"+s, line(s))
	}
	add("plain", Objects, "ripe/in-session", "!!\n-T as-set AS-FOO\n!v\n-i origin AS65003\nAS-NOSUCH\n!q\n")
	add("plain", Objects, "ripe/k-and-query", "-k -T as-set AS-FOO\n-T aut-num AS65003\n!q\n")
	add("plain", Objects, "ripe/s-flag-sticks", "!!\n!sRADB\n-T as-set AS-FOO\n-s RIPE -T as-set AS-FOO\n!s-lc\n!q\n")

	// A last line without its newline: the client then closes its sending
	// side (a Send that does not end in "\n" is sent so, as `printf … | nc -N`
	// does), so the line is all there will be.
	add("plain", Exact, "eof/v", "!v")
	add("plain", Exact, "eof/session", "!!\n!v\n!v")
	add("plain", Words, "eof/g", "!gAS65001")
	add("plain", Objects, "eof/ripe", "-T as-set AS-FOO")

	// RPKI-aware mode.
	for _, s := range []string{"!s-lc", "!j-*", "!jRPKI", "!sRPKI"} {
		add("rpki", Exact, "rpki/"+s, line(s))
	}
	for _, s := range []string{"!gAS65001", "!6AS65001", "!6AS65002", "!gAS65003", "!gAS65005", "!gAS65009",
		"!gAS65007", "!aAS-FOO", "!aAS-REF", "!r192.0.2.0/24,o"} {
		add("rpki", Words, "rpki/"+s, line(s))
	}
	for _, s := range []string{"!iRS-INNER", "!iRS-INNER,1", "!iRS-FOO", "!iRS-FOO,1", "!iAS-REF"} {
		add("rpki", Exact, "rpki/"+s, line(s))
	}
	for _, s := range []string{"!mroute,192.0.2.0/24AS65001", "!mroute,192.0.2.0/25AS65001",
		"!mroute,203.0.113.0/24AS65003", "!mroute,64.6.160.0/19AS65007", "!mroute6,2001:db8:1::/48AS65002",
		"!r192.0.2.0/24", "!r192.0.2.0/24,M", "!r100.64.0.0/24", "-T route 192.0.2.0/24", "-x 192.0.2.0/25",
		"-i origin AS65001", "-K -i origin AS65001", "-i member-of RS-INNER", "-s RPKI 192.0.2.0/24",
		"-s RPKI -i origin AS65001"} {
		add("rpki", Objects, "rpki/"+s, line(s))
	}
	add("rpki", Objects, "rpki/pseudo", "!!\n!sRPKI\n!s-lc\n!gAS65001\n!gAS0\n!r192.0.2.0/24\n!mroute,192.0.2.0/24AS65001\n!r100.64.0.0/24\n!q\n")
	add("rpki", Words, "rpki/all-sources", "!!\n!sRIPE,RADB,RPKI\n!gAS65001\n!r192.0.2.0/24,o\n!q\n")
	return cs
}
