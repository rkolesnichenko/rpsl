package object

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// CLAUDE.md: if a profile lists an attribute on a class with a typed decoder,
// the decoder must read it into the struct — otherwise Decode silently drops
// that data (as-set mp-members once was). Checking only that the value shows up
// somewhere is not enough: it must land in the attribute's own field, and every
// field must be fed by some attribute.

// classKey is a valid key for each decoded class, and a needle proving it was
// decoded.
var classKey = map[string][2]string{
	"aut-num": {"AS65000", "AS65000"}, "mntner": {"MNT-KEY", "MNT-KEY"}, "person": {"Key Person", "Key Person"},
	"role": {"Key Role", "Key Role"}, "route": {"192.0.2.0/24", "192.0.2.0/24"}, "route6": {"2001:db8::/32", "2001:db8::/32"},
	"as-set": {"AS-KEY", "AS-KEY"}, "route-set": {"RS-KEY", "RS-KEY"}, "peering-set": {"PRNG-KEY", "PRNG-KEY"},
	"filter-set": {"FLTR-KEY", "FLTR-KEY"}, "rtr-set": {"RTRS-KEY", "RTRS-KEY"},
	"inetnum": {"192.0.2.0 - 192.0.2.255", "192.0.2.255"}, "inet6num": {"2001:db8::/32", "2001:db8::/32"},
	"as-block": {"AS65000 - AS65010", "AS65010"}, "inet-rtr": {"rtr-key.example", "rtr-key.example"},
	"irt": {"IRT-KEY", "IRT-KEY"}, "domain": {"2.0.192.in-addr.arpa", "2.0.192.in-addr.arpa"},
	"organisation": {"ORG-KEY", "ORG-KEY"}, "key-cert": {"PGPKEY-1234ABCD", "PGPKEY-1234ABCD"},
	"dictionary": {"RPSL-KEY", "RPSL-KEY"}, "poem": {"POEM-KEY", "POEM-KEY"},
	"poetic-form": {"FORM-KEY", "FORM-KEY"},
}

// keyFields are the fields a class's key decodes into.
var keyFields = map[string][]string{
	"aut-num": {"AS"}, "mntner": {"Handle"}, "person": {"Name"}, "role": {"Name"}, "route": {"Prefix"},
	"route6": {"Prefix"}, "as-set": {"Name"}, "route-set": {"Name"}, "peering-set": {"Name"}, "filter-set": {"Name"},
	"rtr-set": {"Name"}, "inetnum": {"Lo", "Hi"}, "inet6num": {"Prefix"}, "as-block": {"Lo", "Hi"},
	"inet-rtr": {"Name"}, "irt": {"Name"}, "domain": {"Name"}, "organisation": {"OrgID"},
	"key-cert": {"Name"}, "dictionary": {"Name"}, "poem": {"Name"}, "poetic-form": {"Name"},
}

// fieldNames maps the attributes whose field is not the attribute's name in
// CamelCase ("mnt-routes" → MntRoutes).
var fieldNames = map[string]string{
	"e-mail": "Email", "import": "Imports", "mp-import": "Imports", "export": "Exports", "mp-export": "Exports",
	"default": "Defaults", "mp-default": "Defaults", "peer": "Peers", "mp-peer": "MpPeers",
	"peering": "Peerings", "mp-peering": "MpPeerings", "local-as": "LocalAS",
	"rp-attribute": "RPAttribute",
}

// unprofiledFields are read although no profile lists their attribute.
var unprofiledFields = map[string]string{
	"as-set.MpMembers": "IRRs other than RIPE accept mp-members on as-sets; RFC 4012 and RIPE do not",
}

func fieldFor(attr string) string {
	if f, ok := fieldNames[attr]; ok {
		return f
	}
	var b strings.Builder
	for _, part := range strings.Split(attr, "-") {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// marker returns a value for attr that decodes cleanly in class, and a needle
// that is unique to it (i numbers the attributes, so no needle contains
// another).
func marker(class, attr string, i int) (value, needle string) {
	n := fmt.Sprintf("%03d", i)
	as := "AS64" + n
	switch attr {
	case class:
		return classKey[class][0], classKey[class][1]
	case "origin", "local-as", "peering", "mp-peering", "filter", "mp-filter":
		return as, as
	case "admin-c", "tech-c", "zone-c", "nic-hdl", "abuse-c", "ping-hdl", "author":
		return "DRIFT" + n + "-TEST", "DRIFT" + n + "-TEST"
	case "member-of":
		switch class {
		case "aut-num":
			return "AS-DRIFT" + n, "AS-DRIFT" + n
		case "inet-rtr":
			return "RTRS-DRIFT" + n, "RTRS-DRIFT" + n
		}
		return "RS-DRIFT" + n, "RS-DRIFT" + n
	case "holes":
		if class == "route6" {
			return "2001:db8::/48", "2001:db8::/48"
		}
		return "192.0.2.0/25", "192.0.2.0/25"
	case "members", "mp-members":
		if class == "rtr-set" {
			return "rtr-drift" + n + ".example", "rtr-drift" + n + ".example"
		}
		return as, as
	case "pingable":
		return fmt.Sprintf("10.11.%d.1", i), fmt.Sprintf("10.11.%d.1", i)
	case "ifaddr":
		return fmt.Sprintf("10.12.%d.1 masklen 24", i), fmt.Sprintf("10.12.%d.1", i)
	case "interface":
		return fmt.Sprintf("10.13.%d.1 masklen 24", i), fmt.Sprintf("10.13.%d.1", i)
	case "peer":
		return fmt.Sprintf("BGP4 10.14.%d.1", i), fmt.Sprintf("10.14.%d.1", i)
	case "mp-peer":
		return fmt.Sprintf("BGP4 10.15.%d.1", i), fmt.Sprintf("10.15.%d.1", i)
	case "components":
		return fmt.Sprintf("{10.16.%d.0/24}", i), fmt.Sprintf("10.16.%d.0/24", i)
	case "export-comps":
		return fmt.Sprintf("{10.17.%d.0/24}", i), fmt.Sprintf("10.17.%d.0/24", i)
	case "inject":
		return "at drift" + n + ".example", "drift" + n + ".example"
	case "aggr-bndry":
		return as, as
	case "aggr-mtd":
		return "outbound " + as, as
	case "auth":
		return "MD5-PW $1$drift" + n + "$xyz", "drift" + n
	case "rp-attribute":
		return "attr" + n + " operator=(integer)", "attr" + n
	case "typedef":
		return "type" + n + " list of integer", "type" + n
	case "protocol":
		return "PROTO" + n + " MANDATORY asno(as_number)", "proto" + n
	case "import", "mp-import":
		return "from " + as + " accept ANY", as
	case "export", "mp-export":
		return "to " + as + " announce ANY", as
	case "import-via":
		return "AS1 from " + as + " accept ANY", as
	case "export-via":
		return "AS1 to " + as + " announce ANY", as
	case "default", "mp-default":
		return "to " + as, as
	}
	return "drift-marker-" + n, "drift-marker-" + n
}

// fields returns the exported fields of a typed object, with those of embedded
// structs (Common, Registry) flattened, each rendered as text, and which of
// them are the class's own rather than embedded.
func fields(v reflect.Value) (text map[string]string, own map[string]bool) {
	text, own = map[string]string{}, map[string]bool{}
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		switch {
		case f.Anonymous:
			inner, _ := fields(v.Field(i))
			for k, s := range inner {
				text[k] = s
			}
		case f.IsExported():
			text[f.Name] = fmt.Sprintf("%v", v.Field(i).Interface())
			own[f.Name] = true
		}
	}
	return text, own
}

func TestEveryAttributeLandsInItsOwnField(t *testing.T) {
	for class := range registry {
		attrs := map[string]bool{}
		for _, p := range []Profile{RIPE, RFCStrict} {
			if spec, ok := p.Class(class); ok {
				for a := range spec.Attrs {
					attrs[a] = true
				}
			}
		}
		var names []string
		for a := range attrs {
			if a != class {
				names = append(names, a)
			}
		}
		sort.Strings(names)
		key, keyNeedle := marker(class, class, 0)
		src := class + ": " + key + "\n"
		needles := map[string]string{class: keyNeedle}
		for i, a := range names {
			value, needle := marker(class, a, i+1)
			src += a + ": " + value + "\n"
			needles[a] = needle
		}
		obj, diags := Decode(parse(src))
		for _, d := range diags {
			if d.Severity == ast.Error {
				t.Errorf("%s: the test object does not decode cleanly: %v", class, d)
			}
		}
		got, own := fields(reflect.ValueOf(obj))
		fed := map[string]bool{}
		for attr, needle := range needles {
			want := []string{fieldFor(attr)}
			if attr == class {
				want = keyFields[class]
			}
			var in []string
			for name, text := range got {
				if strings.Contains(text, needle) {
					in = append(in, name)
					fed[name] = true
				}
			}
			sort.Strings(in)
			ok := len(in) > 0
			for _, name := range in {
				ok = ok && contains(want, name)
			}
			if !ok {
				t.Errorf("%s.%s: its value is in fields %v, want %v", class, attr, in, want)
			}
		}
		for _, name := range keyFields[class] {
			fed[name] = true
		}
		// Common and Registry are shared by every class, so a field of theirs may
		// stay empty where a class has no such attribute; a class's own may not.
		for name := range own {
			if _, known := unprofiledFields[class+"."+name]; !fed[name] && !known {
				t.Errorf("%s.%s: no attribute either profile lists is decoded into it", class, name)
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
