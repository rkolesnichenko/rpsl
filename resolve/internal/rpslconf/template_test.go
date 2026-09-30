package rpslconf

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseTemplate(t *testing.T) {
	text := "hello\n" +
		"@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\r\n" +
		" @RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n" +
		"@RtConfigure x\n" +
		"@rtconfig set cisco_map_name = \"AS%d-IN-%d\"\n" +
		"@RTCONFIG set cisco_prefix_acl_no = 200\n" +
		"@RtConfig set sources = RIPE,radb\n" +
		"@RtConfig printPrefixes \"%p/%l\\n\" filter AS-FOO\n" +
		"@RtConfig access_list filter afi ipv6.unicast AS-FOO\n" +
		"@RtConfig default AS1 AS2\n" +
		"@RtConfig configureRouter r1.example.net\n" +
		"end"
	items, err := ParseTemplate(text)
	if err != nil {
		t.Fatal(err)
	}
	var back strings.Builder
	for _, it := range items {
		if it.Cmd != nil {
			back.WriteString(it.Cmd.Raw + it.NL)
		} else {
			back.WriteString(it.Text)
		}
	}
	if back.String() != text {
		t.Errorf("the items do not add up to the template:\n%q\n%q", back.String(), text)
	}
	var cmds []Command
	var texts []string
	for _, it := range items {
		if it.Cmd != nil {
			c := *it.Cmd
			c.Raw = ""
			cmds = append(cmds, c)
		} else {
			texts = append(texts, it.Text)
		}
	}
	wantTexts := []string{"hello\n", " @RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n", "@RtConfigure x\n", "end"}
	if !reflect.DeepEqual(texts, wantTexts) {
		t.Errorf("texts %q, want %q", texts, wantTexts)
	}
	want := []Command{
		{Line: 2, Name: "import", Args: []string{"AS1", "10.0.0.1", "AS2", "10.0.0.2"}},
		{Line: 5, Name: "set", Knob: "cisco_map_name", Value: "AS%d-IN-%d"},
		{Line: 6, Name: "set", Knob: "prefix_acl_no", Value: "200"},
		{Line: 7, Name: "set", Knob: "sources", Value: "RIPE,radb"},
		{Line: 8, Name: "printprefixes", Format: `%p/%l\n`, Filter: "AS-FOO"},
		{Line: 9, Name: "access_list", Filter: "afi ipv6.unicast AS-FOO"},
		{Line: 10, Name: "default", Args: []string{"AS1", "AS2"}},
		{Line: 11, Name: "configurerouter", Args: []string{"r1.example.net"}},
	}
	if !reflect.DeepEqual(cmds, want) {
		t.Errorf("commands\n%+v\nwant\n%+v", cmds, want)
	}
	if items[1].NL != "\r\n" {
		t.Errorf("line ending %q", items[1].NL)
	}
}

func TestParseTemplateRefuses(t *testing.T) {
	for _, c := range []struct{ line, inErr string }{
		{"@RtConfig", "command"},
		{"@RtConfig frob", "frob"},
		{"@RtConfig import AS1 10.0.0.1 AS2", "import"},
		{"@RtConfig import ASX 10.0.0.1 AS2 10.0.0.2", "ASX"},
		{"@RtConfig import AS1 10.0.0.1 AS2 2001:db8::2", "family"},
		{"@RtConfig import AS1 r1 AS2 10.0.0.2", "r1"},
		{"@RtConfig default AS1", "default"},
		{"@RtConfig networks", "networks"},
		{"@RtConfig set cisco_map_name = \"%s\"", "cisco_map_name"},
		{"@RtConfig set cisco_map_name = \"a%db%dc%d\"", "cisco_map_name"},
		{"@RtConfig set cisco_map_name = \"my map\"", "cisco_map_name"},
		{"@RtConfig set cisco_map_first_no = x", "cisco_map_first_no"},
		{"@RtConfig set cisco_map_first_no = -1", "cisco_map_first_no"},
		{"@RtConfig set nonsense = 1", "nonsense"},
		{"@RtConfig set sources = RIPE,R ADB", "sources"},
		{"@RtConfig set cisco_map_first_no 1", "="},
		{"@RtConfig printPrefixes \"%p filter AS1", "quote"},
		{"@RtConfig printPrefixes \"%p\" AS1", "filter"},
		{"@RtConfig printPrefixes \"%q\" filter AS1", "%q"},
		{"@RtConfig printPrefixes \"\\x\" filter AS1", `\x`},
		{"@RtConfig access_list AS1", "filter"},
		{"@RtConfig access_list filter ", "filter"},
	} {
		_, err := ParseTemplate("ok\n" + c.line + "\n")
		if err == nil || !strings.Contains(err.Error(), c.inErr) || !strings.Contains(err.Error(), "line 2") {
			t.Errorf("%q: err %v, want one naming line 2 and %q", c.line, err, c.inErr)
		}
	}
}

func FuzzParseTemplate(f *testing.F) {
	for _, s := range []string{
		"@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n", "x\n@rtconfig set cisco_map_name = \"M_%d_%d\"\n",
		"@RtConfig printPrefixRanges \"%p/%l^%n-%m\\n\" filter {10.0.0.0/8^+}\n", "@RtConfig\n",
		"@RtConfig set sources = RIPE\r\n@RtConfig networks AS1", "@RtConfig importGroup AS1 PRNG-X\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		items, err := ParseTemplate(s)
		var back strings.Builder
		for _, it := range items {
			if it.Cmd == nil {
				back.WriteString(it.Text)
				continue
			}
			back.WriteString(it.Cmd.Raw + it.NL)
			again, err := parseCommand(it.Cmd.Raw, it.Cmd.Line)
			if err != nil || !reflect.DeepEqual(again, it.Cmd) {
				t.Fatalf("%q parses back to %+v, %v; first %+v", it.Cmd.Raw, again, err, it.Cmd)
			}
			if !supported[it.Cmd.Name] && !deferred[it.Cmd.Name] {
				t.Fatalf("%q: unknown command %q accepted", it.Cmd.Raw, it.Cmd.Name)
			}
			if it.Cmd.Name == "set" && knobs[it.Cmd.Knob] != it.Cmd.Knob {
				t.Fatalf("%q: knob %q is not a current name", it.Cmd.Raw, it.Cmd.Knob)
			}
		}
		if err == nil && back.String() != s || err != nil && !strings.HasPrefix(s, back.String()) {
			t.Fatalf("the items (%v) add up to %q, not %q", err, back.String(), s)
		}
	})
}
