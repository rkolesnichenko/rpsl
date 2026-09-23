package policy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rfcImports returns the import: and mp-import: examples of the RFCs, with
// whether each is an mp-import.
func rfcImports(b *testing.B) (values []string, mp []bool) {
	b.Helper()
	f, err := os.Open(filepath.Join("testdata", "rfc-examples.txt"))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		example, _, _ := strings.Cut(sc.Text(), " ## expect:")
		attr, value, ok := strings.Cut(example, ":")
		if ok && (attr == "import" || attr == "mp-import") {
			values = append(values, strings.TrimSpace(value))
			mp = append(mp, attr == "mp-import")
		}
	}
	if len(values) == 0 {
		b.Fatal("no import examples read")
	}
	return values, mp
}

// BenchmarkParseImport parses every import: and mp-import: example of the RFCs.
func BenchmarkParseImport(b *testing.B) {
	values, mp := rfcImports(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j, v := range values {
			if mp[j] {
				ParseMPImport(v)
			} else {
				ParseImport(v)
			}
		}
	}
}

// BenchmarkParseImportLarge parses one value with a 10,000-prefix filter, the
// shape of a bogon or customer filter written out in full.
func BenchmarkParseImportLarge(b *testing.B) {
	prefixes := make([]string, 10000)
	for i := range prefixes {
		prefixes[i] = fmt.Sprintf("10.%d.%d.0/24^24-28", i/256, i%256)
	}
	src := "from AS65000 action pref=100; accept {" + strings.Join(prefixes, ", ") + "}"
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ds := ParseImport(src); len(ds) != 0 {
			b.Fatal(diagRules(ds))
		}
	}
}

func BenchmarkParseASPathRegexp(b *testing.B) {
	in := []string{
		"^AS1 AS2 .* AS3$",
		"^[AS1 - AS10]* AS-FOO+$",
		"^PeerAS+ .{0,5} (AS1|AS2)$",
		"^AS1:AS-CUSTOMERS:PeerAS~* [^AS64512 AS64513]$",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseASPathRegexp(in[i%len(in)]); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFlatten resolves a policy that nests REFINE and EXCEPT over lists.
func BenchmarkFlatten(b *testing.B) {
	imp, ds := ParseMPImport("afi any { from AS-ANY action pref=10; accept ANY; } " +
		"refine { from AS1 accept AS1; from AS2 accept AS2; from AS3 accept AS3; } " +
		"except { from AS1 accept {192.0.2.0/24^+}; from AS4 accept AS4; }")
	if len(ds) != 0 {
		b.Fatal(diagRules(ds))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(Flatten(imp.Expr)) == 0 {
			b.Fatal("no terms")
		}
	}
}

// BenchmarkImportString renders every import: and mp-import: example of the
// RFCs back to canonical RPSL.
func BenchmarkImportString(b *testing.B) {
	values, mp := rfcImports(b)
	imports := make([]Import, len(values))
	for j, v := range values {
		if mp[j] {
			imports[j], _ = ParseMPImport(v)
		} else {
			imports[j], _ = ParseImport(v)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, imp := range imports {
			_ = imp.String()
		}
	}
}
