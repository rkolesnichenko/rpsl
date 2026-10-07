# API Consolidation (v0.26.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the public API follow five written conventions, and add a checked-in golden of every public signature (plus three mechanical convention checks) so later API changes are always visible, without changing any behaviour.

**Architecture:** A standard-library command, `internal/apisurface`, renders each public package's exported signatures into `api/<pkg>.txt` and checks conventions C1–C3; `scripts/check.sh` runs it. Then five mechanical API changes land one commit each — policy options, object pointers, renames, small moves — each showing its own diff under `api/`.

**Tech Stack:** Go 1.23 floor (local toolchain 1.27.1, cached go1.23.0), standard library only (`go/parser`, `go/ast`, `go/printer`), `gopls rename`, `gofmt`, `perl -pi` for mechanical rewrites.

**Spec:** `docs/superpowers/specs/2026-10-07-api-consolidation-design.md` (commit 659400b). Read it first; this plan argues from it.

## Global Constraints

- Branch `api-v0.26`; release v0.26.0. No deprecated shims: nothing imports the module (GitHub code search, 2026-10-07).
- `go.mod` floors stay at `go 1.23` (memory: keep the lowest viable floor). Range-over-int and `maps.Keys`/`slices.Sorted` are fine (1.22/1.23).
- No third-party dependency anywhere; `internal/apisurface` imports the standard library only.
- No behaviour change: no file under any `testdata/` changes except the new `internal/apisurface/testdata/`. A golden that moves is a bug to root-cause, never a re-recording.
- Existing tests change mechanically only (names, `&`, `With` forms), never in what they assert.
- Every commit compiles and passes `scripts/check.sh` on its own.
- Heavy commands (`scripts/check.sh`, real-data tests, `scripts/bench.sh`) run one at a time through the memory guard, never two at once:
  `MEMGUARD_NORMAL_PRIORITY=1 .superpowers/sdd/tools/memguard.sh 8 3600 env GOMAXPROCS=4 GOMEMLIMIT=6GiB <command>`
  It prints a final line SUCCESS / FAILURE / MEMLIMIT / PRESSURE / SWAP / LOWMEM / TIMEOUT / NOT STARTED. NOT STARTED means too little free memory: wait and retry, never run unguarded. Only SUCCESS is green.
- The shell is zsh: quote any argument holding `=`, `*`, `?` or `[`; there is no `timeout` command.
- Never `cat > file`; create files with the Write tool.

## Review Focus

1. **A copy that was relied on.** Code that took a value class, changed a field and stored the copy now mutates a shared object. Expected: no non-test code writes a field of a class it did not just build. Task 3 Step 9 greps for this and pins each site it finds.
2. **A nil result on error.** `AutNum`, `InetRtr`, `Mntner` and `Irt` lookups used to return a zero value next to their error; now they return nil. Expected: every implementation returns nil exactly when the error is non-nil, and no caller dereferences before checking. Task 3 Step 8 converts each implementation, and Task 3 Step 1's test pins the `MemSource` miss.
3. **`ParseDefaultWith` with `Via`.** Expected: one Error `policy/no-default-via` covering the whole value, then exactly what `MP` alone gives. Pinned in Task 2 Step 1.
4. **Fuzz corpus compatibility.** `policy/testdata/fuzz/FuzzParseImport` already exists, so `FuzzParseImport` keeps its `(t, s string)` signature and tries each option set inside the body. Changing the signature would invalidate the corpus files. Task 2 Step 6.
5. **The golden checked on Go 1.23.** CI runs `check.sh` on 1.23 and stable. `go/printer` output for these declarations was identical on 1.23.0 and 1.27.1 (measured for `go doc -all` on four packages, 2026-10-07). Task 1 Step 9 runs `-check` under `GOTOOLCHAIN=go1.23.0` to pin it.

## Where this plan departs from the spec's §8 order

- **The two sentinel fixes (spec §4.5) land in Task 1, not Task 5.** C3 is wired into `check.sh` in Task 1, and every commit must pass `check.sh`.
- **C1 (spec §5.3) lands in Task 2.** Before Task 2, the three old `ParseXWith(s, mp, o)` functions break it.
- **`FuzzParseImport` keeps its signature** (Review Focus 4). Spec §6's "fuzzed MP and Via" becomes "every option set, for every input".
- **The golden keeps a const's written value** (`const Info = ast.Info`, rule IDs, default caps): a const's value is compiled into its callers. Spec §5.1 says "full signature"; for a const, that includes its value.

---

## File map

| Path | Task | Responsibility |
|---|---|---|
| `internal/apisurface/main.go` | 1 | flags; `run`: regenerate, compare or rewrite `api/`, report |
| `internal/apisurface/surface.go` | 1 | discover public packages; render one package's surface |
| `internal/apisurface/conventions.go` | 1 (C2, C3), 2 (C1) | the convention checks |
| `internal/apisurface/*_test.go`, `testdata/` | 1, 2 | tests and fixtures |
| `api/*.txt` (18 files) | 1, then every task | the golden |
| `scripts/check.sh` | 1 | runs `go run ./internal/apisurface -check` |
| `policy/parse.go`, `policy/dict.go`, `policy/via.go` | 2 | 13 entry points → 6; `Options{MP, Via, Dict}` |
| `object/*.go` | 3, 4 | pointer receivers; `Decode` returns pointers; `RouterGroup` |
| `resolve/**`, `auth/**`, `*.go` in root, `examples/**` | 3 | pointer signatures and call sites |
| `resolve/result.go` and users | 4 | `Peerings`, `Routers` |
| `ast/object.go`, `ast/text_test.go`, `resolve/corpus.go` | 5 | `(*ast.Object).Text` replaces `resolve.ObjectText` |
| `resolve/memsource.go` (wherever `LoadDumps` lives) | 5 | delete `LoadDumps`, fix `LoadDump`'s doc |
| `CLAUDE.md`, `docs/rpsl-go-design.md`, `README.md`, `CHANGELOG.md` | 2–6 | docs |

---

### Task 1: `internal/apisurface` — golden, C2, C3, and the two sentinels

**Files:**
- Create: `internal/apisurface/main.go`, `internal/apisurface/surface.go`, `internal/apisurface/conventions.go`
- Create: `internal/apisurface/surface_test.go`, `internal/apisurface/run_test.go`, `internal/apisurface/conventions_test.go`
- Create fixtures: `internal/apisurface/testdata/surface/lib.go`, `…/surface/lib_test.go`, `…/surface/sub/sub.go`, `…/surface/internal/x/x.go`, `…/surface/cmd/tool/main.go`, `…/surface/mainpkg/main.go`, `…/surface/.hidden/h.go`, `internal/apisurface/testdata/conventions/bad/bad.go`, `…/conventions/good/good.go`
- Create: `api/*.txt` (generated, 18 files)
- Modify: `scripts/check.sh` (after the "engine purity" step), `resolve/rdap/rdap.go:125-126`, `resolve/irrd/irrd.go:127-133` and `resolve/irrd/pipeline.go:69,443`

**Interfaces:**
- Produces (package `main` in `internal/apisurface`):
  - `type pkg struct { dir string; fset *token.FileSet; files []*ast.File }`
  - `func discover(root string) ([]*pkg, error)`
  - `func render(p *pkg) string`
  - `func goldenName(dir string) string`
  - `func baseName(t ast.Expr) string`
  - `func text(fset *token.FileSet, n any) string`
  - `func conventions(root string, pkgs []*pkg) []string`
  - `func run(root string, update bool, w io.Writer) (bool, error)`
- Command: `go run ./internal/apisurface -check`; `RPSL_API_UPDATE=1` rewrites `api/`.

- [ ] **Step 1: Write the surface fixtures**

`internal/apisurface/testdata/surface/lib.go`:

```go
// Package lib is a fixture: every kind of declaration the surface lists.
package lib

import "errors"

// Doc comments never reach the golden.
const (
	KindA Kind = iota
	KindB
	kindHidden
)

const Max = 10

var ErrBad = errors.New("lib: bad")

var Default = Options{Strict: true}

var Hook func(string) error

type Kind uint8

type Options struct {
	Strict bool `json:"strict"`
	hidden int
	Embedded
}

type Embedded struct{ A, b int }

type Shape interface {
	Area() float64
	isShape()
}

type Alias = Options

type Set[T comparable] struct{ m map[T]bool }

func NewSet[T comparable](xs ...T) *Set[T] { return nil }

func (s *Set[T]) Has(x T) bool { return s.m[x] }

func (k Kind) String() string { return "" }

func (k Kind) hidden() {}

func Parse(s string,
	strict bool,
) (Options, error) {
	return Options{}, nil
}

func helper() {}
```

`internal/apisurface/testdata/surface/lib_test.go`:

```go
package lib

// TestOnly is exported but lives in a test file: not part of the surface.
func TestOnly() {}
```

`…/surface/sub/sub.go`:

```go
package sub

func F() int { return 1 }
```

`…/surface/internal/x/x.go` (`package x` + `func X() {}`), `…/surface/cmd/tool/main.go` (`package main` + `func main() {}`), `…/surface/mainpkg/main.go` (`package main` + `func main() {}`), `…/surface/.hidden/h.go` (`package h` + `func H() {}`). Each follows the same three-line shape as `sub.go`.

- [ ] **Step 2: Write the failing surface test**

`internal/apisurface/surface_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

// TestRender: the surface lists every exported declaration of a public
// package, one per line, without comments, unexported members or var values,
// with a signature split over lines joined into one.
func TestRender(t *testing.T) {
	pkgs, err := discover("testdata/surface")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, p := range pkgs {
		dirs = append(dirs, p.dir)
	}
	// internal/, cmd/, hidden directories, package main and test files are not public.
	if got := strings.Join(dirs, " "); got != ". sub" {
		t.Fatalf("public packages %q, want %q", got, ". sub")
	}
	const want = `package lib
const KindA Kind = iota
const KindB Kind
const Max = 10
var Default Options
var ErrBad = errors.New(…)
var Hook func(string) error
func NewSet[T comparable](xs ...T) *Set[T]
func Parse(s string, strict bool) (Options, error)
type Alias = Options
type Embedded struct
	A int
type Kind uint8
func (Kind) String() string
type Options struct
	Strict bool ` + "`json:\"strict\"`" + `
	Embedded
type Set[T comparable] struct
func (*Set[T]) Has(x T) bool
type Shape interface
	Area() float64
	isShape()
`
	if got := render(pkgs[0]); got != want {
		t.Errorf("render:\n%s\nwant:\n%s", got, want)
	}
	if got := render(pkgs[1]); got != "package sub\nfunc F() int\n" {
		t.Errorf("render(sub) = %q", got)
	}
	for dir, want := range map[string]string{".": "rpsl.txt", "policy": "policy.txt", "resolve/rpki": "resolve_rpki.txt"} {
		if got := goldenName(dir); got != want {
			t.Errorf("goldenName(%q) = %q, want %q", dir, got, want)
		}
	}
}
```

Run: `go test ./internal/apisurface/`
Expected: FAIL to compile (`undefined: discover`).

- [ ] **Step 3: Write `surface.go`**

```go
package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// pkg is one public package: its directory below the repository root and its
// parsed non-test files.
type pkg struct {
	dir   string // slash-separated; "." for the root
	fset  *token.FileSet
	files []*ast.File
}

// skipped reports whether the walk leaves a directory out: nothing below
// internal/, cmd/, examples/ or testdata/ is public, nor anything hidden.
func skipped(name string) bool {
	switch name {
	case "internal", "cmd", "examples", "testdata", "vendor":
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// discover returns the public packages below root, sorted by directory: every
// directory holding non-test Go files of a package other than main. Files are
// parsed, not type-checked, so the nested modules need no module plumbing.
func discover(root string) ([]*pkg, error) {
	var pkgs []*pkg
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && skipped(d.Name()) {
			return filepath.SkipDir
		}
		p, err := parseDir(root, path)
		if p != nil {
			pkgs = append(pkgs, p)
		}
		return err
	})
	slices.SortFunc(pkgs, func(a, b *pkg) int { return strings.Compare(a.dir, b.dir) })
	return pkgs, err
}

// parseDir parses dir's non-test Go files; it returns nil for a directory with
// none, or holding package main.
func parseDir(root, dir string) (*pkg, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return nil, err
	}
	p := &pkg{dir: filepath.ToSlash(rel), fset: token.NewFileSet()}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(p.fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		if f.Name.Name == "main" {
			return nil, nil
		}
		p.files = append(p.files, f)
	}
	if len(p.files) == 0 {
		return nil, nil
	}
	return p, nil
}

// goldenName is the file under api/ holding the surface of the package in dir.
func goldenName(dir string) string {
	if dir == "." {
		return "rpsl.txt"
	}
	return strings.ReplaceAll(dir, "/", "_") + ".txt"
}

// typeDecl is one exported type: its head line, its members (exported struct
// fields, or every element of an interface) in declaration order, and its
// exported methods by name.
type typeDecl struct {
	head    string
	members []string
	methods map[string]string
}

// render returns p's surface: a package line, then the consts, vars, funcs and
// types, each sorted by name, every type followed by its members and then its
// methods sorted by name.
func render(p *pkg) string {
	consts, vars, funcs := map[string]string{}, map[string]string{}, map[string]string{}
	types := map[string]*typeDecl{}
	type method struct{ recv, name, line string }
	var methods []method
	for _, f := range p.files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				switch d.Tok {
				case token.CONST:
					addConsts(p.fset, d, consts)
				case token.VAR:
					addVars(p.fset, d, vars)
				case token.TYPE:
					for _, s := range d.Specs {
						if ts := s.(*ast.TypeSpec); ts.Name.IsExported() {
							types[ts.Name.Name] = newTypeDecl(p.fset, ts)
						}
					}
				}
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				sig := strings.TrimPrefix(text(p.fset, d.Type), "func")
				if d.Recv == nil {
					funcs[d.Name.Name] = "func " + d.Name.Name + sig
					continue
				}
				r := d.Recv.List[0].Type
				methods = append(methods, method{baseName(r), d.Name.Name, "func (" + text(p.fset, r) + ") " + d.Name.Name + sig})
			}
		}
	}
	for _, m := range methods {
		if t, ok := types[m.recv]; ok {
			t.methods[m.name] = m.line
		}
	}
	var b strings.Builder
	b.WriteString("package " + p.files[0].Name.Name + "\n")
	for _, group := range []map[string]string{consts, vars, funcs} {
		for _, name := range slices.Sorted(maps.Keys(group)) {
			b.WriteString(group[name] + "\n")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(types)) {
		t := types[name]
		b.WriteString(t.head + "\n")
		for _, m := range t.members {
			b.WriteString("\t" + m + "\n")
		}
		for _, mn := range slices.Sorted(maps.Keys(t.methods)) {
			b.WriteString(t.methods[mn] + "\n")
		}
	}
	return b.String()
}

// newTypeDecl describes ts: a struct or interface is headed by its kind alone,
// its members listed below it; any other type, an alias included, is one line.
func newTypeDecl(fset *token.FileSet, ts *ast.TypeSpec) *typeDecl {
	t := &typeDecl{methods: map[string]string{}}
	head := *ts
	head.Doc, head.Comment = nil, nil
	switch x := ts.Type.(type) {
	case *ast.StructType:
		head.Type = ast.NewIdent("struct")
		for _, f := range x.Fields.List {
			t.members = append(t.members, fieldLines(fset, f)...)
		}
	case *ast.InterfaceType:
		head.Type = ast.NewIdent("interface")
		for _, f := range x.Methods.List {
			t.members = append(t.members, elemLine(fset, f))
		}
	}
	t.head = "type " + text(fset, &head)
	return t
}

// fieldLines returns a struct field's exported names, one line each, with its
// type and tag; an embedded field is listed when its type is exported.
func fieldLines(fset *token.FileSet, f *ast.Field) []string {
	typ := text(fset, f.Type)
	if f.Tag != nil {
		typ += " " + f.Tag.Value
	}
	if len(f.Names) == 0 {
		if ast.IsExported(baseName(f.Type)) {
			return []string{typ}
		}
		return nil
	}
	var out []string
	for _, n := range f.Names {
		if n.IsExported() {
			out = append(out, n.Name+" "+typ)
		}
	}
	return out
}

// elemLine is one element of an interface, exported or not (an unexported
// method seals the interface, which is API too): a method with its signature,
// or an embedded type or type set.
func elemLine(fset *token.FileSet, f *ast.Field) string {
	if len(f.Names) == 0 {
		return text(fset, f.Type)
	}
	return f.Names[0].Name + strings.TrimPrefix(text(fset, f.Type), "func")
}

// baseName is the name of the type t denotes, without a pointer, a package or
// type arguments: Set for *Set[T], Diagnostic for ast.Diagnostic.
func baseName(t ast.Expr) string {
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.SelectorExpr:
			return x.Sel.Name
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

// addConsts records a const declaration's exported names with their type —
// written, or carried down a group from the last spec that has one, as Go
// carries it — and their value where one is written: a constant's value is
// compiled into its callers.
func addConsts(fset *token.FileSet, d *ast.GenDecl, out map[string]string) {
	var typ ast.Expr
	for _, s := range d.Specs {
		vs := s.(*ast.ValueSpec)
		if vs.Type != nil || len(vs.Values) > 0 {
			typ = vs.Type
		}
		for i, n := range vs.Names {
			if !n.IsExported() {
				continue
			}
			line := "const " + n.Name
			if typ != nil {
				line += " " + text(fset, typ)
			}
			if i < len(vs.Values) {
				line += " = " + text(fset, vs.Values[i])
			}
			out[n.Name] = line
		}
	}
}

// addVars records a var declaration's exported names: with the type written,
// or else what the value tells of it — a composite literal's type, a call's
// function, or the expression itself.
func addVars(fset *token.FileSet, d *ast.GenDecl, out map[string]string) {
	for _, s := range d.Specs {
		vs := s.(*ast.ValueSpec)
		for i, n := range vs.Names {
			if !n.IsExported() {
				continue
			}
			line := "var " + n.Name
			switch {
			case vs.Type != nil:
				line += " " + text(fset, vs.Type)
			case i < len(vs.Values):
				line += describe(fset, vs.Values[i])
			}
			out[n.Name] = line
		}
	}
}

// describe is what a var's value says of the var, for a var with no type.
func describe(fset *token.FileSet, v ast.Expr) string {
	switch x := v.(type) {
	case *ast.CompositeLit:
		return " " + text(fset, x.Type)
	case *ast.UnaryExpr:
		if cl, ok := x.X.(*ast.CompositeLit); ok && x.Op == token.AND {
			return " *" + text(fset, cl.Type)
		}
	case *ast.CallExpr:
		return " = " + text(fset, x.Fun) + "(…)"
	}
	return " = " + text(fset, v)
}

var squeeze = strings.NewReplacer("( ", "(", ", )", ")", " )", ")", "[ ", "[", ", ]", "]", " ]", "]")

// text prints n on one line: go/printer's output with each run of white space
// made one space and none just inside brackets, so a signature reads the same
// however its source was wrapped.
func text(fset *token.FileSet, n any) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, n); err != nil {
		panic(err) // n came from go/parser; printing it to memory cannot fail
	}
	return squeeze.Replace(strings.Join(strings.Fields(buf.String()), " "))
}
```

(This code was run against the fixture and the repository on 2026-10-07: the fixture renders exactly as Step 2 expects, and the repository yields the 18 public packages and 1,647 lines.)

Run: `go test ./internal/apisurface/ -run TestRender`
Expected: still FAIL to compile until `main.go` and `conventions.go` exist (Steps 5–6), or PASS if you run it after them.

- [ ] **Step 4: Write the conventions fixtures and their failing test**

`internal/apisurface/testdata/conventions/bad/bad.go` — the line numbers matter, keep it byte for byte:

```go
package bad

import (
	"errors"
	"fmt"
)

var errInner = errors.New("bad: inner")

var ErrAlias = errInner

var ErrFormatted = fmt.Errorf("bad: formatted")

var ErrOK = errors.New("bad: ok")

func ParseThing(s string) (int, bool) { return 0, false }

func (t Thing) ParseField(s string) (string, bool) { return s, true }

type Thing struct{}
```

`internal/apisurface/testdata/conventions/good/good.go`:

```go
package good

import "errors"

var ErrNotFound = errors.New("good: not found")

// Errors starts with "Err" but is not a sentinel: no capital follows.
var Errors = []string{"not a sentinel"}

func ParseThing(s string) (int, error) { return 0, nil }

// Lookup's bool is comma-ok for a miss, which rule 2 allows outside Parse*.
func Lookup(k string) (int, bool) { return 0, false }
```

`internal/apisurface/conventions_test.go`:

```go
package main

import (
	"slices"
	"testing"
)

// TestConventions: each check reports the declarations that break it, with
// file and line, in declaration order, and nothing for a package that keeps
// the conventions.
func TestConventions(t *testing.T) {
	for _, c := range []struct {
		dir  string
		want []string
	}{
		{"testdata/conventions/good", nil},
		{"testdata/conventions/bad", []string{
			"bad.go:10: C3: ErrAlias is not declared with errors.New",
			"bad.go:12: C3: ErrFormatted is not declared with errors.New",
			"bad.go:16: C2: ParseThing returns bool as its last result; malformed input is an error",
			"bad.go:18: C2: ParseField returns bool as its last result; malformed input is an error",
		}},
	} {
		pkgs, err := discover(c.dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := conventions(c.dir, pkgs); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.dir, got, c.want)
		}
	}
}
```

- [ ] **Step 5: Write `conventions.go`**

```go
package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
	"unicode"
)

// conventions checks the API conventions (CLAUDE.md, "Go conventions") over
// pkgs and returns each violation as "file:line: Cn: message", file relative
// to root, in declaration order.
func conventions(root string, pkgs []*pkg) []string {
	var out []string
	for _, p := range pkgs {
		report := func(pos token.Pos, msg string) {
			at := p.fset.Position(pos)
			name, err := filepath.Rel(root, at.Filename)
			if err != nil {
				name = at.Filename
			}
			out = append(out, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(name), at.Line, msg))
		}
		for _, f := range p.files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					checkParseBool(d, report)
				case *ast.GenDecl:
					if d.Tok == token.VAR {
						checkSentinels(d, report)
					}
				}
			}
		}
	}
	return out
}

// checkParseBool is C2: no exported Parse function or method returns bool as
// its last result. Malformed input is an error; comma-ok is for an expected
// false, such as a lookup miss or an empty result.
func checkParseBool(d *ast.FuncDecl, report func(token.Pos, string)) {
	if !d.Name.IsExported() || !strings.HasPrefix(d.Name.Name, "Parse") || d.Type.Results == nil {
		return
	}
	rs := d.Type.Results.List
	if id, ok := rs[len(rs)-1].Type.(*ast.Ident); ok && id.Name == "bool" {
		report(d.Pos(), "C2: "+d.Name.Name+" returns bool as its last result; malformed input is an error")
	}
}

// checkSentinels is C3: every exported ErrX var is declared with errors.New.
func checkSentinels(d *ast.GenDecl, report func(token.Pos, string)) {
	for _, s := range d.Specs {
		vs := s.(*ast.ValueSpec)
		for i, n := range vs.Names {
			if !n.IsExported() || !isSentinelName(n.Name) {
				continue
			}
			if i < len(vs.Values) && isErrorsNew(vs.Values[i]) {
				continue
			}
			report(n.Pos(), "C3: "+n.Name+" is not declared with errors.New")
		}
	}
}

// isSentinelName reports whether name reads as a sentinel error: "Err" and a
// capital (ErrNotFound, not Errors).
func isSentinelName(name string) bool {
	return len(name) > 3 && strings.HasPrefix(name, "Err") && unicode.IsUpper(rune(name[3]))
}

// isErrorsNew reports whether e is a call of errors.New.
func isErrorsNew(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "errors" && sel.Sel.Name == "New"
}
```

- [ ] **Step 6: Write `main.go` and the failing run test**

`internal/apisurface/run_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun: a fresh golden checks clean; a changed signature, a package with
// no golden and a golden with no package are each reported; an update
// rewrites api/ to match, removing the stale golden.
func TestRun(t *testing.T) {
	root := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out strings.Builder
	check := func(update, wantOK bool) {
		t.Helper()
		out.Reset()
		ok, err := run(root, update, &out)
		if err != nil || ok != wantOK {
			t.Fatalf("run(update=%v) = %v, %v; want %v\n%s", update, ok, err, wantOK, out.String())
		}
	}

	write("a.go", "package a\n\nfunc F(x int) int { return x }\n")
	check(true, true)
	if b, err := os.ReadFile(filepath.Join(root, "api", "rpsl.txt")); err != nil || string(b) != "package a\nfunc F(x int) int\n" {
		t.Fatalf("api/rpsl.txt = %q, %v", b, err)
	}
	check(false, true)

	write("a.go", "package a\n\nfunc F(x int64) int { return int(x) }\n")
	write("b/b.go", "package b\n\nfunc G() {}\n")
	write("api/gone.txt", "package gone\n")
	check(false, false)
	for _, want := range []string{
		"api/b.txt: missing",
		"api/gone.txt: no public package",
		"- func F(x int) int",
		"+ func F(x int64) int",
		"RPSL_API_UPDATE=1",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}

	check(true, true)
	if _, err := os.Stat(filepath.Join(root, "api", "gone.txt")); !os.IsNotExist(err) {
		t.Errorf("api/gone.txt survived an update: %v", err)
	}
	check(false, true)
}
```

`internal/apisurface/main.go`:

```go
// Command apisurface keeps api/, the golden of the public API's signatures
// (one file per public package), and checks the API conventions (CLAUDE.md,
// "Go conventions"). scripts/check.sh runs it:
//
//	go run ./internal/apisurface -check                    # compare with api/
//	RPSL_API_UPDATE=1 go run ./internal/apisurface -check  # rewrite api/; review the diff
//
// It runs as a command, not a test: the published root-module zip, which
// release.sh step 6 tests, does not hold the nested modules it reads.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func main() {
	check := flag.Bool("check", false, "compare api/ with the source and check the conventions (RPSL_API_UPDATE=1 rewrites api/)")
	root := flag.String("root", ".", "the repository root")
	flag.Parse()
	if !*check || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	ok, err := run(*root, os.Getenv("RPSL_API_UPDATE") == "1", os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "apisurface:", err)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}

// run renders the public API below root and compares it with root/api — or,
// with update, rewrites root/api to match — then checks the conventions. It
// writes every difference and violation to w and reports whether there were
// none.
func run(root string, update bool, w io.Writer) (bool, error) {
	pkgs, err := discover(root)
	if err != nil {
		return false, err
	}
	want := map[string]string{}
	for _, p := range pkgs {
		want[goldenName(p.dir)] = render(p)
	}
	dir := filepath.Join(root, "api")
	have, err := readGoldens(dir)
	if err != nil {
		return false, err
	}
	ok := true
	if update {
		if err := writeGoldens(dir, have, want); err != nil {
			return false, err
		}
	} else {
		names := maps.Clone(want)
		maps.Copy(names, have)
		for _, name := range slices.Sorted(maps.Keys(names)) {
			wantText, inWant := want[name]
			haveText, inHave := have[name]
			switch {
			case !inHave:
				fmt.Fprintf(w, "api/%s: missing; a public package has no golden\n", name)
			case !inWant:
				fmt.Fprintf(w, "api/%s: no public package has this surface\n", name)
			case wantText != haveText:
				fmt.Fprintf(w, "api/%s differs from the source (- golden, + source):\n", name)
				for _, l := range diffLines(lines(haveText), lines(wantText)) {
					fmt.Fprintln(w, l)
				}
			default:
				continue
			}
			ok = false
		}
		if !ok {
			fmt.Fprintln(w, "RPSL_API_UPDATE=1 go run ./internal/apisurface -check rewrites api/; review the diff")
		}
	}
	for _, v := range conventions(root, pkgs) {
		fmt.Fprintln(w, v)
		ok = false
	}
	return ok, nil
}

// readGoldens returns the .txt files in dir by name; a missing dir has none.
func readGoldens(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = string(b)
	}
	return out, nil
}

// writeGoldens makes dir hold exactly want: stale goldens are removed.
func writeGoldens(dir string, have, want map[string]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name := range have {
		if _, ok := want[name]; !ok {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	for name, text := range want {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func lines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

// diffLines is a minimal line diff of a against b, by longest common
// subsequence: "- " for a line only in a, "+ " for one only in b, no context.
// A golden is a few hundred lines, so the quadratic table is small.
func diffLines(a, b []string) []string {
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case j < len(b) && (i == len(a) || lcs[i][j+1] >= lcs[i+1][j]):
			out = append(out, "+ "+b[j])
			j++
		default:
			out = append(out, "- "+a[i])
			i++
		}
	}
	return out
}
```

- [ ] **Step 7: Run the tool's tests**

Run: `go test ./internal/apisurface/ && go vet ./internal/apisurface/ && gofmt -l internal/apisurface`
Expected: `ok`, no vet output, no gofmt output. If `TestRender` differs, compare the got/want blocks line by line and fix `surface.go`. The expected text was produced by this exact code, so a difference means the code was mistyped.

- [ ] **Step 8: Fix the two sentinels C3 flags in the repository**

Run: `go run ./internal/apisurface -check 2>&1 | grep ': C'`
Expected before the fix (exactly these two):

```
resolve/irrd/irrd.go:133: C3: ErrQueryRefused is not declared with errors.New
resolve/rdap/rdap.go:126: C3: ErrNotFound is not declared with errors.New
```

In `resolve/rdap/rdap.go`, change `var ErrNotFound = fmt.Errorf("rdap: object not found")` to `var ErrNotFound = errors.New("rdap: object not found")`. `errors` is already imported. Keep `fmt` if other code uses it: `go build` will say.

In `resolve/irrd/irrd.go`, replace the `errQuery` and `ErrQueryRefused` declarations (lines 127-133) with:

```go
// ErrQueryRefused is returned when the server refuses a query outright ('F'),
// as a server without IRRd 4's "!a" does for ASSetPrefixes. The connection is
// still in step.
var ErrQueryRefused = errors.New("irrd: query error")
```

Then rename the remaining uses: `perl -pi -e 's/\berrQuery\b/ErrQueryRefused/g' resolve/irrd/*.go`, then `grep -n 'errQuery' resolve/irrd/*.go` (expect no output). The message text stays "irrd: query error", so anything that compares error strings is unaffected.

Run: `cd resolve && go build ./... && go test ./irrd/ ./rdap/ && cd ..`
Expected: `ok` for both.

- [ ] **Step 9: Generate the goldens and wire the check into `check.sh`**

Run: `RPSL_API_UPDATE=1 go run ./internal/apisurface -check; echo "exit=$?"`
Expected: no output, `exit=0`, and `ls api | wc -l` prints `18`.

Then pin rule 5 of the Review Focus: `GOTOOLCHAIN=go1.23.0 go run ./internal/apisurface -check; echo "exit=$?"` → `exit=0`.

Read `api/policy.txt` and `api/resolve.txt` once by eye: one declaration per line, no comments.

In `scripts/check.sh`, after the "engine purity" step (the line `if (cd resolve && go list -deps …`), add:

```sh
step "api surface: api/ matches the public API, and the API conventions hold"
go run ./internal/apisurface -check ||
	bad "api surface (RPSL_API_UPDATE=1 go run ./internal/apisurface -check rewrites api/; review the diff)"
```

- [ ] **Step 10: Run the full check**

Run (alone): `MEMGUARD_NORMAL_PRIORITY=1 .superpowers/sdd/tools/memguard.sh 8 3600 env GOMAXPROCS=4 GOMEMLIMIT=6GiB scripts/check.sh > .superpowers/sdd/api-v0.26/check-t1.log 2>&1; echo "exit=$?"`, after `mkdir -p .superpowers/sdd/api-v0.26`, then `tail -5 .superpowers/sdd/api-v0.26/check-t1.log`.
Expected: `check: ok` and `SUCCESS`.

- [ ] **Step 11: Commit**

```bash
git add internal/apisurface api scripts/check.sh resolve/irrd resolve/rdap
git commit -m "internal/apisurface: golden of the public API and convention checks"
```

---

### Task 2: `policy` — 13 parse entry points become 6, and C1

**Files:**
- Modify: `policy/parse.go:15-110` (entry points, `Options`, shared setup), `policy/dict.go:160-228` (delete the three old `With` functions and move `Options` out), `policy/via.go:1-73` (delete the four via entry points and the two `parseXVia`; keep the grammar comment and `parseViaFactor`/`startsViaClause`)
- Modify: `object/classes.go:55-90` (the aut-num decoder)
- Modify tests: `policy/*_test.go`, `rules_test.go:103,117`, `examples/bulk-ripe/bulk/realdata_test.go:241-243`
- Create: `policy/options_test.go`, `policy/helpers_test.go`
- Modify: `internal/apisurface/conventions.go`, `…/conventions_test.go`, `…/testdata/conventions/{bad/bad.go,good/good.go}`
- Modify docs: `README.md:182`, `policy/ast.go:22`, `docs/rpsl-go-design.md:409`
- Regenerate: `api/policy.txt`

**Interfaces:**
- Consumes: Task 1's `conventions`, `baseName`, `text`.
- Produces:

```go
type Options struct {
	MP   bool        // mp-import:/mp-export:/mp-default: syntax (RFC 4012)
	Via  bool        // import-via:/export-via: syntax; implies MP
	Dict *Dictionary // nil: actions and protocols are checked for syntax only
}
func ParseImport(s string) (Import, []ast.Diagnostic)
func ParseImportWith(s string, o Options) (Import, []ast.Diagnostic)
func ParseExport(s string) (Export, []ast.Diagnostic)
func ParseExportWith(s string, o Options) (Export, []ast.Diagnostic)
func ParseDefault(s string) (Default, []ast.Diagnostic)
func ParseDefaultWith(s string, o Options) (Default, []ast.Diagnostic)
```

Removed: `ParseMPImport`, `ParseMPExport`, `ParseMPDefault`, `ParseImportVia`, `ParseExportVia`, `ParseImportViaWith`, `ParseExportViaWith`, and the 3-argument `ParseImportWith`/`ParseExportWith`/`ParseDefaultWith`.

- [ ] **Step 1: Write the failing options tests**

`policy/options_test.go`:

```go
package policy

import (
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// TestOptionsMPAndVia: MP marks a policy multiprotocol; Via reads the via
// grammar and implies MP, set or not.
func TestOptionsMPAndVia(t *testing.T) {
	const via = "AS6777 from AS15562 action pref = 2; accept AS-SNIJDERS"
	for _, o := range []Options{{Via: true}, {Via: true, MP: true}} {
		imp, ds := ParseImportWith(via, o)
		if len(ds) != 0 || !imp.MP {
			t.Errorf("ParseImportWith(%q, %+v): MP=%v %v; want MP, clean", via, o, imp.MP, ds)
		}
	}
	if imp, ds := ParseImportWith("from AS1 accept ANY", Options{MP: true}); len(ds) != 0 || !imp.MP {
		t.Errorf("MP import: MP=%v %v", imp.MP, ds)
	}
	if imp, _ := ParseImport("from AS1 accept ANY"); imp.MP {
		t.Error("plain import is MP")
	}
	if exp, ds := ParseExportWith("AS6777 195.69.144.255 to AS-AMS-IX-RS announce AS-SNIJDERS", Options{Via: true}); len(ds) != 0 || !exp.MP {
		t.Errorf("via export: MP=%v %v", exp.MP, ds)
	}
}

// TestDefaultHasNoVia: RFC 2622 has no default-via:. With Via, the value is
// read as mp-default: and one Error spanning the whole value comes first.
func TestDefaultHasNoVia(t *testing.T) {
	const s = "to AS1 action pref = 10; networks ANY"
	got, ds := ParseDefaultWith(s, Options{Via: true})
	want, wantDs := ParseDefaultWith(s, Options{MP: true})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Via default = %+v, want the MP parse %+v", got, want)
	}
	if len(ds) != len(wantDs)+1 {
		t.Fatalf("diagnostics %v, want one more than %v", ds, wantDs)
	}
	d := ds[0]
	if d.Rule != "policy/no-default-via" || d.Severity != ast.Error ||
		d.Span.StartByte != 0 || d.Span.EndByte != len(s) {
		t.Errorf("first diagnostic %+v, want an Error policy/no-default-via over bytes 0..%d", d, len(s))
	}
}

// TestPlainEqualsZeroOptions: X(s) is XWith(s, Options{}) for every input of
// the grammar tables and FuzzParseImport's seeds (the root testdata/ holds
// only 8 policy lines, too few to stand alone).
func TestPlainEqualsZeroOptions(t *testing.T) {
	for _, s := range policyInputs() {
		i1, d1 := ParseImport(s)
		i2, d2 := ParseImportWith(s, Options{})
		e1, f1 := ParseExport(s)
		e2, f2 := ParseExportWith(s, Options{})
		g1, h1 := ParseDefault(s)
		g2, h2 := ParseDefaultWith(s, Options{})
		if !reflect.DeepEqual(i1, i2) || !reflect.DeepEqual(d1, d2) ||
			!reflect.DeepEqual(e1, e2) || !reflect.DeepEqual(f1, f2) ||
			!reflect.DeepEqual(g1, g2) || !reflect.DeepEqual(h1, h2) {
			t.Errorf("%q: the plain parse differs from the zero-options parse", s)
		}
	}
}
```

(`lexer.Span` has `StartByte, EndByte int`, checked 2026-10-07. The parser's own whole-value diagnostic, `policy/too-long` at `policy/parse.go:272`, is the model: `token{tEOF, "", 0, len(s)}`.)

`policyInputs` (Step 5, `policy/helpers_test.go`) needs two lists that are locals today, so lift both to package level, unchanged:
- In `policy/parse_test.go`, `FuzzParseImport`'s seed literal (`for _, s := range []string{ … } { f.Add(s) }`) becomes `var importSeeds = []string{ … }`, and the fuzz target loops `for _, s := range importSeeds { f.Add(s) }`.
- In `policy/grammar_test.go`, `TestPolicyGrammar`'s `cases := []struct{ name string; parse func(string) (Import, []ast.Diagnostic); in, want string }{ … }` becomes `var grammarCases = []struct{ … }{ … }` at package level, and the test begins `cases := grammarCases`. Its rows name `ParseMPImport` as a function value; Step 5's rename turns that into `mpImport`, which has the same type.

Run: `go test ./policy/ -run 'TestOptions|TestDefaultHasNoVia|TestPlainEquals'`
Expected: FAIL to compile (`unknown field MP in struct literal of type Options`, wrong argument count).

- [ ] **Step 2: Replace the entry points in `policy/parse.go`**

Replace lines 15-110 (from `// ParseImport parses an import:` through the end of `parseDefault`) with:

```go
// Options configures a policy parse. The zero Options — what ParseImport,
// ParseExport and ParseDefault use — reads the RFC 2622 attribute and checks
// actions and protocol names for syntax only, as the RP-attribute set is
// open-ended by design.
type Options struct {
	// MP reads the RFC 4012 form (mp-import:, mp-export:, mp-default:): the
	// result is marked MP, which makes an absent afi clause mean every family.
	MP bool

	// Via reads import-via: or export-via: (draft-ietf-grow-rpsl-via): every
	// clause names, before "from" or "to", the peering its routes pass
	// through. It implies MP. There is no default-via:, so ParseDefaultWith
	// reports one Error ("policy/no-default-via") and reads the value as
	// mp-default:.
	Via bool

	// Dict, when set, checks actions and protocols against a dictionary;
	// both diagnostics are warnings.
	Dict *Dictionary
}

// parser returns a parser for s set up by o; viaKw is the keyword a via
// clause's peering comes before ("from" or "to").
func (o Options) parser(s, viaKw string) *parser {
	p := newParser(s)
	p.mp, p.dict = o.MP || o.Via, o.Dict
	if o.Via {
		p.via = viaKw
	}
	return p
}

// ParseImport parses an import: value ("[protocol …] [into …] from <peering>
// [action …] … accept <filter>", optionally structured with {…}, except and
// refine). It returns a best-effort Import plus diagnostics whose byte offsets
// are relative to s (the caller re-bases them onto the owning attribute).
// Every token is either parsed or diagnosed; it never panics.
func ParseImport(s string) (Import, []ast.Diagnostic) { return ParseImportWith(s, Options{}) }

// ParseImportWith is ParseImport with options: mp-import: and import-via:
// syntax, and a dictionary.
func ParseImportWith(s string, o Options) (Import, []ast.Diagnostic) {
	imp, p := parseImport(s, o)
	return imp, p.diags
}

func parseImport(s string, o Options) (Import, *parser) {
	p := o.parser(s, "from")
	imp := Import{MP: p.mp}
	if p.empty() {
		return imp, p
	}
	imp.Protocol, imp.IntoProtocol = p.parseProtocols()
	imp.AFIs = p.parseAFIs()
	imp.Expr = p.parseExpr("from", "accept")
	p.finish()
	return imp, p
}

// ParseExport parses an export: value ("… to <peering> [action …] … announce
// <filter>"). Structurally identical to ParseImport but with to/announce.
func ParseExport(s string) (Export, []ast.Diagnostic) { return ParseExportWith(s, Options{}) }

// ParseExportWith is ParseExport with options: mp-export: and export-via:
// syntax, and a dictionary.
func ParseExportWith(s string, o Options) (Export, []ast.Diagnostic) {
	exp, p := parseExport(s, o)
	return exp, p.diags
}

func parseExport(s string, o Options) (Export, *parser) {
	p := o.parser(s, "to")
	exp := Export{MP: p.mp}
	if p.empty() {
		return exp, p
	}
	exp.Protocol, exp.IntoProtocol = p.parseProtocols()
	exp.AFIs = p.parseAFIs()
	exp.Expr = p.parseExpr("to", "announce")
	p.finish()
	return exp, p
}

// ParseDefault parses a default: value ("to <peering> [action …] [networks
// <filter>]"). Networks is nil when no networks clause is present.
func ParseDefault(s string) (Default, []ast.Diagnostic) { return ParseDefaultWith(s, Options{}) }

// ParseDefaultWith is ParseDefault with options: mp-default: syntax and a
// dictionary. RFC 2622 has no default-via:; with Via set it reports one Error
// over the whole value and reads it as mp-default:.
func ParseDefaultWith(s string, o Options) (Default, []ast.Diagnostic) {
	d, p := parseDefault(s, o)
	return d, p.diags
}

func parseDefault(s string, o Options) (Default, *parser) {
	p := Options{MP: o.MP || o.Via, Dict: o.Dict}.parser(s, "")
	if o.Via {
		p.errf(token{tEOF, "", 0, len(s)}, "policy/no-default-via",
			"there is no default-via: attribute; the value is read as mp-default:")
	}
	d := Default{MP: p.mp}
	if p.empty() {
		return d, p
	}
	d.AFIs = p.parseAFIs()
	if !p.cur().kw("to") {
		p.errf(p.cur(), "policy/default-to", "expected 'to' at start of default")
		return d, p
	}
	p.advance()
	d.Peering = p.parsePeering()
	if p.cur().kw("action") {
		p.advance()
		d.Actions = p.parseActions()
	}
	if p.cur().kw("networks") {
		p.advance()
		d.Networks = p.parseFilter()
	}
	p.finish()
	return d, p
}
```

The `policy/default-to` message keeps the plain form's wording ("at start of default"), which the decoder emits today. The old `ParseDefaultWith` said "in a default policy". No test or golden asserts that text: `grep -rn 'in a default policy' .` should show only `policy/dict.go`, which Step 3 deletes.

- [ ] **Step 3: Delete the old forms**

- `policy/dict.go`: delete `type Options` and its comment, and `ParseImportWith`, `ParseExportWith` and `ParseDefaultWith` (lines 160-228, from `// Options configures a policy parse.` to the closing `}` of `ParseDefaultWith`). Keep `checkAction` and everything after it.
- `policy/via.go`: delete `ParseImportVia`, `ParseImportViaWith`, `ParseExportVia`, `ParseExportViaWith`, `parseImportVia` and `parseExportVia` (everything from `// ParseImportVia parses` to the end of `parseExportVia`). Keep the package comment block describing the grammar, changing its last sentence to: "The via peering is PeerAction.Via. Everything else is the mp-* grammar, so a via policy has the same Import and Export types, renders with String and flattens with Flatten; Options.Via selects it." Remove now-unused imports (`go build` lists them).

Run: `go build ./policy/`
Expected: success.

- [ ] **Step 4: Update the aut-num decoder**

In `object/classes.go`, replace the `switch a.Name { … }` cases for import, export, import-via, export-via and default (lines 56-89) with:

```go
		switch a.Name {
		case "import", "mp-import", "import-via":
			var imp policy.Import
			imp, ds = policy.ParseImportWith(a.Value, policy.Options{MP: a.Name == "mp-import", Via: a.Name == "import-via"})
			if a.Name == "import-via" {
				an.ImportVia = append(an.ImportVia, imp)
			} else {
				an.Imports = append(an.Imports, imp)
			}
		case "export", "mp-export", "export-via":
			var exp policy.Export
			exp, ds = policy.ParseExportWith(a.Value, policy.Options{MP: a.Name == "mp-export", Via: a.Name == "export-via"})
			if a.Name == "export-via" {
				an.ExportVia = append(an.ExportVia, exp)
			} else {
				an.Exports = append(an.Exports, exp)
			}
		case "default", "mp-default":
			var def policy.Default
			def, ds = policy.ParseDefaultWith(a.Value, policy.Options{MP: a.Name == "mp-default"})
			an.Defaults = append(an.Defaults, def)
		default:
			continue
		}
```

- [ ] **Step 5: Migrate the tests mechanically**

Create `policy/helpers_test.go`:

```go
package policy

import "github.com/rkolesnichenko/rpsl/ast"

// The table tests name a parse function per row; these are the option sets
// they use, as functions.

func mpImport(s string) (Import, []ast.Diagnostic)  { return ParseImportWith(s, Options{MP: true}) }
func mpExport(s string) (Export, []ast.Diagnostic)  { return ParseExportWith(s, Options{MP: true}) }
func mpDefault(s string) (Default, []ast.Diagnostic) { return ParseDefaultWith(s, Options{MP: true}) }
func viaImport(s string) (Import, []ast.Diagnostic) { return ParseImportWith(s, Options{Via: true}) }
func viaExport(s string) (Export, []ast.Diagnostic) { return ParseExportWith(s, Options{Via: true}) }

// policyInputs is every policy value the grammar tables and FuzzParseImport's
// seeds hold, for properties that must hold of all of them.
func policyInputs() []string {
	var out []string
	for _, c := range grammarCases {
		out = append(out, c.in)
	}
	return append(out, importSeeds...)
}
```

Then rewrite the old names in the policy package's tests. These are word-boundary renames to helpers with the same call shape. Function-value uses in tables (`{"…", ParseMPImport, …}`) are renamed too.

```bash
perl -pi -e 's/\bParseMPImport\b/mpImport/g; s/\bParseMPExport\b/mpExport/g; s/\bParseMPDefault\b/mpDefault/g; s/\bParseImportVia\b/viaImport/g; s/\bParseExportVia\b/viaExport/g' policy/*_test.go
perl -pi -e 's/\b(Parse(?:Import|Export|Default)With)\((.*?), false, /$1($2, /g' policy/*_test.go
```

Fix by hand, then `go vet ./policy/` until it is clean:
- `policy/dict_test.go`: any `ParseXWith(…, true, Options{Dict: &d})` becomes `ParseXWith(…, Options{MP: true, Dict: &d})`.
- `policy/via_test.go:280,283`: `ParseImportViaWith(s, o)` becomes `ParseImportWith(s, Options{Via: true, Dict: o.Dict})`, and the same for export. If `o` is a literal, write the literal with `Via: true` added.
- Error strings that quoted an old name (`t.Errorf("ParseImportWith(%q) …")`) may keep their wording; they are messages only.

Outside `policy/`:
- `rules_test.go:103`: `policy.ParseMPImport(v)` becomes `policy.ParseImportWith(v, policy.Options{MP: true})`.
- `rules_test.go:117`: `policy.ParseImportWith(v, false, policy.Options{Dict: &dict})` becomes `policy.ParseImportWith(v, policy.Options{Dict: &dict})`.
- `examples/bulk-ripe/bulk/realdata_test.go:241,243`: `policy.ParseImportVia(v)` becomes `policy.ParseImportWith(v, policy.Options{Via: true})`, and the same for export.

Run: `grep -rnwE 'ParseMP(Import|Export|Default)|Parse(Import|Export)Via(With)?' --include='*.go' .`
Expected: no output.

- [ ] **Step 6: Rewrite `FuzzParseImport`'s body (keep its signature)**

`policy/testdata/fuzz/FuzzParseImport` holds a corpus encoded for `func(t *testing.T, s string)`. Keep that signature and try every option set inside. In `policy/parse_test.go`, replace the `f.Fuzz(func(t *testing.T, s string) { … })` body with:

```go
	f.Fuzz(func(t *testing.T, s string) {
		for _, o := range []Options{{}, {MP: true}, {Via: true}} {
			imp, pi := parseImport(s, o)
			exp, pe := parseExport(s, o)
			def, pd := parseDefault(s, o)
			for _, p := range []*parser{pi, pe, pd} {
				assertNothingDropped(t, s, p)
			}
			checkParse(t, s, imp, pi.diags, func(v string) (any, []ast.Diagnostic) { return ParseImportWith(v, o) })
			checkParse(t, s, exp, pe.diags, func(v string) (any, []ast.Diagnostic) { return ParseExportWith(v, o) })
			checkParse(t, s, def, pd.diags, func(v string) (any, []ast.Diagnostic) { return ParseDefaultWith(v, o) })
			if !o.Via {
				continue
			}
			// A clean via policy renders to text that parses back to the same policy.
			if len(pi.diags) == 0 {
				if again, ds := ParseImportWith(imp.String(), o); len(ds) != 0 || again.String() != imp.String() {
					t.Fatalf("%q renders as %q, which parses back as %q %v", s, imp.String(), again.String(), diagRules(ds))
				}
			}
			if len(pe.diags) == 0 {
				if again, ds := ParseExportWith(exp.String(), o); len(ds) != 0 || again.String() != exp.String() {
					t.Fatalf("%q renders as %q, which parses back as %q %v", s, exp.String(), again.String(), diagRules(ds))
				}
			}
		}
	})
```

This is a superset of the old body, which tried plain import, MP export, plain default, via import and via export.

Run: `go test ./policy/ -run 'FuzzParseImport|TestOptions|TestDefaultHasNoVia|TestPlainEquals' -v 2>&1 | tail -15`
Expected: PASS for all four. (`go test` runs the fuzz seeds and the checked-in corpus without `-fuzz`.)

Then: `go test ./policy/ ./object/ . && (cd examples/bulk-ripe && go vet ./...)`
Expected: `ok` for each, no vet output.

- [ ] **Step 7: Add C1 to `apisurface`, test first**

Append to `internal/apisurface/testdata/conventions/bad/bad.go`, after line 20 (`type Thing struct{}`), keeping a blank line between declarations:

```go

func Expand(s string) []string { return nil }

func ExpandWith(s string, o Options) []string { return nil }

func LoadWith(s string, o Options) error { return nil }

func Merge(a string) int { return 0 }

func MergeWith(a string, b int, o Options) int { return 0 }

type Options struct{}
```

That puts `LoadWith` on line 26 and `MergeWith` on line 30. Check with `grep -n With internal/apisurface/testdata/conventions/bad/bad.go`.

Append to `…/good/good.go`:

```go

func Read(s string) int { return 0 }

func ReadWith(s string, o Options) int { return 0 }

// With alone is not an XWith: it has no X to pair with.
func (o Options) With(n int) Options { return o }

type Options struct{}
```

In `conventions_test.go`, extend the bad case's `want`, after the two C2 lines:

```go
			"bad.go:26: C1: LoadWith has no Load",
			"bad.go:30: C1: MergeWith's parameters are not Merge's plus one options parameter",
```

Run: `go test ./internal/apisurface/ -run TestConventions`
Expected: FAIL (the two C1 lines missing).

Then in `conventions.go`, add `"maps"` and `"slices"` to the imports and replace `conventions` with:

```go
func conventions(root string, pkgs []*pkg) []string {
	var out []string
	for _, p := range pkgs {
		report := func(pos token.Pos, msg string) {
			at := p.fset.Position(pos)
			name, err := filepath.Rel(root, at.Filename)
			if err != nil {
				name = at.Filename
			}
			out = append(out, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(name), at.Line, msg))
		}
		funcs := map[string]*ast.FuncDecl{} // by receiver type and name: "Thing.Parse", ".Parse"
		for _, f := range p.files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					checkParseBool(d, report)
					funcs[recvKey(d)+d.Name.Name] = d
				case *ast.GenDecl:
					if d.Tok == token.VAR {
						checkSentinels(d, report)
					}
				}
			}
		}
		checkWith(p.fset, funcs, report)
	}
	return out
}

// recvKey is the receiver part of a function's key in conventions' map: the
// receiver's type name and a dot, or a dot alone for a function.
func recvKey(d *ast.FuncDecl) string {
	if d.Recv == nil {
		return "."
	}
	return baseName(d.Recv.List[0].Type) + "."
}

// checkWith is C1: an exported XWith has a sibling X with the same receiver,
// whose parameters are XWith's less the last (the options) and whose results
// are XWith's. A bare With is not an XWith.
func checkWith(fset *token.FileSet, funcs map[string]*ast.FuncDecl, report func(token.Pos, string)) {
	for _, key := range slices.Sorted(maps.Keys(funcs)) {
		d := funcs[key]
		name := d.Name.Name
		if !d.Name.IsExported() || name == "With" || !strings.HasSuffix(name, "With") {
			continue
		}
		plainName := strings.TrimSuffix(name, "With")
		plain, ok := funcs[strings.TrimSuffix(key, "With")]
		if !ok {
			report(d.Pos(), "C1: "+name+" has no "+plainName)
			continue
		}
		wp, pp := fieldTypes(fset, d.Type.Params), fieldTypes(fset, plain.Type.Params)
		if len(wp) == 0 || !slices.Equal(wp[:len(wp)-1], pp) {
			report(d.Pos(), "C1: "+name+"'s parameters are not "+plainName+"'s plus one options parameter")
		}
		if !slices.Equal(fieldTypes(fset, d.Type.Results), fieldTypes(fset, plain.Type.Results)) {
			report(d.Pos(), "C1: "+name+"'s results are not "+plainName+"'s")
		}
	}
}

// fieldTypes lists a parameter or result list's types, one per name.
func fieldTypes(fset *token.FileSet, fl *ast.FieldList) []string {
	if fl == nil {
		return nil
	}
	var out []string
	for _, f := range fl.List {
		t := text(fset, f.Type)
		for range max(len(f.Names), 1) {
			out = append(out, t)
		}
	}
	return out
}
```

Run: `go test ./internal/apisurface/`
Expected: PASS.

- [ ] **Step 8: Docs and golden**

- `README.md:182`: the policy row's description becomes "Routing-policy AST + `ParseImport`/`ParseExport`/`ParseDefault` and their `…With(s, Options{MP, Via, Dict})` forms".
- `policy/ast.go:22`: "mp-import: (ParseMPImport)" becomes "mp-import: (Options.MP)".
- `docs/rpsl-go-design.md:409`: "mp-import: (ParseMPImport)" becomes "mp-import: (Options.MP)".
- Run `grep -rn 'ParseMP\(Import\|Export\|Default\)\|Parse\(Import\|Export\)Via' --include='*.md' . | grep -v CHANGELOG | grep -v docs/superpowers | grep -v reports/ | grep -v research_notes/`. Expected: no output. CHANGELOG history and the dated reports keep their wording.

Run: `RPSL_API_UPDATE=1 go run ./internal/apisurface -check && git diff --stat api/`
Expected: only `api/policy.txt` changes: 7 functions gone, the `Options` fields `MP` and `Via` added, and the three `With` signatures changed. Read `git diff api/policy.txt` to confirm.

- [ ] **Step 9: Full check, then commit**

Run the guarded `scripts/check.sh` exactly as Task 1 Step 10, logging to `check-t2.log`. Expected: `check: ok`, `SUCCESS`. Also confirm `git diff --stat main -- '*testdata*'` lists only `internal/apisurface/testdata/`.

```bash
git add -A policy object/classes.go rules_test.go examples/bulk-ripe/bulk/realdata_test.go internal/apisurface api README.md docs/rpsl-go-design.md
git commit -m "policy: one plain and one With form per family; Options.MP and Options.Via"
```

---

### Task 3: `object` classes are pointers

**Files:**
- Modify: `object/*.go` (all 23 class types' receivers; `object/decode.go` registry and `Decode`)
- Modify: every package that type-switches on, asserts, builds or passes a class — compiler-driven across all modules: the root (`rpsl.go`, tests), `auth/`, `resolve/` and its subpackages, `resolve/internal/**`, `resolve/cmd/**`, `examples/bulk-ripe/**`
- Modify: `resolve/claims.go:152-200` (delete `value()`), its callers, and `ClaimAllowed`'s doc
- Create: `object/pointer_test.go`
- Modify docs: `README.md:213,261`, and any code block in `docs/*.md` that asserts a class by value
- Regenerate: `api/*.txt`

**Interfaces:**
- Consumes: Task 2's `policy` API (unchanged here).
- Produces:
  - `object.Decode(o *ast.Object) (object.Object, []ast.Diagnostic)` returns a non-nil `*object.X` for each of `AsBlock, AsSet, AutNum, Dictionary, Domain, FilterSet, Generic, Inet6num, Inetnum, InetRtr, Irt, KeyCert, Mntner, Organisation, PeeringSet, Person, Poem, PoeticForm, Role, Route, Route6, RouteSet, RtrSet`, all methods on pointer receivers.
  - `resolve.PolicySource`: `AutNum(ctx, as, source) (*object.AutNum, error)`, `InetRtr(ctx, name, source) (*object.InetRtr, error)`, implemented by `*MemSource`, `*Cache`, `*irrd.Source`, `*whois.Source`, `*rpki.Filter`.
  - `auth.Registry.Mntner(ctx, name) (*object.Mntner, error)`; `auth.IrtRegistry.Irt(ctx, name) (*object.Irt, error)`; `auth.Database.ASBlocks(ctx, as) ([]*object.AsBlock, error)`; `auth.ReferralChain(...) ([]*object.Mntner, error)`; `auth.CheckMntner(ctx, m *object.Mntner, …)`; `auth.CheckIrt(ctx, irt *object.Irt, …)`; `auth.RouteRequestFor(r *object.Route, origin, space object.Object)`; `auth.RouteRequestFor6(r *object.Route6, …)`.
  - Every pointer result is nil exactly when its error is non-nil.

- [ ] **Step 1: Write the failing tests**

`object/pointer_test.go`:

```go
package object

import (
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// TestDecodeReturnsPointers: every class any profile knows decodes to a
// non-nil pointer of its own class, and an unknown class to *Generic, so a
// type switch over object.Object meets one form only.
func TestDecodeReturnsPointers(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range []Profile{RIPE, IRRd, ARIN, RFCStrict} {
		for _, class := range p.Classes() {
			if seen[class] {
				continue
			}
			seen[class] = true
			o, _ := Decode(ast.New(lexer.Tokenize(class + ": X\nsource: RIPE\n")))
			if v := reflect.ValueOf(o); v.Kind() != reflect.Pointer || v.IsNil() {
				t.Errorf("Decode(%s) = %T, want a non-nil pointer", class, o)
				continue
			}
			if o.Class() != class {
				t.Errorf("Decode(%s).Class() = %q", class, o.Class())
			}
		}
	}
	if o, _ := Decode(ast.New(lexer.Tokenize("no-such-class: X\n"))); reflect.TypeOf(o) != reflect.TypeOf(&Generic{}) {
		t.Errorf("unknown class decodes to %T, want *object.Generic", o)
	}
}
```

Add to `resolve/memsource_test.go`, or whichever `resolve` test file already builds a `MemSource` with an aut-num (`grep -ln 'AutNum(context' resolve/*_test.go`):

```go
// TestPolicyLookupMissIsNil: a lookup that finds nothing returns a nil
// pointer beside its error, never a zero object.
func TestPolicyLookupMissIsNil(t *testing.T) {
	src := (&resolve.Corpus{KeepPolicy: true}).Source()
	an, err := src.AutNum(context.Background(), 64500, "")
	if err == nil || an != nil {
		t.Errorf("AutNum miss = %v, %v; want nil and an error", an, err)
	}
	ir, err := src.InetRtr(context.Background(), "rtr.example.net", "")
	if err == nil || ir != nil {
		t.Errorf("InetRtr miss = %v, %v; want nil and an error", ir, err)
	}
}
```

Run: `go test ./object/ -run TestDecodeReturnsPointers`
Expected: FAIL ("Decode(aut-num) = object.AutNum, want a non-nil pointer"). The `resolve` test does not compile yet (it compares a value with nil). That is expected and fixed in Step 8.

- [ ] **Step 2: Pointer receivers on the 23 classes**

```bash
C='AsBlock|AsSet|AutNum|Dictionary|Domain|FilterSet|Generic|Inet6num|Inetnum|InetRtr|Irt|KeyCert|Mntner|Organisation|PeeringSet|Person|Poem|PoeticForm|Role|Route|Route6|RouteSet|RtrSet'
for f in object/*.go; do case $f in *_test.go) continue;; esac; perl -pi -e 's/^func \((\w+) ('"$C"')\) /func ($1 *$2) /' "$f"; done
grep -nE '^func \(\w+ ('"$C"')\) ' object/*.go | grep -v _test.go
```

Expected: the final grep prints nothing (every class method now has a pointer receiver). Also run `grep -nE '^func \(('"$C"')\) ' object/*.go`, for receivers without a name. Expected: nothing.

- [ ] **Step 3: `Decode` returns pointers**

In `object/decode.go`, make each registry entry return the address of the decoded value, and `Generic` a pointer:

```bash
perl -pi -e 's/\{ return (decode\w+)\(d\) \}/{ v := $1(d); return &v }/' object/decode.go
perl -pi -e 's/return Generic\{raw: o\}, nil/return &Generic{raw: o}, nil/' object/decode.go
grep -c 'return &v' object/decode.go
```

Expected: `22`. The `decodeX` functions keep returning values; they are unexported.

- [ ] **Step 4: Rewrite type switches and assertions everywhere, mechanically**

Type-switch `case` lines and type assertions naming a class take a `*`. In package `object` the names are bare; elsewhere they are `object.X`. Run on every non-vendored Go file in all modules (tests included):

```bash
C='AsBlock|AsSet|AutNum|Dictionary|Domain|FilterSet|Generic|Inet6num|Inetnum|InetRtr|Irt|KeyCert|Mntner|Organisation|PeeringSet|Person|Poem|PoeticForm|Role|Route|Route6|RouteSet|RtrSet'
git ls-files '*.go' | grep -v '/testdata/' > .superpowers/sdd/api-v0.26/gofiles.txt
while read -r f; do
  perl -pi -e 'if (/^\s*case /) { s/(?<![*\w.])((?:object\.)?(?:'"$C"'))(?=\s*[,:])/*$1/g } s/\.\(((?:object\.)?(?:'"$C"'))\)/.(*$1)/g' "$f"
done < .superpowers/sdd/api-v0.26/gofiles.txt
```

(Shell variables do not survive between separate commands. Every later block that uses `$C` starts by setting it again with this same line.)

(The `case` rule only touches a class name that ends at `,` or `:` and is not already starred. A quoted `"Route"` cannot match, because it is followed by `"`.)

Run `git diff --stat | tail -1` and read a sample of the diff (`git diff object/classes.go resolve/expander.go | head -80`). Expected: only `case` lines and `.(…)` assertions changed, each with an added `*`.

- [ ] **Step 5: Build every module and fix what the compiler names**

Run, module by module, until each is clean:

```bash
for m in . lexer ast types resolve examples/bulk-ripe; do (cd $m && go vet ./... 2>&1 | head -40); done
```

The errors fall into these shapes. Fix each by hand:

| Compiler message | Fix |
|---|---|
| `impossible type switch case` / `impossible type assertion` left over | add the `*` the Step 4 rewrite missed (a multi-line case, a class in a parenthesised list) |
| `object.X does not implement object.Object (method Class has pointer receiver)` where a literal is passed or stored | `object.X{…}` → `&object.X{…}`, or `&v` for a variable |
| `cannot use x (variable of type *object.X) as object.X value` | change the receiving variable, field, slice or parameter type to `*object.X` (in tests, prefer changing the expectation: `want := &object.Route{…}`) |
| `invalid operation: x == nil (mismatched types object.X and untyped nil)` | the new pointer API makes the comparison valid once the result type is a pointer |
| a struct literal compared with `reflect.DeepEqual(got, object.X{…})` that now fails at run time | `&object.X{…}`, or compare `*got` |

The exported signatures in the Interfaces block above must end up with pointers. Change each interface and every implementation together. Step 10 checks this against the regenerated golden.

- [ ] **Step 6: Delete `value()`**

In `resolve/claims.go`, delete `value` (lines 152-200, with its comment). Replace each call `value(x)` with `x`: `grep -rn 'value(' resolve/*.go | grep -v _test`. The callers are in `resolve/policyindex.go:95,140` and wherever else that grep shows. In `ClaimAllowed`'s doc, change "Only aut-num, route and route6 objects claim membership (as values or pointers); they are judged by their typed fields" to "Only aut-num, route and route6 objects claim membership; they are judged by their typed fields".

Run: `cd resolve && go build ./... && cd ..`
Expected: success.

- [ ] **Step 7: Run the unit tests of every module**

```bash
for m in . lexer ast types resolve examples/bulk-ripe; do (cd $m && go test -count=1 ./... 2>&1 | grep -v '^ok' | head -30); done
```

Expected: no output besides `?  … [no test files]` lines. A failing test is either a value expectation compared with a pointer result (fix the expectation as in Step 5) or a real change in behaviour. A real change gets root-caused before anything else: no testdata golden may be edited.

`TestEveryAttributeLandsInItsOwnField` (in `object`) uses reflection on decoded objects. If it fails, read through the pointer with `reflect.ValueOf(o).Elem()`.

- [ ] **Step 8: Nil exactly on error (Review Focus 2)**

Every implementation of a pointer-returning lookup returns `nil, err` on every error path and never `&object.X{}, err`. Check:

```bash
grep -rnE 'return (object\.)?(AutNum|InetRtr|Mntner|Irt|AsBlock)\{\}, ' --include='*.go' . | grep -v _test.go
grep -rnE 'return &(object\.)?(AutNum|InetRtr|Mntner|Irt)\{\}, ' --include='*.go' . | grep -v _test.go
```

Expected: both print nothing. Convert any hit to `return nil, err`. Then `go test ./resolve/ -run TestPolicyLookupMissIsNil` (from the repo root, through the workspace) → PASS.

- [ ] **Step 9: No shared object mutated (Review Focus 1)**

A value assertion used to hand back a private copy; a pointer assertion hands back the shared object. List every non-test site that asserts a class and then assigns to a field of the result:

```bash
C='AsBlock|AsSet|AutNum|Dictionary|Domain|FilterSet|Generic|Inet6num|Inetnum|InetRtr|Irt|KeyCert|Mntner|Organisation|PeeringSet|Person|Poem|PoeticForm|Role|Route|Route6|RouteSet|RtrSet'
grep -rnE '(\w+)(, ok)? :?= [^=]*\.\(\*(object\.)?('"$C"')\)' --include='*.go' . | grep -v _test.go > .superpowers/sdd/api-v0.26/asserts.txt; wc -l < .superpowers/sdd/api-v0.26/asserts.txt
```

For each line, read the enclosing function (`sed -n 'L-5,L+40p' file`) and check whether the asserted variable has a field written (`v.Field = …`, `v.Field = append(v.Field, …)`) or is passed to code that writes one. On 2026-10-07 there were 25 such sites and none wrote a field. If one does now, copy first (`c := *v; c.Field = …; use &c`) and add a test in that package proving the source object is unchanged after the call.

- [ ] **Step 10: Docs and golden**

Set `C='AsBlock|AsSet|AutNum|Dictionary|Domain|FilterSet|Generic|Inet6num|Inetnum|InetRtr|Irt|KeyCert|Mntner|Organisation|PeeringSet|Person|Poem|PoeticForm|Role|Route|Route6|RouteSet|RtrSet'` in each command below.

- `README.md:213` and `README.md:261`: `decoded.(object.AutNum)` → `decoded.(*object.AutNum)`.
- `grep -rnE '\.\((object\.)?('"$C"')\)|case (object\.)?('"$C"')\b' --include='*.md' . | grep -v CHANGELOG | grep -v docs/superpowers | grep -v reports/ | grep -v research_notes/`: fix each hit the same way. Expected afterwards: no output.

Run: `RPSL_API_UPDATE=1 go run ./internal/apisurface -check && git diff --stat api/`
Expected: `api/object.txt` (receivers `func (*AutNum) …`), `api/resolve.txt`, `api/auth.txt`, `api/resolve_irrd.txt`, `api/resolve_whois.txt` and `api/resolve_rpki.txt` change. Then:
`grep -nE '\b(object\.)('"$C"')\b' api/*.txt | grep -v '\*object\.'` → no output.

- [ ] **Step 11: Full check, then commit**

Run the guarded `scripts/check.sh` as Task 1 Step 10 (`check-t3.log`). Expected: `check: ok`, `SUCCESS`. Then `git diff --stat main -- '*testdata*'`: only `internal/apisurface/testdata/`.

```bash
git add -A
git status --short | grep -v '^[MA] ' # expect nothing untracked or unexpected
git commit -m "object: classes are pointers; lookups return *object.X"
```

---

### Task 4: Renames — `RouterGroup`, `Peerings`, `Routers`

**Files:**
- Modify: `object/` (the `RouterSet` interface and its users), `resolve/result.go:156,194` and every user (`resolve/expander.go`, `resolve/expand_more.go`, `resolve/claims.go`, `resolve/peval/{match,peval}.go`, tests, `resolve/internal/**`)
- Modify docs: comments naming the old types; `docs/rpsl-go-design.md` where it names the result types
- Regenerate: `api/object.txt`, `api/resolve.txt`

**Interfaces:**
- Produces: `object.RouterGroup` (was `object.RouterSet`, an interface: `NamedSet` plus `SetRouters() []RtrSetMember`); `resolve.Peerings` (was `resolve.PeeringSet`); `resolve.Routers` (was `resolve.RouterSet`). Methods unchanged. `Expander.ExpandPeerings` returns `(Peerings, error)`, `Expander.ExpandRouters` returns `(Routers, error)`.

- [ ] **Step 1: Rename with gopls (type-aware, across the workspace)**

```bash
L=$(grep -n '^type RouterSet interface' object/*.go); echo "$L"
```

Take the file and line from the output (for example `object/peersets.go:NN`). The type name starts at column 6. Then run:

```bash
gopls rename -w object/<file>.go:<line>:6 RouterGroup
gopls rename -w resolve/result.go:194:6 Peerings
gopls rename -w resolve/result.go:156:6 Routers
```

(Lines 156 and 194 are `type RouterSet struct` and `type PeeringSet struct` as of 2026-10-07. Re-check them with `grep -n '^type \(RouterSet\|PeeringSet\) struct' resolve/result.go` before running, and run the `Routers` rename after `Peerings`, since 194 comes after 156 and neither rename shifts lines.)

`gopls rename` changes identifiers only and leaves `object.PeeringSet` (the class) alone, because it resolves types. Comments are not renamed.

- [ ] **Step 2: Fix comments and docs by hand**

```bash
grep -rnE '\bRouterSet\b' --include='*.go' . | grep -v 'RouterSetRef'
grep -rnE '\b(resolve\.)?PeeringSet\b' --include='*.go' resolve | grep -v 'object\.PeeringSet' | grep -v 'PeeringSetRef'
```

Read each remaining hit. A comment that means the result type gets the new name ("PeeringSet is the result of expanding a peering-set" → "Peerings is the result of expanding a peering-set"). Mentions of the RPSL class (`peering-set`, `object.PeeringSet`, `rtr-set`) stay. Do the same in `docs/rpsl-go-design.md` and `README.md` for any mention of the result types or of `object.RouterSet`.

- [ ] **Step 3: Test and golden**

Run: `for m in . resolve; do (cd $m && go vet ./... && go test -count=1 ./... 2>&1 | grep -v '^ok' | head); done`
Expected: no failures.

Run: `RPSL_API_UPDATE=1 go run ./internal/apisurface -check && git diff --stat api/`
Expected: `api/object.txt` and `api/resolve.txt` only, and `api/resolve_peval.txt` if peval's exported API names the types. Read the diff: renames only.

- [ ] **Step 4: Full check, then commit**

Guarded `scripts/check.sh` as before (`check-t4.log`) → `check: ok`, `SUCCESS`.

```bash
git add -A
git commit -m "object.RouterGroup, resolve.Peerings, resolve.Routers: names that do not read as classes"
```

---

### Task 5: `(*ast.Object).Text`, and one fewer way to build a `MemSource`

**Files:**
- Modify: `ast/object.go` (add `Text`), `resolve/corpus.go:242-274` (delete `ObjectText`) and its callers `resolve/corpus.go:147,175,477`, `resolve/irrdq/objects.go:52`
- Create: `ast/text_test.go`
- Modify: `resolve/corpus_test.go:750-830` (keep the stream and loader cases, calling the method), `resolve/policyindex_test.go`, `resolve/irrdq/objects_test.go` (calls)
- Modify: the file defining `LoadDumps`/`LoadDump` (`grep -n 'func LoadDumps\?(' resolve/*.go`), `resolve/infra_test.go`
- Regenerate: `api/ast.txt`, `api/resolve.txt`

**Interfaces:**
- Produces: `func (o *Object) Text() string` in `ast`. Removed: `resolve.ObjectText`, `resolve.LoadDumps`.

- [ ] **Step 1: Write the failing `ast` test**

`ast/text_test.go` holds the cases that exercise the function itself (from `resolve/corpus_test.go`'s `TestObjectTextKeepsAttributesAfterABlankLine` and `TestObjectTextLineRules`), built with the package's own `parse` helper, which is what `rpsl.ParseObject` does:

```go
package ast

import "testing"

// TestText: an object's text runs from its first attribute line to its last
// attribute or continuation line. Leading and trailing blank, comment and
// malformed lines are dropped; one between attributes stays. Lines are read as
// the lexer reads them: a line led by a space, a tab or '+' continues an
// attribute only right after an attribute or continuation line.
func TestText(t *testing.T) {
	const obj = "aut-num: AS1\nsource: RIPE\n"
	for _, c := range []struct{ text, want string }{
		{"# head\n\nroute: 192.0.2.0/24\n# inside\norigin: AS1\nremarks: a\n+\n b\nsource: RIPE\n\n# tail\nEOF\n\n",
			"route: 192.0.2.0/24\n# inside\norigin: AS1\nremarks: a\n+\n b\nsource: RIPE\n"},
		{"aut-num: AS1\nas-name: A\n\nimport: from AS2 accept ANY\nsource: RIPE\n# trailing\nEOF\n\n",
			"aut-num: AS1\nas-name: A\n\nimport: from AS2 accept ANY\nsource: RIPE\n"},
		{"# aut-num: AS1\naut-num: AS1\nsource: RIPE\n", obj}, // a comment quoting the first line is still trivia
		{obj + "\n stray\n", obj},
		{obj + "\n+\n", obj},
		{obj + "\n  # c\n", obj},
		{obj + "# c\n stray\n", obj},
		{obj + "EOF\n\tstray\n", obj},
		{"aut-num: AS1\r\nremarks: a\r\n b\r\n+\r\nsource: RIPE\r\n\r\n  # c\r\n", "aut-num: AS1\r\nremarks: a\r\n b\r\n+\r\nsource: RIPE\r\n"},
		{"aut-num: AS1\n\n stray\nsource: RIPE\n\n stray\n", "aut-num: AS1\n\n stray\nsource: RIPE\n"},
		{"aut-num: AS1\nremarks: a\n b\n\tc\n+ d\n", "aut-num: AS1\nremarks: a\n b\n\tc\n+ d\n"},
		{"# only trivia\n\n", "# only trivia\n\n"}, // no attribute line: the text unchanged
	} {
		if got := parse(c.text).Text(); got != c.want {
			t.Errorf("Text(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}
```

Run: `cd ast && go test -run TestText . ; cd ..`
Expected: FAIL to compile (`parse(c.text).Text undefined`).

- [ ] **Step 2: Move the function**

Add to `ast/object.go`, near `String`, the body of `resolve.ObjectText` (`resolve/corpus.go:242-274`) as a method. Its doc keeps the reasoning, shortened to the parts that are about `ast`:

```go
// Text returns the object's text from its first attribute line to its last
// attribute or continuation line, without the blank, comment and malformed
// lines a stream attached before or after it (String keeps them, so the
// stream's round-trip stays byte-exact). A line between the first and the last
// attribute line stays. Lines are classified as the lexer classifies them
// (lexer.StartsAttribute), not by searching for the first attribute's text: a
// leading comment may quote it verbatim. An object with no attribute line
// returns String.
func (o *Object) Text() string {
	text := o.String()
	start, end := -1, 0
	inAttr := false // the previous line was an attribute or continuation line
	for rest, off := text, 0; len(rest) > 0; {
		line, eol := rest, len(rest)
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			line, eol = rest[:nl], nl+1
		}
		line = strings.TrimSuffix(line, "\r")
		switch {
		case lexer.IsBlankLine(line):
			inAttr = false // kept only if an attribute line follows
		case line[0] == ' ' || line[0] == '\t' || line[0] == '+':
			if inAttr { // a continuation; otherwise malformed (the lexer's classify)
				end = off + eol
			}
		case lexer.StartsAttribute(line):
			if start < 0 {
				start = off
			}
			end, inAttr = off+eol, true
		default: // a comment or a malformed line
			inAttr = false
		}
		off += eol
		rest = rest[eol:]
	}
	if start < 0 {
		return text
	}
	return text[start:end]
}
```

Delete `ObjectText` and its doc from `resolve/corpus.go`. Replace each call `ObjectText(raw)` / `resolve.ObjectText(raw)` with `raw.Text()`:

```bash
perl -pi -e 's/\b(?:resolve\.)?ObjectText\((\w+)\)/$1.Text()/g' resolve/corpus.go resolve/irrdq/objects.go resolve/*_test.go resolve/irrdq/*_test.go
grep -rn 'ObjectText' --include='*.go' .
```

Expected from the grep: only test function names (`TestObjectText…`) in `resolve/corpus_test.go`. Add `"strings"` to `ast/object.go`'s imports if it is not there. Remove imports `go build` reports unused in `resolve/corpus.go` (likely `lexer`).

In `resolve/corpus_test.go`, delete `TestObjectTextLineRules`: its table now lives in `ast`. Keep its last block, the stream case, by moving it into `TestObjectText`. Keep `TestObjectText` (the stream through `rpsl.Parse` plus the `DumpLoader` route text) and `TestObjectTextKeepsAttributesAfterABlankLine` (the served aut-num). They test the `Corpus`'s use of the method.

Run: `(cd ast && go test ./...) && (cd resolve && go test -count=1 . ./irrdq/)`
Expected: `ok` for each.

- [ ] **Step 3: Delete `LoadDumps`, fix `LoadDump`'s doc**

```bash
grep -n 'func LoadDumps\?(' resolve/*.go
grep -rn 'LoadDumps(' --include='*.go' .
```

Delete `LoadDumps` and its doc. In `resolve/infra_test.go`, rewrite its call `resolve.LoadDumps(rs, prec...)` as a `DumpLoader`:

```go
l := &resolve.DumpLoader{Sources: prec}
for _, r := range rs {
	if err := l.Read(r); err != nil {
		t.Fatal(err)
	}
}
src := l.Source()
```

Use the test's own variable names; read the surrounding function first.

Replace `LoadDump`'s doc with:

```go
// LoadDump reads one dump into a MemSource, with an optional source
// precedence as NewMemSource takes it. It is DumpLoader for the common case;
// use the loader itself to read several files, keep policy objects or route
// text, or see what the dump contained.
```

Run: `cd resolve && go vet ./... && go test -count=1 . && cd ..`
Expected: no vet output, `ok`.

- [ ] **Step 4: Golden, full check, commit**

Run: `RPSL_API_UPDATE=1 go run ./internal/apisurface -check && git diff --stat api/`
Expected: `api/ast.txt` gains `func (*Object) Text() string`; `api/resolve.txt` loses `ObjectText` and `LoadDumps`.

Guarded `scripts/check.sh` (`check-t5.log`) → `check: ok`, `SUCCESS`.

```bash
git add -A
git commit -m "ast: Object.Text replaces resolve.ObjectText; resolve: drop LoadDumps"
```

---

### Task 6: Write the conventions down

**Files:**
- Modify: `CLAUDE.md` ("Go conventions"; "Commands"), `docs/rpsl-go-design.md` (end of §2, before the `---` that precedes §3), `CHANGELOG.md` (`## [Unreleased]`)

- [ ] **Step 1: CLAUDE.md**

Append to the "Go conventions" list (after the "Comparable value types" bullet):

```markdown
- **API conventions** (design §2), held by `go run ./internal/apisurface -check` (check.sh runs it):
  - Options: `X(in)` with the zero options, `XWith(in, XOptions)` with all of them (C1).
  - A whole attribute value's parser returns `(T, []ast.Diagnostic)`; a single value's parser or
    constructor `(T, error)`. A trailing `ok bool` is for an expected false (a lookup miss, an
    empty result: `Intersect`, `Apply`, `NewPrefixRange`), never on a `Parse*` (C2).
  - Every `object` class is a pointer (`Decode` returns `*object.X`, pointer receivers); parsed
    values, policy AST nodes and expansion results are values; a type holding an index, a cache
    or a connection is a pointer.
  - A type is named after an RPSL class only if it is that class. Sentinels use `errors.New` (C3).
```

Under "Commands", after the "Engine purity" bullet:

```markdown
- API surface: `api/<pkg>.txt` is the golden of every public signature (no comments; const
  values kept). `go run ./internal/apisurface -check` fails on any difference and on a broken
  convention (C1–C3); `RPSL_API_UPDATE=1` rewrites `api/` — review the diff, it is the API change list.
```

- [ ] **Step 2: Design document §2**

At the end of §2 in `docs/rpsl-go-design.md` (after the `go.work` paragraph, before the `---`), add a subsection `### API conventions`. Its text is the spec's §3 verbatim (`docs/superpowers/specs/2026-10-07-api-consolidation-design.md`, "## 3. The conventions", rules 1-5 with their sub-bullets), followed by one sentence: "`internal/apisurface` holds `api/`, the golden of the public signatures, and checks rules 1, 2 and 5 mechanically (C1–C3); rule 3 is enforced by the compiler once the receivers are pointers, rule 4 by review."

- [ ] **Step 3: CHANGELOG**

Under `## [Unreleased]`, add:

```markdown
### Breaking

- `policy`: `ParseImport`, `ParseExport` and `ParseDefault` each have one options form,
  `ParseImportWith(s, Options)` etc., with `Options{MP, Via, Dict}`. Removed: `ParseMPImport`,
  `ParseMPExport`, `ParseMPDefault`, `ParseImportVia`, `ParseExportVia`, `ParseImportViaWith`,
  `ParseExportViaWith`, and the `(s, mp, o)` forms. `Via` implies `MP`; `ParseDefaultWith` with
  `Via` reports `policy/no-default-via` (there is no `default-via:`) and reads `mp-default:`.
- `object`: every class is a pointer. `Decode` returns `*object.AutNum`, `*object.Route`, …, and
  only pointers implement `object.Object`; type switches and assertions name `*object.X`.
- `resolve`: `PolicySource.AutNum`/`InetRtr` (and `MemSource`, `Cache`, `irrd.Source`,
  `whois.Source`, `rpki.Filter`) return `*object.AutNum`/`*object.InetRtr`, nil on error.
- `auth`: `Registry.Mntner`, `IrtRegistry.Irt`, `Database.ASBlocks` and `ReferralChain` return
  pointers; `CheckMntner`, `CheckIrt`, `RouteRequestFor` and `RouteRequestFor6` take them.
- Renamed: `object.RouterSet` → `object.RouterGroup`; `resolve.PeeringSet` → `resolve.Peerings`;
  `resolve.RouterSet` → `resolve.Routers`.
- `resolve.ObjectText(raw)` is now `raw.Text()` (`ast.Object.Text`). `resolve.LoadDumps` is
  removed; use `DumpLoader`.

### Changed

- `resolve/irrd`: `ErrQueryRefused` is its own sentinel rather than an alias of an unexported one;
  `errors.Is` answers are unchanged. `resolve/rdap`: `ErrNotFound` is built with `errors.New`.

### Added

- `api/`: the golden of every public package's signatures, checked by
  `go run ./internal/apisurface -check` with three API-convention checks (CLAUDE.md, design §2).
```

- [ ] **Step 4: Check and commit**

Run: `go run ./internal/apisurface -check; echo "exit=$?"` → `exit=0` (docs do not touch the API).

```bash
git add CLAUDE.md docs/rpsl-go-design.md CHANGELOG.md
git commit -m "docs: the API conventions, apisurface, and the v0.26.0 breaking changes"
```

---

### Task 7: Verification before merge

No code. Every command runs alone through the memory guard, and each result goes in `.superpowers/sdd/api-v0.26/`. Figures quoted later must come from these logs. `S` below is the session scratchpad; set it again in every new shell.

- [ ] **Step 1: Baseline at v0.25.0**

```bash
S=/private/tmp/claude-501/-Users-roman-DEV-rpsl/ab056397-567b-410b-b301-ce4f7be10b69/scratchpad
git worktree add "$S/rpsl-v0.25.0" v0.25.0
for r in ripe apnic; do mkdir -p "$S/rd-$r" && ln -sfn "$PWD/.data/$r" "$S/rd-$r/$r"; done
```

In the worktree, for each registry (one process each):

```bash
(cd "$S/rpsl-v0.25.0" && MEMGUARD_NORMAL_PRIORITY=1 /Users/roman/DEV/rpsl/.superpowers/sdd/tools/memguard.sh 8 3600 env GOMAXPROCS=4 GOMEMLIMIT=6GiB RPSL_REALDATA="$S/rd-ripe" go test -count=1 -v -run 'TestRealData$' ./examples/bulk-ripe/bulk) > .superpowers/sdd/api-v0.26/base-realdata-ripe.log 2>&1; echo "exit=$?"
```

Repeat with `rd-apnic` → `base-realdata-apnic.log`, and with `RPSL_REALDATA=/Users/roman/DEV/rpsl/.data go test -count=1 -v -run TestRealDataPeval ./resolve` → `base-peval.log`.
Expected: each log ends with `SUCCESS`.

- [ ] **Step 2: The same three on the branch**

The same commands from the repository root (not the worktree) → `realdata-ripe.log`, `realdata-apnic.log`, `peval.log`. Each ends with `SUCCESS`.

- [ ] **Step 3: Compare**

What to compare: `TestRealData` logs one "N objects, N policy values, …" line and one `asns=… prefixes=…` line per expanded set. `TestRealDataPeval` logs "N aut-nums sampled of N, in T:" and then one indented `  <outcome> <count>` line per outcome, up to the next `--- ` line.

```bash
cd .superpowers/sdd/api-v0.26
counts() { awk '/objects,|asns=/ {print; next} /aut-nums sampled/ {p=1} /^--- / {p=0} p' "$1" | sed -E 's/, in [0-9hms]+:/:/'; }
for f in realdata-ripe realdata-apnic peval; do
  counts base-$f.log > base-$f.counts; counts $f.log > $f.counts
  diff base-$f.counts $f.counts > $f.diff; echo "$f: diff exit $? ($(wc -l < base-$f.counts) lines compared)"
done
```

Expected: `diff exit 0` for each, with a non-zero number of lines compared (zero lines would mean the pattern matched nothing, which is not a pass). Any difference is a behaviour change: stop and root-cause it.

Check one count by hand against the dump. Take RIPE's aut-num count from `realdata-ripe.log` (the "objects" line counts all objects; for a class count use the per-family figure the log prints), and compare it with `grep -c '^aut-num:' .data/ripe/<the aut-num split file>`. Use `ls .data/ripe` to find the file, and `zcat`/`gzcat` if it is compressed. Record both numbers in `summary.log`.

Record peak RSS from each log's `memguard: peak RSS` line next to v0.25.0's (RIPE 1,049 MB in `.superpowers/sdd/release-v0.25.0/realdata-ripe.log`).

- [ ] **Step 4: Benchmarks**

`MEMGUARD_NORMAL_PRIORITY=1 .superpowers/sdd/tools/memguard.sh 8 3600 env GOMAXPROCS=4 scripts/bench.sh v0.25.0 > .superpowers/sdd/api-v0.26/bench.log 2>&1; echo "exit=$?"`
Expected: `SUCCESS`. Read the comparison. Any benchmark more than 10% slower gets explained in `summary.log` (allocation counts from `-benchmem` first) before merge.

- [ ] **Step 5: Full check with fuzzing**

`MEMGUARD_NORMAL_PRIORITY=1 .superpowers/sdd/tools/memguard.sh 8 3600 env FUZZTIME=15s GOMAXPROCS=4 GOMEMLIMIT=6GiB scripts/check.sh > .superpowers/sdd/api-v0.26/check-fuzz.log 2>&1; echo "exit=$?"`
Expected: `check: ok`, `SUCCESS`; `grep -c '^== fuzz' check-fuzz.log` → `45`.

- [ ] **Step 6: Independent review**

Dispatch a reviewer agent on `git diff main...api-v0.26` with the spec, this plan and the Review Focus list. Fix every Critical and Important finding, re-run the affected task's checks, and commit each fix separately. Judge the fixes by `git diff`, not by the agent's account.

- [ ] **Step 7: Clean up**

`git worktree remove "$S/rpsl-v0.25.0"`. Leave the logs. The PR (push, CI on both Go versions, merge) and the release (`scripts/release.sh v0.26.0`) are separate requests to the user.
