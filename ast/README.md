# rpsl/ast

`import "github.com/rkolesnichenko/rpsl/ast"`

The generic, lossless RPSL object model. An `Object` is an *ordered* list of
`Attribute`s that can represent any RPSL class — including ones the typed
[`object`](../object) layer does not know about. `String()` reproduces the
source byte-for-byte, which is what makes the library usable for editing objects,
not just reading them.

Ordering is significant in RPSL (the sequence of `import:` lines encodes
precedence), so attributes are stored as a slice, never a map; `GetAll` preserves
document order.

## API

```go
func New(toks []lexer.Token) *Object   // build from a lexer token stream

func (o *Object) Class() string                       // first attribute name
func (o *Object) Key() string                         // first attribute value
func (o *Object) GetFirst(name string) (Attribute, bool)
func (o *Object) GetAll(name string) []Attribute      // case-insensitive, in order
func (o *Object) Has(name string) bool
func (o *Object) String() string                      // lossless re-serialization
func (o *Object) Append(name, value string)           // editing support
func (o *Object) Set(name string, values ...string)
```

```go
type Attribute struct {
	Name    string     // canonical lowercase
	Value   string     // logical (comment-stripped, continuation-joined)
	Raw     string     // exact source bytes
	Comment string     // inline comment on the name line, if any
	Span    lexer.Span
	// ...
}
```

## Read, edit, re-serialize

```go
obj := ast.New(lexer.Tokenize(src))

descr, ok := obj.GetFirst("descr")     // read
obj.Append("remarks", "added by tool") // edit
fmt.Print(obj.String())                // re-serialize (original attrs unchanged byte-for-byte)
```

## Diagnostics

`Diagnostic` and `Severity` (`Info`/`Warning`/`Error`) live here so the lower
layers can emit them without importing the [`rpsl`](../README.md) façade — which
re-exports both as aliases.

```go
type Diagnostic struct {
	Severity Severity
	Message  string
	Span     lexer.Span
	Rule     string // machine-filterable, e.g. "lexer/malformed-line"
}
```

See the [root README](../README.md) and
[GoDoc](https://pkg.go.dev/github.com/rkolesnichenko/rpsl/ast).
