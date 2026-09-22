# rpsl/lexer

`import "github.com/rkolesnichenko/rpsl/lexer"`

A hand-written, line-oriented scanner for RPSL text. It owns every lexical quirk
— value continuation (leading space/tab/`+`), inline `#` comments, object
boundaries, `\r\n`, trailing whitespace — so nothing downstream has to.

## The invariant

`Tokenize` is a **total partition** of the input: every byte belongs to exactly
one token's `Raw` field, in order. Concatenating every `Token.Raw` reproduces the
source byte-for-byte. This is the foundation of the library's lossless
round-trip guarantee.

```go
toks := lexer.Tokenize(src)

var rebuilt strings.Builder
for _, t := range toks {
	rebuilt.WriteString(t.Raw)
}
// rebuilt.String() == src
```

This snippet is copied from the runnable [`ExampleTokenize`](example_test.go)
test, so `go test` keeps it honest.

## API

```go
func Tokenize(src string) []Token
func TokenizeAt(src string, line, byteOffset int) []Token // positions in stream coordinates
func IsBlankLine[T ~string | ~[]byte](line T) bool       // the line rules, shared with rpsl.Parse
func StartsAttribute[T ~string | ~[]byte](line T) bool
func CanonicalName(name string) string                     // ASCII lower-case, spaces/tabs trimmed
```

```go
type Token struct {
	Kind     Kind      // KindAttribute | KindBlank | KindComment | KindMalformed
	Name     string    // lowercased attribute name ("" for non-attributes)
	Value    string    // comment-stripped, continuation-joined logical value
	Raw      string    // exact source bytes (for round-trip)
	Span     Span      // 1-based line/col + byte offsets
	Segments []Segment // maps Value offsets back to source positions
}

func (t Token) SourceAt(valOffset int) (line, col, byteoff int)
```

A `KindAttribute` token already carries the folded logical `Value`, while `Raw`
preserves the original (continuations and comments included). `Span` and
`Segments`/`SourceAt` let higher layers attach precise diagnostics to a position
inside a folded value.

`KindMalformed` flags a non-continuation, non-blank line with no `:` — the lexer
diagnoses rather than panics.

Most callers do not use this package directly; they use
[`rpsl.ParseObject`/`rpsl.Parse`](../README.md) or [`ast.New`](../ast/README.md),
which sit on top of `Tokenize`.

See the [root README](../README.md) and
[GoDoc](https://pkg.go.dev/github.com/rkolesnichenko/rpsl/lexer).
