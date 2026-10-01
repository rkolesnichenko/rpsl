package resolve

import (
	"io"
	"strings"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
)

// Loading an IRR bulk dump — RIPE's split files, an IRRd export — into a
// MemSource, so the engine can expand against a snapshot with no network at
// all. The dump is streamed one object at a time into a Corpus, which keeps
// only what the engine uses — sets and membership claimants whole, other
// routes as prefix, origin and source — so memory follows that rather than
// the file.
//
// Compression is the caller's business: wrap the reader in a gzip.Reader (or
// anything else) and pass that. Keeping it out here is what lets this file
// stay dependency-free and the core engine socket-free.

// DumpStats counts what a load saw. Diagnosed counts objects that raised at
// least one Error while decoding; they are still kept, since decoding is
// per-attribute and the rest of such an object is good.
type DumpStats struct {
	Objects   int // objects read
	Kept      int // objects the engine uses, and so retained (whole or reduced; see Corpus)
	Diagnosed int // objects that raised at least one Error
}

// DumpLoader reads one or more dumps into a single MemSource. The zero value is
// ready to use; Read may be called once per file, and Source builds the result.
type DumpLoader struct {
	// Sources is the source precedence, as NewMemSource takes it: when the same
	// set name appears in several registries, the earliest listed wins.
	Sources []string

	// KeepPolicy keeps every aut-num and inet-rtr (as Corpus.KeepPolicy does),
	// so that Source and SourceOf are PolicySources that serve them; without
	// it their AutNum and InetRtr return ErrNoPolicy. Set it before the first
	// Read.
	KeepPolicy bool

	// IndexPeers sets Corpus.IndexPeers: Source and SourceOf are PolicyIndexes
	// whose NamedBy answers. It implies KeepPolicy. Set it before the first
	// Read.
	IndexPeers bool

	// OnDiagnostics, when set, is called for every object that raised
	// diagnostics, with the object and its diagnostics. It is the hook for a
	// caller that wants to report on a dump's quality; leaving it nil keeps
	// only the counts in Stats.
	OnDiagnostics func(o *ast.Object, ds []ast.Diagnostic)

	// Stats accumulates across every Read.
	Stats DumpStats

	corpus Corpus
}

// Read streams one dump and retains the objects the engine can use: the set
// classes, route and route6, aut-num and inet-rtr. Everything else is counted
// and dropped. A read error stops the load and is returned.
func (l *DumpLoader) Read(r io.Reader) error {
	l.corpus.KeepPolicy = l.KeepPolicy
	l.corpus.IndexPeers = l.IndexPeers
	for o, ds := range rpsl.Parse(r) {
		l.Stats.Objects++
		if len(ds) > 0 {
			if worstSeverity(ds) >= ast.Error {
				l.Stats.Diagnosed++
			}
			if l.OnDiagnostics != nil {
				l.OnDiagnostics(o, ds)
			}
		}
		if err := streamError(ds); err != nil {
			return err
		}
		obj, dds := object.Decode(o)
		if len(dds) > 0 {
			if worstSeverity(dds) >= ast.Error {
				l.Stats.Diagnosed++
			}
			if l.OnDiagnostics != nil {
				l.OnDiagnostics(o, dds)
			}
		}
		if l.corpus.Put(obj) {
			l.Stats.Kept++
		}
	}
	return nil
}

// Source builds a MemSource over everything read so far. The loader may be read
// from again afterwards; a later Source includes the new objects too.
func (l *DumpLoader) Source() *MemSource {
	return l.corpus.Source(l.Sources...)
}

// SourceOf builds a MemSource whose unscoped lookups and routes see only the
// objects read so far whose source: is one of sources (compared without
// regard to case), in the precedence given: the dumps as if those registries
// alone had been loaded. An object without a source: is left out of them. A
// scoped lookup (RIPE::AS-FOO) and the claims of a set it finds see every
// source the loader holds, as bgpq4's -S list does not limit a SOURCE::
// object.
func (l *DumpLoader) SourceOf(sources ...string) *MemSource {
	return l.corpus.SourceOf(sources...)
}

// Corpus returns what the loader holds, for merging with other corpora — a
// mirror (resolve/nrtm4), RPKI pseudo routes — under one precedence. It is the
// loader's own: reading more dumps changes it.
func (l *DumpLoader) Corpus() *Corpus { return &l.corpus }

// LoadDump reads one dump into a MemSource. It is DumpLoader for the common
// case; use the loader itself to read several files, to set a source
// precedence, or to see what the dump contained.
func LoadDump(r io.Reader, sourcePrecedence ...string) (*MemSource, error) {
	l := &DumpLoader{Sources: sourcePrecedence}
	if err := l.Read(r); err != nil {
		return nil, err
	}
	return l.Source(), nil
}

// LoadDumps reads several dumps into one MemSource, in order.
func LoadDumps(rs []io.Reader, sourcePrecedence ...string) (*MemSource, error) {
	l := &DumpLoader{Sources: sourcePrecedence}
	for _, r := range rs {
		if err := l.Read(r); err != nil {
			return nil, err
		}
	}
	return l.Source(), nil
}

// Expandable reports whether the engine has any use for an object: the set
// classes it traverses, the routes it expands to, and the objects that can
// claim membership indirectly — of which a Corpus keeps what it reads.
// ExpandableClass is the same by class name.
func Expandable(o object.Object) bool {
	if _, ok := o.(object.NamedSet); ok {
		return true
	}
	switch o.(type) {
	case object.Route, object.Route6, object.AutNum, object.InetRtr:
		return true
	}
	return false
}

// expandableClasses are the class names of what Expandable accepts.
var expandableClasses = map[string]bool{
	"as-set": true, "route-set": true, "rtr-set": true, "filter-set": true, "peering-set": true,
	"route": true, "route6": true, "aut-num": true, "inet-rtr": true,
}

// ExpandableClass reports whether the engine has any use for objects of
// class (case and surrounding space do not matter): Expandable by class name,
// for skipping the others without parsing them.
func ExpandableClass(class string) bool {
	return expandableClasses[strings.ToLower(strings.TrimSpace(class))]
}

// worstSeverity returns the highest severity among ds.
func worstSeverity(ds []ast.Diagnostic) ast.Severity {
	worst := ast.Info
	for _, d := range ds {
		if d.Severity > worst {
			worst = d.Severity
		}
	}
	return worst
}

// streamError turns the stream's own read failure into an error, so a truncated
// dump is reported rather than quietly treated as a short one.
func streamError(ds []ast.Diagnostic) error {
	for _, d := range ds {
		if d.Rule == "rpsl/read-error" {
			return &DumpError{Message: d.Message}
		}
	}
	return nil
}

// DumpError reports a failure to read a dump.
type DumpError struct{ Message string }

func (e *DumpError) Error() string { return "resolve: reading dump: " + e.Message }
