package resolve

import "testing"

// TestBuildIndexOffHoldsNoNamedBy regresses a bug in buildIndex: Corpus.build
// first builds a MemSource via newMemSource, which always indexes (index:
// true), then overwrites s.autnums and calls finish (and so buildIndex)
// again with s.index set to Corpus.IndexPeers. With IndexPeers false the
// second pass must leave the MemSource holding no index at all — not just
// answering NamedBy with ErrNoIndex while namedBy itself still holds the
// first pass's map, which would be stale (it was built from only the
// whole-kept claimants, before the text-kept aut-nums a KeepPolicy corpus
// also adds were indexed).
func TestBuildIndexOffHoldsNoNamedBy(t *testing.T) {
	setX := decode(t, "as-set: AS-X\nmembers: AS99\nmbrs-by-ref: MNT-A\nmnt-by: MNT-A\nsource: RIPE\n")
	as1 := decode(t, "aut-num: AS1\nas-name: ONE\nmember-of: AS-X\nimport: from AS2 accept ANY\nmnt-by: MNT-A\nsource: RIPE\n")

	var c Corpus
	c.KeepPolicy = true // IndexPeers left false
	c.Put(setX)
	c.Put(as1) // claims membership of AS-X: kept whole, decoded

	src := c.Source()
	if src.index {
		t.Fatalf("index = true, want false (KeepPolicy without IndexPeers)")
	}
	if src.namedBy != nil {
		t.Errorf("namedBy = %v, want nil: a MemSource with index false must hold no index state", src.namedBy)
	}
}
