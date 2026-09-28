package resolve

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// PolicySource is a Source that also serves the objects routing policy names
// outside sets: aut-nums, whose import/export/default policies a policy
// evaluator reads, and inet-rtrs, which router expressions and peerings name.
// source scopes a lookup as a SetRef does: "" is the Source's precedence, and a
// registry it does not hold is ErrNotFound. Filter-sets, rtr-sets and
// peering-sets keep coming from GetSet.
type PolicySource interface {
	Source
	AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error)
	InetRtr(ctx context.Context, name, source string) (object.InetRtr, error)
}

// ErrNoPolicy is returned by a wrapper (Cache, rpki.Filter) whose inner Source
// is not a PolicySource.
var ErrNoPolicy = errors.New("resolve: source serves no policy objects")

// policyEntry is an aut-num or inet-rtr a MemSource serves: decoded when it
// was given decoded (NewMemSource, or a Corpus claimant), else its text.
type policyEntry struct {
	source string // upper-case
	obj    object.Object
	text   string
}

// decode returns the entry's object, decoding its text on each call: a
// MemSource stays immutable and shareable, and a Cache is what remembers.
// Decode diagnostics are dropped; the loader reported them.
func (e policyEntry) decode() object.Object {
	if e.obj != nil {
		return e.obj
	}
	raw, _ := rpsl.ParseObject(e.text)
	o, _ := object.Decode(raw)
	return value(o)
}

// pick returns the entry a lookup in source selects: "" the first the default
// sources admit, a registry that registry's.
func (s *MemSource) pick(entries []policyEntry, source string) (policyEntry, error) {
	if source != "" {
		src, err := types.ParseSourceName(source)
		if err != nil {
			return policyEntry{}, err
		}
		source = src
	}
	for _, e := range entries {
		if source != "" && e.source == source || source == "" && s.admits(e.source) {
			return e, nil
		}
	}
	return policyEntry{}, ErrNotFound
}

// AutNum returns the aut-num of as, from source ("" for the precedence).
func (s *MemSource) AutNum(_ context.Context, as types.ASN, source string) (object.AutNum, error) {
	e, err := s.pick(s.autnums[as], source)
	if err != nil {
		return object.AutNum{}, fmt.Errorf("resolve: aut-num %s: %w", as, err)
	}
	an, ok := e.decode().(object.AutNum)
	if !ok || an.AS != as {
		return object.AutNum{}, fmt.Errorf("resolve: aut-num %s: %w", as, ErrNotFound)
	}
	return an, nil
}

// InetRtr returns the inet-rtr named name (compared without regard to case),
// from source ("" for the precedence).
func (s *MemSource) InetRtr(_ context.Context, name, source string) (object.InetRtr, error) {
	e, err := s.pick(s.rtrs[rtrKey(name)], source)
	if err != nil {
		return object.InetRtr{}, fmt.Errorf("resolve: inet-rtr %s: %w", name, err)
	}
	ir, ok := e.decode().(object.InetRtr)
	if !ok || rtrKey(ir.Name) != rtrKey(name) {
		return object.InetRtr{}, fmt.Errorf("resolve: inet-rtr %s: %w", name, ErrNotFound)
	}
	return ir, nil
}

// rtrKey is an inet-rtr's primary key as Corpus keys it.
func rtrKey(name string) string { return strings.ToUpper(strings.TrimSpace(name)) }

// addPolicy indexes an aut-num or inet-rtr: decoded (o set) or as text (o nil,
// class and key read from Corpus's key).
func (s *MemSource) addPolicy(class, key, source string, o object.Object, text string) {
	e := policyEntry{source: strings.ToUpper(strings.TrimSpace(source)), obj: o, text: text}
	switch class {
	case "aut-num":
		if as, err := types.ParseASN(key); err == nil {
			s.autnums[as] = append(s.autnums[as], e)
		}
	case "inet-rtr":
		s.rtrs[rtrKey(key)] = append(s.rtrs[rtrKey(key)], e)
	}
}

var _ PolicySource = (*MemSource)(nil)
