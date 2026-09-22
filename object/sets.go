package object

import "github.com/rkolesnichenko/rpsl/types"

// Set is the common interface over the set classes (as-set, route-set) that the
// resolution engine traverses. The methods are named to avoid clashing with the
// concrete types' exported fields.
type Set interface {
	Object
	SetName() types.SetName  // the set's own name
	SetMembers() []SetMember // direct members: members: plus mp-members:
	RefMntners() []string    // mbrs-by-ref: maintainers enabling indirect membership
	SetSource() string       // source: the registry the set belongs to ("" if absent)
}

// SetName returns the set's name.
func (s AsSet) SetName() types.SetName { return s.Name }

// SetMembers returns the union of members: and mp-members: as a fresh slice so
// callers cannot mutate the underlying fields.
func (s AsSet) SetMembers() []SetMember {
	out := make([]SetMember, 0, len(s.Members)+len(s.MpMembers))
	out = append(out, s.Members...)
	out = append(out, s.MpMembers...)
	return out
}

// RefMntners returns the mbrs-by-ref maintainers.
func (s AsSet) RefMntners() []string { return s.MbrsByRef }

// SetSource returns the set's source: attribute.
func (s AsSet) SetSource() string { return s.Source }

// SetName returns the set's name.
func (s RouteSet) SetName() types.SetName { return s.Name }

// SetMembers returns the union of members: and mp-members: as a fresh slice so
// callers cannot mutate the underlying fields.
func (s RouteSet) SetMembers() []SetMember {
	out := make([]SetMember, 0, len(s.Members)+len(s.MpMembers))
	out = append(out, s.Members...)
	out = append(out, s.MpMembers...)
	return out
}

// RefMntners returns the mbrs-by-ref maintainers.
func (s RouteSet) RefMntners() []string { return s.MbrsByRef }

// SetSource returns the set's source: attribute.
func (s RouteSet) SetSource() string { return s.Source }

// Compile-time checks that the set classes satisfy Set.
var (
	_ Set = AsSet{}
	_ Set = RouteSet{}
)
