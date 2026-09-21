package resolve

import (
	"context"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
)

// When the same set exists in several sources, the source precedence decides
// which one is used (like IRRd's !s); without precedence the first loaded wins.
func TestMemSourcePrecedence(t *testing.T) {
	ripe := decode(t, "as-set: AS-A\nmembers: AS1\nsource: RIPE\n")
	radb := decode(t, "as-set: AS-A\nmembers: AS666\nsource: RADB\n")
	other := decode(t, "as-set: AS-A\nmembers: AS9\nsource: OTHER\n")
	cases := []struct {
		name string
		objs []object.Object
		prec []string
		want []uint32
	}{
		{"first loaded wins", []object.Object{ripe, radb}, nil, []uint32{1}},
		{"first loaded wins (reversed)", []object.Object{radb, ripe}, nil, []uint32{666}},
		{"RIPE before RADB", []object.Object{radb, ripe}, []string{"RIPE", "RADB"}, []uint32{1}},
		{"RADB before RIPE", []object.Object{ripe, radb}, []string{"radb", "ripe"}, []uint32{666}}, // case-insensitive
		{"unlisted sources rank last", []object.Object{other, ripe}, []string{"RIPE"}, []uint32{1}},
	}
	for _, c := range cases {
		src := NewMemSource(c.objs, c.prec...)
		got, err := (&Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, "AS-A"))
		if err != nil || !reflect.DeepEqual(asnList(got), c.want) {
			t.Errorf("%s: ExpandAS = %v, %v; want %v", c.name, asnList(got), err, c.want)
		}
	}
}
