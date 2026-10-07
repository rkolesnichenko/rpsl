package good

import "errors"

var ErrNotFound = errors.New("good: not found")

// Errors starts with "Err" but is not a sentinel: no capital follows.
var Errors = []string{"not a sentinel"}

func ParseThing(s string) (int, error) { return 0, nil }

// Lookup's bool is comma-ok for a miss, which rule 2 allows outside Parse*.
func Lookup(k string) (int, bool) { return 0, false }
