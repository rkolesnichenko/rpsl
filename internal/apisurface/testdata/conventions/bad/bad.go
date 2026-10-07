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
