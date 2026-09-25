# IRRd's RPSL classes

`rpsl_objects.py` is IRRd's definition of the RPSL classes it accepts, verbatim
from [irrdnet/irrd](https://github.com/irrdnet/irrd) at tag **v4.5.3**
(`irrd/rpsl/rpsl_objects.py`, blob `f2d760f48b59ba0b1377cc7b9c0c15f8a5d64d42`).
IRRd is BSD-2-Clause licensed.

Each class lists its attributes as `("name", Field(...))`: a field without
`optional=True` is mandatory, and one without `multiple=True` may appear once.
`object.IRRd` transcribes these tables; `TestIRRdProfileMatchesSource` keeps the
two in step, and `TestIRRdSourceIsCurrent` (`RPSL_LIVE=1`) compares this file
with IRRd's latest release.
