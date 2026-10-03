package irrdserver

// LimitsWithDefaults is l with each zero field its default, for the
// external tests.
func LimitsWithDefaults(l Limits) Limits { return l.withDefaults() }
