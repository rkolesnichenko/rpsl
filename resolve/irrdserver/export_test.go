package irrdserver

// LimitsWithDefaults is l with each zero field its default, for the
// external tests.
func LimitsWithDefaults(l Limits) Limits { return l.withDefaults() }

// GaveUp is closed once Shutdown's context has ended and it has cancelled
// the commands still running.
func GaveUp(s *Server) <-chan struct{} {
	s.init()
	return s.base.Done()
}
