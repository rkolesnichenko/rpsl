package irrdserver

import "time"

// LimitsWithDefaults is l with each zero field its default, for the
// external tests.
func LimitsWithDefaults(l Limits) Limits { return l.withDefaults() }

// GaveUp is closed once Shutdown's context has ended and it has cancelled
// the commands still running.
func GaveUp(s *Server) <-chan struct{} {
	s.init()
	return s.base.Done()
}

// CommandName is commandName, for the external tests.
var CommandName = commandName

// SetRefusedLogEvery sets how often, at most, s logs refused connections;
// before its first Serve.
func SetRefusedLogEvery(s *Server, d time.Duration) { s.refused.every = d }
