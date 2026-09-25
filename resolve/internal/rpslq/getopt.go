package rpslq

import (
	"fmt"
	"strings"
)

// A command line is read the way bgpq4 reads it, with getopt: short options
// bundle (-6Ab), an option's argument may follow it in the same word
// (-lNAME) or be the next one, and, as glibc's getopt does, options may come
// after the objects. "--" ends the options. rpslq's own options, which bgpq4
// does not have, are long: --whois, --dump FILE.

// opt is one option read from the command line, in the order given.
type opt struct {
	name string // a single letter, or a long name without its dashes
	arg  string
}

// shortArgs is bgpq4's getopt string with the arguments marked, and rpslq's
// -P and -c: the options that take an argument are followed by ':'.
const shortArgs = "23467a:AbBdDEeF:S:jJKf:l:L:m:M:NnpW:r:R:G:H:tTh:UuwXsvzPc:"

// longArgs are rpslq's long options and whether each takes an argument.
var longArgs = map[string]bool{
	"whois": false, "dump": true, "ranges": false, "timeout": true, "help": false, "server-expand": false,
}

// usageError is a command line that cannot be read.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return &usageError{fmt.Sprintf(format, args...)} }

// getopt splits args into options and operands (the objects, EXCEPT and what
// follows it).
func getopt(args []string) (opts []opt, operands []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return opts, append(operands, args[i+1:]...), nil
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := strings.Cut(a[2:], "=")
			takes, ok := longArgs[name]
			switch {
			case !ok:
				return nil, nil, usagef("unknown option --%s", name)
			case takes && !hasVal:
				if i+1 == len(args) {
					return nil, nil, usagef("option --%s needs an argument", name)
				}
				i++
				val = args[i]
			case !takes && hasVal:
				return nil, nil, usagef("option --%s takes no argument", name)
			}
			opts = append(opts, opt{name, val})
		case len(a) > 1 && a[0] == '-':
			if h := longHint(a); h != "" {
				return nil, nil, usagef("%s is not an option%s", a, h)
			}
			for j := 1; j < len(a); j++ {
				c := a[j]
				k := strings.IndexByte(shortArgs, c)
				if c == ':' || k < 0 {
					return nil, nil, usagef("unknown option -%c", c)
				}
				if k+1 < len(shortArgs) && shortArgs[k+1] == ':' {
					val := a[j+1:]
					if val == "" {
						if i+1 == len(args) {
							return nil, nil, usagef("option -%c needs an argument", c)
						}
						i++
						val = args[i]
					}
					opts = append(opts, opt{string(c), val})
					break
				}
				opts = append(opts, opt{string(c), ""})
			}
		default:
			operands = append(operands, a)
		}
	}
	return opts, operands, nil
}

// longHint points a user of rpslq's former single-dash long options at their
// new spelling. Read as getopt reads it, "-whois" is -w -h ois: without the
// hint it would quietly query a server named "ois".
func longHint(word string) string {
	for name := range longArgs {
		if word == "-"+name {
			return fmt.Sprintf(" (rpslq's own options are long now: --%s)", name)
		}
	}
	return ""
}
