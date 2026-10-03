package rpsld

import (
	"reflect"
	"testing"
)

func TestParseSourceSpec(t *testing.T) {
	for _, tc := range []struct {
		in, want string // want "" means an error
	}{
		{"RIPE=dump:/a/ripe.db.gz,/a/ripe.db.route.gz", "RIPE=dump:/a/ripe.db.gz,/a/ripe.db.route.gz"},
		{"radb=dump:radb.db", "RADB=dump:radb.db"},
		{"RIPE=nrtm4:https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose,key=ripe.pem",
			"RIPE=nrtm4:https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose,key=ripe.pem"},
		{"A=nrtm4:file:///srv/n.jose,key=k.pem", "A=nrtm4:file:///srv/n.jose,key=k.pem"},
		{"RIPE=nrtm4:https://x/n.jose", ""},         // no key
		{"RIPE=nrtm4:https://x/n.jose,key=", ""},    // an empty key file name
		{"RIPE=nrtm4:https://x/n.jose,key=a,b", ""}, // a key file name with a comma
		{"RIPE=nrtm4:,key=k", ""},                   // no URL
		{"RIPE=nrtm4:https:///n.jose,key=k", ""},    // no host
		{"RIPE=nrtm4:file://,key=k", ""},            // no path
		{"RIPE=dump:", ""},                          // no file
		{"RIPE=dump:a,,b", ""},                      // an empty file name
		{"RIPE=ftp:x", ""},                          // unknown kind
		{"RIPE=x", ""},                              // no kind
		{"=dump:x", ""},                             // no name
		{"RI PE=dump:x", ""},                        // not a source name
		{"RIPE", ""},                                // no "="
		{"RPKI=dump:x", ""},                         // reserved for -rpki
		{"rpki=dump:x", ""},                         // reserved, in any case
		{"RIPE=nrtm4:http://x/n.jose,key=k", ""},    // NRTMv4 is https or file
	} {
		s, err := ParseSourceSpec(tc.in)
		switch {
		case tc.want == "" && err == nil:
			t.Errorf("%q: accepted as %v", tc.in, s)
		case tc.want != "" && err != nil:
			t.Errorf("%q: %v", tc.in, err)
		case tc.want != "" && s.String() != tc.want:
			t.Errorf("%q: String %q, want %q", tc.in, s.String(), tc.want)
		}
	}
}

// FuzzSourceSpec: what ParseSourceSpec accepts, String writes back as a
// spec that parses to the same SourceSpec.
func FuzzSourceSpec(f *testing.F) {
	for _, s := range []string{"RIPE=dump:a,b", "RADB=nrtm4:https://x/y.jose,key=k.pem", "X=dump:", "=", "A=nrtm4:file:///n,key=k"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		s, err := ParseSourceSpec(in)
		if err != nil {
			return
		}
		back, err := ParseSourceSpec(s.String())
		if err != nil || !reflect.DeepEqual(back, s) {
			t.Fatalf("%q -> %q -> %v, %v", in, s.String(), back, err)
		}
	})
}
