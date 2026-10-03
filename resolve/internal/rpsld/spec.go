package rpsld

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// SourceSpec is one -source: a registry and where its data comes from.
type SourceSpec struct {
	Name    string   // canonical source name
	Kind    string   // "dump" or "nrtm4"
	Paths   []string // dump: the files, read in order (gzip or plain)
	URL     string   // nrtm4: the Update Notification File, https:// or file://
	KeyFile string   // nrtm4: the PEM of the key it is signed with
}

// ParseSourceSpec reads NAME=dump:FILE[,FILE…] or NAME=nrtm4:URL,key=FILE.
// A file name may not hold a comma, nor a URL one. RPKI is no -source: it is
// the registry -rpki makes.
func ParseSourceSpec(s string) (SourceSpec, error) {
	name, rest, ok := strings.Cut(s, "=")
	if !ok {
		return SourceSpec{}, errors.New(`missing "=": want NAME=dump:FILE,… or NAME=nrtm4:URL,key=FILE`)
	}
	n, err := types.ParseSourceName(name)
	if err != nil {
		return SourceSpec{}, err
	}
	if n == rpki.PseudoSource {
		return SourceSpec{}, fmt.Errorf("%s is the registry -rpki makes", n)
	}
	kind, arg, ok := strings.Cut(rest, ":")
	if !ok {
		return SourceSpec{}, fmt.Errorf("%s: missing kind (dump: or nrtm4:)", n)
	}
	spec := SourceSpec{Name: n, Kind: kind}
	switch kind {
	case "dump":
		for _, p := range strings.Split(arg, ",") {
			if p == "" {
				return SourceSpec{}, fmt.Errorf("%s: an empty dump file name", n)
			}
			spec.Paths = append(spec.Paths, p)
		}
	case "nrtm4":
		u, key, ok := strings.Cut(arg, ",key=")
		if !ok || key == "" || strings.Contains(key, ",") {
			return SourceSpec{}, fmt.Errorf("%s: want nrtm4:URL,key=FILE", n)
		}
		pu, err := url.Parse(u)
		if err != nil || strings.Contains(u, ",") ||
			!(pu.Scheme == "https" && pu.Host != "" || pu.Scheme == "file" && pu.Path != "") {
			return SourceSpec{}, fmt.Errorf("%s: %q is no https:// or file:// URL", n, u)
		}
		spec.URL, spec.KeyFile = u, key
	default:
		return SourceSpec{}, fmt.Errorf("%s: unknown kind %q (dump or nrtm4)", n, kind)
	}
	return spec, nil
}

// String writes s back as ParseSourceSpec reads it.
func (s SourceSpec) String() string {
	if s.Kind == "nrtm4" {
		return s.Name + "=nrtm4:" + s.URL + ",key=" + s.KeyFile
	}
	return s.Name + "=dump:" + strings.Join(s.Paths, ",")
}
