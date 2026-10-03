package rpsld

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/backend"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/nrtm4"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
)

// dumpStats counts what loadDump read.
type dumpStats struct {
	objects int // objects in the files
	other   int // left out: their source: is not the registry's
}

// loadDump reads spec's files into a registry of serial. A registry holds
// its own source alone (irrdq.NewRegistry), so an object of any other
// source is left out, and counted. It stops when ctx ends.
func loadDump(ctx context.Context, spec SourceSpec, keepText bool, serial uint64) (*irrdq.Registry, dumpStats, error) {
	c := &resolve.Corpus{KeepPolicy: true, KeepRouteText: keepText}
	var st dumpStats
	for _, p := range spec.Paths {
		err := backend.ReadInput(p, func(r io.Reader) error {
			for o, ds := range rpsl.Parse(r) {
				if err := ctx.Err(); err != nil {
					return err
				}
				for _, d := range ds {
					if d.Rule == "rpsl/read-error" { // the stream's end is no dump's end
						return errors.New(d.Message)
					}
				}
				if o == nil {
					continue
				}
				st.objects++
				if a, ok := o.GetFirst("source"); !ok || strings.ToUpper(strings.TrimSpace(a.Value)) != spec.Name {
					st.other++
					continue
				}
				obj, _ := object.Decode(o)
				c.Put(obj)
			}
			return nil
		})
		if err != nil {
			return nil, st, err
		}
	}
	r, err := irrdq.NewRegistry(spec.Name, serial, c)
	return r, st, err
}

// mtimes is the modification times of spec's files, for change detection.
func mtimes(spec SourceSpec) ([]time.Time, error) {
	var out []time.Time
	for _, p := range spec.Paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		out = append(out, fi.ModTime())
	}
	return out, nil
}

// keyPath is where -state-dir keeps the key of the mirror name.
func keyPath(stateDir, name string) string { return filepath.Join(stateDir, name+".pem") }

// newMirror is spec's NRTMv4 client, its key the one saved in stateDir when
// there is one, so that a rotation while rpsld was down still verifies.
func newMirror(spec SourceSpec, keepText bool, stateDir string, hc *http.Client) (*nrtm4.Client, string, error) {
	keyFile := spec.KeyFile
	if stateDir != "" {
		if _, err := os.Stat(keyPath(stateDir, spec.Name)); err == nil {
			keyFile = keyPath(stateDir, spec.Name)
		}
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, "", err
	}
	return &nrtm4.Client{URL: spec.URL, Database: spec.Name, PublicKey: string(key), HTTP: hc,
		MaxAge: 24 * time.Hour, KeepPolicy: true, KeepRouteText: keepText}, keyFile, nil
}

// mirrorRegistry is the mirror's current version as a registry. A mirror
// holds its own database's objects alone: nrtm4 discards any other (§9.2).
func mirrorRegistry(c *nrtm4.Client, name string, keepText bool) (*irrdq.Registry, error) {
	corpus := &resolve.Corpus{KeepPolicy: true, KeepRouteText: keepText}
	c.CopyTo(corpus)
	return irrdq.NewRegistry(name, uint64(c.Status().Version), corpus)
}

// saveKey writes key to stateDir/<name>.pem, by way of a temporary file, so
// that a crash never leaves a part of a key behind for the next start.
func saveKey(stateDir, name, key string) error {
	f, err := os.CreateTemp(stateDir, name+".pem.*")
	if err != nil {
		return err
	}
	_, err = f.WriteString(key)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0o600)
	}
	if err == nil {
		err = os.Rename(f.Name(), keyPath(stateDir, name))
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// loadVRPs reads VRPs from a file or an https:// URL, then applies SLURM.
func loadVRPs(ctx context.Context, src, slurm string, hc *http.Client) (*rpki.VRPs, error) {
	var v *rpki.VRPs
	read := func(r io.Reader) (err error) { v, err = rpki.ReadJSON(r); return }
	if strings.HasPrefix(src, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", src, resp.Status)
		}
		if err := read(resp.Body); err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
	} else if err := backend.ReadInput(src, read); err != nil {
		return nil, err
	}
	if slurm != "" {
		err := backend.ReadInput(slurm, func(r io.Reader) (err error) { v, err = v.ApplySLURM(r); return })
		if err != nil {
			return nil, err
		}
	}
	return v, nil
}

// rpkiRegistry is IRRd's pseudo route objects for v, as a registry.
func rpkiRegistry(v *rpki.VRPs, serial uint64) (*irrdq.Registry, error) {
	var b strings.Builder
	if err := v.WriteRPSL(&b); err != nil {
		return nil, err
	}
	l := &resolve.DumpLoader{KeepPolicy: true, KeepRouteText: true}
	if err := l.Read(strings.NewReader(b.String())); err != nil {
		return nil, err
	}
	return irrdq.NewRegistry(rpki.PseudoSource, serial, l.Corpus())
}
