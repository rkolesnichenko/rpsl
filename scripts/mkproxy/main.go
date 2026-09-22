// Command mkproxy publishes modules of a git repository to a file-system Go
// module proxy, the way the Go proxy would serve them at a tag: a module's zip
// holds the committed files of its directory, minus nested modules, plus the
// repository's LICENSE when the module has none. scripts/release-dryrun.sh uses
// it to rehearse a release without publishing anything.
//
//	mkproxy -repo DIR -out PROXYDIR -version v0.1.0 lexer types
//
// Each argument is a module directory relative to the repository root ("." for
// the root module). The repository must be a git work tree: only files git
// tracks are published, as only they would be at a tag.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	repo := flag.String("repo", ".", "git work tree holding the modules")
	out := flag.String("out", "", "proxy directory to write (GOPROXY=file://DIR)")
	version := flag.String("version", "", "version to publish, e.g. v0.1.0")
	flag.Parse()
	if *out == "" || *version == "" || flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	files, err := tracked(*repo)
	if err != nil {
		fail(err)
	}
	for _, dir := range flag.Args() {
		if err := publish(*repo, files, path.Clean(dir), *version, *out); err != nil {
			fail(fmt.Errorf("%s: %w", dir, err))
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mkproxy:", err)
	os.Exit(1)
}

// tracked returns the files git tracks in repo, slash-separated and relative to
// its root.
func tracked(repo string) ([]string, error) {
	cmd := exec.Command("git", "-C", repo, "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// publish writes dir's module at version into the proxy directory out.
func publish(repo string, files []string, dir, version, out string) error {
	gomod, err := os.ReadFile(filepath.Join(repo, dir, "go.mod"))
	if err != nil {
		return err
	}
	modPath := modulePath(gomod)
	if modPath == "" {
		return fmt.Errorf("no module line in go.mod")
	}
	// Module roots other than dir: their files belong to their own modules.
	var nested []string
	for _, f := range files {
		if d := path.Dir(f); path.Base(f) == "go.mod" && d != dir && within(d, dir) {
			nested = append(nested, d)
		}
	}
	var members []string
	haveLicense := false
	for _, f := range files {
		if !within(f, dir) || f == dir {
			continue
		}
		skip := false
		for _, n := range nested {
			skip = skip || within(f, n)
		}
		if skip {
			continue
		}
		rel := strings.TrimPrefix(f, dir+"/")
		if dir == "." {
			rel = f
		}
		haveLicense = haveLicense || rel == "LICENSE"
		members = append(members, rel)
	}
	sort.Strings(members)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) error {
		w, err := zw.Create(modPath + "@" + version + "/" + name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	for _, rel := range members {
		data, err := os.ReadFile(filepath.Join(repo, dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if err := add(rel, data); err != nil {
			return err
		}
	}
	if !haveLicense && dir != "." {
		// The Go command adds the repository's LICENSE to a nested module
		// that has none (cmd/go/internal/modfetch/coderepo.go).
		if data, err := os.ReadFile(filepath.Join(repo, "LICENSE")); err == nil {
			if err := add("LICENSE", data); err != nil {
				return err
			}
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}

	vdir := filepath.Join(out, escape(modPath), "@v")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		return err
	}
	info, _ := json.Marshal(struct {
		Version string
		Time    time.Time
	}{version, time.Now().UTC().Truncate(time.Second)})
	for name, data := range map[string][]byte{
		version + ".zip":  buf.Bytes(),
		version + ".mod":  gomod,
		version + ".info": info,
	} {
		if err := os.WriteFile(filepath.Join(vdir, name), data, 0o644); err != nil {
			return err
		}
	}
	list, _ := os.ReadFile(filepath.Join(vdir, "list"))
	if !strings.Contains("\n"+string(list), "\n"+version+"\n") {
		list = append(list, version+"\n"...)
	}
	fmt.Printf("published %s@%s (%d files)\n", modPath, version, len(members))
	return os.WriteFile(filepath.Join(vdir, "list"), list, 0o644)
}

// within reports whether the slash path f is dir or inside it.
func within(f, dir string) bool {
	return dir == "." || f == dir || strings.HasPrefix(f, dir+"/")
}

// modulePath returns the path on go.mod's module line.
func modulePath(gomod []byte) string {
	for _, line := range strings.Split(string(gomod), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module"); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}

// escape applies the module proxy's case encoding: each upper-case letter
// becomes '!' and its lower-case form.
func escape(p string) string {
	var b strings.Builder
	for _, r := range p {
		if 'A' <= r && r <= 'Z' {
			b.WriteByte('!')
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}
