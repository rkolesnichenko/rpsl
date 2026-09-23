package auth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
)

// irtRegistry is an IrtRegistry over decoded irt objects.
type irtRegistry map[string]object.Irt

func newIrtRegistry(t *testing.T, srcs ...string) irtRegistry {
	t.Helper()
	r := irtRegistry{}
	for _, src := range srcs {
		irt, ok := decode(t, src).(object.Irt)
		if !ok {
			t.Fatalf("not an irt: %q", src)
		}
		r[strings.ToUpper(irt.Name)] = irt
	}
	return r
}

func (r irtRegistry) Irt(_ context.Context, name string) (object.Irt, error) {
	irt, ok := r[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return object.Irt{}, ErrNoIrt
	}
	return irt, nil
}

// failingIrts is an IrtRegistry whose every lookup fails.
type failingIrts struct{ err error }

func (f failingIrts) Irt(context.Context, string) (object.Irt, error) { return object.Irt{}, f.err }

func irt(name, auth string) string {
	return "irt: " + name + "\naddress: Somewhere\ne-mail: irt@example.net\nauth: " + auth + "\nsource: RIPE\n"
}

func inetnum(mntIrt ...string) string {
	src := "inetnum: 192.0.2.0 - 192.0.2.255\nnetname: EXAMPLE\n"
	for _, m := range mntIrt {
		src += "mnt-irt: " + m + "\n"
	}
	return src + "source: RIPE\n"
}

func TestAddedMntIrt(t *testing.T) {
	obj := func(src string) object.Object { return decode(t, src) }
	for _, c := range []struct {
		name          string
		before, after object.Object
		want          []string
	}{
		{"a creation adds every reference", nil, obj(inetnum("IRT-A", "IRT-B")), []string{"IRT-A", "IRT-B"}},
		{"a modification adds only the new ones", obj(inetnum("IRT-A")), obj(inetnum("IRT-A", "IRT-B")), []string{"IRT-B"}},
		{"a change of case adds nothing", obj(inetnum("irt-a")), obj(inetnum("IRT-A")), nil},
		{"a removal adds nothing", obj(inetnum("IRT-A", "IRT-B")), obj(inetnum("IRT-A")), nil},
		{"duplicates count once, as first written", nil, obj(inetnum("Irt-A", "IRT-A")), []string{"Irt-A"}},
		{"inet6num carries references too", nil, obj("inet6num: 2001:db8::/32\nnetname: EXAMPLE\nmnt-irt: IRT-A\nsource: RIPE\n"), []string{"IRT-A"}},
		{"other classes carry none", nil, obj(mntner("MNT-A", "MD5-PW $1$abc$xyz")), nil},
	} {
		if got := AddedMntIrt(c.before, c.after); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: AddedMntIrt = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCheckIrt(t *testing.T) {
	ctx, v := context.Background(), verifier()
	good := decode(t, irt("IRT-A", "MD5-PW $1$abc$xyz")).(object.Irt)
	if ok, unsup, err := CheckIrt(ctx, good, goodCred(), v); err != nil || !ok || unsup {
		t.Errorf("CheckIrt = %v, %v, %v; want true, false, nil", ok, unsup, err)
	}
	if ok, _, err := CheckIrt(ctx, good, wrongCred(), v); err != nil || ok {
		t.Error("a wrong password was accepted")
	}
	pgp := decode(t, irt("IRT-P", "PGPKEY-1234ABCD")).(object.Irt)
	if ok, unsup, err := CheckIrt(ctx, pgp, goodCred(), v); err != nil || ok || !unsup {
		t.Errorf("CheckIrt = %v, %v, %v; want false, true, nil", ok, unsup, err)
	}
	if ok, unsup, err := CheckIrt(ctx, good, goodCred(), nil); err != nil || ok || !unsup {
		t.Errorf("a nil Verifier accepted something: %v, %v, %v", ok, unsup, err)
	}
	boom := errors.New("hsm offline")
	if _, _, err := CheckIrt(ctx, good, goodCred(), erroring{boom}); !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}

func TestCheckIrts(t *testing.T) {
	reg := newIrtRegistry(t, irt("IRT-A", "MD5-PW $1$abc$xyz"), irt("IRT-P", "PGPKEY-1234ABCD"))
	ctx, v := context.Background(), verifier()
	d, err := CheckIrts(ctx, reg, []string{"IRT-GONE", "IRT-P", "IRT-A"}, goodCred(), v)
	if err != nil || !d.OK {
		t.Fatalf("CheckIrts = %v, %v; want authorised", d, err)
	}
	for _, want := range []string{"IRT-GONE: no such irt", "IRT-P: no verifier", "IRT-A: credential accepted"} {
		if !strings.Contains(d.String(), want) {
			t.Errorf("reasons %q lack %q", d.String(), want)
		}
	}
	if d, _ := CheckIrts(ctx, reg, []string{"IRT-A"}, wrongCred(), v); d.OK || !strings.Contains(d.String(), "rejected") {
		t.Errorf("CheckIrts = %v, want a rejection", d)
	}
	if d, _ := CheckIrts(ctx, reg, []string{"IRT-GONE"}, goodCred(), v); d.OK {
		t.Errorf("CheckIrts = %v: an irt the registry lacks authorised something", d)
	}
	boom := errors.New("registry down")
	if _, err := CheckIrts(ctx, failingIrts{boom}, []string{"IRT-A"}, goodCred(), v); !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
	hsm := errors.New("hsm offline")
	if _, err := CheckIrts(ctx, reg, []string{"IRT-A"}, goodCred(), erroring{hsm}); !errors.Is(err, hsm) {
		t.Errorf("a verifier error: err = %v, want %v", err, hsm)
	}
}

// MntIrtChange follows RIPE's MntIrtAuthentication (whois-update, strategy
// package): only added references need an irt's authorisation, and the
// credential of any one added irt is enough.
func TestMntIrtChange(t *testing.T) {
	reg := newIrtRegistry(t, irt("IRT-A", "MD5-PW $1$abc$xyz"), irt("IRT-B", "MD5-PW $1$other$xyz"))
	ctx, v := context.Background(), verifier()
	obj := func(src string) object.Object { return decode(t, src) }
	for _, c := range []struct {
		name          string
		before, after object.Object
		cred          Credential
		ok            bool
		reason        string
	}{
		{"nothing added passes", obj(inetnum("IRT-A")), obj(inetnum("IRT-A")), wrongCred(), true, "no mnt-irt: reference is added"},
		{"the added irt's credential passes", nil, obj(inetnum("IRT-A")), goodCred(), true, "IRT-A: credential accepted"},
		{"a wrong credential is refused", nil, obj(inetnum("IRT-A")), wrongCred(), false, "IRT-A: credential rejected"},
		{"one of two added irts is enough (RIPE)", nil, obj(inetnum("IRT-B", "IRT-A")), goodCred(), true, "IRT-A: credential accepted"},
		{"an existing reference is not re-authorised", obj(inetnum("IRT-A", "IRT-B")), obj(inetnum("IRT-B")), wrongCred(), true, "no mnt-irt: reference is added"},
		{"an added irt the registry lacks is refused", obj(inetnum("IRT-A")), obj(inetnum("IRT-A", "IRT-GONE")), goodCred(), false, "IRT-GONE: no such irt"},
	} {
		d, err := MntIrtChange(ctx, reg, c.before, c.after, c.cred, v)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if d.OK != c.ok || !strings.Contains(d.String(), c.reason) {
			t.Errorf("%s: %s; want OK=%v with %q", c.name, d, c.ok, c.reason)
		}
	}
}
