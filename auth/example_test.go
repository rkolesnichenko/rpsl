package auth_test

import (
	"context"
	"fmt"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/auth"
	"github.com/rkolesnichenko/rpsl/object"
)

// plainPasswords is a Verifier for the example: it accepts the password
// "secret" for any CRYPT-PW line. A real one checks the hash; see Verifier.
type plainPasswords struct{}

func (plainPasswords) Verify(_ context.Context, a object.Auth, cred auth.Credential) (bool, error) {
	if a.Method != object.AuthCrypt {
		return false, auth.ErrUnsupportedMethod
	}
	return cred.Password == "secret", nil
}

func decoded(text string) object.Object {
	raw, _ := rpsl.ParseObject(text)
	o, _ := rpsl.Decode(raw)
	return o
}

// Creating a route in the RIPE Database needs the route's own maintainer and
// the covering address space's consent: here its mnt-routes:.
func ExampleRules_Authorise() {
	db := auth.NewMemDatabase([]object.Object{
		decoded("mntner: MNT-LIR\nauth: CRYPT-PW xxxxxx\nmnt-by: MNT-LIR\nsource: RIPE\n"),
		decoded("inetnum: 192.0.2.0 - 192.0.2.255\nnetname: EXAMPLE\n" +
			"mnt-routes: MNT-LIR\nmnt-by: MNT-LIR\nsource: RIPE\n"),
	})
	route := decoded("route: 192.0.2.0/24\norigin: AS64500\nmnt-by: MNT-LIR\nsource: RIPE\n")

	d, err := auth.RIPE.Authorise(context.Background(), db,
		auth.Update{Action: auth.Create, Object: route}, auth.Credential{Password: "secret"}, plainPasswords{})
	if err != nil {
		panic(err)
	}
	fmt.Println(d.OK)
	for _, r := range d.Reasons {
		fmt.Println(r)
	}
	// Output:
	// true
	// the object's own maintainers ([MNT-LIR]): authorised: MNT-LIR: credential accepted
	// the parent inetnum 192.0.2.0 - 192.0.2.255 ([MNT-LIR]): authorised: MNT-LIR: credential accepted
}
