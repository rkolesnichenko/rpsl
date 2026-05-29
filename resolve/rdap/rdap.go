// Package rdap is a thin RDAP (RFC 9082/9083) registration-lookup client for
// autonomous systems and IP networks.
//
// Scope note: RDAP has no object class for IRR policy sets (as-set/route-set)
// and does not expose origin→route mappings, so it cannot drive set expansion.
// It is therefore a standalone registration-metadata client, NOT a substitute
// for the IRRd or WHOIS resolve.Source backends. A no-op Source adapter
// (SetSource) is provided so it can sit in a composite chain without
// contributing expansion data.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// Client is an RDAP HTTP client rooted at a bootstrap or registry base URL
// (e.g. "https://rdap.db.ripe.net"). A nil HTTP uses http.DefaultClient.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// Entity is an RDAP entity (registrant, admin/tech contact, …).
type Entity struct {
	Handle string   `json:"handle"`
	Roles  []string `json:"roles"`
}

// Autnum is the parsed subset of an RDAP autnum response.
type Autnum struct {
	Handle      string   `json:"handle"`
	StartAutnum uint32   `json:"startAutnum"`
	EndAutnum   uint32   `json:"endAutnum"`
	Name        string   `json:"name"`
	Country     string   `json:"country"`
	Status      []string `json:"status"`
	Entities    []Entity `json:"entities"`
}

// IPNetwork is the parsed subset of an RDAP ip network response.
type IPNetwork struct {
	Handle       string   `json:"handle"`
	StartAddress string   `json:"startAddress"`
	EndAddress   string   `json:"endAddress"`
	Name         string   `json:"name"`
	Country      string   `json:"country"`
	Type         string   `json:"type"`
	Status       []string `json:"status"`
	Entities     []Entity `json:"entities"`
}

// ErrNotFound is returned for a 404 RDAP response.
var ErrNotFound = fmt.Errorf("rdap: object not found")

// LookupAutnum fetches registration data for an AS via GET {BaseURL}/autnum/{n}.
func (c *Client) LookupAutnum(ctx context.Context, as types.ASN) (*Autnum, error) {
	var out Autnum
	if err := c.get(ctx, fmt.Sprintf("/autnum/%d", uint32(as)), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LookupIP fetches registration data for a prefix via GET {BaseURL}/ip/{cidr}.
func (c *Client) LookupIP(ctx context.Context, prefix netip.Prefix) (*IPNetwork, error) {
	var out IPNetwork
	if err := c.get(ctx, "/ip/"+prefix.String(), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rdap: unexpected status %s for %s", resp.Status, path)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// SetSource adapts a Client to resolve.Source for composition in a multi-source
// chain. RDAP serves no expansion data, so every method is empty: GetSet returns
// resolve.ErrNotFound and the others return nothing.
type SetSource struct{ Client *Client }

var _ resolve.Source = SetSource{}

func (SetSource) GetSet(context.Context, types.SetName) (object.Set, error) {
	return nil, resolve.ErrNotFound
}

func (SetSource) OriginatedRoutes(context.Context, types.ASN, types.AFI) ([]netip.Prefix, error) {
	return nil, nil
}

func (SetSource) MembersByRef(context.Context, types.SetName, []string) ([]object.Object, error) {
	return nil, nil
}
