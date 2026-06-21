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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// Client is an RDAP HTTP client rooted at a bootstrap or registry base URL
// (e.g. "https://rdap.db.ripe.net"). A nil HTTP installs a default client with
// a safe redirect policy that refuses non-https and private/loopback hosts.
//
// Defensive defaults: the BaseURL scheme must be https (set AllowInsecure to
// opt into http for testing/internal use); response bodies are read through
// an io.LimitReader bounded by MaxResponse (default 8 MiB; well above any
// real registration record).
type Client struct {
	BaseURL       string
	HTTP          *http.Client
	MaxResponse   int64 // per-call body cap; 0 = default (defaultMaxResponse)
	AllowInsecure bool  // permit http:// BaseURLs and http redirects
}

// defaultMaxResponse caps an RDAP response body. Real autnum/ip records are
// well under 100 KiB; 8 MiB is the order-of-magnitude safety margin for
// pathologically large but plausibly legitimate responses, while bounding the
// allocation a hostile server can force.
const defaultMaxResponse = 8 << 20

func (c *Client) maxResponse() int64 {
	if c.MaxResponse > 0 {
		return c.MaxResponse
	}
	return defaultMaxResponse
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

// ErrInsecure is returned when an http:// URL is used without AllowInsecure.
var ErrInsecure = errors.New("rdap: insecure (non-https) URL refused; set AllowInsecure to opt in")

// ErrForbiddenHost is returned for a request or redirect to a private,
// loopback, or link-local address — a defense-in-depth guard against SSRF via
// a hostile registry referral.
var ErrForbiddenHost = errors.New("rdap: target host is private/loopback/link-local")

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
	if err := c.validateURL(c.BaseURL + path); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json")
	hc := c.HTTP
	if hc == nil {
		hc = c.defaultHTTP()
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
	max := c.maxResponse()
	// Read max+1 so a body that exactly fills the budget is accepted but one
	// byte beyond is rejected (vs. silently truncated, which json.Decoder would
	// surface as a parse error and hide the real cause).
	body := io.LimitReader(resp.Body, max+1)
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(data)) > max {
		return fmt.Errorf("rdap: response exceeds %d bytes", max)
	}
	return json.Unmarshal(data, dst)
}

// validateURL refuses an URL whose scheme is not https (unless AllowInsecure)
// or whose host resolves to an IP literal in a private/loopback/link-local
// range (unless AllowInsecure — the same opt-in that admits http:// also
// admits local/internal targets, since both express "I know what I'm doing").
// Hostnames are admitted as-is — DNS-time-of-check/use is a separate concern
// handled at the transport layer.
func (c *Client) validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("rdap: invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "https" && !c.AllowInsecure {
		return ErrInsecure
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("rdap: unsupported URL scheme %q", u.Scheme)
	}
	if c.AllowInsecure {
		return nil
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil && isForbiddenAddr(ip) {
		return ErrForbiddenHost
	}
	return nil
}

// defaultHTTP builds the fallback http.Client used when c.HTTP is nil. The
// CheckRedirect hook applies validateURL to every redirect target so a hostile
// registry referral cannot drag the caller into a private address or a scheme
// downgrade.
func (c *Client) defaultHTTP() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("rdap: too many redirects")
			}
			return c.validateURL(req.URL.String())
		},
	}
}

// isForbiddenAddr reports whether ip belongs to a range a public RDAP server
// has no legitimate reason to point at: loopback, link-local, private
// (RFC1918/RFC4193), or the unspecified address.
func isForbiddenAddr(ip netip.Addr) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// IsPrivate covers 10/8, 172.16/12, 192.168/16, fc00::/7. Add 100.64/10
	// (CGNAT) explicitly — Go does not classify it as private.
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return true
		}
	}
	return false
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
