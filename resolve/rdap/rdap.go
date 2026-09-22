// Package rdap is a thin RDAP (RFC 9082/9083) registration-lookup client for
// autonomous systems and IP networks.
//
// Scope note: RDAP has no object class for IRR policy sets (as-set/route-set)
// and does not expose origin→route mappings, so it cannot drive set expansion.
// It is therefore a standalone registration-metadata client, NOT a substitute
// for the IRRd or WHOIS resolve.Source backends.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rkolesnichenko/rpsl/types"
)

// Client is an RDAP HTTP client rooted at a bootstrap or registry base URL
// (e.g. "https://rdap.db.ripe.net").
//
// With a nil HTTP, a built-in client is used whose dialer refuses private,
// loopback, link-local and other special-purpose addresses at connect time —
// so hostnames and numeric forms that resolve to them (localhost, 127.1, DNS
// rebinding) are caught — and whose redirect policy refuses non-https targets.
// It does not use HTTP proxies. A caller-supplied HTTP client is used as given:
// only the URL check applies, so guard its dialer yourself.
//
// Defensive defaults: the BaseURL scheme must be https (set AllowInsecure to
// opt into http and internal targets for testing/internal use); response bodies
// are bounded by MaxResponse (default 8 MiB; well above any real registration
// record); and each request is bounded by Timeout (default DefaultTimeout), so
// a server that never answers cannot block a lookup forever. A Client is safe
// for concurrent use; like http.Transport, it must not be copied or have its
// fields changed after first use.
type Client struct {
	BaseURL       string
	HTTP          *http.Client
	MaxResponse   int64         // per-call body cap; 0 = default (defaultMaxResponse)
	AllowInsecure bool          // permit http:// BaseURLs, http redirects, and internal targets
	UserAgent     string        // User-Agent header; "" = "rpsl-go"
	Timeout       time.Duration // per-request deadline; 0 = DefaultTimeout, < 0 = none (ctx only)

	once        sync.Once
	builtinHTTP *http.Client
}

// defaultMaxResponse caps an RDAP response body. Real autnum/ip records are
// well under 100 KiB; 8 MiB is the order-of-magnitude safety margin for
// pathologically large but plausibly legitimate responses, while bounding the
// allocation a hostile server can force.
const defaultMaxResponse = 8 << 20

// DefaultTimeout is the per-request deadline used when Client.Timeout is zero,
// matching the irrd and whois backends.
const DefaultTimeout = 60 * time.Second

func (c *Client) timeout() time.Duration {
	switch {
	case c.Timeout == 0:
		return DefaultTimeout
	case c.Timeout < 0:
		return 0
	}
	return c.Timeout
}

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
	Handle      string    `json:"handle"`
	StartAutnum types.ASN `json:"startAutnum"`
	EndAutnum   types.ASN `json:"endAutnum"`
	Name        string    `json:"name"`
	Country     string    `json:"country"`
	Status      []string  `json:"status"`
	Entities    []Entity  `json:"entities"`
}

// IPNetwork is the parsed subset of an RDAP ip network response.
type IPNetwork struct {
	Handle       string     `json:"handle"`
	StartAddress netip.Addr `json:"startAddress"`
	EndAddress   netip.Addr `json:"endAddress"`
	Name         string     `json:"name"`
	Country      string     `json:"country"`
	Type         string     `json:"type"`
	Status       []string   `json:"status"`
	Entities     []Entity   `json:"entities"`
}

// RateLimitedError is returned, as a *RateLimitedError, for a 429 response.
// RetryAfter is the server's
// Retry-After hint (0 when absent or unparseable, at most maxRetryAfter);
// retry policy is the caller's.
type RateLimitedError struct{ RetryAfter time.Duration }

// Error implements error.
func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("rdap: rate limited (retry after %v)", e.RetryAfter)
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
// An invalid prefix is an error, and no request is made.
func (c *Client) LookupIP(ctx context.Context, prefix netip.Prefix) (*IPNetwork, error) {
	if !prefix.IsValid() {
		return nil, errors.New("rdap: invalid prefix")
	}
	var out IPNetwork
	if err := c.get(ctx, "/ip/"+prefix.Masked().String(), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) get(ctx context.Context, path string, dst any) error {
	target := strings.TrimRight(c.BaseURL, "/") + path
	if err := c.validateURL(target); err != nil {
		return err
	}
	if t := c.timeout(); t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json")
	ua := c.UserAgent
	if ua == "" {
		ua = "rpsl-go"
	}
	req.Header.Set("User-Agent", ua)
	hc := c.HTTP
	if hc == nil {
		hc = c.defaultHTTP()
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain (a bounded amount of) any unread body so the keep-alive
		// connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return &RateLimitedError{RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
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

// retryAfter parses a Retry-After header: delay-seconds or an HTTP-date.
func retryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if secs, err := strconv.ParseUint(v, 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		if err != nil || secs > uint64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// maxRetryAfter caps a Retry-After hint; servers ask for seconds or minutes, and
// a larger value would overflow time.Duration into a negative wait.
const maxRetryAfter = 24 * time.Hour

// defaultHTTP returns the built-in client used when c.HTTP is nil, created once
// so connections are reused. Its dialer applies guardDial (unless
// AllowInsecure) to the address actually dialed, and its CheckRedirect applies
// validateURL to every redirect target, so a hostile registry referral cannot
// reach an internal address or downgrade the scheme.
func (c *Client) defaultHTTP() *http.Client {
	c.once.Do(func() {
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		if !c.AllowInsecure {
			dialer.Control = guardDial
		}
		c.builtinHTTP = &http.Client{
			Transport: &http.Transport{
				DialContext:         dialer.DialContext,
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: 10 * time.Second,
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConns:        16,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("rdap: too many redirects")
				}
				return c.validateURL(req.URL.String())
			},
		}
	})
	return c.builtinHTTP
}

// guardDial is a net.Dialer Control hook refusing a connection to a forbidden
// address. It sees the resolved IP, so it also catches hostnames and numeric
// forms (localhost, 127.1, 2130706433) and DNS rebinding.
func guardDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable address %q", ErrForbiddenHost, address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: unparseable address %q", ErrForbiddenHost, address)
	}
	if isForbiddenAddr(ip) {
		return fmt.Errorf("%w: %s", ErrForbiddenHost, ip)
	}
	return nil
}

// forbiddenPrefixes are special-purpose ranges beyond what netip classifies:
// "this network", CGNAT, IETF protocol assignments, benchmarking, reserved
// (incl. broadcast), deprecated site-local IPv6, and the IPv6 forms that carry
// or tunnel to an IPv4 address — NAT64, IPv4-compatible, 6to4 and Teredo — so
// none can reach an internal IPv4 host.
var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// isForbiddenAddr reports whether ip belongs to a range a public RDAP server
// has no legitimate reason to point at: loopback, link-local, private
// (RFC1918/RFC4193), unspecified, multicast, or forbiddenPrefixes. An
// IPv4-mapped IPv6 address is checked as the IPv4 address it carries.
func isForbiddenAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, p := range forbiddenPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
