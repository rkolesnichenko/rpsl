package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func newServer(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range routes {
		body := body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/rdap+json")
			w.Write([]byte(body))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, HTTP: srv.Client()}
}

func TestLookupAutnum(t *testing.T) {
	c := newServer(t, map[string]string{
		"/autnum/65001": `{"handle":"AS65001","startAutnum":65001,"endAutnum":65001,
			"name":"EXAMPLE-AS","country":"NL","status":["active"],
			"entities":[{"handle":"EX1-RIPE","roles":["registrant"]}]}`,
	})
	a, err := c.LookupAutnum(context.Background(), 65001)
	if err != nil {
		t.Fatalf("LookupAutnum: %v", err)
	}
	if a.Handle != "AS65001" || a.Name != "EXAMPLE-AS" || a.Country != "NL" {
		t.Errorf("autnum = %+v", a)
	}
	if len(a.Entities) != 1 || a.Entities[0].Handle != "EX1-RIPE" {
		t.Errorf("entities = %+v", a.Entities)
	}
}

func TestLookupIP(t *testing.T) {
	c := newServer(t, map[string]string{
		"/ip/192.0.2.0/24": `{"handle":"192.0.2.0-192.0.2.255","startAddress":"192.0.2.0",
			"endAddress":"192.0.2.255","name":"EXAMPLE-NET","country":"NL","type":"ASSIGNED"}`,
	})
	n, err := c.LookupIP(context.Background(), netip.MustParsePrefix("192.0.2.0/24"))
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if n.Name != "EXAMPLE-NET" || n.Type != "ASSIGNED" {
		t.Errorf("ipnetwork = %+v", n)
	}
}

func TestLookupNotFound(t *testing.T) {
	// Empty mux -> 404 for everything.
	c := newServer(t, map[string]string{})
	if _, err := c.LookupAutnum(context.Background(), 1); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
