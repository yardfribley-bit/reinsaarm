package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProxyAllowAndDeny(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	var denied []string
	proxy := &Proxy{
		Allow: func(host string) (bool, string, string) {
			if host == "evil.example" || strings.HasPrefix(host, "evil.") {
				return false, "R-EGRESS-HOST", "blocked"
			}
			return true, "R-DEFAULT-ALLOW", "ok"
		},
		OnDecision: func(d Decision) {
			if !d.Allowed {
				denied = append(denied, d.Host)
			}
		},
	}
	ps := httptest.NewServer(proxy)
	defer ps.Close()
	pu, _ := url.Parse(ps.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("allow status %d body %s", resp.StatusCode, body)
	}

	resp, err = client.Get("http://evil.example/steal")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("deny status %d", resp.StatusCode)
	}
	if len(denied) != 1 || denied[0] != "evil.example" {
		t.Fatalf("denied %#v", denied)
	}
}
