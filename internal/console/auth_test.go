package console

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoopbackRequestSkipsToken(t *testing.T) {
	srv := authServer(t, "127.0.0.1:8787")

	// A loopback peer needs no token, including a stale or wrong one.
	for _, remote := range []string{
		"127.0.0.1:40000",
		"127.0.0.2:40000",
		"[::1]:40000",
		"[::ffff:127.0.0.1]:40000",
	} {
		rec := authGet(srv, remote, "/")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s without token: %d", remote, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "实时流") {
			t.Fatalf("%s: page was not served", remote)
		}
	}
	rec := authGet(srv, "127.0.0.1:40000", "/?token=not-the-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback with a stale token: %d", rec.Code)
	}

	// A non-loopback peer is denied until it presents the token.
	rec = authGet(srv, "192.0.2.10:40000", "/")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-loopback without token: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "missing or invalid token") {
		t.Fatal("non-loopback denial did not explain the missing token")
	}
	rec = authGet(srv, "192.0.2.10:40000", "/?token=not-the-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-loopback with a wrong token: %d", rec.Code)
	}

	// X-Forwarded-For must not turn a remote client into a loopback client.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.8:40000"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	fwd := httptest.NewRecorder()
	srv.Handler().ServeHTTP(fwd, req)
	if fwd.Code != http.StatusUnauthorized {
		t.Fatalf("forwarded header treated as loopback: %d", fwd.Code)
	}

	// The same non-loopback peer is allowed with the valid token, on a route
	// that exists. The cookie set by that request also authorizes the next one.
	rec = authGet(srv, "192.0.2.10:40000", "/api/health?token="+srv.Token())
	if rec.Code != http.StatusOK {
		t.Fatalf("non-loopback with token: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"items"`) {
		t.Fatal("non-loopback token request did not reach /api/health")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "reinsaarm_token" || cookies[0].Value != srv.Token() {
		t.Fatal("valid token did not set the console cookie")
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:40001"
	req.AddCookie(cookies[0])
	page := httptest.NewRecorder()
	srv.Handler().ServeHTTP(page, req)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "实时流") {
		t.Fatalf("non-loopback cookie: %d", page.Code)
	}

	// An empty peer address is not loopback.
	rec = authGet(srv, "", "/")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty remote: %d", rec.Code)
	}
}

func TestNonLoopbackBindStillRequiresToken(t *testing.T) {
	if _, err := New(Config{Addr: "0.0.0.0:8787", Token: "tok"}); err == nil {
		t.Fatal("non-loopback bind should fail")
	}
	// New rejects the bind today. If a later change allowed it, a loopback
	// peer of that listener must still present the token.
	srv := authServer(t, "127.0.0.1:8787")
	srv.cfg.Addr = "0.0.0.0:8787"

	rec := authGet(srv, "127.0.0.1:40000", "/")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wildcard bind, loopback peer, no token: %d", rec.Code)
	}
	rec = authGet(srv, "127.0.0.1:40000", "/?token="+srv.Token())
	if rec.Code != http.StatusOK {
		t.Fatalf("wildcard bind, loopback peer, valid token: %d", rec.Code)
	}

	u := srv.OpenURL(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 8787})
	if !strings.Contains(u, "token=") || !strings.Contains(u, srv.Token()) {
		t.Fatal("non-loopback open URL must still carry the token")
	}
}

func TestLiveLoopbackBareURL(t *testing.T) {
	srv := authServer(t, "127.0.0.1:0")
	ln, err := srv.Listen()
	if err != nil {
		t.Fatal(err)
	}
	u := srv.OpenURL(ln.Addr())
	ln.Close()
	if strings.Contains(u, "token=") || !strings.HasPrefix(u, "http://127.0.0.1:") || !strings.HasSuffix(u, "/") {
		t.Fatal("loopback open URL must be the bare listener URL")
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	res, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("live loopback without token: %d", res.StatusCode)
	}
	if !strings.Contains(string(body), "实时流") {
		t.Fatal("live loopback response was not the console page")
	}
	if len(res.Cookies()) != 0 {
		t.Fatal("bare loopback response set a cookie")
	}

	res, err = http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"items"`) {
		t.Fatalf("live loopback /api/health: %d", res.StatusCode)
	}
}

func TestLiveIPv6LoopbackBareURL(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 loopback unavailable: %v", err)
	}
	srv := authServer(t, "[::1]:0")
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Listener = ln
	ts.Start()
	defer ts.Close()

	res, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("live ::1 without token: %d", res.StatusCode)
	}
	u := srv.OpenURL(ln.Addr())
	if strings.Contains(u, "token=") || !strings.HasPrefix(u, "http://[::1]:") {
		t.Fatal("ipv6 loopback open URL must be bare")
	}
}

func authServer(t *testing.T, addr string) *Server {
	t.Helper()
	srv, err := New(Config{Addr: addr, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func authGet(srv *Server, remote, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}
