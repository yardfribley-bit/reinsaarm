// Package egress is a localhost forward proxy. It is the second line of defense
// when a coding-agent hook fails open and the process still makes an HTTP request.
package egress

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Decision is one proxy verdict.
type Decision struct {
	Host    string
	Allowed bool
	RuleID  string
	Reason  string
}

// Proxy checks the target host before dialing.
type Proxy struct {
	Allow      func(host string) (bool, string, string)
	OnDecision func(Decision)
	Dial       func(network, addr string) (net.Conn, error)
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r)
	allowed, rule, reason := false, "R-EGRESS-HOST", "host is not on the network allowlist"
	if p.Allow != nil {
		allowed, rule, reason = p.Allow(host)
	}
	if p.OnDecision != nil {
		p.OnDecision(Decision{Host: host, Allowed: allowed, RuleID: rule, Reason: reason})
	}
	if !allowed {
		http.Error(w, "reinsaarm: "+reason, http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r, host)
		return
	}
	p.forward(w, r)
}

func (p *Proxy) dial(network, addr string) (net.Conn, error) {
	if p.Dial != nil {
		return p.Dial(network, addr)
	}
	return net.DialTimeout(network, addr, 10*time.Second)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request, host string) {
	dest := r.Host
	if !strings.Contains(dest, ":") {
		dest = net.JoinHostPort(host, "443")
	}
	up, err := p.dial("tcp", dest)
	if err != nil {
		http.Error(w, "reinsaarm: upstream dial failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "reinsaarm: hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		_, _ = io.Copy(up, client)
		_ = up.Close()
	}()
	_, _ = io.Copy(client, up)
	_ = client.Close()
	_ = up.Close()
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	if out.URL.Host == "" {
		out.URL.Host = r.Host
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if p.Dial != nil {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.dial(network, addr)
		}
	}
	resp, err := (&http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}).Do(out)
	if err != nil {
		http.Error(w, "reinsaarm: upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func requestHost(r *http.Request) string {
	h := r.URL.Hostname()
	if h == "" {
		h = r.Host
	}
	h = strings.TrimSuffix(h, ".")
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h, "]") {
		// Host header may still include a port when URL.Hostname failed.
		if _, _, err := net.SplitHostPort(h); err == nil {
			h, _, _ = net.SplitHostPort(h)
		}
	}
	return strings.ToLower(h)
}
