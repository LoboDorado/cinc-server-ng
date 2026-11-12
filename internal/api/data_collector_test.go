package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// newDataCollectorTestAPI returns an API configured with WithDataCollector,
// wrapped in an httptest server, backed by a store containing org "acme".
func newDataCollectorTestAPI(t *testing.T, upstream, token string, openProxy bool, timeout time.Duration) *httptest.Server {
	t.Helper()
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	a := New(st, WithDataCollector(upstream, token, openProxy, timeout))
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestDataCollectorSignedForwardsRequest(t *testing.T) {
	var gotMethod, gotPath, gotContentType, gotToken, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotToken = r.Header.Get("X-Data-Collector-Token")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	srv := newDataCollectorTestAPI(t, upstream.URL+"/data-collector/v0", "secret-token", false, time.Second)

	req, err := http.NewRequest("POST", srv.URL+"/organizations/acme/data-collector",
		strings.NewReader(`{"message_type":"run_start"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q, want upstream response passed through", body)
	}
	if gotMethod != "POST" {
		t.Errorf("upstream method = %q, want POST", gotMethod)
	}
	if gotPath != "/data-collector/v0" {
		t.Errorf("upstream path = %q, want /data-collector/v0 (the configured URL, not joined with the incoming path)", gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("upstream Content-Type = %q, want application/json", gotContentType)
	}
	if gotToken != "secret-token" {
		t.Errorf("upstream token header = %q, want the configured token", gotToken)
	}
	if gotBody != `{"message_type":"run_start"}` {
		t.Errorf("upstream body = %q", gotBody)
	}
}

func TestDataCollectorOpenProxyForwardsVerbatim(t *testing.T) {
	var gotToken, gotCustom string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Data-Collector-Token")
		gotCustom = r.Header.Get("X-Client-Thing")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv := newDataCollectorTestAPI(t, upstream.URL+"/data-collector/v0", "server-secret", true, time.Second)

	req, err := http.NewRequest("POST", srv.URL+"/data-collector", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Data-Collector-Token", "client-own-token")
	req.Header.Set("X-Client-Thing", "hello")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotToken != "client-own-token" {
		t.Errorf("upstream token = %q, want the client's own token unchanged (the server must not inject its own)", gotToken)
	}
	if gotCustom != "hello" {
		t.Errorf("upstream custom header = %q, want it forwarded unchanged", gotCustom)
	}
}

func TestDataCollectorOpenProxyDisabledByDefault(t *testing.T) {
	srv := newDataCollectorTestAPI(t, "http://127.0.0.1:1/data-collector/v0", "", false, time.Second)
	resp, _ := do(t, "POST", srv.URL+"/data-collector", "{}")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: the open proxy route must not exist unless explicitly enabled", resp.StatusCode)
	}
}

func TestDataCollectorRoutesUnregisteredWhenURLEmpty(t *testing.T) {
	srv := newDataCollectorTestAPI(t, "", "", true, time.Second)
	for _, path := range []string{"/organizations/acme/data-collector", "/data-collector"} {
		resp, _ := do(t, "POST", srv.URL+path, "{}")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestDataCollectorUpstreamUnreachableReturns502(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing listens here now

	srv := newDataCollectorTestAPI(t, deadURL+"/data-collector/v0", "tok", false, time.Second)
	resp, body := do(t, "POST", srv.URL+"/organizations/acme/data-collector", "{}")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"error"`) {
		t.Errorf("body = %q, want a JSON error (never a bare http.Error-style body)", body)
	}
}

func TestDataCollectorUpstreamTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv := newDataCollectorTestAPI(t, upstream.URL+"/data-collector/v0", "tok", false, 20*time.Millisecond)
	resp, _ := do(t, "POST", srv.URL+"/organizations/acme/data-collector", "{}")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestDataCollectorSignedUnknownOrg(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()

	srv := newDataCollectorTestAPI(t, upstream.URL+"/data-collector/v0", "tok", false, time.Second)
	resp, _ := do(t, "POST", srv.URL+"/organizations/nosuchorg/data-collector", "{}")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// Both data-collector routes are mutating (POST) routes classifyRequest does
// not recognize, so the build-time guard in failclosed.go
// (TestEveryMutatingRouteIsAuthorized) requires a declared openWrites
// exception. This confirms the declaration is in place for the paths these
// handlers actually register, independent of whether that broader scan
// happens to construct the API with the data collector configured.
func TestDataCollectorRoutesAreDeclaredOpen(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/organizations/acme/data-collector"},
		{http.MethodPost, "/data-collector"},
	} {
		if _, ok := classifyRequest(route.method, route.path); ok {
			t.Errorf("%s %s: expected unclassified (governed by openWrites, not an ACL check), got classified", route.method, route.path)
		}
		if reason := openWriteReason(route.method, route.path); reason == "" {
			t.Errorf("%s %s: expected a declared openWrites reason", route.method, route.path)
		}
	}
}
