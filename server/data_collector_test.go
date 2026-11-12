package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doSigned executes req and returns its status code and body.
func doSigned(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// The signed, org-scoped data-collector route requires a real Mixlib
// signature like every other org route, but — per real Chef Infra Server —
// carries no object ACL: any authenticated org member may use it, not just
// an admin. Assert the baseline denial (no signature at all) before the
// low-privilege actor succeeds, per CLAUDE.md's guidance for authorization
// tests: a passing exploit proves nothing if the setup was already broken.
func TestDataCollectorSignedRouteAnyActorAllowed(t *testing.T) {
	var gotToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Data-Collector-Token")
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	srv := startServer(t, Options{
		Orgs:               []string{"acme"},
		EnforceACL:         true,
		DataCollectorURL:   upstream.URL + "/data-collector/v0",
		DataCollectorToken: "server-secret",
	})
	url := srv.URL() + "/organizations/acme/data-collector"

	// Baseline: an unsigned request is rejected before anything else.
	unsigned, err := http.NewRequest("POST", url, strings.NewReader(`{"message_type":"run_start"}`))
	if err != nil {
		t.Fatal(err)
	}
	if code := statusOf(t, unsigned); code != http.StatusUnauthorized {
		t.Fatalf("unsigned request = %d, want 401", code)
	}

	// The org's validator key is a real client with no special grants — the
	// same actor a bootstrapping node registers with, not an administrator.
	validatorKey := srv.ValidatorKey("acme")
	req := signedAs(t, "acme-validator", validatorKey, "POST", url, `{"message_type":"run_start"}`)
	code, _ := doSigned(t, req)
	if code != http.StatusCreated {
		t.Fatalf("signed request from a low-privilege actor = %d, want 201 (forwarded from upstream)", code)
	}
	if gotToken != "server-secret" {
		t.Errorf("upstream saw token %q, want the configured server secret", gotToken)
	}
}

// The unauthenticated open-proxy route must actually bypass signature
// verification end to end (not just at the API layer, which never sees
// authentication): this is what server/auth.go's exemption is for.
func TestDataCollectorOpenProxyBypassesSignatureVerification(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv := startServer(t, Options{
		Orgs:                   []string{"acme"},
		EnforceACL:             true,
		DataCollectorURL:       upstream.URL + "/data-collector/v0",
		DataCollectorOpenProxy: true,
	})

	// Entirely unsigned: no X-Ops-* headers, no Authorization header at all.
	req, err := http.NewRequest("POST", srv.URL()+"/data-collector", strings.NewReader(`{"report":"inspec"}`))
	if err != nil {
		t.Fatal(err)
	}
	code, _ := doSigned(t, req)
	if code != http.StatusOK {
		t.Fatalf("unsigned request to the open proxy = %d, want 200", code)
	}
	if !hit {
		t.Fatal("the downstream data-collector service never received the request")
	}
}

// When DataCollectorOpenProxy is left at its default (off), the unauthenticated
// route must not exist. A *signed* request still has to clear authentication
// before routing decides there is no such route (authMiddleware wraps the
// whole handler), so this signs as the admin to isolate "route not
// registered" (404) from "unsigned" (401, covered by the baseline check in
// TestDataCollectorSignedRouteAnyActorAllowed).
func TestDataCollectorOpenProxyOffByDefault(t *testing.T) {
	srv := startServer(t, Options{
		Orgs:             []string{"acme"},
		EnforceACL:       true,
		DataCollectorURL: "http://127.0.0.1:1/data-collector/v0",
	})
	req := signed(t, srv, "POST", srv.URL()+"/data-collector", "{}")
	if code := statusOf(t, req); code != http.StatusNotFound {
		t.Fatalf("open proxy route with DataCollectorOpenProxy unset = %d, want 404", code)
	}
}
