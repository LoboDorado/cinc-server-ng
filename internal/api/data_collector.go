package api

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// The data-collector routes reverse-proxy requests to a downstream
// data-collector service (converge history, compliance scan results, and the
// like), mirroring Chef Infra Server's data_collector['root_url']/['token']/
// ['proxy'] reverse proxy. Neither route touches the store: this package
// only forwards bytes, the same way the real server does.
//
// Two routes exist, with two different trust models:
//
//   - POST /organizations/{org}/data-collector requires a normal signed
//     request, like every other org route, and the server injects its own
//     pre-shared token when forwarding.
//   - POST /data-collector (opt-in) requires no signature at all and relays
//     the request verbatim, headers included, injecting nothing. This exists
//     because some compliance-scan reporters cannot sign a Mixlib request;
//     enabling it is a deliberate trust decision, off by default.

// dataCollectorConfig holds the per-API configuration and reverse proxies for
// the data-collector routes. The zero value disables both routes.
type dataCollectorConfig struct {
	target      *url.URL
	token       string
	openProxy   bool
	timeout     time.Duration
	proxySigned *httputil.ReverseProxy
	proxyOpen   *httputil.ReverseProxy
}

// newDataCollectorConfig builds the configuration for WithDataCollector. An
// empty or unparsable rawURL disables both routes, since this package may be
// used directly as a library where nothing validates the URL beforehand
// (server.New validates it for the standalone binary).
func newDataCollectorConfig(rawURL, token string, openProxy bool, timeout time.Duration) dataCollectorConfig {
	if rawURL == "" {
		return dataCollectorConfig{}
	}
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return dataCollectorConfig{}
	}
	rewriteTo := func(pr *httputil.ProxyRequest) {
		// Route to exactly target, discarding the incoming request's own
		// path and query: unlike a subtree proxy, every request here goes to
		// the one configured downstream URL. ProxyRequest.SetURL would
		// instead join target's path with the incoming path, which is not
		// what we want.
		dest := *target
		pr.Out.URL = &dest
		pr.Out.Host = ""
	}
	return dataCollectorConfig{
		target:    target,
		token:     token,
		openProxy: openProxy,
		timeout:   timeout,
		proxySigned: &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				rewriteTo(pr)
				if token != "" {
					pr.Out.Header.Set("X-Data-Collector-Token", token)
				}
			},
			ErrorHandler: dataCollectorUpstreamError,
		},
		proxyOpen: &httputil.ReverseProxy{
			Rewrite:      rewriteTo,
			ErrorHandler: dataCollectorUpstreamError,
		},
	}
}

// dataCollectorUpstreamError reports a downstream failure (unreachable,
// timed out) as a JSON error, per this package's convention that responses
// are always JSON — httputil.ReverseProxy's default error handler writes a
// bare "502 Bad Gateway" body instead.
func dataCollectorUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	writeError(w, http.StatusBadGateway, "data collector endpoint unreachable: "+err.Error())
}

// registerDataCollectorRoutes wires the signed, org-scoped route whenever a
// data collector URL is configured, and the unauthenticated, non-org route
// additionally when openProxy is set.
func (a *API) registerDataCollectorRoutes(mux *recordingMux) {
	if a.dataCollector.target == nil {
		return
	}
	mux.HandleFunc("POST /organizations/{org}/data-collector", a.dataCollectorSigned)
	if a.dataCollector.openProxy {
		mux.HandleFunc("POST /data-collector", a.dataCollectorOpen)
	}
}

// dataCollectorSigned forwards a signed request to the configured downstream
// data-collector service, injecting the configured token. The org is not
// otherwise used: this route carries no store lookup and no object ACL, the
// same as real Chef Infra Server.
func (a *API) dataCollectorSigned(w http.ResponseWriter, r *http.Request) {
	if a.org(w, r) == nil {
		return
	}
	a.serveDataCollectorProxy(a.dataCollector.proxySigned, w, r)
}

// dataCollectorOpen forwards an unsigned request verbatim to the configured
// downstream data-collector service. Only reachable when openProxy is set:
// registerDataCollectorRoutes does not register this route otherwise.
func (a *API) dataCollectorOpen(w http.ResponseWriter, r *http.Request) {
	a.serveDataCollectorProxy(a.dataCollector.proxyOpen, w, r)
}

// serveDataCollectorProxy bounds the forwarded request to the configured
// timeout before handing it to proxy.
func (a *API) serveDataCollectorProxy(proxy *httputil.ReverseProxy, w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), a.dataCollector.timeout)
	defer cancel()
	proxy.ServeHTTP(w, r.WithContext(ctx))
}
