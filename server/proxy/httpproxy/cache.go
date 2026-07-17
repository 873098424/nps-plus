package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"

	"github.com/djylb/nps/lib/cache"
	"github.com/djylb/nps/lib/logs"
)

// ctxParentTransport is a context key used to pass the per-host *http.Transport
// to CachingTransport, avoiding a shared mutable parent field with races.
type ctxKeyTransport struct{}

var ctxParentTransport = ctxKeyTransport(struct{}{})

// cacheableExts is the whitelist of file extensions allowed to be cached.
// Only static resources such as CSS/JS/images/fonts are cached.
var cacheableExts = map[string]struct{}{
	".css":   {},
	".js":    {},
	".mjs":   {},
	".png":   {},
	".jpg":   {},
	".jpeg":  {},
	".gif":   {},
	".webp":  {},
	".svg":   {},
	".ico":   {},
	".bmp":   {},
	".woff":  {},
	".woff2": {},
	".ttf":   {},
	".otf":   {},
	".eot":   {},
}

// isCacheablePath reports whether the URL path points to a cacheable static file
// based on its extension whitelist.
func isCacheablePath(urlPath string) bool {
	ext := strings.ToLower(path.Ext(urlPath))
	if ext == "" {
		return false
	}
	_, ok := cacheableExts[ext]
	return ok
}

// cacheEntry holds a serialized HTTP response for static file caching.
type cacheEntry struct {
	raw    []byte // DumpResponse serialized bytes (headers + body)
	status int    // HTTP status code
}

// CachingTransport wraps per-request parent transports with LRU-based
// response caching for GET requests to static files (URL path contains ".").
// The parent transport is NOT stored on the struct; instead it is read from
// the request context (key ctxParentTransport).  This is safe for concurrent
// use across many host/transport pairs.
type CachingTransport struct {
	lru      *cache.Cache
	useCache bool
}

// NewCachingTransport creates a CachingTransport.
// If maxEntries <= 0, caching is disabled and all requests fall through to parent.
func NewCachingTransport(maxEntries int) *CachingTransport {
	ct := &CachingTransport{
		useCache: maxEntries > 0,
	}
	if ct.useCache {
		ct.lru = cache.New(maxEntries)
	}
	return ct
}

// ParentFromContext returns the *http.Transport stored in ctx.
// It is used by CachingTransport.RoundTrip to find the real transport.
func ParentFromContext(ctx context.Context) *http.Transport {
	t, _ := ctx.Value(ctxParentTransport).(*http.Transport)
	return t
}

// ContextWithParent returns a child context with the parent transport attached.
func ContextWithParent(ctx context.Context, t *http.Transport) context.Context {
	return context.WithValue(ctx, ctxParentTransport, t)
}

// UseCache reports whether caching is enabled.
func (ct *CachingTransport) UseCache() bool { return ct.useCache }

// Invalidate removes a cached entry by path.
func (ct *CachingTransport) Invalidate(path string) {
	if ct.useCache {
		ct.lru.Remove(path)
	}
}

// Clear purges all cached entries.
func (ct *CachingTransport) Clear() {
	if ct.useCache {
		ct.lru.Clear()
	}
}

// RoundTrip implements http.RoundTripper.
// For cacheable GET requests, it checks the LRU cache first;
// on cache miss it delegates to the parent transport (from request context) and caches the result.
func (ct *CachingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only cache GET requests for whitelisted static file extensions (css/js/images/fonts).
	canCache := ct.useCache &&
		req.Method == http.MethodGet &&
		isCacheablePath(req.URL.Path)

	// Cache lookup.
	if canCache {
		if val, ok := ct.lru.Get(req.URL.Path); ok {
			entry := val.(*cacheEntry)
			logs.Trace("http cache hit: %s %s", req.Host, req.URL.Path)
			return entryToResponse(req, entry), nil
		}
	}

	// Cache miss — real request via per-host parent transport from context.
	parent := ParentFromContext(req.Context())
	if parent == nil {
		// Fallback: should not happen, but use default transport to avoid panic.
		parent = http.DefaultTransport.(*http.Transport)
	}
	resp, err := parent.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	// Store in cache (only successful responses).
	if canCache && resp.StatusCode >= 200 && resp.StatusCode < 400 {
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return resp, nil
		}

		// Rebuild body for the current caller.
		resp.Body = io.NopCloser(bytes.NewReader(body))

		// Serialize the full response for caching.
		dumped, dumpErr := httputil.DumpResponse(
			&http.Response{
				Status:     resp.Status,
				StatusCode: resp.StatusCode,
				Proto:      resp.Proto,
				ProtoMajor: resp.ProtoMajor,
				ProtoMinor: resp.ProtoMinor,
				Header:     resp.Header.Clone(),
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, true,
		)
		if dumpErr == nil {
			ct.lru.Add(req.URL.Path, &cacheEntry{
				raw:    dumped,
				status: resp.StatusCode,
			})
			logs.Trace("http cache store: %s %s", req.Host, req.URL.Path)
		}
	}

	return resp, nil
}

// entryToResponse reconstructs an *http.Response from a cached entry.
func entryToResponse(req *http.Request, entry *cacheEntry) *http.Response {
	buf := bytes.NewReader(entry.raw)
	resp, err := http.ReadResponse(bufio.NewReader(buf), req)
	if err != nil {
		// Fallback: minimal response so the caller gets something.
		return &http.Response{
			Status:        http.StatusText(entry.status),
			StatusCode:    entry.status,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader(entry.raw)),
			ContentLength: int64(len(entry.raw)),
			Request:       req,
		}
	}
	resp.Request = req
	return resp
}
