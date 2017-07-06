package handler

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	"../static"
)

func must(h http.Handler, err error) http.Handler {
	if err != nil {
		panic(err)
	}
	return h
}

// staticHandler serves static content from memory.
type staticHandler struct {
	content     []byte
	contentType string
	modTime     time.Time
}

func newStatic(content []byte, contentType string) *staticHandler {
	return &staticHandler{
		content:     content,
		contentType: contentType,
	}
}

func newAsset(name, contentType string) (*staticHandler, error) {
	asset, err := static.Asset(name)
	if err != nil {
		return nil, fmt.Errorf("could not get asset %q: %v", name, err)
	}
	return newStatic(asset, contentType), nil
}

func newCacheableAsset(name, contentType string) (*staticHandler, error) {
	asset, err := static.Asset(name)
	if err != nil {
		return nil, fmt.Errorf("could not get asset %q: %v", name, err)
	}
	fi, err := static.AssetInfo(name)
	if err != nil {
		return nil, fmt.Errorf("could not get asset %q info: %v", name, err)
	}
	return &staticHandler{
		content:     asset,
		contentType: contentType,
		modTime:     fi.ModTime(),
	}, nil
}

func (sh staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", sh.contentType)
	http.ServeContent(w, r, "", sh.modTime, bytes.NewReader(sh.content))
}

// secureHeaderHandler adds a few security-oriented headers.
type secureHeaderHandler struct {
	h http.Handler
}

func (shh secureHeaderHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	shh.h.ServeHTTP(w, r)
}

func NewSecureHeader(h http.Handler) http.Handler {
	return secureHeaderHandler{h}
}

// filteredHandler filters a handler to only serve one path; anything else is given a 404.
type filteredHandler struct {
	allowedPath string
	h           http.Handler
}

func newFiltered(allowedPath string, h http.Handler) http.Handler {
	return &filteredHandler{
		allowedPath: allowedPath,
		h:           h,
	}
}

func (fh filteredHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if path.Clean(r.URL.Path) != fh.allowedPath {
		http.NotFound(w, r)
	} else {
		fh.h.ServeHTTP(w, r)
	}
}

// loggingHandler is a wrapping handler that logs the IP of the requestor and the path of the request.
type loggingHandler struct {
	h       http.Handler
	logName string
}

func NewLogging(logName string, h http.Handler) http.Handler {
	return loggingHandler{
		h:       h,
		logName: logName,
	}
}

func (lh loggingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s requested %s", lh.logName, clientIP(r), r.URL.RequestURI())
	lh.h.ServeHTTP(w, r)
}

func clientIP(r *http.Request) string {
	// Strip port from remote address.
	ra := r.RemoteAddr
	idx := strings.LastIndex(ra, ":")
	if idx != -1 {
		ra = ra[:idx]
	}
	return ra
}
