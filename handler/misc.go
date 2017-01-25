package handler

import (
	"fmt"
	"log"
	"net/http"
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
	content     string
	contentType string
}

func newStatic(content, contentType string) *staticHandler {
	return &staticHandler{
		content:     content,
		contentType: contentType,
	}
}

func newAsset(name, contentType string) (*staticHandler, error) {
	assetBytes, err := static.Asset(name)
	if err != nil {
		return nil, fmt.Errorf("could not get asset %q: %v", name, err)
	}
	return &staticHandler{
		content:     string(assetBytes),
		contentType: contentType,
	}, nil
}

func (sh staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", sh.contentType)
	http.ServeContent(w, r, "", time.Time{}, strings.NewReader(sh.content))
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
	if r.RequestURI != fh.allowedPath {
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
	// Strip port from remote address, as the client port is not useful information.
	ra := r.RemoteAddr
	idx := strings.LastIndex(ra, ":")
	if idx != -1 {
		ra = ra[:idx]
	}
	log.Printf("[%s] %s requested %s", lh.logName, ra, r.RequestURI)
	lh.h.ServeHTTP(w, r)
}
