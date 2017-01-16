package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"../static"
)

func contentHandler() (http.Handler, error) {
	mux := http.NewServeMux()

	// Serve static content.
	styleHandler, err := assetHandler("etc/style.css", "text/css; charset=utf-8")
	if err != nil {
		return nil, err
	}
	mux.Handle("/style.css", styleHandler)

	mux.Handle("/", staticHandler{content: "Hello, world!\n", contentType: "text/plain; charset=utf-8"})

	return mux, nil
}

type loggingHandler struct {
	h       http.Handler
	logName string
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

func NewLoggingHandler(logName string, h http.Handler) http.Handler {
	return loggingHandler{
		h:       h,
		logName: logName,
	}
}

type staticHandler struct {
	content     string
	contentType string
	modTime     time.Time
}

func (sh staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", sh.contentType)
	http.ServeContent(w, r, "", sh.modTime, strings.NewReader(sh.content))
}

func assetHandler(name, contentType string) (*staticHandler, error) {
	assetBytes, err := static.Asset(name)
	if err != nil {
		return nil, fmt.Errorf("could not get asset %q: %v", name, err)
	}
	assetInfo, err := static.AssetInfo(name)
	if err != nil {
		return nil, fmt.Errorf("could not get asset info for %q: %v", name, err)
	}
	return &staticHandler{
		content:     string(assetBytes),
		contentType: contentType,
		modTime:     assetInfo.ModTime(),
	}, nil
}
