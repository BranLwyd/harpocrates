// Package handler provides the HTTP handlers used by harpocrates.
package handler

import (
	"fmt"
	"net/http"

	"../session"
)

const (
	sessionCookieName = "harp-sid"
)

func NewContent(sh *session.Handler) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.Handle("/", newFiltered("/", http.RedirectHandler("/p/", http.StatusFound)))

	// Static content handlers.
	styleHandler, err := newAsset("etc/style.css", "text/css; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create style handler: %v", err)
	}
	mux.Handle("/style.css", styleHandler)

	robotsHandler, err := newAsset("etc/robots.txt", "text/plain; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create robots handler: %v", err)
	}
	mux.Handle("/robots.txt", robotsHandler)

	// Dynamic content handler.
	dh, err := newDynamic(sh)
	if err != nil {
		return nil, fmt.Errorf("could not create dynamic content handler: %v", err)
	}
	mux.Handle("/p/", dh)

	return mux, nil
}
