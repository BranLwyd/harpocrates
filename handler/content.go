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

	// Static content handlers.
	mux.Handle("/", newFiltered("/", http.RedirectHandler("/p/", http.StatusFound)))

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

	u2fAPIHandler, err := newAsset("etc/u2f-api.js", "application/javascript")
	if err != nil {
		return nil, fmt.Errorf("could not create U2F API handler: %v", err)
	}
	mux.Handle("/u2f-api.js", u2fAPIHandler)

	// Dynamic content handlers.
	rh, err := newRegister()
	if err != nil {
		return nil, fmt.Errorf("could not create registration handler: %v", err)
	}
	rh, err = newLogin(sh, rh)
	if err != nil {
		return nil, fmt.Errorf("could not create login handler for registration: %v", err)
	}
	mux.Handle("/register", rh)

	dh, err := newLogin(sh, newDynamic())
	if err != nil {
		return nil, fmt.Errorf("could not create dynamic content handler: %v", err)
	}
	mux.Handle("/p/", dh)

	return mux, nil
}
