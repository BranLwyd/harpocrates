package handler

import (
	"log"
	"net/http"
)

// dynamicHandler handles all dynamic password content.
// It assumes it can get an authenticated session from the request.
type dynamicHandler struct{}

func newDynamic() http.Handler {
	return &dynamicHandler{}
}

func (dh dynamicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		log.Printf("Could not get authenticated session in password handler")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// TODO: handle logged-in UI
	staticHandler{content: "Logged in.", contentType: "text/plain; charset=utf-8"}.ServeHTTP(w, r)
}
