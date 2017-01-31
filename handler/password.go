package handler

import (
	"log"
	"net/http"
)

// passwordHandler handles all password content (i.e. the main UI).
// It assumes it can get an authenticated session from the request.
type passwordHandler struct{}

func newPassword() http.Handler {
	return &passwordHandler{}
}

func (ph passwordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		log.Printf("Could not get authenticated session in password handler")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// TODO: handle logged-in UI
	staticHandler{content: []byte("Logged in."), contentType: "text/plain; charset=utf-8"}.ServeHTTP(w, r)
}
