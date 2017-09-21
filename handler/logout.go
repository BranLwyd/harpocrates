package handler

import (
	"log"
	"net/http"
)

// logoutHandler handles requests to log out.
type logoutHandler struct{}

func newLogout() *logoutHandler {
	return &logoutHandler{}
}

func (lh logoutHandler) authPath(r *http.Request) (string, error) {
	return authAny, nil
}

func (lh logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		log.Print("Could not get authenticated session in password handler")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	sess.Close()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
