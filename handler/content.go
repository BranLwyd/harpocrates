// Package handler provides the HTTP handlers used by harpocrates.
package handler

import (
	"net/http"

	"../session"
)

var (
	contentStyleHandler  = must(newAsset("etc/style.css", "text/css; charset=utf-8"))
	contentRobotsHandler = must(newAsset("etc/robots.txt", "text/plain; charset=utf-8"))
	contentU2FAPIHandler = must(newAsset("etc/u2f-api.js", "application/javascript"))
)

func NewContent(sh *session.Handler) http.Handler {
	mux := http.NewServeMux()

	// Static content handlers.
	mux.Handle("/", newFiltered("/", http.RedirectHandler("/p/", http.StatusSeeOther)))
	mux.Handle("/style.css", contentStyleHandler)
	mux.Handle("/robots.txt", contentRobotsHandler)
	mux.Handle("/u2f-api.js", contentU2FAPIHandler)

	// Dynamic content handlers.
	mux.Handle("/register", newLogin(sh, newRegister()))
	mux.Handle("/p/", newLogin(sh, newPassword()))

	return mux
}
