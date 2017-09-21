// Package handler provides the HTTP handlers used by harpocrates.
package handler

import (
	"net/http"

	"../session"
)

var (
	contentStyleHandler           = must(newCacheableAsset("etc/style.css", "text/css; charset=utf-8"))
	contentRobotsHandler          = must(newCacheableAsset("etc/robots.txt", "text/plain; charset=utf-8"))
	contentFaviconHandler         = must(newCacheableAsset("etc/favicon.ico", "image/x-icon"))
	contentU2FAPIHandler          = must(newCacheableAsset("etc/u2f-api.js", "application/javascript"))
	contentU2FAuthenticateHandler = must(newCacheableAsset("etc/u2f-authenticate.js", "application/javascript"))
	contentU2FRegisterHandler     = must(newCacheableAsset("etc/u2f-register.js", "application/javascript"))
	contentEntryViewHandler       = must(newCacheableAsset("etc/entry-view.js", "application/javascript"))
	contentFontAwesomeHandler     = must(newCacheableAsset("etc/font-awesome.otf", "application/font-sfnt"))
)

func NewContent(sh *session.Handler) http.Handler {
	mux := http.NewServeMux()

	// Static content handlers.
	mux.Handle("/style.css", contentStyleHandler)
	mux.Handle("/robots.txt", contentRobotsHandler)
	mux.Handle("/favicon.ico", contentFaviconHandler)
	mux.Handle("/u2f-api.js", contentU2FAPIHandler)
	mux.Handle("/u2f-authenticate.js", contentU2FAuthenticateHandler)
	mux.Handle("/u2f-register.js", contentU2FRegisterHandler)
	mux.Handle("/entry-view.js", contentEntryViewHandler)
	mux.Handle("/font-awesome.otf", contentFontAwesomeHandler)

	// Dynamic content handlers.
	mux.Handle("/logout", newAuth(sh, newLogout()))
	mux.Handle("/register", newAuth(sh, newRegister()))
	mux.Handle("/s", newAuth(sh, newSearch()))
	mux.Handle("/", newAuth(sh, newPassword()))

	return mux
}
