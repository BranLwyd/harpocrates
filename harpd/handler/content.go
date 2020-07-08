// Package handler provides the HTTP handlers used by harpocrates.
package handler

import (
	"net/http"

	"github.com/BranLwyd/harpocrates/harpd/session"
)

var (
	contentStyleHandler           = must(newCacheableAsset("harpd/assets/etc/style.css", "text/css; charset=utf-8"))
	contentRobotsHandler          = must(newCacheableAsset("harpd/assets/etc/robots.txt", "text/plain; charset=utf-8"))
	contentFaviconHandler         = must(newCacheableAsset("harpd/assets/etc/favicon.ico", "image/x-icon"))
	contentMFAAPIHandler          = must(newCacheableAsset("harpd/assets/etc/mfa-api.js", "application/javascript"))
	contentMFAAuthenticateHandler = must(newCacheableAsset("harpd/assets/etc/mfa-authenticate.js", "application/javascript"))
	contentMFARegisterHandler     = must(newCacheableAsset("harpd/assets/etc/mfa-register.js", "application/javascript"))
	contentEntryViewHandler       = must(newCacheableAsset("harpd/assets/etc/entry-view.js", "application/javascript"))
	contentFontAwesomeHandler     = must(newCacheableAsset("harpd/assets/etc/font-awesome.otf", "application/font-sfnt"))
)

func NewContent(sh *session.Handler) http.Handler {
	mux := http.NewServeMux()

	// Static content handlers.
	mux.Handle("/style.css", contentStyleHandler)
	mux.Handle("/robots.txt", contentRobotsHandler)
	mux.Handle("/favicon.ico", contentFaviconHandler)
	mux.Handle("/mfa-api.js", contentMFAAPIHandler)
	mux.Handle("/mfa-authenticate.js", contentMFAAuthenticateHandler)
	mux.Handle("/mfa-register.js", contentMFARegisterHandler)
	mux.Handle("/entry-view.js", contentEntryViewHandler)
	mux.Handle("/font-awesome.otf", contentFontAwesomeHandler)

	// Dynamic content handlers.
	mux.Handle("/logout", newLogout(sh))
	mux.Handle("/register", newAuth(sh, newRegister()))
	mux.Handle("/search", newAuth(sh, newSearch()))
	mux.Handle("/", newAuth(sh, newPassword()))

	return mux
}
