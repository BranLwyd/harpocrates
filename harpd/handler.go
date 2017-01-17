package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"../session"
	"../static"
)

const (
	sessionCookieName = "harp-sid"
)

func addSessionIDToRequest(w http.ResponseWriter, sid string) {
	encodedSID := base64.RawURLEncoding.EncodeToString([]byte(sid))
	// TODO: make secure (once debug runs in https)
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    encodedSID,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func sessionIDFromRequest(r *http.Request) (string, error) {
	c, err := r.Cookie(sessionCookieName)
	if err == http.ErrNoCookie {
		return "", err
	}
	if err != nil {
		return "", fmt.Errorf("could not get session cookie: %v", err)
	}
	sid, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", fmt.Errorf("could not decode session cookie value: %v", err)
	}
	return string(sid), nil
}

func newContentHandler(sh *session.Handler) (http.Handler, error) {
	mux := http.NewServeMux()

	// Serve static content.
	styleHandler, err := assetHandler("etc/style.css", "text/css; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create style handler: %v", err)
	}
	mux.Handle("/style.css", styleHandler)

	// Login handler.
	lh, err := newLoginHandler(sh)
	if err != nil {
		return nil, fmt.Errorf("could not create login handler: %v", err)
	}
	mux.Handle("/", newFilteredHandler("/", lh))

	// TODO(bran)
	mux.Handle("/p/", staticHandler{content: "TODO(bran)", contentType: "text/plain; charset=utf-8"})

	return mux, nil
}

// loginHandler handles the root path, which is responsible for logging the user in.
type loginHandler struct {
	sessionHandler       *session.Handler
	passwordLoginHandler http.Handler
}

func (lh loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If there is an sid with an authenticated session attached, forward to /p/.
	sid, err := sessionIDFromRequest(r)
	if err != nil && err != http.ErrNoCookie {
		log.Printf("Login handler could not get session ID from request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if sid != "" {
		sess, err := lh.sessionHandler.GetSession(sid)
		if err != nil && err != session.ErrNoSession {
			log.Printf("Login handler could not get session: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if sess != nil {
			http.Redirect(w, r, "/p/", http.StatusFound)
			return
		}
	}

	// If the user is posting some data, try to password auth.
	if r.Method == http.MethodPost {
		pass := r.FormValue("pass")
		sid, err := lh.sessionHandler.CreateSession([]byte(pass))
		if err == session.ErrWrongPassphrase {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("Login handler could not create session: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		addSessionIDToRequest(w, sid)
		http.Redirect(w, r, "/p/", http.StatusFound)
		return
	}

	// If none of the above, just request password.
	lh.passwordLoginHandler.ServeHTTP(w, r)
}

func newLoginHandler(sh *session.Handler) (http.Handler, error) {
	plh, err := assetHandler("pages/login-password.html", "text/html; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create password login handler: %v", err)
	}

	return &loginHandler{
		sessionHandler:       sh,
		passwordLoginHandler: plh,
	}, nil
}

// filteredHandler filters a handler to only serve one path; anything else is given a 404.
type filteredHandler struct {
	allowedPath string
	h           http.Handler
}

func (fh filteredHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.RequestURI != fh.allowedPath {
		http.NotFound(w, r)
	} else {
		fh.h.ServeHTTP(w, r)
	}
}

func newFilteredHandler(allowedPath string, h http.Handler) http.Handler {
	return &filteredHandler{
		allowedPath: allowedPath,
		h:           h,
	}
}

// loggingHandler is a wrapping handler that logs the IP of the requestor and the path of the request.
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

func newLoggingHandler(logName string, h http.Handler) http.Handler {
	return loggingHandler{
		h:       h,
		logName: logName,
	}
}

// staticHandler serves static content from memory.
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
