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

func newContentHandler(sh *session.Handler) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.Handle("/", newFilteredHandler("/", http.RedirectHandler("/p/", http.StatusFound)))

	// Static content handlers.
	styleHandler, err := assetHandler("etc/style.css", "text/css; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create style handler: %v", err)
	}
	mux.Handle("/style.css", styleHandler)

	robotsHandler, err := assetHandler("etc/robots.txt", "text/plain; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create robots handler: %v", err)
	}
	mux.Handle("/robots.txt", robotsHandler)

	// Dynamic content handler.
	dh, err := newDynamicHandler(sh)
	if err != nil {
		return nil, fmt.Errorf("could not create dynamic content handler: %v", err)
	}
	mux.Handle("/p/", dh)

	return mux, nil
}

// dynamicHandler handles all dynamic content.
type dynamicHandler struct {
	sessionHandler       *session.Handler
	loginPasswordHandler http.Handler
}

func (dh dynamicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := dh.getSession(w, r)
	if sess == nil {
		return
	}

	// TODO: handle logged-in UI
	staticHandler{content: "Logged in.", contentType: "text/plain; charset=utf-8"}.ServeHTTP(w, r)
}

// getSession gets the user's session based on the user's session cookie. If it
// can't do so, it handles the HTTP request appropriately to allow a login
// flow.
func (dh dynamicHandler) getSession(w http.ResponseWriter, r *http.Request) *session.Session {
	// If there is an sid with an authenticated session attached, return it.
	sid, err := sessionIDFromRequest(r)
	if err != nil {
		log.Printf("Could not get session ID: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	if sid != "" {
		sess, err := dh.sessionHandler.GetSession(sid)
		if err != nil && err != session.ErrNoSession {
			log.Printf("Could not get session: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}
		if sess != nil {
			return sess
		}
	}

	// No current session. Handle the login flow.
	switch r.Method {
	case http.MethodGet:
		// Ask the user to login.
		dh.loginPasswordHandler.ServeHTTP(w, r)
		return nil

	case http.MethodPost:
		// If the user is posting some data with "login" action, try to password auth.
		switch r.FormValue("action") {
		case "login":
			sid, sess, err := dh.sessionHandler.CreateSession(r.FormValue("pass"))
			if err == session.ErrWrongPassphrase {
				dh.loginPasswordHandler.ServeHTTP(w, r)
				return nil
			}
			if err != nil {
				log.Printf("Could not create session: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return nil
			}
			addSessionIDToRequest(w, sid)
			return sess

		default:
			dh.loginPasswordHandler.ServeHTTP(w, r)
			return nil
		}

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return nil
	}
}

func addSessionIDToRequest(w http.ResponseWriter, sid string) {
	encodedSID := base64.RawURLEncoding.EncodeToString([]byte(sid))
	// TODO: make secure (once debug runs in https)
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    encodedSID,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func sessionIDFromRequest(r *http.Request) (string, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", nil
		} else {
			return "", fmt.Errorf("could not get cookie: %v", err)
		}
	}

	sid, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		if _, ok := err.(base64.CorruptInputError); ok {
			return "", nil
		} else {
			return "", fmt.Errorf("could not decode cookie value: %v", err)
		}
	}
	return string(sid), nil
}

func newDynamicHandler(sh *session.Handler) (http.Handler, error) {
	lph, err := assetHandler("pages/login-password.html", "text/html; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create password login handler: %v", err)
	}

	return &dynamicHandler{
		sessionHandler:       sh,
		loginPasswordHandler: lph,
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
