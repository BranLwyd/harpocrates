package handler

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"../session"
)

// dynamicHandler handles all dynamic content.
type dynamicHandler struct {
	sessionHandler       *session.Handler
	loginPasswordHandler http.Handler
}

func newDynamic(sh *session.Handler) (http.Handler, error) {
	lph, err := newAsset("pages/login-password.html", "text/html; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create password login handler: %v", err)
	}

	return &dynamicHandler{
		sessionHandler:       sh,
		loginPasswordHandler: lph,
	}, nil
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
		Path:     "/",
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
