package handler

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"../session"
)

// sessionProvider handles getting an authenticated session for the user,
// either by retrieving an existing session from the user's session ID cookie,
// or by prompting the user for credentials to create a new session.
type sessionProvider struct {
	sh  *session.Handler
	lph http.Handler
}

func newSessionProvider(sh *session.Handler) (*sessionProvider, error) {
	lph, err := newAsset("pages/login-password.html", "text/html; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create password login handler: %v", err)
	}

	return &sessionProvider{
		sh:  sh,
		lph: lph,
	}, nil
}

// GetSession either returns an existing session based on the user's session ID
// cookie (and does not touch the ResponseWriter), or uses the ResponseWriter
// to prompt the user for their password before returning nil.
func (sp sessionProvider) GetSession(w http.ResponseWriter, r *http.Request) *session.Session {
	// If there is an sid with an authenticated session attached, return it.
	sid, err := sessionIDFromRequest(r)
	if err != nil {
		log.Printf("Could not get session ID: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	if sid != "" {
		sess, err := sp.sh.GetSession(sid)
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
		sp.lph.ServeHTTP(w, r)
		return nil

	case http.MethodPost:
		// If the user is posting some data with "login" action, try to password auth.
		switch r.FormValue("action") {
		case "login":
			sid, _, err := sp.sh.CreateSession(r.FormValue("pass"))
			if err == session.ErrWrongPassphrase {
				sp.lph.ServeHTTP(w, r)
				return nil
			}
			if err != nil {
				log.Printf("Could not create session: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return nil
			}
			addSessionIDToRequest(w, sid)
			http.Redirect(w, r, r.RequestURI, http.StatusFound) // redirect to avoid re-POSTing data
			return nil

		default:
			sp.lph.ServeHTTP(w, r)
			return nil
		}

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return nil
	}
}

func addSessionIDToRequest(w http.ResponseWriter, sid string) {
	encodedSID := base64.RawURLEncoding.EncodeToString([]byte(sid))
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    encodedSID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
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
