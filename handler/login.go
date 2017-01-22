package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"../session"
	"../static"

	"github.com/tstranex/u2f"
)

// sessionProvider handles getting an authenticated session for the user,
// either by retrieving an existing session from the user's session ID cookie,
// or by prompting the user for credentials to create a new session.
type sessionProvider struct {
	sh          *session.Handler
	lph         http.Handler
	u2fAuthTmpl *template.Template
}

func newSessionProvider(sh *session.Handler) (*sessionProvider, error) {
	lph, err := newAsset("pages/login-password.html", "text/html; charset=utf-8")
	if err != nil {
		return nil, fmt.Errorf("could not create password login handler: %v", err)
	}

	uat, err := static.Asset("templates/u2f-authenticate.html")
	if err != nil {
		return nil, fmt.Errorf("could not get U2F authentication template: %v", err)
	}
	u2fAuthTmpl, err := template.New("u2f-authenticate").Parse(string(uat))
	if err != nil {
		return nil, fmt.Errorf("could not parse U2F authentication template: %v", err)
	}

	return &sessionProvider{
		sh:          sh,
		lph:         lph,
		u2fAuthTmpl: u2fAuthTmpl,
	}, nil
}

// GetSession either returns an existing session based on the user's session ID
// cookie (and does not touch the ResponseWriter), or uses the ResponseWriter
// to prompt the user for their password or U2F authentication before returning
// nil.
func (sp sessionProvider) GetSession(w http.ResponseWriter, r *http.Request) *session.Session {
	// If there is an sid with an authenticated session attached, return it.
	sid, err := sessionIDFromRequest(r)
	if err != nil {
		log.Printf("Could not get session ID: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	sess, err := sp.sh.GetSession(sid)
	if err != nil && err != session.ErrNoSession {
		log.Printf("Could not get session: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	if sess != nil && sess.GetState() == session.AUTHENTICATED {
		return sess
	}

	// No current authenticated session. Handle the login flow.
	switch r.Method {
	case http.MethodGet:
		switch {
		case sess == nil:
			// Ask the user to login.
			sp.lph.ServeHTTP(w, r)
			return nil

		case sess.GetState() == session.U2F_REQUIRED:
			c, err := sess.GenerateAuthenticateChallenge()
			if err != nil {
				log.Printf("Could not create U2F authentication challenge: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return nil
			}
			req := c.SignRequest(sess.GetRegistrations())

			var buf bytes.Buffer
			if err := sp.u2fAuthTmpl.Execute(&buf, req); err != nil {
				log.Printf("Could not execute U2F authentication template: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return nil
			}
			newStatic(buf.String(), "text/html; charset=utf-8").ServeHTTP(w, r)
			return nil

		default:
			// This should not be able to occur.
			log.Printf("Could not login: session in unexpected state %s", sess.GetState())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}

	case http.MethodPost:
		// If the user is posting some data with "login" action, try to password auth.
		switch r.FormValue("action") {
		case "login":
			sid, _, err := sp.sh.CreateSession(r.FormValue("pass"))
			if err == session.ErrWrongPassphrase {
				http.Redirect(w, r, r.RequestURI, http.StatusFound)
				return nil
			}
			if err != nil {
				log.Printf("Could not create session: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return nil
			}
			addSessionIDToRequest(w, sid)
			http.Redirect(w, r, r.RequestURI, http.StatusFound)
			return nil

		case "u2f-auth":
			if sess == nil {
				http.Redirect(w, r, r.RequestURI, http.StatusFound)
				return nil
			}

			var resp u2f.SignResponse
			if err := json.Unmarshal([]byte(r.FormValue("response")), &resp); err != nil {
				log.Printf("Could not parse U2F authentication response: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return nil
			}

			if err := sess.U2FAuthenticate(resp); err != nil && err != session.ErrU2FAuthenticationFailed {
				log.Printf("Could not U2F authenticate: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return nil
			}
			http.Redirect(w, r, r.RequestURI, http.StatusFound)
			return nil

		default:
			// User's session probably timed out. Forward to get standard login flow.
			http.Redirect(w, r, r.RequestURI, http.StatusFound)
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
