package handler

import (
	"bytes"
	"context"
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

type handlerContextKey int

const (
	sessionContextKey handlerContextKey = 0

	sessionCookieName = "harp-sid"
)

var (
	loginPasswordHandler = must(newAsset("pages/login-password.html", "text/html; charset=utf-8"))
	loginU2FAuthTmpl     = template.Must(template.New("u2f-authenticate").Parse(string(static.MustAsset("templates/u2f-authenticate.html"))))
)

// loginHandler handles getting an authenticated session for the user session.
// If the user is already logged in, it adds the authenticated session to the
// request context and runs a wrapped handler.
type loginHandler struct {
	hh http.Handler
	sh *session.Handler
}

func newLogin(sh *session.Handler, hh http.Handler) *loginHandler {
	return &loginHandler{
		hh: hh,
		sh: sh,
	}
}

func (lh loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If there is an sid with an authenticated session attached, add the
	// session to the context and run the wrapped handler.
	sid, err := sessionIDFromRequest(r)
	if err != nil {
		log.Printf("Could not get session ID: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	sess, err := lh.sh.GetSession(sid)
	if err != nil && err != session.ErrNoSession {
		log.Printf("Could not get session: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if sess != nil && sess.GetState() == session.AUTHENTICATED {
		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey, sess))
		lh.hh.ServeHTTP(w, r)
		return
	}

	// No current authenticated session. Handle the login flow.
	switch r.Method {
	case http.MethodGet:
		switch {
		case sess == nil:
			// Ask the user to password authenticate.
			loginPasswordHandler.ServeHTTP(w, r)
			return

		case sess.GetState() == session.U2F_REQUIRED:
			// Ask the user to U2F authenticate.
			c, err := sess.GenerateAuthenticateChallenge()
			if err != nil {
				log.Printf("Could not create U2F authentication challenge: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			req := c.SignRequest(sess.GetRegistrations())

			var buf bytes.Buffer
			if err := loginU2FAuthTmpl.Execute(&buf, req); err != nil {
				log.Printf("Could not execute U2F authentication template: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			newStatic(buf.Bytes(), "text/html; charset=utf-8").ServeHTTP(w, r)
			return

		default:
			// This should not be able to occur.
			log.Printf("Could not login: session in unexpected state %s", sess.GetState())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

	case http.MethodPost:
		// If the user is posting some data with "login" action, try to password auth.
		switch r.FormValue("action") {
		case "login":
			sid, _, err := lh.sh.CreateSession(clientIP(r), r.FormValue("pass"))
			if err == session.ErrWrongPassphrase {
				http.Redirect(w, r, r.RequestURI, http.StatusSeeOther)
				return
			}
			if err != nil {
				log.Printf("Could not create session: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			addSessionIDToRequest(w, sid)
			http.Redirect(w, r, r.RequestURI, http.StatusSeeOther)
			return

		case "u2f-auth":
			if sess == nil {
				http.Redirect(w, r, r.RequestURI, http.StatusSeeOther)
				return
			}

			var resp u2f.SignResponse
			if err := json.Unmarshal([]byte(r.FormValue("response")), &resp); err != nil {
				log.Printf("Could not parse U2F authentication response: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			if err := sess.U2FAuthenticate(resp); err != nil && err != session.ErrU2FAuthenticationFailed {
				log.Printf("Could not U2F authenticate: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, r.RequestURI, http.StatusSeeOther)
			return

		default:
			// User's session probably timed out. Forward to get standard login flow.
			http.Redirect(w, r, r.RequestURI, http.StatusSeeOther)
			return
		}

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
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

func sessionFrom(r *http.Request) *session.Session {
	sess, _ := r.Context().Value(sessionContextKey).(*session.Session)
	return sess
}
