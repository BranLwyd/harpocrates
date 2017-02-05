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
	"path"
	"strings"

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
	// Try to get an existing session with the session ID from the user's
	// cookie; if it doesn't exist, start the password login flow.
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
	if sess == nil {
		lh.servePasswordHTTP(w, r)
		return
	}

	// The user has a session. If this page needs additional U2F
	// authentication, prompt for it.
	if lh.needsU2F(sess, r.URL.Path) {
		lh.serveU2FHTTP(w, r, sess)
		return
	}

	// User is fully authenticated for this page. Add the session to the request
	// context and run the wrapped handler.
	r = r.WithContext(context.WithValue(r.Context(), sessionContextKey, sess))
	lh.hh.ServeHTTP(w, r)
}

func (lh loginHandler) servePasswordHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		loginPasswordHandler.ServeHTTP(w, r)

	case http.MethodPost:
		if r.FormValue("action") != "login" {
			// User's session probably timed out. Forward to get standard login flow.
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		sid, _, err := lh.sh.CreateSession(clientIP(r), r.FormValue("pass"))
		if err == session.ErrWrongPassphrase {
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		if err != nil {
			log.Printf("Could not create session: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		addSessionIDToRequest(w, sid)
		http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (lh loginHandler) needsU2F(sess *session.Session, p string) bool {
	// Check for trailing slash before cleaning, since path.Clean removes
	// any trailing slashes.
	isEntryRequest := !strings.HasSuffix(p, "/")
	p = path.Clean(p)

	switch {
	case strings.HasPrefix(p, "/p/") && isEntryRequest:
		// Entries require per-entry authentication.
		return !sess.IsU2FAuthenticatedFor(p)

	case p == "/register":
		// The registration page is available without U2F if there are
		// no U2F registrations.
		if len(sess.GetRegistrations()) == 0 {
			return false
		}
		fallthrough

	default:
		// Other pages require any path to have been authenticated.
		return !sess.IsU2FAuthenticated()
	}
}

func (lh loginHandler) serveU2FHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	switch r.Method {
	case http.MethodGet:
		c, err := sess.GenerateU2FChallenge(path.Clean(r.URL.Path))
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

	case http.MethodPost:
		if r.FormValue("action") != "u2f-auth" {
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		var resp u2f.SignResponse
		if err := json.Unmarshal([]byte(r.FormValue("response")), &resp); err != nil {
			log.Printf("Could not parse U2F authentication response: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if err := sess.AuthenticateU2FResponse(path.Clean(r.URL.Path), resp); err != nil && err != session.ErrU2FAuthenticationFailed {
			log.Printf("Could not U2F authenticate: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
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
