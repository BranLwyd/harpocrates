package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/tstranex/u2f"

	"github.com/BranLwyd/harpocrates/harpd/assets"
	"github.com/BranLwyd/harpocrates/harpd/rate"
	"github.com/BranLwyd/harpocrates/harpd/session"
	"github.com/BranLwyd/harpocrates/secret"
)

type sessionContextKey struct{}

const (
	sessionCookieName = "harp-sid"

	authAny = "#_ANY_#"
)

var (
	loginPasswordHandler = must(newAsset("pages/login-password.html", "text/html; charset=utf-8"))
	loginU2FAuthTmpl     = template.Must(template.New("u2f-authenticate").Parse(string(assets.MustAsset("templates/u2f-authenticate.html"))))
)

// authHandler handles getting an authenticated session for the user session.
// If the user is already logged in, it adds the authenticated session to the
// request context and runs a wrapped handler.
type authHandler struct {
	ahh authenticatedHTTPHandler
	sh  *session.Handler
}

type authenticatedHTTPHandler interface {
	// http.Handler is responsible for rendering the authenticated page.
	// A session.Session is guaranteed to be available from the passed
	// http.Request.
	http.Handler

	// authPath returns the path that should be U2F-authenticated for this
	// request. It can also return the empty string if no U2F
	// authentication is required, or authAny if U2F-authentication of any
	// page is sufficient to allow access to this page. A session.Session
	// is guaranteed to be available from the passed http.Request.
	authPath(*http.Request) (string, error)
}

func newAuth(sh *session.Handler, ahh authenticatedHTTPHandler) *authHandler {
	return &authHandler{
		ahh: ahh,
		sh:  sh,
	}
}

func (lh authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Don't allow caching of anything that requires authentication.
	w.Header().Set("Cache-Control", "no-store")

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
	r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, sess))

	// The user has a session. If this page needs additional U2F
	// authentication, prompt for it.
	ap, err := lh.u2fPath(r, sess)
	if err != nil {
		log.Printf("Could not determine U2F authentication path: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if ap != "" {
		lh.serveU2FHTTP(w, r, sess, ap)
		return
	}

	// User is fully authenticated for this page. Add the session to the request
	// context and run the wrapped handler.
	lh.ahh.ServeHTTP(w, r)
}

func (lh authHandler) servePasswordHTTP(w http.ResponseWriter, r *http.Request) {
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
		if err == secret.ErrWrongPassphrase {
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		if err == rate.ErrTooManyEvents {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
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

func (lh authHandler) u2fPath(r *http.Request, sess *session.Session) (string, error) {
	ap, err := lh.ahh.authPath(r)
	if err != nil {
		return "", fmt.Errorf("could not get authentication path: %v", err)
	}

	if ap == authAny && sess.IsU2FAuthenticated() {
		return "", nil
	}
	if ap != "" && sess.IsU2FAuthenticatedFor(ap) {
		return "", nil
	}
	return ap, nil
}

func (lh authHandler) serveU2FHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session, authPath string) {
	switch r.Method {
	case http.MethodGet:
		// If the user has no U2F device registrations, send them to where they can register a U2F device.
		if len(sess.U2FRegistrations()) == 0 {
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		c, err := sess.GenerateU2FChallenge(authPath)
		if err != nil {
			log.Printf("Could not create U2F authentication challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		req := c.SignRequest(sess.U2FRegistrations())
		reqBytes, err := json.Marshal(req)
		if err != nil {
			log.Printf("Could not marshal U2F authentication challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		serveTemplate(w, r, loginU2FAuthTmpl, string(reqBytes))

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
		if err := sess.AuthenticateU2FResponse(authPath, resp); err != nil && err != session.ErrU2FAuthenticationFailed {
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

	// Hack: add SameSite attribute to cookie, not yet officially supported by Go (https://github.com/golang/go/issues/15867)
	// TODO: once Go supports SameSite, go back to using http.SetCookie()
	if v := c.String(); v != "" {
		w.Header().Add("Set-Cookie", v+"; SameSite=strict")
	}
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
	sess, _ := r.Context().Value(sessionContextKey{}).(*session.Session)
	return sess
}
