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
	loginPasswordHandler = must(newAsset("harpd/assets/pages/login-password.html", "text/html; charset=utf-8"))
	loginMFAAuthTmpl     = template.Must(template.New("mfa-authenticate").Parse(string(assets.MustAsset("harpd/assets/templates/mfa-authenticate.html"))))
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

	// authPath returns the path that should be multi-factor authenticated for this request. It can
	// also return the empty string if no MFA is required, or authAny if MFA of any path is sufficient
	// to allow access to this page. A session.Session is guaranteed to be available from the passed
	// http.Request.
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

	// The user has a session. If this page needs additional multi-factor authentication, prompt for it.
	ap, err := lh.mfaPath(r, sess)
	if err != nil {
		log.Printf("Could not determine multi-factor authentication path: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if ap != "" {
		lh.serveMFAHTTP(w, r, sess, ap)
		return
	}

	// User is fully authenticated for this page. Add the session to the request
	// context and run the wrapped handler.
	lh.ahh.ServeHTTP(w, r)
}

func (lh authHandler) servePasswordHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Add("Link", "</font-awesome.otf>; rel=prefetch")
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

func (lh authHandler) mfaPath(r *http.Request, sess *session.Session) (string, error) {
	ap, err := lh.ahh.authPath(r)
	if err != nil {
		return "", fmt.Errorf("could not get authentication path: %v", err)
	}

	if ap == authAny && sess.IsMFAAuthenticated() {
		return "", nil
	}
	if ap != "" && sess.IsMFAAuthenticatedFor(ap) {
		return "", nil
	}
	return ap, nil
}

func (lh authHandler) serveMFAHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session, authPath string) {
	switch r.Method {
	case http.MethodGet:
		// If the user has no MFA device registrations, send them to where they can register an MFA device.
		if len(sess.MFARegistrations()) == 0 {
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		c, err := sess.GenerateMFAChallenge(authPath)
		if err != nil {
			log.Printf("Could not create multi-factor authentication challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		req := c.SignRequest(sess.MFARegistrations())
		reqBytes, err := json.Marshal(req)
		if err != nil {
			log.Printf("Could not marshal MFA authentication challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		serveTemplate(w, r, loginMFAAuthTmpl, string(reqBytes))

	case http.MethodPost:
		if r.FormValue("action") != "mfa-auth" {
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		var resp u2f.SignResponse
		if err := json.Unmarshal([]byte(r.FormValue("response")), &resp); err != nil {
			log.Printf("Could not parse multi-factor authentication response: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if err := sess.AuthenticateMFAResponse(authPath, resp); err != nil && err != session.ErrMFAAuthenticationFailed {
			log.Printf("Could not authenticate MFA response: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func addSessionIDToRequest(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(sid)),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
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
