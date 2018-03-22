package handler

import (
	"log"
	"net/http"

	"github.com/BranLwyd/harpocrates/harpd/session"
)

// logoutHandler handles requests to log out.
type logoutHandler struct {
	sh *session.Handler
}

func newLogout(sh *session.Handler) *logoutHandler {
	return &logoutHandler{
		sh: sh,
	}
}

func (lh logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Try to get an existing session with the session ID from the user's
	// cookie; if it doesn't exist, we're already done.
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
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	sess.Close()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
