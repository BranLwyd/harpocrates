// Package api provides an HTTP handler implementing harpd's RESTful Handler.
package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"../session"
)

const (
	sessionCookieName = "HARP-SESS"
)

// Handler provides HTTP handlers for handling harpd's RESTful Handler. The following
// method/paths are supported:
//
// POST /api/login: allows user to authenticate and create a new session
// POST /api/logout: allows user to prematurely end an unneeded session
// GET /api/p: get list of password files
// GET /api/p/...: get the contents of a password file
// PUT /api/p/...: update (or create) the contents of a password file
// DELETE /api/p/...: delete a password file
//
// It is considered a programmer error to pass in a URL whose path does not
// start with /api/.
type Handler struct {
	sessionHandler *session.Handler
}

func NewHandler(sessHandler *session.Handler) *Handler {
	return &Handler{
		sessionHandler: sessHandler,
	}
}

// ServeHTTP serves an API request, which must start with /api/.
func (a *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		log.Printf("Handler.ServeHTTP called on unexpected path: %v", r.URL)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	switch {
	case r.URL.Path == "/api/login":
		a.handleLogin(w, r)
	case r.URL.Path == "/api/logout":
		a.handleLogout(w, r)
	case r.URL.Path == "/api/p":
		a.handlePassList(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/p/"):
		a.handlePass(w, r)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

type loginRequest struct {
	Passphrase string `json:"passphrase"`
}

func (a *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	// TODO(bran): what if the request is literal "null"?
	sessID, err := a.sessionHandler.CreateSession([]byte(req.Passphrase))
	if err != nil {
		if err == session.ErrWrongPassphrase {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		} else {
			log.Printf("Got unexpected error when creating session: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    base64.StdEncoding.EncodeToString([]byte(sessID)),
		Path:     "/api",
		Secure:   true,
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
}

func (a *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	sessID, err := getSessionIDForRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Clear session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/api",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
	a.sessionHandler.CloseSession(sessID)
}

func (a *Handler) handlePassList(w http.ResponseWriter, r *http.Request) {
	// TODO(bran)
}

func (a *Handler) handlePass(w http.ResponseWriter, r *http.Request) {
	// TODO(bran)
}

func getSessionIDForRequest(r *http.Request) (string, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", fmt.Errorf("couldn't get session ID for request: %v", err)
	}
	sessID, err := base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		return "", fmt.Errorf("couldn't get session ID for request: %v", err)
	}
	return string(sessID), nil
}
