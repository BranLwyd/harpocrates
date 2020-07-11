// Package session provides session-management functionality.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/tstranex/u2f"

	"github.com/BranLwyd/harpocrates/harpd/alert"
	"github.com/BranLwyd/harpocrates/harpd/rate"
	"github.com/BranLwyd/harpocrates/secret"
)

const (
	sessionIDLength = 32
	alertTimeLimit  = 10 * time.Second
)

var (
	ErrNoSession               = errors.New("no such session")
	ErrNoChallenge             = errors.New("no current challenge")
	ErrMFAAuthenticationFailed = errors.New("MFA authentication failed")
)

// Handler handles management of sessions, including creation, deletion, and
// timeout. It is safe for concurrent use from multiple goroutines.
type Handler struct {
	mu       sync.RWMutex        // protects sessions
	sessions map[string]*Session // by session ID

	vault           secret.Vault       // locked password data
	sessionDuration time.Duration      // how long sessions last
	appID           string             // MFA app ID
	registrations   []u2f.Registration // MFA device registrations
	rateLimiter     rate.Limiter       // rate limiter for creating new sessions
	alerter         alert.Alerter      // used to notify user of alerts
}

// NewHandler creates a new session handler.
func NewHandler(vault secret.Vault, host string, registrations []string, sessionDuration time.Duration, newSessionRate float64, alerter alert.Alerter) (*Handler, error) {
	if sessionDuration <= 0 {
		return nil, errors.New("nonpositive session length")
	}

	var regs []u2f.Registration
	for i, r := range registrations {
		rBytes, err := base64.RawStdEncoding.DecodeString(r)
		if err != nil {
			return nil, fmt.Errorf("could not decode registration %d: %v", i, err)
		}
		var reg u2f.Registration
		if err := reg.UnmarshalBinary(rBytes); err != nil {
			return nil, fmt.Errorf("could not parse registration %d: %v", i, err)
		}
		regs = append(regs, reg)
	}

	return &Handler{
		sessions:        make(map[string]*Session),
		vault:           vault,
		sessionDuration: sessionDuration,
		appID:           fmt.Sprintf("https://%s", host),
		registrations:   regs,
		rateLimiter:     rate.NewLimiter(newSessionRate, 1),
		alerter:         alerter,
	}, nil
}

// CreateSession attempts to create a new session, using the given passphrase.
// It returns the new session's ID and the session, or
// secret.ErrWrongPassphrase if an authentication error occurs, and other
// errors if they occur.
func (h *Handler) CreateSession(clientID, passphrase string) (string, *Session, error) {
	// Respect rate limit.
	if err := h.rateLimiter.Wait(clientID); err != nil {
		if err == rate.ErrTooManyEvents {
			return "", nil, err
		}
		return "", nil, fmt.Errorf("couldn't wait for rate limiter: %v", err)
	}

	// Get a secret.Store using the supplied passphrase.
	store, err := h.vault.Unlock(passphrase)
	if err == secret.ErrWrongPassphrase {
		return "", nil, err
	} else if err != nil {
		return "", nil, fmt.Errorf("could not unlock vault: %v", err)
	}

	// Generate session ID.
	var sID [sessionIDLength]byte
	if _, err := rand.Read(sID[:]); err != nil {
		return "", nil, fmt.Errorf("could not generate session ID: %v", err)
	}
	sessID := string(sID[:])

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ok := h.sessions[sessID]; ok; _, ok = h.sessions[sessID] {
		// This loop body is overwhelmingly likely to never run.
		if _, err := rand.Read(sID[:]); err != nil {
			return "", nil, fmt.Errorf("could not generate session ID: %v", err)
		}
		sessID = string(sID[:])
	}

	// Start reaper timer and return.
	sess := &Session{
		h:           h,
		id:          sessID,
		store:       store,
		authedPaths: map[string]struct{}{},
	}
	sess.expirationTimer = time.AfterFunc(h.sessionDuration, func() { h.closeSession(sessID) })
	h.sessions[sessID] = sess
	return sessID, sess, nil
}

// GetSession gets an existing session if the session exists.  It returns
// ErrNoSession if the session does not exist. If the session does exist and is
// fully authenticated, its expiration timeout is reset.
func (h *Handler) GetSession(sessionID string) (*Session, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if sess := h.sessions[sessionID]; sess != nil {
		sess.mu.RLock()
		defer sess.mu.RUnlock()

		// Only reset the timer if the user has completed MFA, to ensure that partially-authenticated
		// users can't keep a session open indefinitely.
		if len(sess.authedPaths) > 0 {
			if !sess.expirationTimer.Stop() {
				return nil, ErrNoSession
			}
			sess.expirationTimer.Reset(h.sessionDuration)
		}
		return sess, nil
	}
	return nil, ErrNoSession
}

func (h *Handler) closeSession(sessID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sess := h.sessions[sessID]; sess != nil {
		sess.expirationTimer.Stop()
		delete(h.sessions, sessID)

		if !sess.IsMFAAuthenticated() {
			h.alert(alert.UNAUTHENTICATED_SESSION_CLOSED, "Session closed without completing multi-factor authentication.")
		}
	}
}

func (h *Handler) alert(code alert.Code, details string) {
	go func() {
		ctx, c := context.WithTimeout(context.Background(), alertTimeLimit)
		defer c()
		if err := h.alerter.Alert(ctx, code, details); err != nil {
			log.Printf("Could not send alert (%s %q): %v", code, details, err)
		}
	}()
}

// Session stores all data associated with a given active user session.
// It is safe for concurrent use from multiple goroutines.
type Session struct {
	id              string
	h               *Handler
	store           secret.Store
	expirationTimer *time.Timer

	mu            sync.RWMutex // protects all fields below
	authedPaths   map[string]struct{}
	challenge     *u2f.Challenge
	challengePath string
}

// Close closes this existing session, freeing all resources used by the
// session.
func (s *Session) Close() {
	s.h.closeSession(s.id)
}

// GetStore returns the password store associated with this session.
func (s *Session) GetStore() secret.Store {
	return s.store
}

// IsMFAAuthenticated determines if the user has performed multi-factor authentication for any
// path.
func (s *Session) IsMFAAuthenticated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.authedPaths) > 0
}

// IsMFAAuthenticatedFor determines if the user has performed multi-factor authentication for the
// given path.
func (s *Session) IsMFAAuthenticatedFor(path string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.authedPaths[path]
	return ok
}

// GenerateMFAChallenge generates a new multi-factor authentication challenge for the given path. It
// replaces any previous MFA challenges that may exist for this or any other paths.
func (s *Session) GenerateMFAChallenge(path string) (*u2f.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := u2f.NewChallenge(s.h.appID, []string{s.h.appID})
	if err != nil {
		return nil, fmt.Errorf("could not generate challenge: %v", err)
	}
	s.challenge = c
	s.challengePath = path
	return c, nil
}

// GetMFAChallenge gets the existing multi-factor authentication challenge for the given path. It
// returns ErrNoChallenge if there is no existing MFA challenge for the given path.
func (s *Session) GetMFAChallenge(path string) (*u2f.Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.challengePath != path || s.challenge == nil {
		return nil, ErrNoChallenge
	}
	return s.challenge, nil
}

// AuthenticateMFAResponse authenticates the user for the given path with the given multi-factor
// authentication signing response. It returns ErrNoChallenge if there is no existing challenge for
// the given path, and ErrMFAAuthenticationFailed if it was not possible to authenticate the user
// with the given MFA signing response.
func (s *Session) AuthenticateMFAResponse(path string, sr u2f.SignResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.challengePath != path || s.challenge == nil {
		return ErrNoChallenge
	}
	for _, reg := range s.h.registrations {
		if _, err := reg.Authenticate(sr, *s.challenge, 0); err == nil {
			if len(s.authedPaths) == 0 {
				s.h.alert(alert.LOGIN, fmt.Sprintf("New session authenticated."))
			}
			s.authedPaths[path] = struct{}{}
			s.challenge = nil
			s.challengePath = ""
			return nil
		}
	}
	return ErrMFAAuthenticationFailed
}

// MFARegistrations gets the set of registrations for MFA devices.
func (s *Session) MFARegistrations() []u2f.Registration {
	return s.h.registrations
}
