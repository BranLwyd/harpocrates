// Package session provides session-management functionality.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tstranex/u2f"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

	"../alert"
	"../password"
	"../rate"
)

const (
	sessionIDLength = 32
	alertTimeLimit  = 10 * time.Second
)

var (
	ErrWrongPassphrase         = errors.New("wrong passphrase")
	ErrNoSession               = errors.New("no such session")
	ErrNoChallenge             = errors.New("no current challenge")
	ErrU2FAuthenticationFailed = errors.New("U2F authentication failed")
)

// Handler handles management of sessions, including creation, deletion, and
// timeout. It is safe for concurrent use from multiple goroutines.
type Handler struct {
	mu       sync.RWMutex        // protects sessions
	sessions map[string]*Session // by session ID

	counters         *CounterStore      // Store of U2F counters by key handle.
	sessionDuration  time.Duration      // how long sessions last
	serializedEntity string             // entity used to encrypt/decrypt password entries
	baseDir          string             // base directory containing password entries
	appID            string             // U2F app ID
	registrations    []u2f.Registration // U2F device registrations
	rateLimiter      rate.Limiter       // rate limiter for creating new sessions
	alerter          alert.Alerter      // used to notify user of alerts
}

// NewHandler creates a new session handler.
func NewHandler(serializedEntity, baseDir, host string, registrations []string, sessionDuration time.Duration, cs *CounterStore, newSessionRate float64, alerter alert.Alerter) (*Handler, error) {
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
		sessions:         make(map[string]*Session),
		sessionDuration:  sessionDuration,
		serializedEntity: serializedEntity,
		baseDir:          filepath.Clean(baseDir),
		appID:            fmt.Sprintf("https://%s", host),
		registrations:    regs,
		counters:         cs,
		rateLimiter:      rate.NewLimiter(newSessionRate, 1),
		alerter:          alerter,
	}, nil
}

// CreateSession attempts to create a new session, using the given passphrase.
// It returns the new session's ID and the session, or ErrWrongPassphrase if
// authentication occurs, and other errors if they occur.
func (h *Handler) CreateSession(clientID, passphrase string) (string, *Session, error) {
	// Respect rate limit.
	if err := h.rateLimiter.Wait(clientID); err != nil {
		return "", nil, fmt.Errorf("couldn't wait for rate limiter: %v", err)
	}

	// Read entity, decrypt keys using passphrase, create password store.
	entity, err := openpgp.ReadEntity(packet.NewReader(strings.NewReader(h.serializedEntity)))
	if err != nil {
		return "", nil, fmt.Errorf("could not read entity: %v", err)
	}
	pb := []byte(passphrase)
	if err := entity.PrivateKey.Decrypt(pb); err != nil {
		return "", nil, ErrWrongPassphrase
	}
	for _, sk := range entity.Subkeys {
		if err := sk.PrivateKey.Decrypt(pb); err != nil {
			return "", nil, ErrWrongPassphrase
		}
	}
	store, err := password.NewStore(h.baseDir, entity)
	if err != nil {
		return "", nil, fmt.Errorf("could not create password store: %v", err)
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
		store:       store,
		authedPaths: map[string]struct{}{},
	}
	sess.expirationTimer = time.AfterFunc(h.sessionDuration, func() { h.timeoutSession(sessID, sess) })
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

		// Only reset the timer if the user has completed U2F
		// authentication, to ensure that partially-authenticated users
		// can't keep a session open indefinitely.
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

// CloseSession closes an existing session, freeing all resources used by the
// session.
func (h *Handler) CloseSession(sessID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sess := h.sessions[sessID]; sess != nil {
		sess.expirationTimer.Stop()
		delete(h.sessions, sessID)
	}
}

func (h *Handler) timeoutSession(sessID string, sess *Session) {
	h.CloseSession(sessID)
	if !sess.IsU2FAuthenticated() {
		h.alert(alert.TIMEOUT_UNAUTHENTICATED, "Session timed out without completing U2F authentication.")
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
	h               *Handler
	store           *password.Store
	expirationTimer *time.Timer

	mu            sync.RWMutex // protects all fields below
	authedPaths   map[string]struct{}
	challenge     *u2f.Challenge
	challengePath string
}

// GetStore returns the password store associated with this session.
func (s *Session) GetStore() *password.Store {
	return s.store
}

// IsU2FAuthenticated determines if the user has authenticated with U2F for
// any path.
func (s *Session) IsU2FAuthenticated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.authedPaths) > 0
}

// IsU2FAuthenticatedFor determines if the user has authenticated with U2F for
// the given path.
func (s *Session) IsU2FAuthenticatedFor(path string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.authedPaths[path]
	return ok
}

// GenerateU2FChallenge generates a new U2F challenge for the given path.
// It replaces any previous U2F challenges that may exist for this or any other
// paths.
func (s *Session) GenerateU2FChallenge(path string) (*u2f.Challenge, error) {
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

// GetU2FChallenge gets the existing U2F challenge for the given path.
// It returns ErrNoChallenge if there is no existing U2F challenge for the
// given path.
func (s *Session) GetU2FChallenge(path string) (*u2f.Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.challengePath != path || s.challenge == nil {
		return nil, ErrNoChallenge
	}
	return s.challenge, nil
}

// AuthenticateU2FResponse authenticates the user for the given path with the
// given U2F signing response. It returns ErrNoChallenge if there is no
// existing challenge for the given path, and ErrU2FAuthenticationFailed if it
// was not possible to authenticate the user with the given U2F signing
// response.
func (s *Session) AuthenticateU2FResponse(path string, sr u2f.SignResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.challengePath != path || s.challenge == nil {
		return ErrNoChallenge
	}
	ctr := s.h.counters.Get(sr.KeyHandle)
	for _, reg := range s.h.registrations {
		if newCtr, err := reg.Authenticate(sr, *s.challenge, ctr); err == nil {
			// Successful authentication. Store counter before we allow progress.
			if err := s.h.counters.Set(sr.KeyHandle, newCtr); err != nil {
				return fmt.Errorf("could not set new counter value: %v", err)
			}

			if len(s.authedPaths) == 0 {
				s.h.alert(alert.LOGIN, fmt.Sprintf("New session authenticated."))
			}
			s.authedPaths[path] = struct{}{}
			s.challenge = nil
			s.challengePath = ""
			return nil
		}
	}
	return ErrU2FAuthenticationFailed
}

// GetRegistrations gets the set of registrations for U2F devices.
func (s *Session) GetRegistrations() []u2f.Registration {
	return s.h.registrations
}
