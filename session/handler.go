// Package session provides session-management functionality.
package session

import (
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tstranex/u2f"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

	"../password"
)

const (
	sessionIDLength = 16
)

var (
	ErrWrongPassphrase = errors.New("wrong passphrase")

	ErrNoSession = errors.New("no such session")
)

// Handler handles management of sessions, including creation, deletion, and
// timeout. It is safe for concurrent use from multiple goroutines.
type Handler struct {
	mu       sync.RWMutex        // protects sessions
	sessions map[string]*Session // by session ID

	sessionDuration  time.Duration // how long sessions last
	serializedEntity string        // entity used to encrypt/decrypt password entries
	baseDir          string        // base directory containing password entries
	appID            string        // U2F app ID
}

// NewHandler creates a new session handler.
func NewHandler(serializedEntity, baseDir, host string, sessionDuration time.Duration) (*Handler, error) {
	if sessionDuration <= 0 {
		return nil, errors.New("nonpositive session length")
	}

	return &Handler{
		sessions:         make(map[string]*Session),
		sessionDuration:  sessionDuration,
		serializedEntity: serializedEntity,
		baseDir:          filepath.Clean(baseDir),
		appID:            fmt.Sprintf("https://%s", host),
	}, nil
}

// CreateSession attempts to create a new session, using the given passphrase.
// It returns the new session's ID and the session, or ErrWrongPassphrase if
// authentication occurs, and other errors if they occur.
func (h *Handler) CreateSession(passphrase string) (string, *Session, error) {
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
	h.mu.Lock()
	defer h.mu.Unlock()
	var sessID string
	for {
		// This loop is overwhelmingly likely to run for 1 iteration.
		var sID [sessionIDLength]byte
		if _, err := rand.Read(sID[:]); err != nil {
			return "", nil, err
		}
		sessID = string(sID[:])
		if _, ok := h.sessions[sessID]; !ok {
			break
		}
	}

	// Start reaper timer and return.
	sess := &Session{
		h:               h,
		passwordStore:   store,
		expirationTimer: time.AfterFunc(h.sessionDuration, func() { h.CloseSession(sessID) }),
	}
	h.sessions[sessID] = sess
	return sessID, sess, nil
}

// GetSession gets an existing session if the session exists.  It returns
// ErrNoSession if the session does not exist. If the session does exist, its
// expiration timeout is reset.
func (h *Handler) GetSession(sessionID string) (*Session, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if sess := h.sessions[sessionID]; sess != nil {
		if sess.expirationTimer.Stop() {
			sess.expirationTimer.Reset(h.sessionDuration)
			return sess, nil
		}
	}
	return nil, ErrNoSession
}

// CloseSession closes an existing session, freeing all resources used by the
// session.
func (h *Handler) CloseSession(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sess := h.sessions[sessionID]; sess != nil {
		sess.expirationTimer.Stop()
		delete(h.sessions, sessionID)
	}
}

// Session stores all data associated with a given active user session.
// It is safe for concurrent use from multiple goroutines.
type Session struct {
	h               *Handler
	passwordStore   *password.Store
	expirationTimer *time.Timer

	challengeMu sync.RWMutex // protects challenge
	challenge   *u2f.Challenge
}

// GetStore returns the password store associated with this session.
func (s Session) GetStore() *password.Store {
	return s.passwordStore
}

// GenerateChallenge generates a new challenge for U2F registration/verification.
// This replaces any previous challenge that may exist.
func (s *Session) GenerateChallenge() (*u2f.Challenge, error) {
	c, err := u2f.NewChallenge(s.h.appID, []string{s.h.appID})
	if err != nil {
		return nil, fmt.Errorf("could not generate challenge: %v", err)
	}

	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	s.challenge = c
	return c, nil
}

// GetChallenge gets the current challenge for U2F registration/verification.
// It returns nil if there is no current challenge.
func (s Session) GetChallenge() *u2f.Challenge {
	s.challengeMu.RLock()
	defer s.challengeMu.RUnlock()
	return s.challenge
}
