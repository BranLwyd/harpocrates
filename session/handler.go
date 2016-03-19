// Package session provides session-management functionality.
package session

import (
	"bytes"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

	"../password"
)

const (
	sessionIDLength = 16
)

// Handler handles management of sessions, including creation, deletion, and
// timeout. It is safe for concurrent use from multiple goroutines.
type Handler struct {
	mu               sync.RWMutex        // protects sessions
	sessions         map[string]*session // by session ID
	sessionDuration  time.Duration       // how long sessions last
	serializedEntity []byte              // entity used to encrypt/decrypt password entries
	baseDir          string              // base directory containing password entries
}

type session struct {
	passwordStore   *password.Store
	expirationTimer *time.Timer
}

// NewHandler creates a new session handler.
func NewHandler(serializedEntity []byte, baseDir string, sessionDuration time.Duration) (*Handler, error) {
	if sessionDuration <= 0 {
		return nil, errors.New("nonpositive session length")
	}

	return &Handler{
		sessions:         make(map[string]*session),
		sessionDuration:  sessionDuration,
		serializedEntity: serializedEntity,
		baseDir:          filepath.Clean(baseDir),
	}, nil
}

// CreateSession attempts to create a new session, using the given passphrase.
// It returns the new session's ID along with the session, or an error if
// authentication fails or some other error occurs.
func (h *Handler) CreateSession(passphrase []byte) (string, error) {
	// Read entity, decrypt keys using passphrase, create password store.
	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(h.serializedEntity)))
	if err != nil {
		return "", err
	}
	if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
		return "", err
	}
	for _, sk := range entity.Subkeys {
		if err := sk.PrivateKey.Decrypt(passphrase); err != nil {
			return "", err
		}
	}
	store, err := password.NewStore(h.baseDir, entity)
	if err != nil {
		return "", err
	}

	// Generate session ID.
	h.mu.Lock()
	defer h.mu.Unlock()
	var sessID string
	for {
		// This loop is overwhelmingly likely to run for 1 iteration.
		var sID [sessionIDLength]byte
		if _, err := rand.Read(sID[:]); err != nil {
			return "", err
		}
		sessID = string(sID[:])
		if _, ok := h.sessions[sessID]; !ok {
			break
		}
	}

	// Start reaper goroutine and return.
	h.sessions[sessID] = &session{
		passwordStore:   store,
		expirationTimer: time.AfterFunc(h.sessionDuration, func() { h.CloseSession(sessID) }),
	}
	return sessID, nil
}

// GetPasswordStore gets an existing session's password store, if the session
// exists.  It returns nil if the session does not exist. If the session does
// exist, its expiration timeout is reset.
func (h *Handler) GetPasswordStore(sessionID string) *password.Store {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if sess := h.sessions[sessionID]; sess != nil {
		if sess.expirationTimer.Reset(h.sessionDuration) {
			return sess.passwordStore
		}
	}
	return nil
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
