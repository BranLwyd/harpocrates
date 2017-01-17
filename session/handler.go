// Package session provides session-management functionality.
package session

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
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

var (
	ErrWrongPassphrase = errors.New("wrong passphrase")

	ErrNoSession = errors.New("no such session")
)

// Handler handles management of sessions, including creation, deletion, and
// timeout. It is safe for concurrent use from multiple goroutines.
type Handler struct {
	mu               sync.RWMutex        // protects sessions
	sessions         map[string]*Session // by session ID
	sessionDuration  time.Duration       // how long sessions last
	serializedEntity []byte              // entity used to encrypt/decrypt password entries
	baseDir          string              // base directory containing password entries
}

// Session stores all data associated with a given active user session.
type Session struct {
	PasswordStore   *password.Store
	expirationTimer *time.Timer
}

// NewHandler creates a new session handler.
func NewHandler(serializedEntity []byte, baseDir string, sessionDuration time.Duration) (*Handler, error) {
	if sessionDuration <= 0 {
		return nil, errors.New("nonpositive session length")
	}

	return &Handler{
		sessions:         make(map[string]*Session),
		sessionDuration:  sessionDuration,
		serializedEntity: serializedEntity,
		baseDir:          filepath.Clean(baseDir),
	}, nil
}

// CreateSession attempts to create a new session, using the given passphrase.
// It returns the new session's ID, or ErrWrongPassphrase if authentication occurs,
// and other errors if they occur.
func (h *Handler) CreateSession(passphrase []byte) (string, error) {
	// Read entity, decrypt keys using passphrase, create password store.
	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(h.serializedEntity)))
	if err != nil {
		return "", err
	}
	if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
		return "", ErrWrongPassphrase
	}
	for _, sk := range entity.Subkeys {
		if err := sk.PrivateKey.Decrypt(passphrase); err != nil {
			return "", ErrWrongPassphrase
		}
	}
	store, err := password.NewStore(h.baseDir, entity)
	if err != nil {
		return "", fmt.Errorf("could not create password store: %v", err)
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
	h.sessions[sessID] = &Session{
		PasswordStore:   store,
		expirationTimer: time.AfterFunc(h.sessionDuration, func() { h.CloseSession(sessID) }),
	}
	return sessID, nil
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
