// Package session provides session-management functionality.
package session

import (
	"crypto/rand"
	"encoding/base64"
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
}

// NewHandler creates a new session handler.
func NewHandler(serializedEntity, baseDir, host string, registrations []string, sessionDuration time.Duration, cs *CounterStore) (*Handler, error) {
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
			return "", nil, fmt.Errorf("could not generate session ID: %v", err)
		}
		sessID = string(sID[:])
		if _, ok := h.sessions[sessID]; !ok {
			break
		}
	}

	// Start reaper timer and return.
	state := U2F_REQUIRED
	if len(h.registrations) == 0 {
		state = AUTHENTICATED
	}
	sess := &Session{
		h:               h,
		passwordStore:   store,
		state:           state,
		expirationTimer: time.AfterFunc(h.sessionDuration, func() { h.CloseSession(sessID) }),
	}
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
		if sess.state == AUTHENTICATED {
			if sess.expirationTimer.Stop() {
				sess.expirationTimer.Reset(h.sessionDuration)
				return sess, nil
			}
		} else {
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

// state represents the possible states of an existing session.
// Sessions aren't created until password authentication is successful,
// so there is no state for requiring password authentication.
type State uint8

const (
	U2F_REQUIRED State = iota
	AUTHENTICATED
)

func (s State) String() string {
	switch s {
	case U2F_REQUIRED:
		return "U2F_REQUIRED"
	case AUTHENTICATED:
		return "AUTHENTICATED"
	default:
		return "UNKNOWN"
	}
}

// Session stores all data associated with a given active user session.
// It is safe for concurrent use from multiple goroutines.
type Session struct {
	h               *Handler
	passwordStore   *password.Store
	expirationTimer *time.Timer

	mu        sync.RWMutex // protects state, challenge
	state     State
	challenge *u2f.Challenge
}

// GetStore returns the password store associated with this session.  The
// session must be in state AUTHENTICATED.
func (s Session) GetStore() (*password.Store, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state != AUTHENTICATED {
		return nil, fmt.Errorf("in state %s, expected state AUTHENTICATED", s.state)
	}
	return s.passwordStore, nil
}

func (s Session) GetState() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Session) U2FAuthenticate(sr u2f.SignResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != U2F_REQUIRED {
		return fmt.Errorf("in state %s, expected state U2F_REQUIRED", s.state)
	}
	if s.challenge == nil {
		return ErrNoChallenge
	}
	ctr := s.h.counters.Get(sr.KeyHandle)
	for _, reg := range s.h.registrations {
		if newCtr, err := reg.Authenticate(sr, *s.challenge, ctr); err == nil {
			// Successful authentication. Store counter before we allow progress.
			if err := s.h.counters.Set(sr.KeyHandle, newCtr); err != nil {
				return fmt.Errorf("could not set new counter value: %v", err)
			}

			s.state = AUTHENTICATED
			s.challenge = nil
			return nil
		}
	}
	return ErrU2FAuthenticationFailed
}

func (s *Session) generateChallenge(requiredState State) (*u2f.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != requiredState {
		return nil, fmt.Errorf("in state %s, expected state %s", s.state, requiredState)
	}
	c, err := u2f.NewChallenge(s.h.appID, []string{s.h.appID})
	if err != nil {
		return nil, fmt.Errorf("could not generate challenge: %v", err)
	}
	s.challenge = c
	return c, nil
}

func (s Session) getChallenge(requiredState State) (*u2f.Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state != requiredState {
		return nil, fmt.Errorf("in state %s, expected state %s", s.state, requiredState)
	}
	if s.challenge == nil {
		return nil, ErrNoChallenge
	}
	return s.challenge, nil
}

// GenerateAuthenticateChallenge generates a new challenge for U2F
// authentication. This replaces any previous challenge that may exist. The
// session must be in state U2F_REQUIRED.
func (s *Session) GenerateAuthenticateChallenge() (*u2f.Challenge, error) {
	return s.generateChallenge(U2F_REQUIRED)
}

// GetAuthenticateChallenge gets the current challenge for U2F authentication.
// It returns ErrNoChallenge if there is no current challenge. The session must
// be in state U2F_REQUIRED.
func (s Session) GetAuthenticateChallenge() (*u2f.Challenge, error) {
	return s.getChallenge(U2F_REQUIRED)
}

// GenerateRegisterChallenge generates a new challenge for U2F registration.
// This replaces any previous challenge that may exist.  The session must be in
// state AUTHENTICATED.
func (s *Session) GenerateRegisterChallenge() (*u2f.Challenge, error) {
	return s.generateChallenge(AUTHENTICATED)
}

// GetRegisterChallenge gets the current challenge for U2F registration.  It
// returns ErrNoChallenge if there is no current challenge.  The session must
// be in state AUTHENTICATED.
func (s Session) GetRegisterChallenge() (*u2f.Challenge, error) {
	return s.getChallenge(AUTHENTICATED)
}

// GetRegistrations gets the set of registrations for U2F devices.
func (s Session) GetRegistrations() []u2f.Registration {
	return s.h.registrations
}
