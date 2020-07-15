// Package session provides session-management functionality.
package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/e3b0c442/warp"

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
	ErrMFARegistrationFailed   = errors.New("MFA registration failed")
)

// Handler handles management of sessions, including creation, deletion, and
// timeout. It is safe for concurrent use from multiple goroutines.
type Handler struct {
	mu       sync.RWMutex        // protects sessions
	sessions map[string]*Session // by session ID

	vault                    secret.Vault                         // locked password data
	sessionDuration          time.Duration                        // how long sessions last
	origin                   string                               // origin to use for MFA. (e.g. "https://example.com:8080")
	domain                   string                               // domain to use for MFA (e.g. "example.com")
	mfaCredentials           map[string]warp.Credential           // registered MFA device credentials
	mfaCredentialDescriptors []warp.PublicKeyCredentialDescriptor // registerd MFA device credential descriptors
	rateLimiter              rate.Limiter                         // rate limiter for creating new sessions
	alerter                  alert.Alerter                        // used to notify user of alerts
}

type credential struct {
	h *Handler
	c *warp.AttestedCredentialData
}

var _ warp.Credential = credential{}

func (c credential) Owner() warp.User            { return user{c.h} }
func (c credential) CredentialID() []byte        { return c.c.CredentialID }
func (c credential) CredentialPublicKey() []byte { return c.c.CredentialPublicKey }
func (c credential) CredentialSignCount() uint   { return 0 }

type relyingParty struct{ h *Handler }

var _ warp.RelyingParty = relyingParty{}

func (rp relyingParty) EntityID() string   { return rp.h.domain }
func (rp relyingParty) EntityName() string { return "Harpocrates" }
func (rp relyingParty) EntityIcon() string { return fmt.Sprintf("%s/favicon.ico", rp.h.origin) }
func (rp relyingParty) Origin() string     { return rp.h.origin }

type user struct{ h *Handler }

var _ warp.User = user{}

func (u user) EntityName() string                      { return "" }
func (u user) EntityIcon() string                      { return "" }
func (u user) EntityID() []byte                        { return []byte{} }
func (u user) EntityDisplayName() string               { return "" }
func (u user) Credentials() map[string]warp.Credential { return u.h.mfaCredentials }

// NewHandler creates a new session handler.
func NewHandler(vault secret.Vault, origin string, mfaCredentials []string, sessionDuration time.Duration, newSessionRate float64, alerter alert.Alerter) (*Handler, error) {
	if sessionDuration <= 0 {
		return nil, errors.New("nonpositive session length")
	}

	u, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse origin: %w", err)
	}
	domain := u.Hostname()

	h := &Handler{
		sessions:        map[string]*Session{},
		vault:           vault,
		sessionDuration: sessionDuration,
		origin:          origin,
		domain:          domain,
		mfaCredentials:  map[string]warp.Credential{},
		rateLimiter:     rate.NewLimiter(newSessionRate, 1),
		alerter:         alerter,
	}

	for i, c := range mfaCredentials {
		cred, err := decodeCredential(c)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse registration %d: %w", i, err)
		}
		h.mfaCredentials[base64.RawURLEncoding.EncodeToString(cred.CredentialID)] = credential{h, cred}
		h.mfaCredentialDescriptors = append(h.mfaCredentialDescriptors, warp.PublicKeyCredentialDescriptor{
			Type: warp.PublicKey,
			ID:   cred.CredentialID,
		})
	}
	return h, nil
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
		return "", nil, fmt.Errorf("couldn't wait for rate limiter: %w", err)
	}

	// Get a secret.Store using the supplied passphrase.
	store, err := h.vault.Unlock(passphrase)
	if err == secret.ErrWrongPassphrase {
		return "", nil, err
	} else if err != nil {
		return "", nil, fmt.Errorf("couldn't unlock vault: %w", err)
	}

	// Generate session ID.
	var sID [sessionIDLength]byte
	if _, err := rand.Read(sID[:]); err != nil {
		return "", nil, fmt.Errorf("couldn't generate session ID: %w", err)
	}
	sessID := string(sID[:])

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ok := h.sessions[sessID]; ok; _, ok = h.sessions[sessID] {
		// This loop body is overwhelmingly likely to never run.
		if _, err := rand.Read(sID[:]); err != nil {
			return "", nil, fmt.Errorf("couldn't generate session ID: %w", err)
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
			log.Printf("Could not send alert (%s %q): %w", code, details, err)
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

	mu               sync.RWMutex // protects all fields below
	mfaRegChallenge  *warp.PublicKeyCredentialCreationOptions
	authedPaths      map[string]struct{}
	mfaChallengePath string
	mfaChallenge     *warp.PublicKeyCredentialRequestOptions
}

// Close closes this existing session, freeing all resources used by the session.
func (s *Session) Close() { s.h.closeSession(s.id) }

// GetStore returns the password store associated with this session.
func (s *Session) GetStore() secret.Store { return s.store }

// GenerateMFARegistrationChallenge generates a new multi-factor authentication registration
// challenge. It replaces any previous registration challenge that may exist.
func (s *Session) GenerateMFARegistrationChallenge() (*warp.PublicKeyCredentialCreationOptions, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	opts, err := warp.StartRegistration(relyingParty{s.h}, user{s.h})
	if err != nil {
		return nil, fmt.Errorf("couldn't generate MFA registration challenge: %w", err)
	}
	s.mfaRegChallenge = opts
	return opts, nil
}

// GetMFARegistrationChallenge gets the existing multi-factor authentication registration challenge.
// It returns ErrNoChallenge if there is no existing registration challenge.
func (s *Session) GetMFARegistrationChallenge() (*warp.PublicKeyCredentialCreationOptions, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.mfaRegChallenge == nil {
		return nil, ErrNoChallenge
	}
	return s.mfaRegChallenge, nil
}

// CompleteMFARegistration completes registration of a new multi-factor authentication device with
// the given registration response. It returns ErrNoChallenge if there is no existing challenge for
// the given path, and ErrMFARegistrationFailed if it was not possible to complete registration with
// the given response. On success, a credential is returned as would be passed to NewHandler.
func (s *Session) CompleteMFARegistration(cred *warp.AttestationPublicKeyCredential) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mfaRegChallenge == nil {
		return "", ErrNoChallenge
	}
	att, err := warp.FinishRegistration(relyingParty{s.h}, func(credID []byte) (warp.Credential, error) {
		c, ok := s.h.mfaCredentials[base64.RawURLEncoding.EncodeToString(credID)]
		if !ok {
			return nil, errors.New("no credential")
		}
		return c, nil
	}, s.mfaRegChallenge, cred)
	if err != nil {
		return "", ErrMFARegistrationFailed
	}
	encodedCred, err := encodeCredential(&att.AuthData.AttestedCredentialData)
	if err != nil {
		return "", fmt.Errorf("couldn't encode credential: %w", err)
	}
	s.mfaRegChallenge = nil
	return encodedCred, nil
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
func (s *Session) GenerateMFAChallenge(path string) (*warp.PublicKeyCredentialRequestOptions, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	opts, err := warp.StartAuthentication(warp.AllowCredentials(s.h.mfaCredentialDescriptors), warp.RelyingPartyID(s.h.domain))
	if err != nil {
		return nil, fmt.Errorf("couldn't generate MFA challenge: %w", err)
	}
	s.mfaChallengePath = path
	s.mfaChallenge = opts
	return opts, nil
}

// GetMFAChallenge gets the existing multi-factor authentication challenge for the given path. It
// returns ErrNoChallenge if there is no existing MFA challenge for the given path.
func (s *Session) GetMFAChallenge(path string) (*warp.PublicKeyCredentialRequestOptions, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.mfaChallengePath != path || s.mfaChallenge == nil {
		return nil, ErrNoChallenge
	}
	return s.mfaChallenge, nil
}

// AuthenticateMFAResponse authenticates the user for the given path with the given multi-factor
// authentication signing response. It returns ErrNoChallenge if there is no existing challenge for
// the given path, and ErrMFAAuthenticationFailed if it was not possible to authenticate the user
// with the given MFA signing response.
func (s *Session) AuthenticateMFAResponse(path string, cred *warp.AssertionPublicKeyCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mfaChallengePath != path || s.mfaChallenge == nil {
		return ErrNoChallenge
	}

	if _, err := warp.FinishAuthentication(relyingParty{s.h}, func(_ []byte) (warp.User, error) { return user{s.h}, nil }, s.mfaChallenge, cred); err != nil {
		return ErrMFAAuthenticationFailed
	}

	if len(s.authedPaths) == 0 {
		s.h.alert(alert.LOGIN, fmt.Sprintf("New session authenticated."))
	}
	s.authedPaths[path] = struct{}{}
	s.mfaChallengePath = ""
	s.mfaChallenge = nil
	return nil
}

// HasRegisteredMFADevice returns true if & only if there is at least one registered MFA deviec.
func (s *Session) HasRegisteredMFADevice() bool { return len(s.h.mfaCredentials) > 0 }

func encodeCredential(cred *warp.AttestedCredentialData) (string, error) {
	var buf bytes.Buffer
	if err := cred.Encode(&buf); err != nil {
		return "", fmt.Errorf("couldn't encode credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

func decodeCredential(encodedCred string) (*warp.AttestedCredentialData, error) {
	credBytes, err := base64.RawURLEncoding.DecodeString(encodedCred)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode credential: %w", err)
	}
	cred := &warp.AttestedCredentialData{}
	if err := cred.Decode(bytes.NewReader(credBytes)); err != nil {
		return nil, fmt.Errorf("couldn't parse registration: %w", err)
	}
	return cred, nil
}
