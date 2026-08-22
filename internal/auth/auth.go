// Package auth password-protects the dashboard and API.
//
// The model follows LAN Orangutan's, so that the two siblings behave the same
// way: a fresh install has no password; when the server is reachable from the
// network, the first visitor must create one before anything is shown; after
// that a password is exchanged for a session cookie.
//
// Bound to loopback only, no password is required, a dashboard nothing else
// can reach is already private, and demanding a password would be friction with
// no benefit. That default is what keeps the zero-configuration promise intact.
//
// This differs from Orangutan in one respect: LAN Sheriff's front end is a
// single-page app, so setup and login are JSON endpoints the app calls rather
// than server-rendered form pages with redirects.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// SessionCookie holds the session token.
	SessionCookie = "sheriff_session"

	// MinPasswordLength is the shortest password setup accepts.
	MinPasswordLength = 8

	// MaxPasswordBytes is bcrypt's own limit. It is checked here so the failure
	// can be explained in plain terms rather than surfacing the library's
	// "password length exceeds 72 bytes".
	MaxPasswordBytes = 72

	// A client may fail this many logins within the window before being locked
	// out for the remainder of it.
	maxAttempts   = 5
	attemptWindow = 15 * time.Minute

	sessionIDBytes = 32

	// DefaultSessionTTL is how long a login lasts.
	DefaultSessionTTL = 7 * 24 * time.Hour
)

// Authenticator guards the API with a password.
type Authenticator struct {
	mu sync.Mutex

	// hash is the bcrypt hash of the current password; empty means none set.
	hash []byte

	// setupRequired means that, with no password set, the app should demand one
	// be created rather than allowing access.
	setupRequired bool

	sessionTTL time.Duration
	sessions   map[string]time.Time // token -> expiry
	attempts   map[string]*attemptRecord
}

type attemptRecord struct {
	count  int
	resets time.Time
}

// New creates an Authenticator. password may be a plaintext password or an
// existing bcrypt hash, so a stored hash can be passed straight through.
func New(password string, sessionTTL time.Duration) (*Authenticator, error) {
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	a := &Authenticator{
		sessionTTL: sessionTTL,
		sessions:   make(map[string]time.Time),
		attempts:   make(map[string]*attemptRecord),
	}
	if password == "" {
		return a, nil
	}
	hash, err := hashOrPassthrough(password)
	if err != nil {
		return nil, err
	}
	a.hash = hash
	return a, nil
}

func hashOrPassthrough(password string) ([]byte, error) {
	if IsHash(password) {
		return []byte(password), nil
	}
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// IsHash reports whether s looks like a bcrypt hash rather than a plaintext
// password.
func IsHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") ||
		strings.HasPrefix(s, "$2b$") ||
		strings.HasPrefix(s, "$2y$")
}

// Enabled reports whether a password is currently set.
func (a *Authenticator) Enabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.hash) > 0
}

// SetSetupRequired controls what happens when no password is set: either the
// user must create one, or access is open.
func (a *Authenticator) SetSetupRequired(required bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.setupRequired = required
}

// NeedsSetup reports whether a password still has to be created.
func (a *Authenticator) NeedsSetup() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.setupRequired && len(a.hash) == 0
}

// ErrPasswordAlreadySet reports that a password existed by the time a first-run
// setup got as far as storing one.
var ErrPasswordAlreadySet = errors.New("a password has already been set")

// SetInitialPassword establishes the *first* password, and only if there is not
// one already. This is what first-run setup must call.
//
// The check and the assignment happen under a single lock, which is the entire
// point of the method. Setup used to be a NeedsSetup call in the HTTP handler
// followed by a separate SetPassword, and those are two acquisitions with a gap
// between them. Twelve simultaneous setup requests all passed the check before
// any of them assigned: every one of the twelve was answered with success, the
// last to finish owned the password, and whoever arrived first was handed a
// session cookie that quietly stopped working some minutes later.
//
// On a bind reachable from the network that gap is the difference between two
// very different models. "Whoever gets there first wins" is the documented one,
// and it is defensible: the dashboard is unreachable until someone claims it.
// "Whoever is still in flight last wins" is what the code actually did, and it
// lets a stranger who merely holds requests open take an install away from the
// person sitting in front of the machine, while telling that person setup
// succeeded.
//
// bcrypt runs before the lock is taken rather than inside it. It costs roughly a
// tenth of a second, and holding the mutex across it would park every session
// check in the server behind an unauthenticated stranger's request, which is a
// denial of service offered up for free. The cost is that a loser has burned a
// hash for nothing, and that is exactly the right thing to waste.
func (a *Authenticator) SetInitialPassword(plaintext string) (string, error) {
	if err := ValidatePassword(plaintext); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.hash) > 0 {
		return "", ErrPasswordAlreadySet
	}
	a.hash = hash
	return string(hash), nil
}

// SetPassword replaces the password unconditionally, and returns its hash so the
// caller can persist it.
//
// For *changing* a password that already exists. First-run setup must use
// SetInitialPassword instead: this one overwrites whatever is there, so on the
// setup path it is the race described above. Any caller added here has to
// establish that the person asking already holds the current password.
func (a *Authenticator) SetPassword(plaintext string) (string, error) {
	if err := ValidatePassword(plaintext); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.hash = hash
	// Sessions issued before this password existed predate it and must not
	// outlive it.
	a.sessions = make(map[string]time.Time)
	return string(hash), nil
}

// ValidatePassword reports whether a proposed password is acceptable.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	// len counts bytes, which is what bcrypt limits; say so, because accented
	// and non-Latin characters take more than one byte each.
	if len(password) > MaxPasswordBytes {
		return fmt.Errorf(
			"password is too long: the limit is %d characters, and accented or non-Latin characters count as more than one",
			MaxPasswordBytes)
	}
	return nil
}

// Authenticated reports whether a request carries a valid, unexpired session.
func (a *Authenticator) Authenticated(token string) bool {
	if token == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	expiry, ok := a.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(a.sessions, token)
		return false
	}
	return true
}

// Login verifies a password and, on success, returns a new session token.
func (a *Authenticator) Login(remoteAddr, password string) (string, bool) {
	if !a.Enabled() {
		return "", false
	}
	key := clientKey(remoteAddr)
	if a.LockedOut(remoteAddr) {
		return "", false
	}

	a.mu.Lock()
	hash := append([]byte(nil), a.hash...)
	a.mu.Unlock()

	// bcrypt's comparison is constant-time with respect to the hash, so a wrong
	// password cannot be distinguished by timing.
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
		a.recordFailure(key)
		return "", false
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.attempts, key)
	a.pruneSessionsLocked()

	token, err := newToken()
	if err != nil {
		return "", false
	}
	a.sessions[token] = time.Now().Add(a.sessionTTL)
	return token, true
}

// StartSession issues a session without checking a password, so that completing
// setup signs the user in rather than bouncing them to a login form for the
// password they just chose.
func (a *Authenticator) StartSession() (string, bool) {
	token, err := newToken()
	if err != nil {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneSessionsLocked()
	a.sessions[token] = time.Now().Add(a.sessionTTL)
	return token, true
}

// Logout invalidates a session token.
func (a *Authenticator) Logout(token string) {
	if token == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}

// SessionTTL is how long a login lasts.
func (a *Authenticator) SessionTTL() time.Duration { return a.sessionTTL }

// LockedOut reports whether an address has failed too many logins recently.
func (a *Authenticator) LockedOut(remoteAddr string) bool {
	key := clientKey(remoteAddr)

	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.attempts[key]
	if !ok {
		return false
	}
	if time.Now().After(rec.resets) {
		delete(a.attempts, key)
		return false
	}
	return rec.count >= maxAttempts
}

func (a *Authenticator) recordFailure(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	rec, ok := a.attempts[key]
	if !ok || now.After(rec.resets) {
		a.attempts[key] = &attemptRecord{count: 1, resets: now.Add(attemptWindow)}
		return
	}
	rec.count++
}

// pruneSessionsLocked drops expired sessions so the map cannot grow without
// bound on a server left running for weeks. Callers must hold a.mu.
func (a *Authenticator) pruneSessionsLocked() {
	now := time.Now()
	for token, expiry := range a.sessions {
		if now.After(expiry) {
			delete(a.sessions, token)
		}
	}
}

// clientKey reduces a remote address to its host, so a client cannot dodge the
// login rate limit simply by using a fresh source port.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func newToken() (string, error) {
	buf := make([]byte, sessionIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// LoadHash reads a stored password hash. A missing file is not an error: it
// means no password has been set.
func LoadHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	hash := strings.TrimSpace(string(data))
	if !IsHash(hash) {
		return ""
	}
	return hash
}

// SaveHash writes a password hash to disk, readable only by its owner.
func SaveHash(path, hash string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("could not create the directory for the password file: %w", err)
	}
	if err := os.WriteFile(path, []byte(hash+"\n"), 0o600); err != nil {
		return fmt.Errorf("could not save the password: %w", err)
	}
	return nil
}
