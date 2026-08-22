package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/291-Group/LAN-Sheriff/internal/auth"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// AuthStatus is what the dashboard asks for before rendering anything, so it
// knows whether to show the setup screen, the login screen, or the app.
type AuthStatus struct {
	// Required reports whether this install protects itself with a password at
	// all. False for a loopback-only bind.
	Required bool `json:"required"`
	// NeedsSetup means no password exists yet and one must be created.
	NeedsSetup bool `json:"needs_setup"`
	// Authenticated reports whether the caller is signed in.
	Authenticated bool `json:"authenticated"`
	// Version and Build identify this install on the one screen that is shown
	// before anybody can sign in. A person looking at a login box has no other
	// way to tell what they are looking at, and a bug report from that screen
	// is otherwise unattributable to a build.
	Version string `json:"version,omitempty"`
	Build   string `json:"build,omitempty"`
	// LockedOut reports whether this client has failed too many logins.
	LockedOut bool `json:"locked_out"`
	// Exposed reports whether the server is reachable beyond this machine,
	// which the UI says out loud so nobody is surprised by their own exposure.
	Exposed        bool `json:"exposed"`
	MinPasswordLen int  `json:"min_password_len"`
}

func (s *Server) sessionToken(r *http.Request) string {
	c, err := r.Cookie(auth.SessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// authRoutes registers the endpoints reachable while signed out.
func (s *Server) authRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/auth/setup", s.handleAuthSetup)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, AuthStatus{
		Required:       s.Auth.Enabled() || s.Auth.NeedsSetup(),
		NeedsSetup:     s.Auth.NeedsSetup(),
		Authenticated:  s.authed(r),
		LockedOut:      s.Auth.LockedOut(r.RemoteAddr),
		Exposed:        s.Exposed,
		MinPasswordLen: auth.MinPasswordLength,
		Version:        s.Version,
		Build:          s.Build,
	})
}

// authed reports whether a request may see data.
func (s *Server) authed(r *http.Request) bool {
	if s.Auth.NeedsSetup() {
		return false
	}
	if !s.Auth.Enabled() {
		return true // loopback-only, no password in play
	}
	return s.Auth.Authenticated(s.sessionToken(r))
}

// passwordErrCode maps a validation failure to a code, so the UI can say which
// rule was broken in the viewer's language rather than echoing English.
func passwordErrCode(err error) string {
	if err == nil {
		return types.ErrBadRequest
	}
	if strings.Contains(err.Error(), "too long") {
		return types.ErrPasswordLong
	}
	return types.ErrPasswordShort
}

type passwordRequest struct {
	Password string `json:"password"`
}

func decodePassword(w http.ResponseWriter, r *http.Request) (string, bool) {
	// Bound the body: a password is short, and there is no reason to read a
	// megabyte to find that out.
	var req passwordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "could not read the request")
		return "", false
	}
	return req.Password, true
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.NeedsSetup() {
		writeErr(w, http.StatusConflict, types.ErrPasswordSet, "a password has already been set")
		return
	}
	password, ok := decodePassword(w, r)
	if !ok {
		return
	}

	// The NeedsSetup check above is a courtesy: it gives the ordinary "you have
	// already done this" case a clear answer without paying for a bcrypt hash
	// first. It is not what makes setup safe. SetInitialPassword re-checks under
	// its own lock, and that check is the one that decides, because two callers
	// can both pass the courtesy check before either of them stores anything.
	hash, err := s.Auth.SetInitialPassword(password)
	if errors.Is(err, auth.ErrPasswordAlreadySet) {
		writeErr(w, http.StatusConflict, types.ErrPasswordSet, "a password has already been set")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, passwordErrCode(err), err.Error())
		return
	}
	if s.SaveHash != nil {
		if err := s.SaveHash(hash); err != nil {
			writeErr(w, http.StatusInternalServerError, types.ErrInternal, "could not save the password: "+err.Error())
			return
		}
	}

	// Sign the user straight in rather than bouncing them to a login form for
	// the password they just chose.
	token, ok := s.Auth.StartSession()
	if !ok {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, "could not start a session")
		return
	}
	s.setSessionCookie(w, r, token)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.Auth.LockedOut(r.RemoteAddr) {
		writeErr(w, http.StatusTooManyRequests, types.ErrLockedOut,
			"too many failed attempts; wait a few minutes before trying again")
		return
	}
	password, ok := decodePassword(w, r)
	if !ok {
		return
	}

	token, ok := s.Auth.Login(r.RemoteAddr, password)
	if !ok {
		// Deliberately vague: distinguishing "wrong password" from anything
		// else tells an attacker more than it tells a user.
		writeErr(w, http.StatusUnauthorized, types.ErrWrongPassword, "incorrect password")
		return
	}
	s.setSessionCookie(w, r, token)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	s.Auth.Logout(s.sessionToken(r))
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		// Strict rather than Lax: nothing legitimately links into this
		// dashboard from another site, and Strict is what makes the session
		// cookie useless for cross-site request forgery.
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   int(s.Auth.SessionTTL().Seconds()),
	})
}

// RequireAuth wraps the data API so that nothing is served to a caller who is
// not signed in.
//
// The dashboard's own static assets stay public: they contain no data, and the
// login screen has to be able to style itself.
func (s *Server) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The endpoints that exist precisely to get you signed in.
		if strings.HasPrefix(r.URL.Path, "/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		if s.authed(r) {
			next.ServeHTTP(w, r)
			return
		}
		if s.Auth.NeedsSetup() {
			writeErr(w, http.StatusUnauthorized, types.ErrSetupRequired, "set a password first")
			return
		}
		writeErr(w, http.StatusUnauthorized, types.ErrAuthRequired, "authentication required")
	})
}
