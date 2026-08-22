package auth

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func statFile(path string) (fs.FileInfo, error) { return os.Stat(path) }
func writeFile(path, content string) error      { return os.WriteFile(path, []byte(content), 0o600) }

const testPassword = "correct-horse-battery-staple"

func newTestAuth(t *testing.T) *Authenticator {
	t.Helper()
	a, err := New(testPassword, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestDisabledWithoutPassword(t *testing.T) {
	a, err := New("", time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Enabled() {
		t.Error("no password should mean authentication is disabled")
	}
	if a.NeedsSetup() {
		t.Error("setup should not be demanded until it is asked for")
	}
}

func TestSetupRequiredUntilPasswordSet(t *testing.T) {
	a, _ := New("", time.Hour)
	a.SetSetupRequired(true)

	if !a.NeedsSetup() {
		t.Fatal("setup should be required with no password")
	}
	if _, err := a.SetPassword(testPassword); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if a.NeedsSetup() {
		t.Error("setup should be satisfied once a password exists")
	}
	if !a.Enabled() {
		t.Error("authentication should be enabled once a password exists")
	}
}

func TestLogin(t *testing.T) {
	a := newTestAuth(t)

	if _, ok := a.Login("192.168.1.5:5000", "wrong"); ok {
		t.Error("the wrong password should not be accepted")
	}
	token, ok := a.Login("192.168.1.5:5000", testPassword)
	if !ok || token == "" {
		t.Fatal("the correct password should produce a session")
	}
	if !a.Authenticated(token) {
		t.Error("a fresh session should be valid")
	}
	if a.Authenticated("forged-token") {
		t.Error("a forged token must not be accepted")
	}
	if a.Authenticated("") {
		t.Error("an empty token must not be accepted")
	}
}

func TestLoginIssuesDistinctTokens(t *testing.T) {
	a := newTestAuth(t)
	first, _ := a.Login("192.168.1.5:5000", testPassword)
	second, _ := a.Login("192.168.1.6:5000", testPassword)
	if first == second {
		t.Error("each login must produce its own token")
	}
}

func TestSessionExpires(t *testing.T) {
	a, err := New(testPassword, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, ok := a.Login("192.168.1.5:5000", testPassword)
	if !ok {
		t.Fatal("login failed")
	}
	time.Sleep(40 * time.Millisecond)
	if a.Authenticated(token) {
		t.Error("an expired session must not grant access")
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	a := newTestAuth(t)
	token, _ := a.Login("192.168.1.5:5000", testPassword)
	a.Logout(token)
	if a.Authenticated(token) {
		t.Error("a session must not survive being logged out")
	}
}

func TestSetPasswordInvalidatesExistingSessions(t *testing.T) {
	// Changing the password is how someone locks out a session they no longer
	// trust, so the old sessions must not outlive it.
	a := newTestAuth(t)
	token, _ := a.Login("192.168.1.5:5000", testPassword)
	if !a.Authenticated(token) {
		t.Fatal("session should start valid")
	}
	if _, err := a.SetPassword("a-completely-different-one"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if a.Authenticated(token) {
		t.Error("sessions from before a password change must be invalidated")
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	a := newTestAuth(t)
	const addr = "192.168.1.5:5000"

	for i := 0; i < maxAttempts; i++ {
		if _, ok := a.Login(addr, "wrong"); ok {
			t.Fatal("the wrong password should never succeed")
		}
	}
	if !a.LockedOut(addr) {
		t.Fatal("the client should be locked out after repeated failures")
	}
	// Even the right password is refused while locked out, which is what makes
	// the lockout worth having.
	if _, ok := a.Login(addr, testPassword); ok {
		t.Error("a locked-out client should not be able to log in")
	}
	// A different address is unaffected.
	if a.LockedOut("192.168.1.99:5000") {
		t.Error("one client's failures must not lock out another")
	}
}

func TestLockoutIgnoresSourcePort(t *testing.T) {
	// Otherwise the rate limit is defeated by opening a new connection.
	a := newTestAuth(t)
	for i := 0; i < maxAttempts; i++ {
		a.Login("192.168.1.5:"+string(rune('0'+i))+"000", "wrong")
	}
	if !a.LockedOut("192.168.1.5:9999") {
		t.Error("the lockout should key on the host, not the port")
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "short", true},
		{"exactly the minimum", "12345678", false},
		{"comfortable", testPassword, false},
		{"over bcrypt's limit", string(make([]byte, MaxPasswordBytes+1)), true},
		{"at bcrypt's limit", string(make([]byte, MaxPasswordBytes)), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePassword(c.password)
			if (err != nil) != c.wantErr {
				t.Errorf("ValidatePassword() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestHashRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")

	if got := LoadHash(path); got != "" {
		t.Errorf("a missing file should read as no password, got %q", got)
	}

	a, _ := New("", time.Hour)
	hash, err := a.SetPassword(testPassword)
	if err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := SaveHash(path, hash); err != nil {
		t.Fatalf("SaveHash: %v", err)
	}

	// A restart reconstructs the authenticator from the stored hash, and the
	// original password must still work.
	restored, err := New(LoadHash(path), time.Hour)
	if err != nil {
		t.Fatalf("New from stored hash: %v", err)
	}
	if !restored.Enabled() {
		t.Fatal("the restored authenticator should have a password")
	}
	if _, ok := restored.Login("192.168.1.5:5000", testPassword); !ok {
		t.Error("the password should still work after a restart")
	}
}

func TestSaveHashIsOwnerOnly(t *testing.T) {
	// Windows does not model Unix permission bits; NTFS ACLs are the equivalent
	// control and are not reachable through os.FileMode. Asserting 0600 there
	// tests the platform, not the code.
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not the access control model on Windows")
	}
	path := filepath.Join(t.TempDir(), "password")
	if err := SaveHash(path, "$2a$10$abcdefghijklmnopqrstuv"); err != nil {
		t.Fatalf("SaveHash: %v", err)
	}
	info, err := statFile(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("password file mode = %o, want 600", perm)
	}
}

func TestGarbageIsNotTreatedAsAHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := writeFile(path, "not-a-bcrypt-hash"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := LoadHash(path); got != "" {
		t.Errorf("garbage should not be loaded as a hash, got %q", got)
	}
}
