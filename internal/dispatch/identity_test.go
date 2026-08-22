package dispatch

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// An identity survives a restart. If it did not, every peer's pin would break
// on reboot and the feature would be unusable.
func TestIdentityIsStableAcrossLoads(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Public().Equal(second.Public()) {
		t.Error("reloading produced a different key")
	}
	if first.PeerID() != second.PeerID() {
		t.Errorf("peer ID changed across loads: %q then %q", first.PeerID(), second.PeerID())
	}
}

// Two installs must not collide.
func TestIdentitiesAreDistinct(t *testing.T) {
	a, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a.PeerID() == b.PeerID() {
		t.Fatal("two fresh identities share a peer ID")
	}
	if KeyTag(a.Public()) == KeyTag(b.Public()) {
		t.Error("two fresh identities share a key tag")
	}
}

// The key is a secret. Anything wider than 0600 means another account on this
// machine can impersonate this instance to every peer it has paired with.
func TestKeyIsWrittenPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not the access control model on Windows")
	}
	dir := t.TempDir()
	if _, err := LoadIdentity(dir); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(Dir(dir), keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key mode = %04o, want 0600", got)
	}

	// The containing directory should not be traversable either.
	dinfo, err := os.Stat(Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := dinfo.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("dispatch dir mode = %04o, want no group or other access", got)
	}
}

// A key that has become readable by others is a key to replace. Using it
// silently would hide exactly the fact the user needs to act on.
func TestLooseKeyPermissionsRefuseToLoad(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not the access control model on Windows")
	}
	dir := t.TempDir()
	if _, err := LoadIdentity(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(Dir(dir), keyFileName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadIdentity(dir)
	if err == nil {
		t.Fatal("a world-readable key loaded without complaint")
	}
	// The message has to tell the user what to do, not merely that something
	// is wrong.
	for _, want := range []string{"0644", "0600", "re-pair"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// Nothing may be created until the feature is enabled: an install that never
// turns the Dispatch on must not have a private key sitting on disk.
func TestNoKeyMaterialUntilLoaded(t *testing.T) {
	dir := t.TempDir()
	if _, err := os.Stat(Dir(dir)); !os.IsNotExist(err) {
		t.Fatalf("dispatch dir exists before LoadIdentity: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("data dir is not empty before the feature is enabled: %v", entries)
	}
}

// The certificate is a container; the pinned key is the identity. A peer must
// be able to recover exactly the key it pinned from the certificate presented.
func TestCertificateCarriesTheIdentityKey(t *testing.T) {
	id, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	der, err := id.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("certificate public key is %T, want ed25519", cert.PublicKey)
	}
	if !pub.Equal(id.Public()) {
		t.Error("certificate does not carry the identity key")
	}
	if PeerIDFor(pub) != id.PeerID() {
		t.Error("peer ID derived from the certificate differs from our own")
	}
}

// A regenerated certificate over the same key must not change the identity, or
// every peer would have to re-pair whenever a certificate was replaced.
func TestNewCertificateKeepsTheSameIdentity(t *testing.T) {
	id, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := id.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := id.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := x509.ParseCertificate(first)
	c2, _ := x509.ParseCertificate(second)

	if c1.SerialNumber.Cmp(c2.SerialNumber) == 0 {
		t.Error("two certificates share a serial number")
	}
	if PeerIDFor(c1.PublicKey.(ed25519.PublicKey)) != PeerIDFor(c2.PublicKey.(ed25519.PublicKey)) {
		t.Error("regenerating the certificate changed the identity")
	}
}

// A peer ID is read aloud and compared by eye, so its shape matters.
func TestPeerIDShape(t *testing.T) {
	id, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pid := id.PeerID()
	if len(pid) != PeerIDLen {
		t.Errorf("peer ID %q is %d characters, want %d", pid, len(pid), PeerIDLen)
	}
	// It must group evenly, because it is compared by eye across two screens.
	groups := strings.Split(Fingerprint(pid), "-")
	if len(groups) != 5 {
		t.Errorf("peer ID %q renders as %d groups, want 5", pid, len(groups))
	}
	for _, g := range groups {
		if len(g) != 5 {
			t.Errorf("group %q is %d characters, want 5", g, len(g))
		}
	}
	for _, r := range pid {
		if !strings.ContainsRune(crockfordAlphabet, r) {
			t.Errorf("peer ID %q contains %q, which is not in the alphabet", pid, r)
		}
	}
	// The characters most often misread must not appear at all.
	if strings.ContainsAny(pid, "ILOU") {
		t.Errorf("peer ID %q contains an ambiguous character", pid)
	}
}

func TestFingerprintGroups(t *testing.T) {
	got := Fingerprint("ABCDEFGHJKMNPQRSTVWXYZ0123")
	want := "ABCDE-FGHJK-MNPQR-STVWX-YZ012-3"
	if got != want {
		t.Errorf("Fingerprint = %q, want %q", got, want)
	}
}

// Crockford encoding must be deterministic and injective over the inputs used.
func TestCrockfordIsDeterministicAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		got := crockford(b)
		if again := crockford(b); got != again {
			t.Fatalf("crockford is not deterministic: %q then %q", got, again)
		}
		if seen[got] {
			t.Fatalf("collision on %q", got)
		}
		seen[got] = true
	}
}

// A corrupted or truncated key file must produce a clear error rather than a
// panic or a silently regenerated identity, regenerating would silently break
// every existing pairing.
func TestCorruptKeyIsAnErrorNotAFreshIdentity(t *testing.T) {
	dir := t.TempDir()
	original, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(Dir(dir), keyFileName)
	if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\nnonsense\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadIdentity(dir)
	if err == nil {
		if got.PeerID() == original.PeerID() {
			t.Fatal("a corrupt key somehow produced the original identity")
		}
		t.Fatal("a corrupt key was silently replaced with a new identity, breaking every pairing")
	}
}
