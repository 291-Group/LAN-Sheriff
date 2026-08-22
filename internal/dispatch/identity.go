// Package dispatch implements The Dispatch: peer-to-peer sharing between
// LAN Sheriff installations that the operator has explicitly paired.
//
// The threat model and wire format are in docs/DISPATCH-PROTOCOL.md and were
// written and reviewed before any of this existed. Read that first, the
// reasoning behind several choices here is deliberately not repeated in the
// code, and a change that looks like a simplification may be removing a
// mitigation.
//
// Nothing in this package runs unless the user enables the feature.
package dispatch

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Identity is this instance's cryptographic identity on the Dispatch network.
//
// The key *is* the identity. The certificate is a container TLS requires, and is
// regenerated freely when it expires; peers pin the public key, so a new
// certificate over the same key needs no re-pairing.
type Identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// keyFileName is the private key's name inside the dispatch directory.
const keyFileName = "identity.key"

// keyPerm is the permission the key file must have. Checked on load, not only
// set on write: a key that has become world-readable is a key to replace, and
// silently using it would hide that.
const keyPerm os.FileMode = 0o600

// Dir returns the directory holding Dispatch state, given the data directory.
func Dir(dataDir string) string { return filepath.Join(dataDir, "dispatch") }

// LoadIdentity reads this instance's key, generating one if none exists.
//
// **Called only when the feature is enabled**, never at startup. An install that
// has never turned the Dispatch on should not have a private key on disk that
// could be stolen and used to impersonate it later.
func LoadIdentity(dataDir string) (*Identity, error) {
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("dispatch dir: %w", err)
	}
	path := filepath.Join(dir, keyFileName)

	switch id, err := readIdentity(path); {
	case err == nil:
		return id, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	return generateIdentity(path)
}

// LoadIdentityIfExists reads an existing identity without creating one.
//
// For callers that need to know whether peering has ever been enabled, the
// settings UI, and tests asserting that nothing was written, without the act of
// asking bringing a private key into existence.
func LoadIdentityIfExists(dataDir string) (*Identity, error) {
	return readIdentity(filepath.Join(Dir(dataDir), keyFileName))
}

// readIdentity loads an existing key, refusing one with loose permissions.
func readIdentity(path string) (*Identity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// Windows does not model Unix permission bits, so the check would always
	// fail there and tell the user nothing true. NTFS ACLs are the equivalent
	// control and are not reachable through os.FileMode.
	if runtime.GOOS != "windows" && info.Mode().Perm() != keyPerm {
		return nil, fmt.Errorf(
			"dispatch key %s has permissions %04o, want %04o; "+
				"delete it and re-pair, since a key others could read must be considered compromised",
			path, info.Mode().Perm(), keyPerm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("dispatch key %s is not a PEM private key", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing dispatch key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("dispatch key %s is %T, want ed25519", path, key)
	}
	return &Identity{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// generateIdentity creates a new key and writes it with a restrictive mode.
func generateIdentity(path string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating dispatch key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	// Written through a temporary file created with the final permissions, so
	// the key is never briefly readable at the real path under a wider mode.
	if err := writeAtomicPerm(path, encoded, keyPerm); err != nil {
		return nil, fmt.Errorf("writing dispatch key: %w", err)
	}
	return &Identity{priv: priv, pub: pub}, nil
}

// writeAtomicPerm writes a file atomically with an exact permission mode.
func writeAtomicPerm(path string, b []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// CreateTemp uses 0600 already, but the mode is set explicitly rather than
	// inherited, so this stays correct if that ever changes.
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Public returns the public key peers pin.
func (id *Identity) Public() ed25519.PublicKey { return id.pub }

// PeerIDLen is the peer ID's length in characters.
//
// Twenty-five, not twenty-six, so it divides into exactly five groups of five
// with nothing left over. This is a string a person compares across two screens,
// and a trailing group of one invites the eye to skip it. The cost is three bits
// of a digest that has 125 to spare.
const PeerIDLen = 25

// PeerID is the stable identifier for this instance: the leading bits of
// SHA-256 over the SPKI-encoded public key.
//
// Over the SPKI encoding rather than the raw key bytes so that the identifier
// is well defined if another key type is ever supported, and so it matches what
// a peer computes from the certificate it received.
//
// This is an identifier, not a security control. Nothing is authorized by
// matching a peer ID: authorization is the pinned key, compared in full.
func (id *Identity) PeerID() string { return PeerIDFor(id.pub) }

// PeerIDFor derives a peer ID from a public key.
func PeerIDFor(pub ed25519.PublicKey) string {
	sum := spkiDigest(pub)
	return crockford(sum[:16])[:PeerIDLen]
}

// spkiDigest hashes the SPKI encoding of a public key. A key that cannot be
// marshalled is a programming error rather than a runtime condition, the only
// keys reaching here come from ed25519.GenerateKey or a parsed certificate.
func spkiDigest(pub ed25519.PublicKey) [32]byte {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic("dispatch: marshalling an ed25519 public key: " + err.Error())
	}
	return sha256.Sum256(spki)
}

// KeyTag is the 64-bit truncation of the SPKI digest carried in a join code, so
// the joining side can reject the wrong machine before proving anything to it.
//
// Truncation is safe here only because the pairing proof is bound to the TLS
// session (see the protocol document, §5): the tag defends against an honest
// mistake and an online guess, not against an offline search.
func KeyTag(pub ed25519.PublicKey) [8]byte {
	sum := spkiDigest(pub)
	var tag [8]byte
	copy(tag[:], sum[:8])
	return tag
}

// Fingerprint renders a peer ID as five groups of five characters, for a person
// comparing two screens.
func Fingerprint(peerID string) string {
	var sb strings.Builder
	for i, r := range peerID {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// crockfordAlphabet omits I, L, O and U: the first three because they are
// misread as 1 and 0, and U so that no accidental word needs apologising for.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// crockford encodes bytes in Crockford base32, without padding.
func crockford(b []byte) string {
	var sb strings.Builder
	sb.Grow((len(b)*8 + 4) / 5)
	var acc, bits uint32
	for _, c := range b {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(crockfordAlphabet[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(crockfordAlphabet[(acc<<(5-bits))&31])
	}
	return sb.String()
}

// certLifetime is how long a generated certificate is valid.
//
// Long, because expiry is not a security control here: the pinned key is. A
// short lifetime would only produce avoidable failures on a machine that was
// switched off for a while.
const certLifetime = 10 * 365 * 24 * time.Hour

// Certificate builds the self-signed certificate this identity presents.
//
// Everything a normal certificate carries for the benefit of a verifier is
// absent or arbitrary, there is no name to validate, no chain to build, and no
// CA. Peers compare the public key against the one pinned at pairing and ignore
// the rest.
func (id *Identity) Certificate() (certDER []byte, err error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "lan-sheriff dispatch " + id.PeerID()},
		NotBefore:    time.Now().Add(-time.Hour), // tolerate modest clock skew
		NotAfter:     time.Now().Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.pub, id.priv)
}
