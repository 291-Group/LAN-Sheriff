package dispatch

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
)

// The join code, and the channel-bound proof that makes it safe.
//
// See docs/DISPATCH-PROTOCOL.md §5. The short version: the code carries a
// truncated hash of the displaying instance's public key and a single-use
// secret. The joining side checks the hash *before* disclosing anything, then
// both sides prove knowledge of the secret over a value derived from the
// completed TLS session. Because that value differs between the two connections
// an on-path attacker would have, a proof captured from one is worthless in the
// other.

// JoinCodeVersion is the current code generation. A code from a different
// generation is rejected outright rather than interpreted generously.
const JoinCodeVersion = 1

// Sizes of the code's fields, in bytes.
const (
	tagLen    = 8  // 64 bits of SPKI digest
	secretLen = 16 // 128 bits from crypto/rand
	// codeLen is the whole payload: one header byte, the tag, the secret.
	codeLen = 1 + tagLen + secretLen
	// codeChars is how many base32 characters that occupies. 25 bytes is 200
	// bits, which divides by 5 exactly, so there is no padding to strip.
	codeChars = codeLen * 8 / 5
)

// JoinCode is a pairing code as displayed by one instance and typed into
// another.
type JoinCode struct {
	Version uint8
	Tag     [tagLen]byte
	Secret  [secretLen]byte
}

// NewJoinCode mints a code for the instance holding pub.
//
// The secret is fresh for every code. A code is single-use and short-lived; the
// caller enforces both, because expiry is a property of the pairing session
// rather than of the code's bytes.
func NewJoinCode(pub ed25519.PublicKey) (JoinCode, error) {
	jc := JoinCode{Version: JoinCodeVersion, Tag: KeyTag(pub)}
	if _, err := rand.Read(jc.Secret[:]); err != nil {
		return JoinCode{}, fmt.Errorf("generating pairing secret: %w", err)
	}
	return jc, nil
}

// String renders the code for a human to copy: eight groups of five characters.
func (jc JoinCode) String() string {
	raw := make([]byte, 0, codeLen)
	// The low nibble is reserved and left zero, so the payload stays a whole
	// number of bytes and a future field has somewhere to go.
	raw = append(raw, jc.Version<<4)
	raw = append(raw, jc.Tag[:]...)
	raw = append(raw, jc.Secret[:]...)

	encoded := crockford(raw)
	var sb strings.Builder
	sb.Grow(len(encoded) + len(encoded)/5)
	for i, r := range encoded {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// Matches reports whether a public key is the one this code was minted for.
//
// Constant time, and used before the joining side discloses its proof, an
// attacker who fails this check learns nothing they can grind offline.
func (jc JoinCode) Matches(pub ed25519.PublicKey) bool {
	got := KeyTag(pub)
	return subtle.ConstantTimeCompare(got[:], jc.Tag[:]) == 1
}

// Errors a caller may want to distinguish when telling the user what went wrong.
var (
	ErrCodeLength  = errors.New("pairing code is the wrong length")
	ErrCodeChars   = errors.New("pairing code contains characters that are not part of a code")
	ErrCodeVersion = errors.New("pairing code is from a different version of LAN Sheriff")
)

// ParseJoinCode reads a code a person typed.
//
// Deliberately forgiving about presentation and unforgiving about content:
// separators, spaces and case are all ignored, and the letters most often
// confused for digits are folded (I and L to 1, O to zero) because a person
// copying from a screen will make exactly those substitutions. Anything else is
// an error rather than a guess.
func ParseJoinCode(s string) (JoinCode, error) {
	var cleaned strings.Builder
	cleaned.Grow(codeChars)
	for _, r := range s {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '_':
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}
		switch r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		if !strings.ContainsRune(crockfordAlphabet, r) {
			return JoinCode{}, fmt.Errorf("%w: %q", ErrCodeChars, r)
		}
		cleaned.WriteRune(r)
	}

	text := cleaned.String()
	if len(text) != codeChars {
		return JoinCode{}, fmt.Errorf("%w: got %d characters, want %d",
			ErrCodeLength, len(text), codeChars)
	}

	raw, err := decodeCrockford(text)
	if err != nil {
		return JoinCode{}, err
	}
	if len(raw) != codeLen {
		return JoinCode{}, ErrCodeLength
	}

	// **A wrong version number usually means this is not a code at all.**
	//
	// The version is four bits, so any forty valid characters produce some
	// version, and fifteen times in sixteen it will not be ours. Reporting that
	// as "the other machine is running a different version" sent a tester
	// hunting for a version mismatch that did not exist: what had actually
	// happened was a file path pasted into the code field, forty characters of
	// letters that decoded to a version nobody has ever shipped.
	//
	// So only a version adjacent to this one is reported as a version problem.
	// Anything else is what it almost certainly is: not a pairing code.
	jc := JoinCode{Version: raw[0] >> 4}
	if jc.Version != JoinCodeVersion {
		if jc.Version == JoinCodeVersion+1 || (JoinCodeVersion > 0 && jc.Version == JoinCodeVersion-1) {
			return JoinCode{}, fmt.Errorf("%w: code is version %d, this build speaks %d",
				ErrCodeVersion, jc.Version, JoinCodeVersion)
		}
		return JoinCode{}, fmt.Errorf("%w: decoded to version %d, which no release has used",
			ErrCodeChars, jc.Version)
	}
	copy(jc.Tag[:], raw[1:1+tagLen])
	copy(jc.Secret[:], raw[1+tagLen:])
	return jc, nil
}

// decodeCrockford reverses crockford. The input must already be normalized to
// the alphabet.
func decodeCrockford(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)*5/8)
	var acc, bits uint32
	for _, r := range s {
		idx := strings.IndexRune(crockfordAlphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("%w: %q", ErrCodeChars, r)
		}
		acc = acc<<5 | uint32(idx)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out, nil
}

// ExporterLabel is the RFC 5705 label for the pairing binding. It is part of the
// wire protocol: both sides must use the identical string or no proof will ever
// verify.
const ExporterLabel = "lan-sheriff/dispatch/pair/v1"

// PairProof computes the proof of knowledge of a pairing secret, bound to a
// specific TLS session and to the prover's own key.
//
// binding comes from tls.ConnectionState.ExportKeyingMaterial. Including it is
// the entire defence against an on-path attacker: two relayed connections have
// two different bindings, so a proof lifted from one does not verify in the
// other. Including the prover's public key stops a proof being reflected back at
// its sender.
func PairProof(secret [secretLen]byte, binding []byte, pub ed25519.PublicKey) []byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(binding)
	mac.Write(pub)
	return mac.Sum(nil)
}

// VerifyPairProof checks a proof in constant time.
func VerifyPairProof(secret [secretLen]byte, binding []byte, pub ed25519.PublicKey, proof []byte) bool {
	return hmac.Equal(PairProof(secret, binding, pub), proof)
}
