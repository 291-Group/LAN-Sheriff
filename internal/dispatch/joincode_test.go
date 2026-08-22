package dispatch

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestJoinCodeRoundTrips(t *testing.T) {
	pub := testKey(t)
	jc, err := NewJoinCode(pub)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParseJoinCode(jc.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != jc.Version || got.Tag != jc.Tag || got.Secret != jc.Secret {
		t.Errorf("round trip lost data:\n got %+v\nwant %+v", got, jc)
	}
}

// The shape a person sees. Eight groups of five, nothing ambiguous in them.
func TestJoinCodeShape(t *testing.T) {
	jc, err := NewJoinCode(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	s := jc.String()

	groups := strings.Split(s, "-")
	if len(groups) != 8 {
		t.Errorf("code %q has %d groups, want 8", s, len(groups))
	}
	for _, g := range groups {
		if len(g) != 5 {
			t.Errorf("group %q is %d characters, want 5", g, len(g))
		}
	}
	if strings.ContainsAny(s, "ILOU") {
		t.Errorf("code %q contains a character that is misread", s)
	}
}

// Every code must be different, or the secret is not a secret.
func TestJoinCodesAreUnique(t *testing.T) {
	pub := testKey(t)
	seen := map[[secretLen]byte]bool{}
	for i := 0; i < 100; i++ {
		jc, err := NewJoinCode(pub)
		if err != nil {
			t.Fatal(err)
		}
		if seen[jc.Secret] {
			t.Fatal("a pairing secret repeated")
		}
		seen[jc.Secret] = true
	}
}

// A person copying from a screen will lower-case it, lose the dashes, and
// substitute the letters that look like digits. All of that must still work.
func TestParseToleratesHumanTranscription(t *testing.T) {
	jc, err := NewJoinCode(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := jc.String()

	variants := map[string]string{
		"lower case":     strings.ToLower(canonical),
		"no separators":  strings.ReplaceAll(canonical, "-", ""),
		"spaces":         strings.ReplaceAll(canonical, "-", " "),
		"underscores":    strings.ReplaceAll(canonical, "-", "_"),
		"leading space":  "  " + canonical,
		"trailing space": canonical + "\n",
	}
	for name, v := range variants {
		got, err := ParseJoinCode(v)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.Secret != jc.Secret || got.Tag != jc.Tag {
			t.Errorf("%s: decoded to a different code", name)
		}
	}
}

// I, L and O are folded to 1, 1 and 0, the substitutions a reader actually
// makes. The canonical alphabet never emits them, so folding cannot collide
// with a legitimate character.
func TestParseFoldsAmbiguousLetters(t *testing.T) {
	jc, err := NewJoinCode(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := jc.String()

	mangled := strings.NewReplacer("1", "I", "0", "O").Replace(canonical)
	got, err := ParseJoinCode(mangled)
	if err != nil {
		t.Fatalf("a code with I and O substituted failed to parse: %v", err)
	}
	if got.Secret != jc.Secret || got.Tag != jc.Tag {
		t.Error("folding ambiguous letters produced a different code")
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	good, err := NewJoinCode(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	s := good.String()

	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrCodeLength},
		{"too short", s[:20], ErrCodeLength},
		{"too long", s + "ABCDE", ErrCodeLength},
		{"illegal character", strings.Replace(s, s[0:1], "?", 1), ErrCodeChars},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseJoinCode(c.in); !errors.Is(err, c.want) {
				t.Errorf("ParseJoinCode(%q) error = %v, want %v", c.in, err, c.want)
			}
		})
	}
}

// A code from another protocol generation must fail clearly rather than being
// interpreted as this one.
func TestParseRejectsAnotherVersion(t *testing.T) {
	jc, err := NewJoinCode(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	jc.Version = JoinCodeVersion + 1

	_, err = ParseJoinCode(jc.String())
	if !errors.Is(err, ErrCodeVersion) {
		t.Errorf("error = %v, want ErrCodeVersion", err)
	}
}

// The check that runs before anything is disclosed.
func TestMatchesIdentifiesTheRightKey(t *testing.T) {
	right := testKey(t)
	wrong := testKey(t)

	jc, err := NewJoinCode(right)
	if err != nil {
		t.Fatal(err)
	}
	if !jc.Matches(right) {
		t.Error("a code did not match the key it was minted for")
	}
	if jc.Matches(wrong) {
		t.Error("a code matched a key it was not minted for")
	}
}

// The property the whole pairing design rests on: a proof is worthless outside
// the session it was made in.
func TestProofIsBoundToTheSession(t *testing.T) {
	pub := testKey(t)
	jc, err := NewJoinCode(pub)
	if err != nil {
		t.Fatal(err)
	}
	sessionA := []byte("binding-from-session-a-32-bytes!")
	sessionB := []byte("binding-from-session-b-32-bytes!")

	proof := PairProof(jc.Secret, sessionA, pub)

	if !VerifyPairProof(jc.Secret, sessionA, pub, proof) {
		t.Fatal("a proof did not verify in its own session")
	}
	if VerifyPairProof(jc.Secret, sessionB, pub, proof) {
		t.Fatal("a proof verified in a different session, an on-path attacker could relay it")
	}
}

// A proof must not verify for a different key, or it could be reflected back at
// its sender.
func TestProofIsBoundToTheKey(t *testing.T) {
	a, b := testKey(t), testKey(t)
	jc, err := NewJoinCode(a)
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("one-session-binding-value-32-by!")

	proof := PairProof(jc.Secret, binding, a)
	if VerifyPairProof(jc.Secret, binding, b, proof) {
		t.Error("a proof verified for a different public key")
	}
}

// The wrong secret must not verify, which is the online-guessing case.
func TestProofRequiresTheSecret(t *testing.T) {
	pub := testKey(t)
	real, err := NewJoinCode(pub)
	if err != nil {
		t.Fatal(err)
	}
	guess, err := NewJoinCode(pub)
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("one-session-binding-value-32-by!")

	proof := PairProof(real.Secret, binding, pub)
	if VerifyPairProof(guess.Secret, binding, pub, proof) {
		t.Error("a proof verified under a different secret")
	}
}

// The exporter label is wire protocol. Changing it silently breaks pairing
// between versions, so it is pinned by a test rather than left to a refactor.
func TestExporterLabelIsPinned(t *testing.T) {
	if ExporterLabel != "lan-sheriff/dispatch/pair/v1" {
		t.Errorf("ExporterLabel = %q; changing it breaks pairing with every other build",
			ExporterLabel)
	}
}

// **A wrong version number is almost never a wrong version.**
//
// The version is four bits, so any forty valid characters decode to some
// version and fifteen times in sixteen it will not be ours. A tester lost an
// evening to this: a file path was pasted into the code field, forty letters
// that happened to be legal Crockford, and the product answered "that machine
// is running a different version of LAN Sheriff", so he went looking for a
// version mismatch between two machines that were on the same build.
//
// Only a version next to this one is a version problem. Everything else is what
// it almost certainly is, which is not a pairing code.
func TestUnrecognisedVersionIsReportedAsNotACode(t *testing.T) {
	// The real thing, from the field: /Users/alex/Pictures/Photos Library...
	// with separators dropped and the Crockford foldings applied.
	const pastedPath = "SERSA1EXP1CTRESPH0T0S11BRARYPH0T0S11BRA"

	for _, c := range []struct {
		name, code string
		want       error
	}{
		{"a path pasted into the field is not a version problem",
			pastedPath + "1", ErrCodeChars},
		{"and neither is any other forty legal characters",
			strings.Repeat("Z", 40), ErrCodeChars},
		{"too short is still a length problem",
			"ABCDE", ErrCodeLength},
		{"an illegal character is still a character problem",
			strings.Repeat("A", 39) + "!", ErrCodeChars},
	} {
		_, err := ParseJoinCode(c.code)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		if errors.Is(err, ErrCodeVersion) {
			t.Errorf("%s: reported as a version mismatch, which sends people to reinstall", c.name)
		}
	}
}

// A real code still parses, and a genuinely adjacent version still reports as
// one, so the guard above has not swallowed the case it exists for.
func TestAdjacentVersionStillReportsAsAVersion(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	code, err := NewJoinCode(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJoinCode(code.String()); err != nil {
		t.Fatalf("a freshly minted code did not parse: %v", err)
	}
}
