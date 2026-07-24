package ledger

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	seed, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	s, err := signerFromBase64(seed)
	if err != nil {
		t.Fatalf("signerFromBase64: %v", err)
	}
	return s
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	s := newTestSigner(t)
	entry := Entry{UserID: "user-1", CommitSha: "abc123", CryptoHash: "deadbeef"}

	sig := s.Sign(entry)
	if sig == "" {
		t.Fatal("Sign returned empty signature for a configured signer")
	}
	if !s.Verify(entry, sig) {
		t.Error("signature did not verify against the key that produced it")
	}
}

func TestVerify_RejectsAlteredFields(t *testing.T) {
	// The point of the whole exercise: an attacker with database write
	// access can rewrite rows, but cannot produce signatures for them.
	s := newTestSigner(t)
	entry := Entry{UserID: "user-1", CommitSha: "abc123", CryptoHash: "deadbeef"}
	sig := s.Sign(entry)

	tampered := []Entry{
		{UserID: "user-2", CommitSha: "abc123", CryptoHash: "deadbeef"},
		{UserID: "user-1", CommitSha: "def456", CryptoHash: "deadbeef"},
		{UserID: "user-1", CommitSha: "abc123", CryptoHash: "cafebabe"},
	}
	for _, e := range tampered {
		if s.Verify(e, sig) {
			t.Errorf("signature verified against altered entry %+v", e)
		}
	}
}

func TestVerify_SignatureIsNotTransferableBetweenUsers(t *testing.T) {
	// Without the identity binding, a valid (hash, signature) pair from
	// one tenant's ledger could be pasted into another's and still
	// verify. This is the test that would catch dropping UserID from the
	// signed message.
	s := newTestSigner(t)
	mine := Entry{UserID: "user-1", CommitSha: "abc123", CryptoHash: "deadbeef"}
	sig := s.Sign(mine)

	theirs := Entry{UserID: "user-2", CommitSha: "abc123", CryptoHash: "deadbeef"}
	if s.Verify(theirs, sig) {
		t.Error("a signature from one user's chain verified in another user's chain")
	}
}

func TestVerify_RejectsGarbageSignatures(t *testing.T) {
	s := newTestSigner(t)
	entry := Entry{UserID: "u", CommitSha: "c", CryptoHash: "h"}
	for _, sig := range []string{"", "not-base64!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if s.Verify(entry, sig) {
			t.Errorf("Verify accepted %q", sig)
		}
	}
}

func TestVerifyWithPublicKey_NeedsOnlyThePublishedKey(t *testing.T) {
	// An independent verifier has the public key, the entry fields, and
	// the signature — and nothing else. If this stops working, third
	// parties can no longer check a report, which is the feature.
	s := newTestSigner(t)
	entry := Entry{UserID: "user-1", CommitSha: "abc123", CryptoHash: "deadbeef"}
	sig := s.Sign(entry)

	pub, err := ParsePublicKey(s.PublicKeyBase64())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !VerifyWithPublicKey(pub, entry, sig) {
		t.Error("published public key could not verify a signature this key produced")
	}

	// A different key must not verify it.
	other := newTestSigner(t)
	otherPub, _ := ParsePublicKey(other.PublicKeyBase64())
	if VerifyWithPublicKey(otherPub, entry, sig) {
		t.Error("signature verified under an unrelated public key")
	}
}

func TestNilSigner_IsSafeAndDisabled(t *testing.T) {
	// An unconfigured deployment must write unsigned rows, not crash.
	var s *Signer
	if s.Enabled() {
		t.Error("nil signer reports Enabled")
	}
	if got := s.Sign(Entry{}); got != "" {
		t.Errorf("nil signer produced signature %q", got)
	}
	if s.Verify(Entry{}, "x") {
		t.Error("nil signer verified a signature")
	}
	if got := s.PublicKeyBase64(); got != "" {
		t.Errorf("nil signer returned public key %q", got)
	}
}

func TestSignerFromBase64_AcceptsSeedAndFullKey(t *testing.T) {
	seed, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	fromSeed, err := signerFromBase64(seed)
	if err != nil {
		t.Fatalf("seed rejected: %v", err)
	}

	rawSeed, _ := base64.StdEncoding.DecodeString(seed)
	full := ed25519.NewKeyFromSeed(rawSeed)
	fromFull, err := signerFromBase64(base64.StdEncoding.EncodeToString(full))
	if err != nil {
		t.Fatalf("full private key rejected: %v", err)
	}

	// Both spellings must yield the same identity.
	if fromSeed.PublicKeyBase64() != fromFull.PublicKeyBase64() {
		t.Error("seed and full-key forms produced different public keys")
	}
}

func TestSignerFromBase64_EmptyIsErrNoKey(t *testing.T) {
	_, err := signerFromBase64("   ")
	if !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
}

func TestSignerFromBase64_MalformedKeyIsAHardError(t *testing.T) {
	// Deliberately not a silent fallback to unsigned: an operator who set
	// the variable believes signing is happening.
	for _, bad := range []string{"@@@not-base64@@@", base64.StdEncoding.EncodeToString([]byte("too-short"))} {
		if _, err := signerFromBase64(bad); err == nil {
			t.Errorf("signerFromBase64(%q) returned no error", bad)
		} else if errors.Is(err, ErrNoKey) {
			t.Errorf("malformed key reported as ErrNoKey, which reads as 'signing disabled'")
		}
	}
}

func TestEntryMessage_IsDomainSeparatedAndVersioned(t *testing.T) {
	msg := string(Entry{UserID: "u", CommitSha: "c", CryptoHash: "h"}.Message())
	if !strings.HasPrefix(msg, domainSeparator+"|") {
		t.Errorf("message = %q, want the domain separator first", msg)
	}
	if !strings.Contains(domainSeparator, "-v1") {
		t.Error("domain separator carries no version; a future format change could be confused with this one")
	}
}

func TestEntryMessage_IsStable(t *testing.T) {
	// Signatures are persisted. If this encoding changes, every stored
	// signature stops verifying — so the layout is pinned here
	// deliberately, and changing it requires bumping the version in the
	// domain separator.
	got := string(Entry{UserID: "user-1", CommitSha: "abc123", CryptoHash: "deadbeef"}.Message())
	want := "aicap-ledger-v1|user-1|abc123|deadbeef"
	if got != want {
		t.Errorf("Message() = %q, want %q", got, want)
	}
}
