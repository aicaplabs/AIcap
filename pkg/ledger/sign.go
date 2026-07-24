// Ledger signing (Wave 17).
//
// The hash chain in proof_drills makes the ledger tamper-*evident*
// against a row edit: change a payload and its crypto_hash stops
// matching; delete or reorder a row and the prev_hash links break.
//
// What it does not survive is a wholesale rewrite. Anyone with write
// access to the database — an operator, a leaked service credential, a
// compromised backup restore — can recompute every crypto_hash and
// prev_hash from scratch and produce a chain that verifies perfectly.
// The chain proves internal consistency, not authorship. For a product
// whose paid tier is precisely "an auditor can check this without taking
// your word for it", that gap sits under the main claim.
//
// An Ed25519 signature over each chain entry closes it. The signing key
// lives in the process environment, never in the database, so possession
// of the database is not possession of the key. Rewriting history now
// requires forging a signature rather than running an UPDATE.
//
// Configuration:
//
//	AICAP_LEDGER_SIGNING_KEY  base64 Ed25519 seed (32 bytes) or full
//	                          private key (64 bytes). Unset disables
//	                          signing: rows are written unsigned and
//	                          verification reports them as such. This
//	                          keeps existing deployments working rather
//	                          than failing closed on a missing key.
//
// The public key is served unauthenticated from /api/ledger/public-key
// so a third party can verify a report without an account — which is the
// entire point. A verifier who obtains the public key from the same
// party that produced the signature is trusting that party; publishing
// it at a stable, well-known URL is what makes independent checking
// possible, and the key should also be pinned somewhere outside this
// system (docs, a DPA annex) for anyone who wants a stronger guarantee.

package ledger

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Signer holds the Ed25519 key used to sign ledger entries. A nil
// *Signer is valid and means "signing is not configured" — every method
// degrades to a no-op rather than panicking, so an unconfigured
// deployment writes unsigned rows instead of failing writes.
type Signer struct {
	priv ed25519.PrivateKey
}

// ErrNoKey is returned by LoadSigner when the environment carries no
// signing key. It is not a failure — callers treat it as "signing
// disabled" — but it is distinguishable from a malformed key, which is.
var ErrNoKey = errors.New("ledger: no signing key configured")

// LoadSigner reads AICAP_LEDGER_SIGNING_KEY and returns a Signer.
//
// A malformed key is a hard error rather than a silent fall back to
// unsigned: an operator who set the variable intended signing to happen,
// and quietly writing unsigned rows would leave them believing in a
// guarantee they do not have.
func LoadSigner() (*Signer, error) {
	return signerFromBase64(os.Getenv("AICAP_LEDGER_SIGNING_KEY"))
}

func signerFromBase64(encoded string) (*Signer, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, ErrNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Tolerate the URL-safe alphabet — key material gets copied
		// through a lot of intermediaries.
		raw, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("ledger: signing key is not valid base64: %w", err)
		}
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return &Signer{priv: ed25519.NewKeyFromSeed(raw)}, nil
	case ed25519.PrivateKeySize:
		return &Signer{priv: ed25519.PrivateKey(raw)}, nil
	default:
		return nil, fmt.Errorf("ledger: signing key must be %d or %d bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}

// Enabled reports whether this Signer can actually sign.
func (s *Signer) Enabled() bool { return s != nil && len(s.priv) == ed25519.PrivateKeySize }

// PublicKeyBase64 returns the standard-base64 public key, or "" when
// signing is not configured. This is what /api/ledger/public-key serves
// and what an offline verifier needs.
func (s *Signer) PublicKeyBase64() string {
	if !s.Enabled() {
		return ""
	}
	pub, ok := s.priv.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// KeyID is a short, non-secret identifier for the signing key: the first
// 16 characters of the base64 public key. Stored alongside each entry so
// a key can be rotated without invalidating history — a verifier selects
// the key that was current when the row was written instead of assuming
// one key has signed everything.
func (s *Signer) KeyID() string {
	pub := s.PublicKeyBase64()
	if len(pub) < 16 {
		return pub
	}
	return pub[:16]
}

// Sign returns the base64 signature over the canonical entry message,
// or "" when signing is not configured.
func (s *Signer) Sign(entry Entry) string {
	if !s.Enabled() {
		return ""
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, entry.Message()))
}

// Verify checks a base64 signature against the entry using this
// Signer's own public key.
func (s *Signer) Verify(entry Entry, signature string) bool {
	if !s.Enabled() {
		return false
	}
	pub, ok := s.priv.Public().(ed25519.PublicKey)
	if !ok {
		return false
	}
	return VerifyWithPublicKey(pub, entry, signature)
}

// VerifyWithPublicKey is the verification primitive an independent party
// uses: it needs only the published public key, the entry fields, and
// the signature. Exported so verification never requires access to
// private key material.
func VerifyWithPublicKey(pub ed25519.PublicKey, entry Entry, signature string) bool {
	if len(pub) != ed25519.PublicKeySize || signature == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, entry.Message(), sig)
}

// ParsePublicKey decodes a base64 public key as published by
// /api/ledger/public-key.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("ledger: public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ledger: public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// GenerateSigningKey returns a fresh base64 seed suitable for
// AICAP_LEDGER_SIGNING_KEY. Used by the `--gen-ledger-key` subcommand so
// an operator never has to hand-roll key material.
func GenerateSigningKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), nil
}
