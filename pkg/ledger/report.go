package ledger

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// Report is the verifiable material a shared report carries, as returned
// by GET /api/public/report. It is everything a third party needs — and
// nothing that requires an account, database access, or trust in the
// party who sent the link.
type Report struct {
	// Markdown is the Annex IV document the recipient is shown.
	Markdown string
	// CommitSha, CryptoHash and PrevHash identify the entry and its
	// position in the owner's chain. PrevHash is "" on a genesis entry.
	CommitSha  string
	CryptoHash string
	PrevHash   string
	// ChainVersion is the ledger format the entry was written under.
	ChainVersion int
	// Digests are the SHA-256 digests the chain hash was computed from.
	// Only meaningful for V2 entries.
	Digests Digests
	// Signature and SignedMessage are standard base64, exactly as
	// published in the report's attestation block.
	Signature     string
	SignedMessage string
}

// ReportCheck is the outcome of verifying a Report. The three results
// are reported separately because they are separate claims, and a
// verifier that collapsed them into one boolean could not tell a reader
// which of them failed — or that one was never made.
type ReportCheck struct {
	// SignatureValid: the signature verifies over the published signed
	// message under the given public key. Proves the holder of the key
	// signed those bytes.
	SignatureValid bool
	// MessageMatchesReport: the signed bytes name this report's commit
	// and chain hash, under this report's ledger version. Without this,
	// a valid signature lifted from some other entry would pass.
	MessageMatchesReport bool
	// DocumentBound: the document text hashes to the published digest
	// and the chain hash recomputes from the published digests. Only a
	// V2 entry can satisfy this; for V1 it is always false, because a
	// V1 hash never covered the document.
	DocumentBound bool
	// Problems explains every false above in plain words.
	Problems []string
}

// OK reports whether the report is fully verified: signed by the key,
// about this entry, and bound to this document.
func (c ReportCheck) OK() bool {
	return c.SignatureValid && c.MessageMatchesReport && c.DocumentBound
}

// VerifyReport checks a shared report against a public key.
//
// It deliberately trusts nothing in the report except through the
// signature: the digests are only believed because the chain hash
// recomputed from them equals the hash named in the signed message.
func VerifyReport(pub ed25519.PublicKey, r Report) ReportCheck {
	var c ReportCheck

	// 1. The signature over the published bytes.
	if r.Signature == "" || r.SignedMessage == "" {
		c.Problems = append(c.Problems,
			"the report carries no signature: it cannot be attributed to the ledger operator")
		return c
	}
	msg, err := base64.StdEncoding.DecodeString(r.SignedMessage)
	if err != nil {
		c.Problems = append(c.Problems, "signedMessage is not valid base64")
		return c
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		c.Problems = append(c.Problems, "signature is not valid base64")
		return c
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, msg, sig) {
		c.Problems = append(c.Problems,
			"the signature does not verify under this public key")
		return c
	}
	c.SignatureValid = true

	// 2. The signed bytes are about this entry.
	if matchesEntry(string(msg), r) {
		c.MessageMatchesReport = true
	} else {
		c.Problems = append(c.Problems,
			"the signed message does not name this report's commit and chain hash under ledger version "+
				fmt.Sprint(r.ChainVersion)+
				" — the signature is valid but belongs to something else")
		return c
	}

	// 3. The document is what was signed.
	switch r.ChainVersion {
	case V2:
		if got := Digest([]byte(r.Markdown)); got != r.Digests.AnnexIV {
			c.Problems = append(c.Problems,
				"the document text does not hash to the published Annex IV digest — "+
					"the text has been altered since the entry was written")
			return c
		}
		if got := ChainHashV2(r.CommitSha, r.PrevHash, r.Digests); got != r.CryptoHash {
			c.Problems = append(c.Problems,
				"the chain hash does not recompute from the published digests — "+
					"a digest, the previous hash or the commit has been altered")
			return c
		}
		c.DocumentBound = true
	case V1:
		c.Problems = append(c.Problems,
			"this entry was written under ledger version 1, whose hash covers the commit and the "+
				"AI-BOM but not the rendered document: the signature attributes the scan record, "+
				"and cannot show that this text is what was written at scan time")
	default:
		c.Problems = append(c.Problems,
			fmt.Sprintf("unknown ledger version %d: this verifier cannot check the document binding", r.ChainVersion))
	}
	return c
}

// matchesEntry reports whether a signed message is the Entry message for
// this report's commit and hash under its ledger version. The tenant
// field is not known to a third party, so it is checked for shape only:
// present, and free of the separator.
func matchesEntry(msg string, r Report) bool {
	var prefix string
	switch r.ChainVersion {
	case V1:
		prefix = domainSeparatorV1 + "|"
	case V2:
		prefix = domainSeparatorV2 + "|"
	default:
		return false
	}
	suffix := "|" + r.CommitSha + "|" + r.CryptoHash
	if r.CryptoHash == "" || !strings.HasPrefix(msg, prefix) || !strings.HasSuffix(msg, suffix) {
		return false
	}
	if len(msg) < len(prefix)+len(suffix) {
		return false
	}
	tenant := msg[len(prefix) : len(msg)-len(suffix)]
	if tenant == "" || strings.Contains(tenant, "|") {
		return false
	}
	if r.ChainVersion == V2 && !isHex64(tenant) {
		return false
	}
	return true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
