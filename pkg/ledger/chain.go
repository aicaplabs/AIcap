package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Chain hashing.
//
// The formulas live here, not in the HTTP handlers, for two reasons: the
// write path (save-proof) and the two read paths (verify-chain, the
// public report) must agree byte for byte or every row looks tampered;
// and a third party checking a shared report needs the same function
// without importing an HTTP server.

// Content is everything a ledger entry stores about one scan, in the
// exact bytes the database holds:
//
//	BOM           proof_drills.ai_bom_json::text      (Postgres' canonical JSONB text)
//	AnnexIV       proof_drills.annex_iv_markdown      (TEXT, stored verbatim)
//	RiskRegister  proof_drills.risk_register_state::text
//
// The JSONB columns are hashed in Postgres' canonical text form rather
// than as the bytes the application marshalled, because Postgres
// normalises JSONB on storage (key order, whitespace). Hashing the
// application's bytes would make every row fail verification against
// what a later SELECT returns.
type Content struct {
	BOM          []byte
	AnnexIV      []byte
	RiskRegister []byte
}

// Digests are the SHA-256 hex digests of a Content's three parts. They
// are what a V2 chain hash is computed from, and what a shared report
// publishes so that a recipient can recompute the hash without being
// handed the BOM itself.
type Digests struct {
	BOM          string
	AnnexIV      string
	RiskRegister string
}

// Digest returns the lowercase hex SHA-256 of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Digests hashes each part of the content.
func (c Content) Digests() Digests {
	return Digests{
		BOM:          Digest(c.BOM),
		AnnexIV:      Digest(c.AnnexIV),
		RiskRegister: Digest(c.RiskRegister),
	}
}

// ChainHashV1 is the original formula:
//
//	sha256(commit_sha || ai_bom_json || prev_hash)
//
// with prev_hash omitted on a genesis row (which also makes it match the
// pre-chain formula of the earliest rows). It is kept exactly as it was
// — plain concatenation, no delimiters — because every V1 row's stored
// hash and signature depend on it.
//
// What it does not cover is the reason V2 exists: the Annex IV markdown
// and the risk register are absent, so either can be edited in the
// database without disturbing a V1 hash.
func ChainHashV1(commitSha string, bomJSON []byte, prevHash string) string {
	h := sha256.New()
	h.Write([]byte(commitSha))
	h.Write(bomJSON)
	if prevHash != "" {
		h.Write([]byte(prevHash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// chainDomainV2 prefixes the V2 preimage so a V2 hash can never equal a
// V1 hash, or a hash computed for any other purpose, over the same data.
const chainDomainV2 = "aicap-chain-v2"

// ChainHashV2 covers the rendered document as well as the BOM:
//
//	sha256( "aicap-chain-v2" \n prev_hash \n sha256(bom) \n
//	        sha256(annex_iv) \n sha256(risk_register) \n commit_sha )
//
// Design notes:
//
//   - It hashes digests, not content. A recipient of a shared report is
//     given the Annex IV text and the three digests; they can hash the
//     text themselves, compare, and recompute this value — without the
//     report having to hand over the full BOM.
//   - Fields are newline-delimited and the client-supplied commit SHA
//     comes last. Every field before it is either empty or 64 hex
//     characters, so the preimage parses one way only, whatever the
//     commit string contains. (V1's bare concatenation relied on the
//     commit SHA being well-behaved.)
//   - prev_hash is the empty string on a genesis row.
func ChainHashV2(commitSha, prevHash string, d Digests) string {
	preimage := strings.Join([]string{
		chainDomainV2,
		prevHash,
		d.BOM,
		d.AnnexIV,
		d.RiskRegister,
		commitSha,
	}, "\n")
	return Digest([]byte(preimage))
}

// ChainHash computes the hash for the given ledger version. An unknown
// version is an error rather than a fallback: guessing a formula for a
// row we do not understand would turn "cannot verify" into a false
// "tampered" or, worse, a false "ok".
func ChainHash(version int, commitSha, prevHash string, c Content) (string, error) {
	switch version {
	case V1:
		return ChainHashV1(commitSha, c.BOM, prevHash), nil
	case V2:
		return ChainHashV2(commitSha, prevHash, c.Digests()), nil
	default:
		return "", fmt.Errorf("ledger: unknown chain version %d", version)
	}
}
