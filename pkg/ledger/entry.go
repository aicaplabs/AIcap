package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Ledger format versions. The version is stored on every row
// (proof_drills.chain_version) and selects both the chain-hash formula
// (see chain.go) and the signed-message layout below.
//
//	V1  crypto_hash covers the commit SHA, the AI-BOM and the previous
//	    hash. The rendered Annex IV document and the risk register are
//	    stored beside the row but are NOT inside the hash, so a signature
//	    over a V1 entry attributes the scan record, not the document.
//	V2  crypto_hash additionally covers the Annex IV markdown and the
//	    risk register. A signature over a V2 entry therefore commits to
//	    the exact document a report recipient is shown.
//
// Every row written before v1.8.0 is V1 and stays V1: its hash and its
// signature were computed over the V1 formula and cannot be upgraded in
// place without the ability to re-sign history, which is precisely the
// ability the ledger is meant to deny.
const (
	V1 = 1
	V2 = 2

	// CurrentVersion is what new entries are written as.
	CurrentVersion = V2
)

// domainSeparator prefixes every signed message.
//
// Two reasons. It scopes the signature to this application and this
// message format, so a signature produced here can never be replayed as
// a valid signature for some other protocol that happens to use the same
// key. And the version segment means a change to the message layout
// produces signatures that cannot be confused with earlier ones — a
// verifier checks the version it understands rather than silently
// validating a different structure. Relabelling a V1 row as V2 (or the
// reverse) changes the bytes that were signed, so the signature fails.
const (
	domainSeparatorV1 = "aicap-ledger-v1"
	domainSeparatorV2 = "aicap-ledger-v2"
)

// Entry is the set of fields a ledger signature commits to.
//
// CryptoHash alone would prove the row's contents, since the hash
// already covers the commit SHA, the BOM, and the previous hash (and,
// from V2, the rendered document). The tenant and CommitSha are included
// anyway so a signature is bound to its position in a specific tenant's
// chain: without them, a valid (hash, signature) pair lifted from one
// user's ledger could be pasted into another's, and the chain would
// still verify. Binding the identity makes a signature non-transferable.
type Entry struct {
	// Version selects the message layout. The zero value is treated as
	// V1 so that code and stored rows that predate versioning keep
	// producing exactly the bytes they always did.
	Version    int
	UserID     string
	CommitSha  string
	CryptoHash string
}

// Message is the exact byte sequence that gets signed and verified.
//
//	V1: aicap-ledger-v1|<user id>|<commit sha>|<crypto hash>
//	V2: aicap-ledger-v2|<tenant ref>|<commit sha>|<crypto hash>
//
// The field separator is "|" and the fields are joined in a fixed order.
// The first and last fields after the separator are fixed-shape (a UUID
// or a 64-character hex tenant ref; a 64-character hex hash), so the
// encoding stays unambiguous even though the commit SHA in the middle is
// supplied by the client and is not guaranteed to be hex.
//
// V2 signs TenantRef(UserID) rather than the user id itself. A shared
// report publishes these bytes so a recipient can check the signature,
// and under V1 that disclosed the owner's internal account id to anyone
// holding the link — while the API was careful never to return it as a
// field of its own. The tenant ref binds the signature to one tenant's
// chain just as firmly and tells the recipient nothing.
func (e Entry) Message() []byte {
	if e.Version == V2 {
		return []byte(strings.Join([]string{
			domainSeparatorV2,
			TenantRef(e.UserID),
			e.CommitSha,
			e.CryptoHash,
		}, "|"))
	}
	return []byte(strings.Join([]string{
		domainSeparatorV1,
		e.UserID,
		e.CommitSha,
		e.CryptoHash,
	}, "|"))
}

// TenantRef is the opaque, stable stand-in for a tenant's user id used in
// V2 signed messages: hex(sha256("aicap-tenant-v1|" + userID)). User ids
// are random UUIDs, so the hash cannot practically be reversed, and the
// prefix keeps it from colliding with a hash of the same id computed for
// any other purpose.
func TenantRef(userID string) string {
	sum := sha256.Sum256([]byte("aicap-tenant-v1|" + userID))
	return hex.EncodeToString(sum[:])
}
