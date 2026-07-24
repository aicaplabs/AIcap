package ledger

import "strings"

// domainSeparator prefixes every signed message.
//
// Two reasons. It scopes the signature to this application and this
// message format, so a signature produced here can never be replayed as
// a valid signature for some other protocol that happens to use the same
// key. And the version segment means a future change to the message
// layout produces signatures that cannot be confused with v1 ones — a
// verifier checks the version it understands rather than silently
// validating a different structure.
const domainSeparator = "aicap-ledger-v1"

// Entry is the set of fields a ledger signature commits to.
//
// CryptoHash alone would prove the row's contents, since the hash
// already covers the commit SHA, the BOM, and the previous hash. UserID
// and CommitSha are included anyway so a signature is bound to its
// position in a specific tenant's chain: without them, a valid
// (hash, signature) pair lifted from one user's ledger could be pasted
// into another's, and the chain would still verify. Binding the identity
// makes a signature non-transferable.
type Entry struct {
	UserID     string
	CommitSha  string
	CryptoHash string
}

// Message is the exact byte sequence that gets signed and verified.
//
// The field separator is "|" and the fields are joined in a fixed order.
// None of these fields can contain "|" in practice — UserID is a UUID,
// CommitSha is hex, CryptoHash is hex — so the encoding is unambiguous
// without needing length prefixes. That assumption is worth stating
// because if a future field could contain the separator, this would need
// a length-prefixed encoding to stay injection-proof.
func (e Entry) Message() []byte {
	return []byte(strings.Join([]string{
		domainSeparator,
		e.UserID,
		e.CommitSha,
		e.CryptoHash,
	}, "|"))
}
