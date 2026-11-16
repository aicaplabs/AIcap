package ledger

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// reportFixture builds a signed entry the way save-proof does and
// returns what /api/public/report would publish for it.
func reportFixture(t *testing.T, version int) (ed25519.PublicKey, Report) {
	t.Helper()
	seed, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := signerFromBase64(seed)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	pub, err := ParsePublicKey(signer.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	content := Content{
		BOM:          []byte(`{"projectName": "acme/hiring"}`),
		AnnexIV:      []byte("# Annex IV\n\n## 1. General description\n\nA CV-screening assistant.\n"),
		RiskRegister: []byte(`{"findings": []}`),
	}
	const commit, prev = "9f2c1e7", "aa11"
	hash, err := ChainHash(version, commit, prev, content)
	if err != nil {
		t.Fatalf("chain hash: %v", err)
	}
	entry := Entry{Version: version, UserID: "3b0c2f6e-1111-4222-8333-444455556666", CommitSha: commit, CryptoHash: hash}

	r := Report{
		Markdown:      string(content.AnnexIV),
		CommitSha:     commit,
		CryptoHash:    hash,
		PrevHash:      prev,
		ChainVersion:  version,
		Signature:     signer.Sign(entry),
		SignedMessage: base64.StdEncoding.EncodeToString(entry.Message()),
	}
	if version == V2 {
		r.Digests = content.Digests()
	}
	return pub, r
}

func TestVerifyReport_V2FullyVerifies(t *testing.T) {
	pub, r := reportFixture(t, V2)
	c := VerifyReport(pub, r)
	if !c.OK() {
		t.Fatalf("an untouched V2 report did not verify: %+v", c)
	}
	if len(c.Problems) != 0 {
		t.Errorf("verified report carries problems: %v", c.Problems)
	}
}

// The test the feature exists for. Under V1 this edit was invisible: the
// signature still verified and the page still said "has not been
// altered". The document a recipient reads must be the document that
// was signed.
func TestVerifyReport_V2DetectsAnEditedDocument(t *testing.T) {
	pub, r := reportFixture(t, V2)
	r.Markdown = strings.Replace(r.Markdown, "A CV-screening assistant.", "A spell checker.", 1)

	c := VerifyReport(pub, r)
	if c.OK() || c.DocumentBound {
		t.Fatalf("an edited document verified: %+v", c)
	}
	if !c.SignatureValid || !c.MessageMatchesReport {
		t.Errorf("the signature itself is untouched and should still verify: %+v", c)
	}
	if len(c.Problems) == 0 {
		t.Error("no explanation given for the failure")
	}
}

// Editing the text and replacing its published digest to match does not
// help: the chain hash, which is what was signed, no longer recomputes.
func TestVerifyReport_V2DetectsAnEditedDocumentWithAMatchingDigest(t *testing.T) {
	pub, r := reportFixture(t, V2)
	r.Markdown = "# Annex IV\n\nNothing to see here.\n"
	r.Digests.AnnexIV = Digest([]byte(r.Markdown))

	c := VerifyReport(pub, r)
	if c.OK() || c.DocumentBound {
		t.Fatalf("a re-digested forgery verified: %+v", c)
	}
}

// ...and recomputing the chain hash too means the signed message no
// longer names it. Each layer of the forgery is caught by the next.
func TestVerifyReport_V2DetectsAFullyRecomputedForgery(t *testing.T) {
	pub, r := reportFixture(t, V2)
	r.Markdown = "# Annex IV\n\nNothing to see here.\n"
	r.Digests.AnnexIV = Digest([]byte(r.Markdown))
	r.CryptoHash = ChainHashV2(r.CommitSha, r.PrevHash, r.Digests)

	c := VerifyReport(pub, r)
	if c.OK() || c.MessageMatchesReport {
		t.Fatalf("a forgery with a recomputed chain hash verified: %+v", c)
	}
	if !c.SignatureValid {
		t.Error("the original signature over the original bytes should still be valid")
	}
}

func TestVerifyReport_DetectsATransplantedSignature(t *testing.T) {
	// A valid signature and message from one entry attached to another.
	pub, a := reportFixture(t, V2)
	_, b := reportFixture(t, V2)
	b.CommitSha = "different-commit"
	b.CryptoHash = ChainHashV2(b.CommitSha, b.PrevHash, b.Digests)
	b.Signature, b.SignedMessage = a.Signature, a.SignedMessage

	c := VerifyReport(pub, b)
	if c.OK() {
		t.Fatalf("a signature lifted from another entry verified: %+v", c)
	}
	if !c.SignatureValid || c.MessageMatchesReport {
		t.Errorf("want signature valid but message mismatched, got %+v", c)
	}
}

func TestVerifyReport_RejectsTheWrongKey(t *testing.T) {
	_, r := reportFixture(t, V2)
	otherPub, _ := reportFixture(t, V2)
	if c := VerifyReport(otherPub, r); c.SignatureValid || c.OK() {
		t.Fatalf("verified under a key that did not sign it: %+v", c)
	}
}

// A V1 entry can be attributed but its document cannot be bound. The
// verifier must say exactly that, not "ok" and not "tampered".
func TestVerifyReport_V1IsAttributedButNotDocumentBound(t *testing.T) {
	pub, r := reportFixture(t, V1)
	c := VerifyReport(pub, r)

	if !c.SignatureValid || !c.MessageMatchesReport {
		t.Fatalf("a genuine V1 report failed attribution: %+v", c)
	}
	if c.DocumentBound || c.OK() {
		t.Fatalf("a V1 report claimed its document is bound to the signature: %+v", c)
	}
	if len(c.Problems) != 1 || !strings.Contains(c.Problems[0], "version 1") {
		t.Errorf("V1 limitation not explained: %v", c.Problems)
	}

	// The limitation is real: edit the document and nothing changes.
	r.Markdown += "\n(edited)\n"
	if c2 := VerifyReport(pub, r); c2.SignatureValid != c.SignatureValid || c2.DocumentBound {
		t.Errorf("V1 result changed with the document; it never covered it: %+v", c2)
	}
}

func TestVerifyReport_UnsignedReportIsNotVerified(t *testing.T) {
	pub, r := reportFixture(t, V2)
	r.Signature, r.SignedMessage = "", ""
	c := VerifyReport(pub, r)
	if c.OK() || c.SignatureValid {
		t.Fatalf("an unsigned report verified: %+v", c)
	}
	if len(c.Problems) == 0 {
		t.Error("no explanation for an unsigned report")
	}
}

func TestVerifyReport_VersionCannotBeRelabelled(t *testing.T) {
	// Presenting a V1 entry as V2 (to claim a document binding it never
	// had) fails: the signed bytes carry the version.
	pub, r := reportFixture(t, V1)
	r.ChainVersion = V2
	r.Digests = Content{AnnexIV: []byte(r.Markdown)}.Digests()
	if c := VerifyReport(pub, r); c.OK() || c.MessageMatchesReport {
		t.Fatalf("a V1 entry relabelled as V2 verified: %+v", c)
	}
}

// --- Entry message layout -------------------------------------------------

func TestEntryMessage_ZeroVersionIsV1(t *testing.T) {
	// Rows and call sites that predate versioning must keep producing the
	// bytes they always did, or every stored V1 signature stops verifying.
	e := Entry{UserID: "u", CommitSha: "c", CryptoHash: "h"}
	if got := string(e.Message()); got != "aicap-ledger-v1|u|c|h" {
		t.Errorf("zero-version message = %q", got)
	}
	e.Version = V1
	if got := string(e.Message()); got != "aicap-ledger-v1|u|c|h" {
		t.Errorf("V1 message = %q", got)
	}
}

func TestEntryMessage_V2LayoutIsPinned(t *testing.T) {
	const user = "3b0c2f6e-1111-4222-8333-444455556666"
	got := string(Entry{Version: V2, UserID: user, CommitSha: "c", CryptoHash: "h"}.Message())
	want := "aicap-ledger-v2|" + sha("aicap-tenant-v1|"+user) + "|c|h"
	if got != want {
		t.Errorf("V2 message layout changed.\n got %q\nwant %q\n"+
			"Changing it invalidates every stored V2 signature — it requires a new version.", got, want)
	}
}

// A shared report publishes the signed bytes. Under V1 they contained the
// owner's account id; under V2 they must not.
func TestEntryMessage_V2DoesNotDiscloseTheUserID(t *testing.T) {
	const user = "3b0c2f6e-1111-4222-8333-444455556666"
	msg := string(Entry{Version: V2, UserID: user, CommitSha: "c", CryptoHash: "h"}.Message())
	if strings.Contains(msg, user) {
		t.Errorf("V2 signed message contains the raw user id: %q", msg)
	}
	// ...while still binding the signature to that tenant.
	other := string(Entry{Version: V2, UserID: "another-user", CommitSha: "c", CryptoHash: "h"}.Message())
	if msg == other {
		t.Error("V2 message is identical for two different tenants; the signature would be transferable")
	}
}

func TestSignature_IsBoundToTheLedgerVersion(t *testing.T) {
	seed, _ := GenerateSigningKey()
	s, err := signerFromBase64(seed)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	v1 := Entry{Version: V1, UserID: "u", CommitSha: "c", CryptoHash: "h"}
	v2 := Entry{Version: V2, UserID: "u", CommitSha: "c", CryptoHash: "h"}

	if !s.Verify(v1, s.Sign(v1)) || !s.Verify(v2, s.Sign(v2)) {
		t.Fatal("round trip failed")
	}
	if s.Verify(v2, s.Sign(v1)) || s.Verify(v1, s.Sign(v2)) {
		t.Error("a signature made under one ledger version verified under the other")
	}
}
