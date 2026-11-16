//go:build integration

// Integration tests for ledger signing (Wave 17).
//
// The hash chain alone proves the rows are consistent with each other.
// It does not prove who wrote them — anyone with write access to the
// database can recompute every crypto_hash and prev_hash and produce a
// chain that verifies perfectly. TestVerifyChain_DetectsForgedRewrite is
// the test that matters here: it performs exactly that attack, confirms
// the chain check alone would have passed it, and asserts that the
// signature check catches it.
package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"aicap/pkg/ledger"
	"aicap/pkg/types"
)

// testSigningKey is a fixed Ed25519 seed so tests are deterministic. It
// is a test key: it signs nothing outside this suite.
const testSigningKey = "gO3CkYtR3n7t3XSDLU8dxKr6IF5j1Zx1Q2mJvHwGZ0k="

// enableSigning must run before setup(), since RegisterRoutes reads the
// key once at wiring time.
func enableSigning(t *testing.T) {
	t.Helper()
	t.Setenv("AICAP_LEDGER_SIGNING_KEY", testSigningKey)
}

func fetchPublicKey(t *testing.T, srvURL string) string {
	t.Helper()
	resp, err := http.Get(srvURL + "/api/ledger/public-key")
	if err != nil {
		t.Fatalf("public-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public-key status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if enabled, _ := out["enabled"].(bool); !enabled {
		t.Fatalf("public-key reports signing disabled: %v", out)
	}
	pub, _ := out["publicKey"].(string)
	if pub == "" {
		t.Fatal("public-key returned an empty key")
	}
	return pub
}

func TestLedgerPublicKey_ServedUnauthenticated(t *testing.T) {
	// Unauthenticated by design: a signature is worthless to a recipient
	// who cannot obtain the verifying key, and shared reports go to
	// people without accounts.
	enableSigning(t)
	srv, _ := setup(t)

	pub := fetchPublicKey(t, srv.URL)
	if _, err := ledger.ParsePublicKey(pub); err != nil {
		t.Errorf("published key does not parse: %v", err)
	}
}

func TestLedgerPublicKey_ReportsDisabledWhenNoKey(t *testing.T) {
	// A deployment without signing must say so plainly rather than
	// erroring — "we do not sign" is a legitimate answer to the question.
	t.Setenv("AICAP_LEDGER_SIGNING_KEY", "")
	srv, _ := setup(t)

	resp, err := http.Get(srv.URL + "/api/ledger/public-key")
	if err != nil {
		t.Fatalf("public-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if enabled, _ := out["enabled"].(bool); enabled {
		t.Errorf("reports enabled with no key configured: %v", out)
	}
}

func TestSaveProof_SignsEntry(t *testing.T) {
	enableSigning(t)
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000700"
	token := seedAPIKey(t, db, userID, "pro")

	saveProof(t, srv, token, types.AIBOM{ProjectName: "signed-proj", CommitSha: "sha-sign-1"})

	var signature, keyID, cryptoHash string
	if err := db.QueryRow(
		`SELECT signature, signing_key_id, crypto_hash FROM proof_drills WHERE user_id = $1`,
		userID,
	).Scan(&signature, &keyID, &cryptoHash); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if signature == "" {
		t.Fatal("row written without a signature while signing was configured")
	}
	if keyID == "" {
		t.Error("signing_key_id not recorded; key rotation would strand this row")
	}

	// The signature must verify using only the published public key —
	// that is what an independent party can do.
	pub, err := ledger.ParsePublicKey(fetchPublicKey(t, srv.URL))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	entry := ledger.Entry{Version: ledger.V2, UserID: userID, CommitSha: "sha-sign-1", CryptoHash: cryptoHash}
	if !ledger.VerifyWithPublicKey(pub, entry, signature) {
		t.Error("stored signature does not verify against the published public key")
	}
}

// TestVerifyChain_DetectsForgedRewrite is the reason this feature exists.
//
// It plays the attacker who owns the database: rewrite a row's payload,
// then recompute that row's crypto_hash and every later prev_hash so the
// chain is internally perfect. Before signing, that forgery verified
// clean. Now the signature over the rewritten row cannot be produced
// without the key, so verification fails.
func TestVerifyChain_DetectsForgedRewrite(t *testing.T) {
	enableSigning(t)
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000701"
	token := seedAPIKey(t, db, userID, "pro")

	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "sha-a"})
	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "sha-b"})

	jwtTok := mintJWT(t, userID, "owner@example.com")
	if got := getVerifyChain(t, srv, jwtTok); got["ok"] != true {
		t.Fatalf("setup: chain should start clean, got %v", got)
	}

	// --- the attack -------------------------------------------------
	// Rewrite the genesis row's BOM to hide a dependency, then repair
	// the chain around it exactly as the application would have.
	var genesisPrev *string
	var genesisSha, genesisAnnex, genesisRegister string
	if err := db.QueryRow(
		`SELECT commit_sha, prev_hash, annex_iv_markdown, COALESCE(risk_register_state::text, '')
		 FROM proof_drills WHERE user_id = $1
		 ORDER BY created_at ASC, id ASC LIMIT 1`, userID,
	).Scan(&genesisSha, &genesisPrev, &genesisAnnex, &genesisRegister); err != nil {
		t.Fatalf("read genesis: %v", err)
	}

	forgedBOM := `{"projectName":"p","dependencies":[],"complianceStatus":"Passed"}`
	var canonical string
	if err := db.QueryRow(`SELECT $1::jsonb::text`, forgedBOM).Scan(&canonical); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	prev := ""
	if genesisPrev != nil {
		prev = *genesisPrev
	}
	// Recompute the hash exactly as the application would for the forged
	// content (ledger V2 — the version new rows are written under).
	forgedHash := ledger.ChainHashV2(genesisSha, prev, ledger.Content{
		BOM:          []byte(canonical),
		AnnexIV:      []byte(genesisAnnex),
		RiskRegister: []byte(genesisRegister),
	}.Digests())

	if _, err := db.Exec(
		`UPDATE proof_drills SET ai_bom_json = $1::jsonb, crypto_hash = $2
		 WHERE user_id = $3 AND commit_sha = $4`,
		forgedBOM, forgedHash, userID, genesisSha,
	); err != nil {
		t.Fatalf("forge genesis: %v", err)
	}
	// Repair the link in the following row so the chain is consistent.
	if _, err := db.Exec(
		`UPDATE proof_drills SET prev_hash = $1
		 WHERE user_id = $2 AND commit_sha <> $3`,
		forgedHash, userID, genesisSha,
	); err != nil {
		t.Fatalf("repair chain: %v", err)
	}

	// --- the detection ----------------------------------------------
	got := getVerifyChain(t, srv, jwtTok)
	if got["ok"] != false {
		t.Fatalf("forged rewrite verified clean — the signature check is not catching it: %v", got)
	}
	reason, _ := got["reason"].(string)
	if reason == "" {
		t.Error("no reason given for the failure")
	}
	t.Logf("detected as: %s", reason)
}

func TestVerifyChain_ReportsUnsignedEntriesWithoutFailing(t *testing.T) {
	// Rows written before signing existed, or while no key was set, are
	// legitimately unsigned. They must not fail verification — but the
	// response must not let "ok: true" imply attribution either.
	t.Setenv("AICAP_LEDGER_SIGNING_KEY", "")
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000702"
	token := seedAPIKey(t, db, userID, "pro")

	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "sha-unsigned"})

	got := getVerifyChain(t, srv, mintJWT(t, userID, "o@example.com"))
	if got["ok"] != true {
		t.Fatalf("unsigned-but-consistent chain failed verification: %v", got)
	}
	if signed, _ := got["signed"].(float64); signed != 0 {
		t.Errorf("signed = %v, want 0", got["signed"])
	}
	if unsigned, _ := got["unsigned"].(float64); unsigned != 1 {
		t.Errorf("unsigned = %v, want 1", got["unsigned"])
	}
	if note, _ := got["note"].(string); note == "" {
		t.Error("no note explaining that entries are unsigned; ok:true would overstate the guarantee")
	}
}

func TestVerifyChain_CountsSignedEntries(t *testing.T) {
	enableSigning(t)
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000703"
	token := seedAPIKey(t, db, userID, "pro")

	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "s1"})
	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "s2"})

	got := getVerifyChain(t, srv, mintJWT(t, userID, "o@example.com"))
	if got["ok"] != true {
		t.Fatalf("clean signed chain failed: %v", got)
	}
	if signed, _ := got["signed"].(float64); signed != 2 {
		t.Errorf("signed = %v, want 2", got["signed"])
	}
	if unsigned, _ := got["unsigned"].(float64); unsigned != 0 {
		t.Errorf("unsigned = %v, want 0", got["unsigned"])
	}
	if note, ok := got["note"]; ok {
		t.Errorf("fully signed chain carried an unsigned note: %v", note)
	}
}

func TestPublicReport_CarriesVerifiableAttestation(t *testing.T) {
	// The share link is what an auditor actually receives. Without the
	// attestation block it is a page the report's own subject could have
	// written, and the recipient has no way to tell.
	enableSigning(t)
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000704"
	token := seedAPIKey(t, db, userID, "pro")

	saveProof(t, srv, token, types.AIBOM{ProjectName: "shared", CommitSha: "sha-shared"})

	var cryptoHash string
	if err := db.QueryRow(
		`SELECT crypto_hash FROM proof_drills WHERE user_id = $1`, userID,
	).Scan(&cryptoHash); err != nil {
		t.Fatalf("read hash: %v", err)
	}

	// Mint a share token through the API so the test exercises the real
	// path rather than writing the column directly.
	shareBody, _ := json.Marshal(map[string]string{"hash": cryptoHash})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/share-report", bytes.NewReader(shareBody))
	req.Header.Set("Authorization", "Bearer "+mintJWT(t, userID, "o@example.com"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("share-report: %v", err)
	}
	var shareOut map[string]any
	json.NewDecoder(resp.Body).Decode(&shareOut)
	resp.Body.Close()
	shareToken, _ := shareOut["token"].(string)
	if shareToken == "" {
		t.Fatalf("share-report returned no token: %v", shareOut)
	}

	// Fetch as an anonymous recipient would.
	pubResp, err := http.Get(srv.URL + "/api/public/report?token=" + shareToken)
	if err != nil {
		t.Fatalf("public report: %v", err)
	}
	defer pubResp.Body.Close()
	var report map[string]any
	if err := json.NewDecoder(pubResp.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}

	att, ok := report["attestation"].(map[string]any)
	if !ok {
		t.Fatalf("public report carries no attestation block: %v", report)
	}
	sig, _ := att["signature"].(string)
	msgB64, _ := att["signedMessage"].(string)
	if sig == "" || msgB64 == "" {
		t.Fatalf("attestation missing signature or signed message: %v", att)
	}

	// Verify exactly as an offline third party would: published key,
	// published message bytes, published signature. No account, no
	// database, no trust in the report's subject.
	pub, err := ledger.ParsePublicKey(fetchPublicKey(t, srv.URL))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	msg, err := base64.StdEncoding.DecodeString(msgB64)
	if err != nil {
		t.Fatalf("decode signed message: %v", err)
	}
	rawSig, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, msg, rawSig) {
		t.Error("a third party could not verify the shared report's signature")
	}

	// The tenant's internal user id must not leak to the recipient as a
	// field of its own.
	if _, leaked := report["userId"]; leaked {
		t.Error("public report exposes the owner's user id")
	}
}

// --- Ledger V2: the rendered document is inside the hash -------------------
//
// Under V1 the chain hash covered the commit and the AI-BOM. The Annex IV
// text and the risk register sat beside it, outside the hash and so
// outside the signature. The tests below pin the three things V2 has to
// deliver: an edit to the stored document is detected, a third party can
// tie the text they were sent to the signature, and the V1 rows already
// in production keep verifying.

// shareAndFetchReport mints a share token for one of the caller's proof drills
// and returns the public report as an anonymous recipient would fetch it.
func shareAndFetchReport(t *testing.T, srvURL, jwtTok, cryptoHash string) (string, map[string]any) {
	t.Helper()
	shareBody, _ := json.Marshal(map[string]string{"hash": cryptoHash})
	req, _ := http.NewRequest(http.MethodPost, srvURL+"/api/share-report", bytes.NewReader(shareBody))
	req.Header.Set("Authorization", "Bearer "+jwtTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("share-report: %v", err)
	}
	var shareOut map[string]any
	json.NewDecoder(resp.Body).Decode(&shareOut)
	resp.Body.Close()
	token, _ := shareOut["token"].(string)
	if token == "" {
		t.Fatalf("share-report returned no token: %v", shareOut)
	}
	return token, fetchPublicReport(t, srvURL, token)
}

func fetchPublicReport(t *testing.T, srvURL, token string) map[string]any {
	t.Helper()
	resp, err := http.Get(srvURL + "/api/public/report?token=" + token)
	if err != nil {
		t.Fatalf("public report: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public report status = %d, want 200", resp.StatusCode)
	}
	var report map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return report
}

// toLedgerReport maps the public JSON onto ledger.Report using only
// fields a recipient is given.
func toLedgerReport(t *testing.T, report map[string]any) ledger.Report {
	t.Helper()
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	att, _ := report["attestation"].(map[string]any)
	integ, ok := report["integrity"].(map[string]any)
	if !ok {
		t.Fatalf("public report carries no integrity block: %v", report)
	}
	version, _ := integ["chainVersion"].(float64)
	return ledger.Report{
		Markdown:     str(report, "markdown"),
		CommitSha:    str(report, "commitSha"),
		CryptoHash:   str(report, "cryptoHash"),
		PrevHash:     str(integ, "prevHash"),
		ChainVersion: int(version),
		Digests: ledger.Digests{
			BOM:          str(integ, "bomSha256"),
			AnnexIV:      str(integ, "annexIvSha256"),
			RiskRegister: str(integ, "riskRegisterSha256"),
		},
		Signature:     str(att, "signature"),
		SignedMessage: str(att, "signedMessage"),
	}
}

func TestVerifyChain_DetectsEditedDocument(t *testing.T) {
	// No signing key: this is the hash chain's own job. Before V2 this
	// edit was invisible to verify-chain.
	t.Setenv("AICAP_LEDGER_SIGNING_KEY", "")
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000710"
	token := seedAPIKey(t, db, userID, "pro")
	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "doc-1"})
	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "doc-2"})

	jwtTok := mintJWT(t, userID, "o@example.com")
	clean := getVerifyChain(t, srv, jwtTok)
	if clean["ok"] != true {
		t.Fatalf("setup: chain should start clean, got %v", clean)
	}
	if bound, _ := clean["documentBound"].(float64); bound != 2 {
		t.Errorf("documentBound = %v, want 2 (both entries are V2)", clean["documentBound"])
	}
	if _, has := clean["documentNote"]; has {
		t.Errorf("fully V2 chain carried a V1 caveat: %v", clean["documentNote"])
	}

	if _, err := db.Exec(
		"UPDATE proof_drills SET annex_iv_markdown = annex_iv_markdown || ' (edited after the fact)' "+
			"WHERE user_id = $1 AND commit_sha = 'doc-1'", userID); err != nil {
		t.Fatalf("edit document: %v", err)
	}

	got := getVerifyChain(t, srv, jwtTok)
	if got["ok"] != false {
		t.Fatalf("an edited Annex IV document verified clean: %v", got)
	}
}

func TestVerifyChain_DetectsEditedRiskRegister(t *testing.T) {
	t.Setenv("AICAP_LEDGER_SIGNING_KEY", "")
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000711"
	token := seedAPIKey(t, db, userID, "pro")
	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "reg-1"})

	if _, err := db.Exec(
		"UPDATE proof_drills SET risk_register_state = $2::jsonb WHERE user_id = $1",
		userID, `{"findings": [], "forged": true}`); err != nil {
		t.Fatalf("edit register: %v", err)
	}
	if got := getVerifyChain(t, srv, mintJWT(t, userID, "o@example.com")); got["ok"] != false {
		t.Fatalf("an edited risk register verified clean: %v", got)
	}
}

// The claim the paid tier makes, checked the way a recipient would check
// it: with the public JSON, the public key, and nothing else.
func TestPublicReport_DocumentIsBoundToTheSignature(t *testing.T) {
	enableSigning(t)
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000712"
	token := seedAPIKey(t, db, userID, "pro")
	saveProof(t, srv, token, types.AIBOM{ProjectName: "bound", CommitSha: "sha-bound"})

	var cryptoHash string
	if err := db.QueryRow("SELECT crypto_hash FROM proof_drills WHERE user_id = $1", userID).Scan(&cryptoHash); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	shareToken, report := shareAndFetchReport(t, srv.URL, mintJWT(t, userID, "o@example.com"), cryptoHash)

	pub, err := ledger.ParsePublicKey(fetchPublicKey(t, srv.URL))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	check := ledger.VerifyReport(pub, toLedgerReport(t, report))
	if !check.OK() {
		t.Fatalf("an untouched shared report did not fully verify: %+v", check)
	}

	// V2 signs an opaque tenant reference; the owner's account id must
	// not be recoverable from anything the recipient receives.
	att, _ := report["attestation"].(map[string]any)
	signedB64, _ := att["signedMessage"].(string)
	msg, _ := base64.StdEncoding.DecodeString(signedB64)
	if bytes.Contains(msg, []byte(userID)) {
		t.Error("the signed message discloses the owner's user id")
	}

	// Now the owner (or anyone with database access) rewrites the
	// document after sharing it. The recipient re-fetches the same link.
	if _, err := db.Exec(
		"UPDATE proof_drills SET annex_iv_markdown = '# Annex IV - nothing to report' WHERE user_id = $1",
		userID); err != nil {
		t.Fatalf("rewrite document: %v", err)
	}
	tampered := ledger.VerifyReport(pub, toLedgerReport(t, fetchPublicReport(t, srv.URL, shareToken)))
	if tampered.OK() {
		t.Fatalf("a rewritten document still verified for the recipient: %+v", tampered)
	}
	if !tampered.SignatureValid {
		t.Errorf("the signature itself was not touched and should still be valid: %+v", tampered)
	}
	t.Logf("detected as: %v", tampered.Problems)
}

// Every row in production today is V1. They must keep verifying, keep
// their signatures, and be reported as not document-bound — neither
// broken by the upgrade nor silently promoted.
func TestVerifyChain_LegacyV1EntriesStillVerify(t *testing.T) {
	enableSigning(t)
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000713"
	token := seedAPIKey(t, db, userID, "pro")

	// Write a genesis row exactly as v1.7.x did: V1 hash, V1 signature,
	// chain_version left to its default.
	signer, err := ledger.LoadSigner()
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	var projectID, canonical string
	if err := db.QueryRow(
		"INSERT INTO projects (name) VALUES ('legacy-proj') RETURNING id").Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	const legacyBOM = `{"projectName":"legacy-proj","commitSha":"legacy-1"}`
	if err := db.QueryRow("SELECT $1::jsonb::text", legacyBOM).Scan(&canonical); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	v1Hash := ledger.ChainHashV1("legacy-1", []byte(canonical), "")
	v1Sig := signer.Sign(ledger.Entry{Version: ledger.V1, UserID: userID, CommitSha: "legacy-1", CryptoHash: v1Hash})
	if _, err := db.Exec(
		"INSERT INTO proof_drills (project_id, user_id, commit_sha, ai_bom_json, annex_iv_markdown, "+
			"crypto_hash, signature, signing_key_id, created_at) "+
			"VALUES ($1, $2, 'legacy-1', $3::jsonb, '# legacy Annex IV', $4, $5, $6, NOW() - INTERVAL '1 day')",
		projectID, userID, legacyBOM, v1Hash, v1Sig, signer.KeyID()); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// A new scan chains onto it under V2.
	saveProof(t, srv, token, types.AIBOM{ProjectName: "legacy-proj", CommitSha: "new-2"})

	jwtTok := mintJWT(t, userID, "o@example.com")
	got := getVerifyChain(t, srv, jwtTok)
	if got["ok"] != true {
		t.Fatalf("a V1 entry followed by a V2 entry failed verification: %v", got)
	}
	if signed, _ := got["signed"].(float64); signed != 2 {
		t.Errorf("signed = %v, want 2 — the V1 signature must still verify", got["signed"])
	}
	if bound, _ := got["documentBound"].(float64); bound != 1 {
		t.Errorf("documentBound = %v, want 1 (only the new entry)", got["documentBound"])
	}
	if note, _ := got["documentNote"].(string); note == "" {
		t.Error("no caveat for the V1 entry; ok:true would overstate what was checked")
	}

	// Sharing the V1 entry: attributed, and honest that the document is
	// not covered.
	_, report := shareAndFetchReport(t, srv.URL, jwtTok, v1Hash)
	integ, _ := report["integrity"].(map[string]any)
	if covered, _ := integ["documentCovered"].(bool); covered {
		t.Error("a V1 report claims its document is covered by the hash")
	}
	pub, _ := ledger.ParsePublicKey(fetchPublicKey(t, srv.URL))
	check := ledger.VerifyReport(pub, toLedgerReport(t, report))
	if !check.SignatureValid || !check.MessageMatchesReport {
		t.Errorf("the V1 report's signature no longer verifies: %+v", check)
	}
	if check.DocumentBound {
		t.Error("the verifier reported a V1 document as bound")
	}
}
