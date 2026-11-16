package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aicap/pkg/ledger"
)

// reportServer stands in for the AIcap backend: it serves a signed public
// report and the key that signed it, the way production does.
type reportServer struct {
	*httptest.Server
	publicKey string
	report    map[string]any
}

func newReportServer(t *testing.T, version int) *reportServer {
	t.Helper()
	seed, err := ledger.GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	t.Setenv("AICAP_LEDGER_SIGNING_KEY", seed)
	signer, err := ledger.LoadSigner()
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}

	content := ledger.Content{
		BOM:          []byte(`{"projectName": "acme/hiring"}`),
		AnnexIV:      []byte("# Annex IV\n\nA CV-screening assistant.\n"),
		RiskRegister: []byte(`{"findings": []}`),
	}
	const commit = "9f2c1e7"
	hash, err := ledger.ChainHash(version, commit, "", content)
	if err != nil {
		t.Fatalf("chain hash: %v", err)
	}
	entry := ledger.Entry{Version: version, UserID: "3b0c2f6e-1111-4222-8333-444455556666", CommitSha: commit, CryptoHash: hash}

	integrity := map[string]any{"chainVersion": version, "documentCovered": version == ledger.V2}
	if version == ledger.V2 {
		d := content.Digests()
		integrity["prevHash"] = ""
		integrity["bomSha256"] = d.BOM
		integrity["annexIvSha256"] = d.AnnexIV
		integrity["riskRegisterSha256"] = d.RiskRegister
	}
	rs := &reportServer{
		publicKey: signer.PublicKeyBase64(),
		report: map[string]any{
			"markdown":    string(content.AnnexIV),
			"commitSha":   commit,
			"cryptoHash":  hash,
			"createdAt":   "2026-11-16T09:00:00Z",
			"projectName": "acme/hiring",
			"integrity":   integrity,
			"attestation": map[string]any{
				"signature":     signer.Sign(entry),
				"signedMessage": base64.StdEncoding.EncodeToString(entry.Message()),
				"publicKeyPath": "/api/ledger/public-key",
			},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/public/report", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(rs.report)
	})
	mux.HandleFunc("/api/ledger/public-key", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"enabled": true, "publicKey": rs.publicKey})
	})
	rs.Server = httptest.NewServer(mux)
	t.Cleanup(rs.Close)
	return rs
}

func (rs *reportServer) url() string {
	return rs.URL + "/api/public/report?token=" + strings.Repeat("a", 64)
}

func verify(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runVerifyReport(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func TestVerifyReport_CLI_VerifiesAnUntouchedReport(t *testing.T) {
	rs := newReportServer(t, ledger.V2)
	out, errOut, code := verify(t, rs.url())
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "VERIFIED: this document is the one recorded") || strings.Contains(out, "FAIL") {
		t.Errorf("unexpected output:\n%s", out)
	}
	// A key fetched from the report's own server is the weaker check, and
	// the output has to say so.
	if !strings.Contains(out, "same server as the report") {
		t.Errorf("no caveat about the key's provenance:\n%s", out)
	}
}

// The case the command exists for: the text was changed after it was
// recorded. The signature is still valid; the document is not the one
// that was signed.
func TestVerifyReport_CLI_DetectsAnEditedDocument(t *testing.T) {
	rs := newReportServer(t, ledger.V2)
	rs.report["markdown"] = "# Annex IV\n\nA spell checker.\n"

	out, _, code := verify(t, rs.url())
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "[PASS] Signature verifies") || !strings.Contains(out, "[FAIL] The document text") {
		t.Errorf("want signature PASS and document FAIL:\n%s", out)
	}
	if strings.Contains(out, "\nVERIFIED:") {
		t.Errorf("an edited document was reported as verified:\n%s", out)
	}
}

func TestVerifyReport_CLI_Version1IsOnlyPartlyVerified(t *testing.T) {
	rs := newReportServer(t, ledger.V1)
	out, _, code := verify(t, rs.url())
	if code != 1 {
		t.Fatalf("exit %d, want 1 — a version 1 entry cannot be fully verified\n%s", code, out)
	}
	if !strings.Contains(out, "PARTLY VERIFIED") || !strings.Contains(out, "version 1") {
		t.Errorf("version 1 limitation not explained:\n%s", out)
	}
}

func TestVerifyReport_CLI_PinnedKeyAndFileInput(t *testing.T) {
	rs := newReportServer(t, ledger.V2)

	// From a saved file, with the key obtained out of band.
	b, _ := json.Marshal(rs.report)
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code := verify(t, path, "--public-key", rs.publicKey)
	if code != 0 || strings.Contains(out, "same server as the report") {
		t.Errorf("exit %d; pinned-key run should verify without the provenance caveat:\n%s", code, out)
	}

	// A file with no key cannot be checked, and must not pretend to be.
	if _, errOut, code := verify(t, path); code != 2 || !strings.Contains(errOut, "--public-key") {
		t.Errorf("file without a key: exit %d, stderr %q", code, errOut)
	}

	// The wrong key is a failure, not a partial pass.
	other, _ := ledger.GenerateSigningKey()
	t.Setenv("AICAP_LEDGER_SIGNING_KEY", other)
	otherSigner, _ := ledger.LoadSigner()
	out, _, code = verify(t, rs.url(), "--public-key", otherSigner.PublicKeyBase64())
	if code != 1 || !strings.Contains(out, "NOT VERIFIED") {
		t.Errorf("wrong key: exit %d\n%s", code, out)
	}
}

func TestVerifyReport_CLI_RejectsUnusableInput(t *testing.T) {
	// The share link people actually hold is the web page; say what to
	// use instead rather than failing on its HTML.
	if _, errOut, code := verify(t, "https://aicap.dev/?report="+strings.Repeat("a", 64)); code != 2 ||
		!strings.Contains(errOut, "/api/public/report") {
		t.Errorf("web-page URL: exit %d, stderr %q", code, errOut)
	}
	if _, _, code := verify(t); code != 2 {
		t.Errorf("no arguments: exit %d, want 2", code)
	}
}

// A report must not be able to direct the verifier to a "public key" on a
// server of the report's choosing.
func TestResolveKeyURL_StaysOnTheReportsOrigin(t *testing.T) {
	got, err := resolveKeyURL("https://api.example.com/api/public/report?token=x", "")
	if err != nil || got != "https://api.example.com/api/ledger/public-key" {
		t.Errorf("default path: %q, %v", got, err)
	}
	for _, bad := range []string{"https://evil.example/key", "//evil.example/key", "evil.example/key"} {
		if got, err := resolveKeyURL("https://api.example.com/api/public/report", bad); err == nil {
			t.Errorf("keyPath %q accepted, resolved to %q", bad, got)
		}
	}
}
