package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"aicap/pkg/ledger"
)

// runVerifyReport is the `--verify-report` subcommand: check a shared
// report as a third party would, with nothing but the report and the
// ledger's public key.
//
//	aicap --verify-report <report URL | report.json> [--public-key <base64>]
//
// The paid tier's claim is that a recipient can check a report without
// trusting whoever sent it. Until this command existed, "check" meant
// base64-decoding two fields and finding an Ed25519 implementation — and
// even then it only showed that some entry was signed, not that the text
// in hand was the text that was signed. This performs all three checks
// (see ledger.VerifyReport) and says which of them passed.
//
// Exit codes: 0 fully verified; 1 not fully verified (the output says
// which check failed, or that the entry predates document binding);
// 2 the report or key could not be obtained or parsed.
func runVerifyReport(args []string, stdout, stderr io.Writer) int {
	var source, pinnedKey string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--public-key" && i+1 < len(args):
			pinnedKey = args[i+1]
			i++
		case !strings.HasPrefix(args[i], "--") && source == "":
			source = args[i]
		}
	}
	if source == "" {
		fmt.Fprintln(stderr, "usage: aicap --verify-report <report URL | report.json> [--public-key <base64>]")
		return 2
	}

	isURL := strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
	client := &http.Client{Timeout: 20 * time.Second}

	var body []byte
	var err error
	if isURL {
		if !strings.Contains(source, "/api/public/report") {
			fmt.Fprintln(stderr, "That looks like the report's web page, not its API URL.")
			fmt.Fprintln(stderr, "Use the form: https://<backend>/api/public/report?token=<share token>")
			return 2
		}
		body, err = httpGet(client, source)
	} else {
		body, err = os.ReadFile(source)
	}
	if err != nil {
		fmt.Fprintf(stderr, "could not read the report: %v\n", err)
		return 2
	}

	var doc publicReportJSON
	if err := json.Unmarshal(body, &doc); err != nil {
		fmt.Fprintf(stderr, "the report is not valid JSON: %v\n", err)
		return 2
	}

	// The public key. A key supplied by the caller is the stronger check:
	// a key fetched from the server that produced the signature only
	// shows the report is consistent with what that server says today.
	keySource := "supplied with --public-key"
	if pinnedKey == "" {
		if !isURL {
			fmt.Fprintln(stderr, "a report read from a file needs --public-key <base64>: there is no server to ask")
			return 2
		}
		keyURL, err := resolveKeyURL(source, doc.Attestation.PublicKeyPath)
		if err != nil {
			fmt.Fprintf(stderr, "could not work out where the public key is published: %v\n", err)
			return 2
		}
		keyBody, err := httpGet(client, keyURL)
		if err != nil {
			fmt.Fprintf(stderr, "could not fetch the public key: %v\n", err)
			return 2
		}
		var key struct {
			PublicKey string `json:"publicKey"`
		}
		if err := json.Unmarshal(keyBody, &key); err != nil || key.PublicKey == "" {
			fmt.Fprintf(stderr, "%s did not return a public key\n", keyURL)
			return 2
		}
		pinnedKey = key.PublicKey
		keySource = "fetched from " + keyURL
	}
	pub, err := ledger.ParsePublicKey(pinnedKey)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	check := ledger.VerifyReport(pub, doc.toLedgerReport())
	printReportCheck(stdout, doc, pub, keySource, check)
	if check.OK() {
		return 0
	}
	return 1
}

// publicReportJSON is the subset of GET /api/public/report this command
// reads.
type publicReportJSON struct {
	Markdown    string `json:"markdown"`
	CommitSha   string `json:"commitSha"`
	CryptoHash  string `json:"cryptoHash"`
	CreatedAt   string `json:"createdAt"`
	ProjectName string `json:"projectName"`
	Attestation struct {
		Signature     string `json:"signature"`
		SignedMessage string `json:"signedMessage"`
		PublicKeyPath string `json:"publicKeyPath"`
	} `json:"attestation"`
	Integrity *struct {
		ChainVersion       int    `json:"chainVersion"`
		PrevHash           string `json:"prevHash"`
		BOMSha256          string `json:"bomSha256"`
		AnnexIVSha256      string `json:"annexIvSha256"`
		RiskRegisterSha256 string `json:"riskRegisterSha256"`
	} `json:"integrity"`
}

func (d publicReportJSON) toLedgerReport() ledger.Report {
	r := ledger.Report{
		Markdown:      d.Markdown,
		CommitSha:     d.CommitSha,
		CryptoHash:    d.CryptoHash,
		Signature:     d.Attestation.Signature,
		SignedMessage: d.Attestation.SignedMessage,
		// A report from a backend older than v1.8.0 has no integrity
		// block. Every entry such a backend wrote is version 1.
		ChainVersion: ledger.V1,
	}
	if d.Integrity != nil {
		r.ChainVersion = d.Integrity.ChainVersion
		r.PrevHash = d.Integrity.PrevHash
		r.Digests = ledger.Digests{
			BOM:          d.Integrity.BOMSha256,
			AnnexIV:      d.Integrity.AnnexIVSha256,
			RiskRegister: d.Integrity.RiskRegisterSha256,
		}
	}
	return r
}

func printReportCheck(w io.Writer, doc publicReportJSON, pub ed25519.PublicKey, keySource string, c ledger.ReportCheck) {
	mark := func(ok bool) string {
		if ok {
			return "PASS"
		}
		return "FAIL"
	}
	fmt.Fprintf(w, "Report       %s @ %s\n", orDash(doc.ProjectName), orDash(doc.CommitSha))
	fmt.Fprintf(w, "Recorded     %s\n", orDash(doc.CreatedAt))
	fmt.Fprintf(w, "Ledger hash  %s\n", orDash(doc.CryptoHash))
	fmt.Fprintf(w, "Public key   %s (%s)\n\n", ledger.KeyIDOf(pub), keySource)

	fmt.Fprintf(w, "[%s] Signature verifies under this public key\n", mark(c.SignatureValid))
	fmt.Fprintf(w, "[%s] The signed bytes name this commit and ledger hash\n", mark(c.MessageMatchesReport))
	fmt.Fprintf(w, "[%s] The document text is the text that was signed\n", mark(c.DocumentBound))
	for _, p := range c.Problems {
		fmt.Fprintf(w, "\n  - %s\n", p)
	}

	fmt.Fprintln(w)
	if c.OK() {
		fmt.Fprintln(w, "VERIFIED: this document is the one recorded in the ledger at scan time.")
	} else if c.SignatureValid && c.MessageMatchesReport {
		fmt.Fprintln(w, "PARTLY VERIFIED: the ledger entry is genuine, but the document text is not covered or does not match.")
	} else {
		fmt.Fprintln(w, "NOT VERIFIED.")
	}
	if strings.HasPrefix(keySource, "fetched") {
		fmt.Fprintln(w, "\nThe public key came from the same server as the report. For a check that does not")
		fmt.Fprintln(w, "rest on that server, obtain the key through another channel and pass --public-key.")
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// resolveKeyURL builds the public-key URL from the report URL's origin
// and the path the report names. Only a path on the same origin is
// accepted: a report must not be able to send the verifier to fetch its
// "public key" from somewhere of the report's choosing.
func resolveKeyURL(reportURL, keyPath string) (string, error) {
	u, err := url.Parse(reportURL)
	if err != nil {
		return "", err
	}
	if keyPath == "" {
		keyPath = "/api/ledger/public-key"
	}
	if !strings.HasPrefix(keyPath, "/") || strings.HasPrefix(keyPath, "//") {
		return "", fmt.Errorf("report names a public key location that is not a path on its own server: %q", keyPath)
	}
	return u.Scheme + "://" + u.Host + keyPath, nil
}

func httpGet(client *http.Client, target string) ([]byte, error) {
	resp, err := client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", target, resp.StatusCode)
	}
	// A report is a markdown document plus a few hashes; 16 MB is far
	// more than any real one and keeps a hostile server from feeding an
	// unbounded body.
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}
