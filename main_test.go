package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"aicap/pkg/compliance"
	"aicap/pkg/scanner"
	"aicap/pkg/types"
)

func TestParseCLIArgs_DirectoryOnly(t *testing.T) {
	opts := parseCLIArgs([]string{"./repo"})
	if opts.ScanDir != "./repo" {
		t.Errorf("ScanDir=%q want ./repo", opts.ScanDir)
	}
	if len(opts.ImageRefs) != 0 || len(opts.TarballPaths) != 0 || opts.WantCycloneDX {
		t.Errorf("unexpected flags: %+v", opts)
	}
	if opts.AnnexIVPath != "" || opts.NoAnnexIV {
		t.Errorf("Annex IV defaults wrong: %+v", opts)
	}
}

func TestParseCLIArgs_DefaultsScanDirToDot(t *testing.T) {
	if got := parseCLIArgs(nil).ScanDir; got != "." {
		t.Errorf("ScanDir=%q want .", got)
	}
}

func TestParseCLIArgs_RepeatedImageFlags(t *testing.T) {
	opts := parseCLIArgs([]string{
		"./src",
		"--image", "ghcr.io/foo/bar:1",
		"--image-tar", "/tmp/local.tar",
		"--image", "registry.example.com/baz:latest",
		"--cyclonedx",
	})
	if opts.ScanDir != "./src" {
		t.Errorf("ScanDir=%q want ./src", opts.ScanDir)
	}
	wantRefs := []string{"ghcr.io/foo/bar:1", "registry.example.com/baz:latest"}
	if !reflect.DeepEqual(opts.ImageRefs, wantRefs) {
		t.Errorf("ImageRefs=%v want %v", opts.ImageRefs, wantRefs)
	}
	wantTar := []string{"/tmp/local.tar"}
	if !reflect.DeepEqual(opts.TarballPaths, wantTar) {
		t.Errorf("TarballPaths=%v want %v", opts.TarballPaths, wantTar)
	}
	if !opts.WantCycloneDX {
		t.Error("expected --cyclonedx to be true")
	}
}

func TestParseCLIArgs_UnknownFlagsIgnored(t *testing.T) {
	// Forward-compat: an older binary called by a newer action.yml
	// must not abort on unrecognised flags.
	if got := parseCLIArgs([]string{"--future-flag", "value", "./src"}).ScanDir; got != "./src" {
		t.Errorf("ScanDir=%q want ./src", got)
	}
}

func TestParseCLIArgs_MissingFlagValueIsTolerated(t *testing.T) {
	// --image at the very end with no value should not panic; the
	// flag is simply dropped.
	if got := parseCLIArgs([]string{"./src", "--image"}).ImageRefs; len(got) != 0 {
		t.Errorf("trailing --image with no value should be ignored, got %v", got)
	}
}

// Wave 16: Annex IV flags.

func TestParseCLIArgs_AnnexIVPath(t *testing.T) {
	opts := parseCLIArgs([]string{"./src", "--annex-iv", "out/annex-iv.md"})
	if opts.AnnexIVPath != "out/annex-iv.md" {
		t.Errorf("AnnexIVPath=%q want out/annex-iv.md", opts.AnnexIVPath)
	}
	if opts.ScanDir != "./src" {
		t.Errorf("ScanDir=%q want ./src", opts.ScanDir)
	}
}

func TestParseCLIArgs_NoAnnexIV(t *testing.T) {
	opts := parseCLIArgs([]string{"./src", "--no-annex-iv"})
	if !opts.NoAnnexIV {
		t.Error("--no-annex-iv did not set NoAnnexIV")
	}
}

func TestParseCLIArgs_AnnexIVPathMissingValueIsTolerated(t *testing.T) {
	if got := parseCLIArgs([]string{"./src", "--annex-iv"}).AnnexIVPath; got != "" {
		t.Errorf("trailing --annex-iv with no value should be ignored, got %q", got)
	}
}

// Wave 12: complianceExitCode returns 2 when any policy violation has
// Blocker severity, even if bom.Compliance is otherwise "Passed".
func TestComplianceExitCode_PolicyBlockerWins(t *testing.T) {
	bom := types.AIBOM{
		Compliance: "Passed",
		PolicyViolations: []types.PolicyViolation{
			{Rule: "blocked_model", Severity: "Blocker", Description: "x"},
		},
	}
	if got := complianceExitCode(bom); got != 2 {
		t.Errorf("exit = %d, want 2 for Blocker policy violation", got)
	}
}

// A non-Blocker policy warning alone should not trigger exit 2 — it's
// information, not a fail-fast signal.
func TestComplianceExitCode_WarningDoesNotTrigger2(t *testing.T) {
	bom := types.AIBOM{
		Compliance: "Passed",
		PolicyViolations: []types.PolicyViolation{
			{Rule: "missing_license", Severity: "Warning", Description: "x"},
		},
	}
	if got := complianceExitCode(bom); got != 0 {
		t.Errorf("exit = %d, want 0 when only warnings present", got)
	}
}

// Pre-Wave-12 fallback: high-risk dep without policy still maps to
// exit 1 so existing CI pipelines see no behaviour change.
func TestComplianceExitCode_NonPolicyFailureIsOne(t *testing.T) {
	bom := types.AIBOM{Compliance: "Action Required (Annex IV Documentation Missing)"}
	if got := complianceExitCode(bom); got != 1 {
		t.Errorf("exit = %d, want 1 for non-policy failure", got)
	}
}

func TestComplianceExitCode_PassedIsZero(t *testing.T) {
	if got := complianceExitCode(types.AIBOM{Compliance: "Passed"}); got != 0 {
		t.Errorf("exit = %d, want 0", got)
	}
}

func TestBadgeMarkdown_Passing(t *testing.T) {
	bom := types.AIBOM{Compliance: "Passed"}
	got := badgeMarkdown(bom)
	if !strings.Contains(got, "passing-10b981") {
		t.Errorf("badge=%q want passing/green", got)
	}
	if !strings.Contains(got, "https://aicap.dev") {
		t.Errorf("badge=%q must link back to aicap.dev", got)
	}
}

func TestBadgeMarkdown_ActionRequired(t *testing.T) {
	bom := types.AIBOM{Compliance: "Action Required (Annex IV Documentation Missing)"}
	got := badgeMarkdown(bom)
	if !strings.Contains(got, "action%20required-f59e0b") {
		t.Errorf("badge=%q want action-required/amber", got)
	}
}

func TestBadgeMarkdown_BlockerOutranksPosture(t *testing.T) {
	// A Blocker policy violation must win even when the posture string
	// is "Passed" — mirrors the complianceExitCode precedence.
	bom := types.AIBOM{
		Compliance: "Passed",
		PolicyViolations: []types.PolicyViolation{
			{Rule: "blocked_models", Severity: "Blocker", Description: "gpt-4 is blocked"},
		},
	}
	got := badgeMarkdown(bom)
	if !strings.Contains(got, "policy%20breach-ef4444") {
		t.Errorf("badge=%q want policy-breach/red", got)
	}
}

func TestSyncStatusMessage_CreatedAndIdempotentAreSuccess(t *testing.T) {
	if got := syncStatusMessage(201); !strings.HasPrefix(got, "[+]") {
		t.Errorf("201 message = %q, want success prefix [+]", got)
	}
	got := syncStatusMessage(200)
	if !strings.HasPrefix(got, "[+]") || !strings.Contains(got, "idempotent") {
		t.Errorf("200 message = %q, want success prefix and idempotent mention", got)
	}
}

func TestSyncStatusMessage_KnownRejectionsNameTheirCause(t *testing.T) {
	if got := syncStatusMessage(402); !strings.Contains(got, "quota") {
		t.Errorf("402 message = %q, want quota mention", got)
	}
	if got := syncStatusMessage(401); !strings.Contains(got, "API key") {
		t.Errorf("401 message = %q, want API key mention", got)
	}
	if got := syncStatusMessage(503); !strings.Contains(got, "HTTP 503") {
		t.Errorf("503 message = %q, want status code surfaced", got)
	}
}

func TestParseCLIArgs_FinOpsFlag(t *testing.T) {
	// Cost figures are opt-in for the compliance document.
	if parseCLIArgs([]string{"./src"}).IncludeCosts {
		t.Error("cost estimates must be off by default in the Annex IV draft")
	}
	if !parseCLIArgs([]string{"./src", "--finops"}).IncludeCosts {
		t.Error("--finops did not enable cost estimates")
	}
}

// TestVersionReferencesAreConsistent fails when any user-facing install
// instruction drifts from the canonical version in the repo-root VERSION
// file.
//
// This exists because the drift already happened. v1.5.0 and v1.6.0 were
// released, tagged, and deployed while the dashboard's CI snippet and two
// *published* guides carried on telling readers to install v1.4.0 — the
// release checklist bumped action.yml, the README, and the CI templates,
// and nobody thought to grep the frontend. A version string duplicated
// across six surfaces and bumped by hand will eventually disagree with
// itself, and the surfaces users actually read are exactly the ones that
// get forgotten.
//
// Adding a surface that quotes the version means adding it here.
func TestVersionReferencesAreConsistent(t *testing.T) {
	raw, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	want := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(want, "v") {
		t.Fatalf("VERSION = %q, want a v-prefixed tag", want)
	}

	// Files that must quote the current version, and the pattern that
	// finds any version reference in them.
	surfaces := []string{
		"action.yml",
		"README.md",
		"templates/gitlab-ci.yml",
		"templates/bitbucket-pipelines.yml",
		"frontend/src/lib/version.js",
	}
	// Every published guide, globbed rather than enumerated. Listing them
	// by hand is the same brittleness this test exists to catch: the
	// first version of it named two guides and missed a third that was
	// quietly telling readers to curl the v1.4.0 binary.
	guides, err := filepath.Glob("frontend/guides/*.md")
	if err != nil {
		t.Fatalf("glob guides: %v", err)
	}
	if len(guides) == 0 {
		t.Fatal("no guides found — did frontend/guides move?")
	}
	for _, g := range guides {
		// Only guides that actually quote a version need checking.
		body, err := os.ReadFile(g)
		if err == nil && regexp.MustCompile(`v1\.\d+\.\d+`).Match(body) {
			surfaces = append(surfaces, filepath.ToSlash(g))
		}
	}
	versionRe := regexp.MustCompile(`v1\.\d+\.\d+`)

	for _, path := range surfaces {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		found := versionRe.FindAllString(string(body), -1)
		if len(found) == 0 {
			t.Errorf("%s quotes no version at all — did the install snippet move?", path)
			continue
		}

		for _, got := range found {
			if got != want {
				t.Errorf("%s references %s but VERSION says %s — a user following this "+
					"instruction installs the wrong release", path, got, want)
			}
		}
	}
}

// TestAnnexIVIsByteStableAcrossScans is the end-to-end guard for the
// determinism the ledger depends on.
//
// The BOM is what /api/save-proof hashes into the audit chain. If a scan
// of an unchanged tree can produce a different byte sequence, then two
// runs yield two crypto_hashes and the chain cannot distinguish "the
// code changed" from "a map iterated differently" — which is the whole
// claim the paid tier rests on. It also meant the generated Annex IV
// reshuffled its own sections between runs.
//
// Three separate map-range loops caused it: the Dockerfile pip-install
// match, the Dockerfile base-image match, and the GPU cost lookup. The
// per-package tests cover each; this one covers the property they exist
// to protect.
func TestAnnexIVIsByteStableAcrossScans(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"Dockerfile":       "FROM nvcr.io/nvidia/pytorch:24.01-py3\nRUN pip install openai langchain torch transformers\n",
		"requirements.txt": "openai==1.40.0\ntorch==2.4.0\nlangchain==0.2.0\n",
		"main.tf":          "resource \"aws_instance\" \"a\" {\n  instance_type = \"p4d.24xlarge\"\n}\nresource \"aws_instance\" \"b\" {\n  instance_type = \"g5.xlarge\"\n}\n",
		"app.py":           "import openai\nMODEL = \"gpt-5\"\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	// Drop the two lines that legitimately differ between runs.
	render := func() string {
		bom := scanner.PerformScan(dir)
		md := compliance.GenerateAnnexIVMarkdown(bom)
		var kept []string
		for _, line := range strings.Split(md, "\n") {
			if strings.HasPrefix(line, "*Generated:") || strings.Contains(line, "Scan Timestamp") {
				continue
			}
			kept = append(kept, line)
		}
		return strings.Join(kept, "\n")
	}

	first := render()
	for i := 0; i < 10; i++ {
		if got := render(); got != first {
			t.Fatal("Annex IV differs between scans of an identical tree — " +
				"the ledger hash computed over this BOM would differ too")
		}
	}
}

// runCLIForTest runs the --cli subcommand against the repo's own fixture
// tree with the network switched off, and returns what it wrote to each
// stream.
func runCLIForTest(t *testing.T, extra ...string) (stdout, stderr string, code int) {
	t.Helper()
	// No cloud sync, no OSV lookups, no remote catalog: the test must not
	// depend on the network or on whatever the developer has exported.
	t.Setenv("AICAP_API_KEY", "")
	t.Setenv("AICAP_OSV_DISABLED", "true")
	t.Setenv("AICAP_CATALOG_URL", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_SHA", "")

	var out, errOut bytes.Buffer
	code = runCLI(append([]string{"testing_files"}, extra...), &out, &errOut)
	return out.String(), errOut.String(), code
}

// stdout carries exactly one JSON document, in every output format.
//
// Until v1.8.0 the CLI printed a banner before the JSON and the verdict,
// sync status and README badge after it, all on stdout. Redirecting the
// SBOM to a file — which is what the shipped GitLab template does, and
// what anyone feeding Dependency-Track would do — produced a file no
// parser would accept. Nothing caught it because every other test
// exercises the functions that build the BOM, not the stream it is
// written to.
func TestRunCLI_StdoutIsOneJSONDocument(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantKey string
	}{
		{"aicap json", []string{"--no-annex-iv"}, "complianceStatus"},
		{"cyclonedx", []string{"--cyclonedx", "--no-annex-iv"}, "bomFormat"},
		{"spdx", []string{"--spdx", "--no-annex-iv"}, "spdxVersion"},
		// With the Annex IV path enabled the CLI prints the most prose
		// (risk register, Article 5, Article 50) — the case most likely
		// to leak a line onto stdout.
		{"cyclonedx with annex iv", []string{"--cyclonedx", "--annex-iv", filepath.Join(t.TempDir(), "annex.md")}, "bomFormat"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, _ := runCLIForTest(t, tc.args...)

			var doc map[string]any
			dec := json.NewDecoder(strings.NewReader(stdout))
			if err := dec.Decode(&doc); err != nil {
				t.Fatalf("stdout is not JSON: %v\nfirst bytes: %.120q", err, stdout)
			}
			if _, ok := doc[tc.wantKey]; !ok {
				t.Errorf("stdout JSON has no %q key — wrong document for this format", tc.wantKey)
			}
			// Nothing may follow the document but whitespace.
			if rest, _ := io.ReadAll(dec.Buffered()); strings.TrimSpace(string(rest)) != "" {
				t.Errorf("stdout has trailing non-JSON content: %.120q", rest)
			}
			var extra any
			if err := dec.Decode(&extra); err != io.EOF {
				t.Errorf("stdout carries more than one JSON value (err=%v)", err)
			}

			// The prose has to go somewhere a human will see it.
			if !strings.Contains(stderr, "Running AIcap") {
				t.Errorf("progress line missing from stderr: %.200q", stderr)
			}
			if !strings.Contains(stderr, "compliance badge") {
				t.Errorf("badge snippet missing from stderr")
			}
		})
	}
}

// The GitHub Action reads complianceStatus out of stdout to set its
// `compliance-status` output. That key has to be in the default document.
func TestRunCLI_DefaultOutputCarriesComplianceStatus(t *testing.T) {
	stdout, _, code := runCLIForTest(t, "--no-annex-iv")
	var doc struct {
		ComplianceStatus string `json:"complianceStatus"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if doc.ComplianceStatus == "" {
		t.Fatal("complianceStatus is empty in the default output")
	}
	// The fixture tree contains high-risk components, so the scan fails
	// the pipeline — and the exit code must still be reported with the
	// JSON intact, which is the case action.yml depends on.
	if code == 0 {
		t.Errorf("fixture scan exited 0; expected a non-zero compliance exit code (status %q)", doc.ComplianceStatus)
	}
}

// --no-fail reports without gating. The verdict must still be in the
// JSON and on stderr — the flag changes the exit code, not the finding.
func TestRunCLI_NoFailExitsZeroButKeepsTheVerdict(t *testing.T) {
	_, _, gated := runCLIForTest(t, "--no-annex-iv")
	if gated == 0 {
		t.Skip("fixture scan passes; nothing for --no-fail to suppress")
	}

	stdout, stderr, code := runCLIForTest(t, "--no-annex-iv", "--no-fail")
	if code != 0 {
		t.Errorf("exit code = %d with --no-fail, want 0", code)
	}
	var doc struct {
		ComplianceStatus string `json:"complianceStatus"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if doc.ComplianceStatus == "" || doc.ComplianceStatus == "Passed" {
		t.Errorf("complianceStatus = %q; --no-fail must not launder the verdict", doc.ComplianceStatus)
	}
	if !strings.Contains(stderr, "Compliance scan failed") && !strings.Contains(stderr, "Policy breach") {
		t.Errorf("verdict missing from stderr under --no-fail")
	}
	if !strings.Contains(stderr, "--no-fail") {
		t.Errorf("stderr does not say the exit code was suppressed")
	}
}

func TestParseCLIArgs_NoFail(t *testing.T) {
	if parseCLIArgs([]string{"."}).NoFail {
		t.Error("NoFail defaulted to true; gating must be the default")
	}
	if !parseCLIArgs([]string{".", "--cyclonedx", "--no-fail"}).NoFail {
		t.Error("--no-fail not parsed")
	}
}

// action.yml downloads a binary and runs it inside other people's CI. For
// a tool that sells supply-chain assurance, how it does that is part of
// the product.
func TestActionYML_VerifiesWhatItDownloads(t *testing.T) {
	raw, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatalf("read action.yml: %v", err)
	}
	action := strings.ReplaceAll(string(raw), "\r\n", "\n")

	// A pinned digest, checked before the binary is made executable.
	pin := regexp.MustCompile(`(?m)^\s+AICAP_SHA256: ([0-9a-f]{64})$`).FindStringSubmatch(action)
	if pin == nil {
		t.Fatal("action.yml pins no SHA-256 for the binary it downloads")
	}
	check := strings.Index(action, "sha256sum -c")
	chmod := strings.Index(action, "chmod +x aicap")
	if check < 0 {
		t.Fatal("action.yml never verifies the download against the pinned digest")
	}
	if chmod < 0 || chmod < check {
		t.Error("the binary is made executable before its digest is checked")
	}

	// curl without -f saves a 404 page as the binary and carries on.
	for _, line := range strings.Split(action, "\n") {
		if strings.Contains(line, "curl ") && !strings.HasPrefix(strings.TrimSpace(line), "#") &&
			!regexp.MustCompile(`curl -[a-zA-Z]*f`).MatchString(line) {
			t.Errorf("curl without -f: %s", strings.TrimSpace(line))
		}
	}

	// Inputs must arrive as environment variables. `${{ inputs.x }}`
	// inside a run: script is substituted into the script text before the
	// shell sees it, so an input containing shell syntax is executed.
	envAssignment := regexp.MustCompile(`^\s+[A-Z_]+: \$\{\{ inputs\.[a-z-]+ \}\}$`)
	for _, line := range strings.Split(action, "\n") {
		if strings.Contains(line, "${{ inputs.") && !envAssignment.MatchString(line) {
			t.Errorf("input interpolated outside an env: assignment: %s", strings.TrimSpace(line))
		}
	}
}
