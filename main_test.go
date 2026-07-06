package main

import (
	"reflect"
	"strings"
	"testing"

	"aicap/pkg/types"
)

func TestParseCLIArgs_DirectoryOnly(t *testing.T) {
	dir, refs, tarballs, cdx := parseCLIArgs([]string{"./repo"})
	if dir != "./repo" {
		t.Errorf("dir=%q want ./repo", dir)
	}
	if len(refs) != 0 || len(tarballs) != 0 || cdx {
		t.Errorf("unexpected flags: refs=%v tarballs=%v cdx=%v", refs, tarballs, cdx)
	}
}

func TestParseCLIArgs_DefaultsScanDirToDot(t *testing.T) {
	dir, _, _, _ := parseCLIArgs(nil)
	if dir != "." {
		t.Errorf("dir=%q want .", dir)
	}
}

func TestParseCLIArgs_RepeatedImageFlags(t *testing.T) {
	dir, refs, tarballs, cdx := parseCLIArgs([]string{
		"./src",
		"--image", "ghcr.io/foo/bar:1",
		"--image-tar", "/tmp/local.tar",
		"--image", "registry.example.com/baz:latest",
		"--cyclonedx",
	})
	if dir != "./src" {
		t.Errorf("dir=%q want ./src", dir)
	}
	wantRefs := []string{"ghcr.io/foo/bar:1", "registry.example.com/baz:latest"}
	if !reflect.DeepEqual(refs, wantRefs) {
		t.Errorf("refs=%v want %v", refs, wantRefs)
	}
	wantTar := []string{"/tmp/local.tar"}
	if !reflect.DeepEqual(tarballs, wantTar) {
		t.Errorf("tarballs=%v want %v", tarballs, wantTar)
	}
	if !cdx {
		t.Error("expected --cyclonedx to be true")
	}
}

func TestParseCLIArgs_UnknownFlagsIgnored(t *testing.T) {
	// Forward-compat: an older binary called by a newer action.yml
	// must not abort on unrecognised flags.
	dir, _, _, _ := parseCLIArgs([]string{"--future-flag", "value", "./src"})
	if dir != "./src" {
		t.Errorf("dir=%q want ./src", dir)
	}
}

func TestParseCLIArgs_MissingFlagValueIsTolerated(t *testing.T) {
	// --image at the very end with no value should not panic; the
	// flag is simply dropped.
	_, refs, _, _ := parseCLIArgs([]string{"./src", "--image"})
	if len(refs) != 0 {
		t.Errorf("trailing --image with no value should be ignored, got refs=%v", refs)
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
	if !strings.Contains(got, "https://aicap.eu") {
		t.Errorf("badge=%q must link back to aicap.eu", got)
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
