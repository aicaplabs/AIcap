// Governance-signal detection (Wave 7a).
//
// EU AI Act Annex IV § 3 (Human Oversight & Data Governance) requires
// evidence of HITL controls, training-data provenance, bias monitoring,
// and prompt-injection defences. The Annex IV generator previously
// emitted `[REQUIRES MANUAL INPUT]` for all four — Wave 7a closes that
// gap by parsing the IaC and source files we already walk, looking for
// concrete signals.
//
// Heuristics are intentionally conservative: a deployment named
// `prompt-review-service` is a strong HITL signal, but a generic
// `data-bucket` is not training-data evidence on its own. We prefer
// false negatives (placeholder stays, auditor fills in manually) over
// false positives (we claim a control exists when it doesn't).
//
// Each detector returns []types.GovernanceSignal so the scanner can
// concatenate without per-bucket plumbing. The walk in PerformScan
// dispatches by file type and routes signals into the correct
// bom.Governance bucket.

package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aicap/pkg/types"
)

// Pre-compiled patterns. Centralised so a future Wave can plug in
// configurable rules without scattering regex literals across detectors.
var (
	// HITL: a deployment / service / job whose name implies human review.
	// Word-aware so "review-service" matches but "preview-server" doesn't.
	hitlNamePattern = regexp.MustCompile(`(?i)\b(review|approval|approver|human|hitl|moderation|moderator|feedback|judge|reviewer|escalation)\b`)

	// k8s metadata.name on its own line. Covers Deployment, Service, Job,
	// CronJob, StatefulSet — anything with a Kubernetes-shape manifest.
	k8sNameLine = regexp.MustCompile(`(?m)^\s*name:\s*([\w.\-]+)`)

	// Argo Workflow `suspend:` step is the cleanest HITL signal we can
	// detect: the workflow halts until a human resumes it.
	argoSuspendPattern = regexp.MustCompile(`(?m)^\s*suspend\s*:`)

	// Training-data bucket-name patterns for Terraform aws_s3_bucket /
	// google_storage_bucket. Word-bounded to avoid matching "trainee"
	// or "datasync" as training data.
	trainingBucketPattern = regexp.MustCompile(`(?i)\b(training[-_]?data|train[-_]?set|dataset|labeled[-_]?data|raw[-_]?data|ml[-_]?data|feature[-_]?store)\b`)

	// Terraform resource-block headers we care about. Very narrow on
	// purpose — these are the two cloud bucket types most likely to
	// hold training data; other resources can be added later.
	terraformBucketHeader = regexp.MustCompile(`^\s*resource\s+"(aws_s3_bucket|google_storage_bucket)"\s+"([^"]+)"`)

	// Hugging Face datasets call. Both `from datasets import load_dataset`
	// and the eventual `load_dataset(...)` call are evidence — the import
	// alone is a stronger signal of "this codebase uses HF datasets".
	hfDatasetsImportPattern = regexp.MustCompile(`(?m)^\s*from\s+datasets\s+import\b|^\s*import\s+datasets\b`)
	hfDatasetsCallPattern   = regexp.MustCompile(`\bload_dataset\s*\(\s*["']([^"']+)["']`)

	// Python import lines for known fairness / bias-monitoring libs.
	biasImportPattern = regexp.MustCompile(`(?m)^\s*(?:from|import)\s+(fairlearn|aif360|responsibleai|equalized_odds)\b`)

	// Python import lines for known LLM-firewall / guardrail libs.
	promptDefenseImportPattern = regexp.MustCompile(`(?m)^\s*(?:from|import)\s+(lakera|lakera_guard|rebuff|nemoguardrails|presidio_analyzer|garak|llm_guard)\b`)
)

// detectGovernanceFromYAML inspects a YAML file (k8s manifest or
// Argo Workflow) and routes signals to HITL. We use simple regex
// matching rather than a full YAML parser because the file walker
// already passes us the path and we want zero new dependencies; a
// future Wave can swap in a real parser if false-positive rates
// climb.
func detectGovernanceFromYAML(path string) (hitl []types.GovernanceSignal) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(body)

	// k8s deployment/service/job names matching HITL patterns.
	for _, m := range k8sNameLine.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if hitlNamePattern.MatchString(name) {
			hitl = append(hitl, types.GovernanceSignal{
				Source:      "k8s manifest",
				Location:    path,
				Evidence:    name,
				Description: "Kubernetes resource named " + name + " — implies a human-review or approval step in the runtime topology.",
			})
		}
	}

	// Argo Workflow `suspend:` keyword is a definitive HITL gate.
	if argoSuspendPattern.MatchString(text) {
		hitl = append(hitl, types.GovernanceSignal{
			Source:      "argo workflow",
			Location:    path,
			Evidence:    "suspend:",
			Description: "Argo Workflow `suspend:` step — workflow pauses until a human resumes it (Article 14 human oversight).",
		})
	}

	return hitl
}

// detectGovernanceFromGitHubActions handles `.github/workflows/*.yml`
// files specifically — `environment:` keys gate jobs behind a GitHub
// environment, which can carry required reviewers. The HITL signal
// here is "a deployment is gated behind a configured environment",
// which we treat as evidence of human approval in CI/CD.
func detectGovernanceFromGitHubActions(path string) []types.GovernanceSignal {
	if !strings.Contains(filepath.ToSlash(path), "/.github/workflows/") {
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var signals []types.GovernanceSignal
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "environment:") {
			env := strings.TrimSpace(strings.TrimPrefix(trimmed, "environment:"))
			env = strings.Trim(env, `"'`)
			if env == "" {
				env = "(unnamed)"
			}
			signals = append(signals, types.GovernanceSignal{
				Source:      "github actions",
				Location:    path,
				Evidence:    "environment: " + env,
				Description: "GitHub Actions job gated behind environment `" + env + "` — required reviewers configured at the GitHub repo level enforce human approval before deploy.",
			})
		}
	}
	return signals
}

// detectGovernanceFromTerraform looks for AWS / GCP buckets whose name
// suggests they hold training data. Match is on the resource block's
// declared name (the second capture in terraformBucketHeader) AND on
// the inline `bucket = "…"` value if present, so we catch both
// `resource "aws_s3_bucket" "training_data" {}` and the variant where
// the Terraform identifier is generic but the actual S3 name is not.
func detectGovernanceFromTerraform(path string) []types.GovernanceSignal {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var signals []types.GovernanceSignal
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	var currentResource string
	for scanner.Scan() {
		line := scanner.Text()
		if m := terraformBucketHeader.FindStringSubmatch(line); m != nil {
			currentResource = m[2] // the Terraform-local name
			if trainingBucketPattern.MatchString(currentResource) {
				signals = append(signals, types.GovernanceSignal{
					Source:      "terraform",
					Location:    path,
					Evidence:    m[1] + "." + currentResource,
					Description: "Object-storage bucket `" + currentResource + "` declared in Terraform — name pattern indicates training-data provenance under Article 10.",
				})
			}
			continue
		}
		// `bucket = "actual-name"` inside an open resource block.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "bucket") && strings.Contains(trimmed, "=") {
			value := strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[1])
			value = strings.Trim(value, `"' `)
			if value != "" && trainingBucketPattern.MatchString(value) {
				signals = append(signals, types.GovernanceSignal{
					Source:      "terraform",
					Location:    path,
					Evidence:    value,
					Description: "S3/GCS bucket `" + value + "` referenced in Terraform — name pattern indicates training-data storage under Article 10.",
				})
			}
		}
	}
	return signals
}

// detectGovernanceFromDVC: every DVC file is by definition training-data
// versioning. `*.dvc` and `dvc.yaml` both count.
func detectGovernanceFromDVC(path string) []types.GovernanceSignal {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".dvc") && base != "dvc.yaml" && base != "dvc.lock" {
		return nil
	}
	return []types.GovernanceSignal{{
		Source:      "dvc",
		Location:    path,
		Evidence:    base,
		Description: "DVC file detected — Data Version Control tracks training-data lineage and content hashes (Article 10 evidence).",
	}}
}

// detectGovernanceFromPython routes signals across three buckets:
// training data (HuggingFace `datasets`), bias monitoring (fairlearn,
// aif360), and prompt-injection defences (lakera, rebuff, nemoguardrails).
// One file pass populates all three to keep the walk cheap.
func detectGovernanceFromPython(path string) (training, bias, defenses []types.GovernanceSignal) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil
	}
	text := string(body)

	if hfDatasetsImportPattern.MatchString(text) {
		// If the call site shows a specific dataset name, surface it.
		evidence := "import datasets"
		desc := "HuggingFace `datasets` imported — training-data loading via the HF Hub."
		if m := hfDatasetsCallPattern.FindStringSubmatch(text); m != nil {
			evidence = "load_dataset(\"" + m[1] + "\")"
			desc = "HuggingFace dataset `" + m[1] + "` loaded — training-data provenance is the HF Hub revision (Article 10)."
		}
		training = append(training, types.GovernanceSignal{
			Source:      "python import",
			Location:    path,
			Evidence:    evidence,
			Description: desc,
		})
	}

	for _, m := range biasImportPattern.FindAllStringSubmatch(text, -1) {
		bias = append(bias, types.GovernanceSignal{
			Source:      "python import",
			Location:    path,
			Evidence:    m[1],
			Description: "Fairness library `" + m[1] + "` imported — automated bias-monitoring evidence under Article 10 / 15.",
		})
	}

	for _, m := range promptDefenseImportPattern.FindAllStringSubmatch(text, -1) {
		defenses = append(defenses, types.GovernanceSignal{
			Source:      "python import",
			Location:    path,
			Evidence:    m[1],
			Description: "LLM guardrail `" + m[1] + "` imported — prompt-injection defence evidence under Article 15.",
		})
	}
	return training, bias, defenses
}

// detectGovernanceFromManifest scans dependency manifests for known
// fairness or guardrail libraries that may not show up as imports yet
// (a project might pin them in requirements.txt before any code uses
// them). Pure substring match per line — fast, low false-positive rate
// because the package names are distinctive.
func detectGovernanceFromManifest(path string) (bias, defenses []types.GovernanceSignal) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	biasNames := []string{"fairlearn", "aif360", "responsibleai"}
	defenseNames := []string{"lakera", "rebuff", "nemoguardrails", "presidio-analyzer", "garak", "llm-guard"}
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		for _, n := range biasNames {
			if strings.Contains(lower, n) {
				bias = append(bias, types.GovernanceSignal{
					Source:      "dependency manifest",
					Location:    path,
					Evidence:    n,
					Description: "Fairness library `" + n + "` declared in dependency manifest — bias-monitoring control under Article 10 / 15.",
				})
				break // one signal per line is enough
			}
		}
		for _, n := range defenseNames {
			if strings.Contains(lower, n) {
				defenses = append(defenses, types.GovernanceSignal{
					Source:      "dependency manifest",
					Location:    path,
					Evidence:    n,
					Description: "LLM guardrail `" + n + "` declared in dependency manifest — prompt-injection defence under Article 15.",
				})
				break
			}
		}
	}
	return bias, defenses
}
