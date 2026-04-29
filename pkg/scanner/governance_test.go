package scanner

import (
	"path/filepath"
	"strings"
	"testing"
)

// detectGovernanceFromYAML — k8s name pattern + Argo `suspend:`.

func TestDetectGovernanceFromYAML_HITLNamedDeployment(t *testing.T) {
	path := createTempFile(t, "deploy.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: prompt-review-service
spec:
  replicas: 1
`)
	got := detectGovernanceFromYAML(path)
	if len(got) != 1 {
		t.Fatalf("got %d signals, want 1: %#v", len(got), got)
	}
	if got[0].Source != "k8s manifest" {
		t.Errorf("Source = %q, want k8s manifest", got[0].Source)
	}
	if got[0].Evidence != "prompt-review-service" {
		t.Errorf("Evidence = %q, want prompt-review-service", got[0].Evidence)
	}
}

func TestDetectGovernanceFromYAML_RejectsFalsePositive(t *testing.T) {
	// "preview-server" must NOT match the HITL pattern even though it
	// contains the substring "review" — the regex is word-bounded.
	path := createTempFile(t, "deploy.yaml", `kind: Deployment
metadata:
  name: preview-server
`)
	got := detectGovernanceFromYAML(path)
	if len(got) != 0 {
		t.Errorf("got %d signals, want 0 (preview-server should not match)", len(got))
	}
}

func TestDetectGovernanceFromYAML_ArgoSuspend(t *testing.T) {
	path := createTempFile(t, "workflow.yaml", `apiVersion: argoproj.io/v1alpha1
kind: Workflow
spec:
  templates:
  - name: approve-deploy
    suspend: {}
`)
	got := detectGovernanceFromYAML(path)
	hasArgo := false
	for _, s := range got {
		if s.Source == "argo workflow" {
			hasArgo = true
		}
	}
	if !hasArgo {
		t.Errorf("missing argo workflow suspend signal: %#v", got)
	}
}

// detectGovernanceFromGitHubActions — only fires for files under
// .github/workflows/.

func TestDetectGovernanceFromGitHubActions_EnvironmentLine(t *testing.T) {
	dir := createTempDir(t, map[string]string{
		".github/workflows/deploy.yml": `name: deploy
jobs:
  deploy:
    environment: production
    steps: []
`,
	})
	path := filepath.Join(dir, ".github", "workflows", "deploy.yml")
	got := detectGovernanceFromGitHubActions(path)
	if len(got) != 1 {
		t.Fatalf("got %d signals, want 1: %#v", len(got), got)
	}
	if !strings.Contains(got[0].Evidence, "production") {
		t.Errorf("Evidence = %q, want it to mention production", got[0].Evidence)
	}
}

func TestDetectGovernanceFromGitHubActions_IgnoresNonWorkflowYAML(t *testing.T) {
	// Same `environment:` line in a random YAML must be ignored — only
	// .github/workflows/ paths qualify.
	path := createTempFile(t, "values.yaml", `environment: production`)
	if got := detectGovernanceFromGitHubActions(path); len(got) != 0 {
		t.Errorf("got %d signals, want 0 (path is not a GHA workflow)", len(got))
	}
}

// detectGovernanceFromTerraform — bucket header + inline `bucket=` value.

func TestDetectGovernanceFromTerraform_BucketResourceName(t *testing.T) {
	path := createTempFile(t, "buckets.tf", `resource "aws_s3_bucket" "training_data" {
  bucket = "acme-prod-training-data"
}
`)
	got := detectGovernanceFromTerraform(path)
	if len(got) < 1 {
		t.Fatalf("got %d signals, want >= 1", len(got))
	}
	combined := ""
	for _, s := range got {
		combined += s.Evidence + " "
	}
	if !strings.Contains(combined, "training") {
		t.Errorf("evidence missing 'training': %s", combined)
	}
}

func TestDetectGovernanceFromTerraform_NonTrainingBucketIgnored(t *testing.T) {
	path := createTempFile(t, "buckets.tf", `resource "aws_s3_bucket" "logs_archive" {
  bucket = "acme-cloudtrail-logs"
}
`)
	if got := detectGovernanceFromTerraform(path); len(got) != 0 {
		t.Errorf("got %d signals, want 0 (logs bucket should not match training-data pattern): %#v", len(got), got)
	}
}

// detectGovernanceFromDVC — any `*.dvc`, `dvc.yaml`, or `dvc.lock`.

func TestDetectGovernanceFromDVC_FileSuffix(t *testing.T) {
	path := createTempFile(t, "data.dvc", "outs:\n- path: data\n")
	got := detectGovernanceFromDVC(path)
	if len(got) != 1 {
		t.Fatalf("got %d signals, want 1", len(got))
	}
	if got[0].Source != "dvc" {
		t.Errorf("Source = %q, want dvc", got[0].Source)
	}
}

func TestDetectGovernanceFromDVC_IgnoresUnrelatedFiles(t *testing.T) {
	path := createTempFile(t, "data.txt", "not a DVC file")
	if got := detectGovernanceFromDVC(path); len(got) != 0 {
		t.Errorf("got %d signals for non-DVC file, want 0", len(got))
	}
}

// detectGovernanceFromPython — HF datasets + bias libs + guardrails.

func TestDetectGovernanceFromPython_HuggingFaceDatasets(t *testing.T) {
	path := createTempFile(t, "train.py", `from datasets import load_dataset
ds = load_dataset("glue", "mnli")
`)
	training, _, _ := detectGovernanceFromPython(path)
	if len(training) != 1 {
		t.Fatalf("got %d training signals, want 1", len(training))
	}
	if !strings.Contains(training[0].Evidence, "glue") {
		t.Errorf("Evidence = %q, want it to include the dataset name 'glue'", training[0].Evidence)
	}
}

func TestDetectGovernanceFromPython_BiasAndGuardrails(t *testing.T) {
	path := createTempFile(t, "guard.py", `import fairlearn
from aif360.datasets import BinaryLabelDataset
import lakera_guard
from rebuff import Rebuff
`)
	_, bias, defenses := detectGovernanceFromPython(path)
	if len(bias) != 2 {
		t.Errorf("bias count = %d, want 2 (fairlearn + aif360)", len(bias))
	}
	if len(defenses) != 2 {
		t.Errorf("defenses count = %d, want 2 (lakera_guard + rebuff)", len(defenses))
	}
}

// detectGovernanceFromManifest — declared-but-unused libs still count.

func TestDetectGovernanceFromManifest_RequirementsTxt(t *testing.T) {
	path := createTempFile(t, "requirements.txt", `numpy==1.26.0
fairlearn==0.10.0
lakera-guard==0.1.5
`)
	bias, defenses := detectGovernanceFromManifest(path)
	if len(bias) != 1 || bias[0].Evidence != "fairlearn" {
		t.Errorf("bias = %#v, want one fairlearn entry", bias)
	}
	if len(defenses) != 1 || defenses[0].Evidence != "lakera" {
		t.Errorf("defenses = %#v, want one lakera entry", defenses)
	}
}

// PerformScan integration: dropping these files into a project tree
// produces a populated bom.Governance across all four buckets.
func TestPerformScan_PopulatesGovernance(t *testing.T) {
	dir := createTempDir(t, map[string]string{
		"requirements.txt": "fairlearn==0.10.0\nlakera-guard==0.1.5\n",
		"deploy.yaml":      "kind: Deployment\nmetadata:\n  name: review-queue\n",
		"data.dvc":         "outs:\n- path: data\n",
		"buckets.tf":       `resource "aws_s3_bucket" "training_data" { bucket = "x" }` + "\n",
		"train.py":         "from datasets import load_dataset\nds = load_dataset(\"glue\")\n",
	})

	bom := PerformScan(dir)

	if len(bom.Governance.HITL) == 0 {
		t.Errorf("expected HITL signals, got none")
	}
	if len(bom.Governance.TrainingData) < 2 { // dvc + tf + python = >=2
		t.Errorf("expected >=2 training-data signals, got %d", len(bom.Governance.TrainingData))
	}
	if len(bom.Governance.BiasMonitoring) == 0 {
		t.Errorf("expected bias-monitoring signals, got none")
	}
	if len(bom.Governance.PromptInjectionDefenses) == 0 {
		t.Errorf("expected prompt-injection-defense signals, got none")
	}
}
