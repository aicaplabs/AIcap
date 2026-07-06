package finops

import (
	"strings"
	"testing"

	"aicap/pkg/types"
)

// Wave 11: BuildRightsizingRecommendations contract.

// When the BOM has no training signals and contains a training-class
// GPU finding, we emit a recommendation pointing at the matching
// inference family with a positive savings estimate.
func TestBuildRightsizingRecommendations_InferenceOnly_RecommendsInf2(t *testing.T) {
	bom := types.AIBOM{
		FinOps: []types.FinOpsFinding{{
			Resource: "infra.tf",
			Location: "infra.tf",
			EstimatedCost: &types.FinOpsCost{
				InstanceFamily: "p4d.",
				Cloud:          "AWS",
				MonthlyUSDLow:  32.77 * 730,
				MonthlyUSDHigh: 32.77 * 730,
			},
		}},
	}
	recs := BuildRightsizingRecommendations(bom)
	if len(recs) != 1 {
		t.Fatalf("got %d recommendations, want 1", len(recs))
	}
	r := recs[0]
	if r.CurrentFamily != "p4d." {
		t.Errorf("CurrentFamily = %q, want p4d.", r.CurrentFamily)
	}
	if r.RecommendedFamily != "inf2." {
		t.Errorf("RecommendedFamily = %q, want inf2.", r.RecommendedFamily)
	}
	if r.EstimatedSavingsLow <= 0 {
		t.Errorf("EstimatedSavingsLow = %v, want > 0", r.EstimatedSavingsLow)
	}
	if !strings.Contains(r.Rationale, "inference-only") {
		t.Errorf("Rationale = %q, want mention of inference-only", r.Rationale)
	}
}

// Any training-data governance signal disqualifies the BOM from
// rightsizing — we don't suggest swapping a training GPU for an
// inference SKU when the workload trains.
func TestBuildRightsizingRecommendations_SkipsWhenTrainingSignals(t *testing.T) {
	bom := types.AIBOM{
		Governance: types.GovernanceTelemetry{
			TrainingData: []types.GovernanceSignal{
				{Source: "dvc", Location: "data.dvc", Evidence: "data.dvc", Description: "DVC training data tracker"},
			},
		},
		FinOps: []types.FinOpsFinding{{
			Resource: "infra.tf",
			EstimatedCost: &types.FinOpsCost{
				InstanceFamily: "p4d.",
				Cloud:          "AWS",
				MonthlyUSDLow:  32.77 * 730,
				MonthlyUSDHigh: 32.77 * 730,
			},
		}},
	}
	if recs := BuildRightsizingRecommendations(bom); recs != nil {
		t.Errorf("expected nil recommendations when training signals present, got %#v", recs)
	}
}

// Training-loop dependencies (pytorch-lightning, wandb, deepspeed)
// count as a training signal even without governance evidence.
func TestHasTrainingSignals_DepDetection(t *testing.T) {
	bom := types.AIBOM{Dependencies: []types.AIDependency{{Name: "pytorch-lightning", Version: "2.0"}}}
	if !HasTrainingSignals(bom) {
		t.Error("HasTrainingSignals = false, want true for pytorch-lightning")
	}
}

// Findings on inference-class families (g5, inf2, g6) are not
// candidates — they're already the inference SKU.
func TestBuildRightsizingRecommendations_SkipsInferenceClass(t *testing.T) {
	bom := types.AIBOM{
		FinOps: []types.FinOpsFinding{{
			Resource: "infra.tf",
			EstimatedCost: &types.FinOpsCost{
				InstanceFamily: "g5.",
				Cloud:          "AWS",
				MonthlyUSDLow:  1000, MonthlyUSDHigh: 5000,
			},
		}},
	}
	if recs := BuildRightsizingRecommendations(bom); len(recs) != 0 {
		t.Errorf("expected no recommendations for g5 finding, got %d", len(recs))
	}
}

// GCP a3-highgpu (H100) → g2-standard (L4) is the documented mapping.
func TestBuildRightsizingRecommendations_GCP_a3_to_g2(t *testing.T) {
	bom := types.AIBOM{
		FinOps: []types.FinOpsFinding{{
			Resource: "main.tf",
			EstimatedCost: &types.FinOpsCost{
				InstanceFamily: "a3-highgpu",
				Cloud:          "GCP",
				MonthlyUSDLow:  79.21 * 730, MonthlyUSDHigh: 79.21 * 730,
			},
		}},
	}
	recs := BuildRightsizingRecommendations(bom)
	if len(recs) != 1 {
		t.Fatalf("got %d, want 1", len(recs))
	}
	if recs[0].RecommendedFamily != "g2-standard" {
		t.Errorf("RecommendedFamily = %q, want g2-standard", recs[0].RecommendedFamily)
	}
	if recs[0].CurrentCloud != "GCP" {
		t.Errorf("CurrentCloud = %q, want GCP", recs[0].CurrentCloud)
	}
}

// The savings range must always satisfy low <= high. With a
// single-size current family (identical low/high) and a wide-spread
// recommended family (inf2 spans xlarge–48xlarge), the like-for-like
// pairing produces an inverted pair — the builder must order it.
func TestBuildRightsizingRecommendations_SavingsRangeOrdered(t *testing.T) {
	bom := types.AIBOM{
		FinOps: []types.FinOpsFinding{{
			Resource: "gpu_instances.tf",
			EstimatedCost: &types.FinOpsCost{
				InstanceFamily: "p4d.",
				Cloud:          "AWS",
				// Single-size family: low == high, like the real p4d
				// catalog entry that produced low=23367 > high=14446
				// in production output.
				MonthlyUSDLow:  32.77 * 730,
				MonthlyUSDHigh: 32.77 * 730,
			},
		}},
	}
	recs := BuildRightsizingRecommendations(bom)
	if len(recs) != 1 {
		t.Fatalf("got %d recommendations, want 1", len(recs))
	}
	r := recs[0]
	if r.EstimatedSavingsLow > r.EstimatedSavingsHigh {
		t.Errorf("savings range inverted: low %.2f > high %.2f",
			r.EstimatedSavingsLow, r.EstimatedSavingsHigh)
	}
}

// A finding with no EstimatedCost (typical k8s nvidia.com/gpu request)
// can't be rightsized — we have no current family to compare against.
func TestBuildRightsizingRecommendations_SkipsWhenNoEstimatedCost(t *testing.T) {
	bom := types.AIBOM{
		FinOps: []types.FinOpsFinding{{Resource: "deploy.yaml"}},
	}
	if recs := BuildRightsizingRecommendations(bom); len(recs) != 0 {
		t.Errorf("expected 0 recommendations, got %d", len(recs))
	}
}
