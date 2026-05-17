package finops

import "aicap/pkg/types"

// EstimateBOMCost aggregates per-finding cost attributions into a
// BOM-level summary. Pure function — no I/O, no global state — so the
// scanner can call it once at the end of PerformScan, and the Annex IV
// renderer can re-derive the same result from a stored BOM if needed.
//
// Two findings detecting the same instance family in different files
// (e.g. a Terraform module and a Helm values.yaml both referencing
// p4d.) are summed: every detection is a real workload that's running
// somewhere, so double-counting is the conservative (i.e. budget-safer)
// choice. We surface CostedFindings vs UncostedFindings so auditors can
// tell when the headline figure is missing detections.
//
// Returns nil if the BOM has no FinOps findings at all — there's no
// summary to render. Returns a populated summary even when every
// finding lacks a cost (UncostedFindings == len(findings)) so the
// Annex IV output always has the disclaimer block.
func EstimateBOMCost(bom types.AIBOM) *types.FinOpsCostSummary {
	if len(bom.FinOps) == 0 {
		return nil
	}
	out := &types.FinOpsCostSummary{
		Currency:             "USD",
		AssumedHoursPerMonth: AssumedHoursPerMonth(),
		Disclaimer:           Disclaimer(),
	}
	var anySpot bool
	for _, f := range bom.FinOps {
		if f.EstimatedCost == nil {
			out.UncostedFindings++
			continue
		}
		out.CostedFindings++
		out.TotalMonthlyUSDLow += f.EstimatedCost.MonthlyUSDLow
		out.TotalMonthlyUSDHigh += f.EstimatedCost.MonthlyUSDHigh
		if f.EstimatedCost.SpotMultiplier > 0 {
			anySpot = true
			out.TotalSpotMonthlyUSDLow += f.EstimatedCost.SpotMonthlyUSDLow
			out.TotalSpotMonthlyUSDHigh += f.EstimatedCost.SpotMonthlyUSDHigh
		}
	}
	if anySpot {
		out.SpotSavingsMonthlyUSDLow = out.TotalMonthlyUSDLow - out.TotalSpotMonthlyUSDLow
		out.SpotSavingsMonthlyUSDHigh = out.TotalMonthlyUSDHigh - out.TotalSpotMonthlyUSDHigh
		out.SpotDisclaimer = SpotDisclaimer()
	}
	return out
}
