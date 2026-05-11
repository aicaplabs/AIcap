package types

// AIDependency represents an identified AI library/model in the codebase
type AIDependency struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
	License     string `json:"license,omitempty"`
}

// FinOpsFinding represents a cloud cost optimization warning
type FinOpsFinding struct {
	Resource    string      `json:"resource"`
	Severity    string      `json:"severity"`
	Description string      `json:"description"`
	Location    string      `json:"location,omitempty"`
	// EstimatedCost is set when the scanner could match the resource to
	// a known GPU instance family. Nil means "we detected a GPU but don't
	// know the instance type" (typical for k8s nvidia.com/gpu requests
	// with no node-affinity hint) — auditors should still see the
	// finding, just without a dollar figure.
	EstimatedCost *FinOpsCost `json:"estimatedCost,omitempty"`
}

// FinOpsCost is the per-finding cost attribution, expressed as a
// hourly-rate range (because catalog families like AWS p4d span
// p4d.24xlarge through p4d.metal at different rates) plus the
// computed monthly equivalent. We intentionally publish a range, not
// a single number, so auditors don't read a precise figure that the
// catalog can't actually justify.
type FinOpsCost struct {
	InstanceFamily string  `json:"instanceFamily"` // e.g. "p4d", "a2-highgpu"
	Cloud          string  `json:"cloud"`          // "AWS" | "Azure" | "GCP"
	HourlyUSDLow   float64 `json:"hourlyUsdLow"`
	HourlyUSDHigh  float64 `json:"hourlyUsdHigh"`
	MonthlyUSDLow  float64 `json:"monthlyUsdLow"`
	MonthlyUSDHigh float64 `json:"monthlyUsdHigh"`
	Description    string  `json:"description,omitempty"` // human-readable family description
}

// FinOpsCostSummary aggregates per-finding costs into a BOM-level
// estimate. Disclaimer is rendered into Annex IV verbatim so the
// auditor knows what assumptions were baked in (730 hours/month,
// on-demand pricing, no spot/savings-plan discount).
type FinOpsCostSummary struct {
	TotalMonthlyUSDLow   float64 `json:"totalMonthlyUsdLow"`
	TotalMonthlyUSDHigh  float64 `json:"totalMonthlyUsdHigh"`
	Currency             string  `json:"currency"` // always "USD" for now
	AssumedHoursPerMonth int     `json:"assumedHoursPerMonth"`
	Disclaimer           string  `json:"disclaimer"`
	// CostedFindings counts how many of the FinOps findings had
	// catalog matches; UncostedFindings is the rest. Auditors care
	// because a low TotalMonthlyUSD with many UncostedFindings means
	// "actual cost is probably much higher than the figure shown".
	CostedFindings   int `json:"costedFindings"`
	UncostedFindings int `json:"uncostedFindings"`
}

// AIBOM represents the final Software Bill of Materials for AI
type AIBOM struct {
	ProjectName        string              `json:"projectName"`
	CommitSha          string              `json:"commitSha,omitempty"`
	ScannedFiles       int                 `json:"scannedFiles"`
	Dependencies       []AIDependency      `json:"dependencies"`
	FinOps             []FinOpsFinding     `json:"finOps"`
	FinOpsCostEstimate *FinOpsCostSummary  `json:"finOpsCostEstimate,omitempty"`
	PolicyViolations   []PolicyViolation   `json:"policyViolations,omitempty"`
	Governance         GovernanceTelemetry `json:"governance,omitempty"`
	Compliance         string              `json:"complianceStatus"`
	// Policy carries the parsed .aicap.yml so downstream consumers
	// (Annex IV generator, API save-proof handler) can read declared
	// metadata like Purpose without re-parsing the file.
	Policy *PolicyConfig `json:"policy,omitempty"`
	// ScannedImages records container images inspected for this BOM
	// (Wave 10). Findings extracted from layers land in Dependencies
	// like any other source — this slice is the provenance index so
	// Annex IV can attribute each finding to the image it came from.
	ScannedImages []ScannedImage `json:"scannedImages,omitempty"`
}

// ScannedImage is one container image whose layers were walked
// daemonlessly (registry pull or docker-save tarball). Source is
// "registry" or "tarball"; Digest is the content-addressable sha256
// of the image manifest so downstream tooling can verify what was
// actually inspected even if the tag later mutates.
type ScannedImage struct {
	Reference    string `json:"reference"`
	Digest       string `json:"digest,omitempty"`
	Source       string `json:"source"`
	Layers       int    `json:"layers"`
	FindingCount int    `json:"findingCount"`
}

// GovernanceTelemetry collects evidence of compliance controls discovered
// during the scan. Each bucket maps to a section of Annex IV § 4 that
// would otherwise be `[REQUIRES MANUAL INPUT]`. The presence of one or
// more signals lets the Annex IV generator render concrete evidence
// instead of a placeholder. Empty buckets fall back to the manual-input
// prompt so we don't pretend to have found something we didn't.
type GovernanceTelemetry struct {
	HITL                    []GovernanceSignal `json:"hitl,omitempty"`
	TrainingData            []GovernanceSignal `json:"trainingData,omitempty"`
	BiasMonitoring          []GovernanceSignal `json:"biasMonitoring,omitempty"`
	PromptInjectionDefenses []GovernanceSignal `json:"promptInjectionDefenses,omitempty"`
}

// GovernanceSignal is one piece of evidence for a governance control.
// `Source` describes where it was found (e.g. "k8s manifest",
// "terraform", "dvc", "python import"). `Evidence` is the raw match
// (a service name, bucket name, library name) so auditors can verify
// the heuristic. `Description` is the human-readable summary that
// renders into Annex IV.
type GovernanceSignal struct {
	Source      string `json:"source"`
	Location    string `json:"location"`
	Evidence    string `json:"evidence"`
	Description string `json:"description"`
}

// PolicyViolation represents a policy-as-code rule violation
type PolicyViolation struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
}

// PolicyConfig represents the .aicap.yml policy-as-code configuration
type PolicyConfig struct {
	AllowedModels   []string `json:"allowedModels"`
	BlockedModels   []string `json:"blockedModels"`
	MaxRiskLevel    string   `json:"maxRiskLevel"`
	BlockOnHighRisk bool     `json:"blockOnHighRisk"`
	RequireLicenses bool     `json:"requireLicenses"`
	AllowedLicenses []string `json:"allowedLicenses"`
	// Purpose is the free-text intended purpose of the AI system,
	// used to auto-populate Annex IV Section 1 instead of the
	// [REQUIRES MANUAL INPUT] placeholder.
	Purpose string `json:"purpose,omitempty"`
}

// Map of known AI libraries and their assumed regulatory risk (MVP level)
type LibraryMeta struct {
	Risk string `json:"risk"`
	Desc string `json:"desc"`
}

// ProofRecord represents a historical compliance scan
type ProofRecord struct {
	ProjectName string `json:"projectName"`
	CommitSha   string `json:"commitSha"`
	CryptoHash  string `json:"cryptoHash"`
	Timestamp   string `json:"timestamp"`
}

// RiskFinding is one row of the Article 9 risk register: a detected
// dependency cross-referenced against the curated catalog of OWASP ML
// Top 10 categories, MITRE ATLAS techniques, and EU AI Act articles.
// Persisted as JSONB inside RiskRegister; surfaced in Annex IV § 5.
type RiskFinding struct {
	Component       string   `json:"component"` // e.g. "tensorflow"
	Version         string   `json:"version,omitempty"`
	Ecosystem       string   `json:"ecosystem,omitempty"`
	Severity        string   `json:"severity"` // High | Medium | Low
	OwaspCategory   string   `json:"owaspCategory"`
	MitreAtlas      []string `json:"mitreAtlas,omitempty"`
	EUAIActArticles []string `json:"euAiActArticles"`
	Mitigation      string   `json:"mitigation"`
	Rationale       string   `json:"rationale,omitempty"`
	Status          string   `json:"status"` // open | mitigated | accepted (default: open)
	// LiveVulnIDs (Wave 7f) carries CVE / GHSA / PYSEC identifiers
	// pulled live from OSV.dev for this dep + version. Empty when
	// OSV is disabled or returned no matches; the static catalog
	// fields above still apply.
	LiveVulnIDs []string `json:"liveVulnIds,omitempty"`
}

// RiskRegister is the Article 9 risk-management state for one
// proof_drill. Stored verbatim in proof_drills.risk_register_state
// (JSONB) so auditors can read it back per-commit.
type RiskRegister struct {
	GeneratedAt string        `json:"generatedAt"`
	Findings    []RiskFinding `json:"findings"`
	Summary     RiskSummary   `json:"summary"`
}

// RiskSummary holds counts by severity for the dashboard / Annex IV.
// Computed alongside Findings so views can render a header without
// re-walking the array.
type RiskSummary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Total  int `json:"total"`
}

// LicenseMapping links a local/hardcoded model to its registry or proprietary license
type LicenseMapping struct {
	HFID    string `json:"hf_id,omitempty"`
	License string `json:"license,omitempty"`
}

// CycloneDX SBOM structures — minimal CycloneDX 1.5 compatible output
type CycloneDXBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Metadata     CycloneDXMetadata    `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
}

type CycloneDXMetadata struct {
	Timestamp string             `json:"timestamp"`
	Component CycloneDXComponent `json:"component"`
}

type CycloneDXComponent struct {
	Type       string              `json:"type"`
	BOMRef     string              `json:"bom-ref"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	PURL       string              `json:"purl,omitempty"`
	Licenses   []CycloneDXLicense  `json:"licenses,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

type CycloneDXLicense struct {
	License struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"license"`
}

type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HFModelResponse structure for HuggingFace Hub API
type HFModelResponse struct {
	Id         string `json:"_id"`
	ModelId    string `json:"modelId"`
	Tags       []string `json:"tags"`
	PipelineTag string `json:"pipeline_tag"`
}
