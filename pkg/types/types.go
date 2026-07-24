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
	Resource    string `json:"resource"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
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
	// SpotMultiplier is the spot/preemptible price as a fraction of
	// on-demand (0.30 = spot costs 30% of on-demand → 70% savings).
	// Sourced from the catalog's _meta.spot_multipliers per cloud.
	SpotMultiplier     float64 `json:"spotMultiplier,omitempty"`
	SpotHourlyUSDLow   float64 `json:"spotHourlyUsdLow,omitempty"`
	SpotHourlyUSDHigh  float64 `json:"spotHourlyUsdHigh,omitempty"`
	SpotMonthlyUSDLow  float64 `json:"spotMonthlyUsdLow,omitempty"`
	SpotMonthlyUSDHigh float64 `json:"spotMonthlyUsdHigh,omitempty"`
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
	// Spot/preemptible projection (Wave 11). Computed from per-finding
	// SpotMonthlyUSD fields. Zero when the catalog has no spot
	// multipliers or every finding lacks a catalog match.
	TotalSpotMonthlyUSDLow    float64 `json:"totalSpotMonthlyUsdLow,omitempty"`
	TotalSpotMonthlyUSDHigh   float64 `json:"totalSpotMonthlyUsdHigh,omitempty"`
	SpotSavingsMonthlyUSDLow  float64 `json:"spotSavingsMonthlyUsdLow,omitempty"`
	SpotSavingsMonthlyUSDHigh float64 `json:"spotSavingsMonthlyUsdHigh,omitempty"`
	SpotDisclaimer            string  `json:"spotDisclaimer,omitempty"`
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
	// FinOpsRecommendations (Wave 11) are rightsizing suggestions:
	// for inference-only workloads running on training-class GPUs, we
	// recommend the matching inference-optimized family. Empty when no
	// candidate finding matched or when training signals were detected.
	FinOpsRecommendations []FinOpsRightsizing `json:"finOpsRecommendations,omitempty"`
	// ProhibitedPractices (Wave 20) are EU AI Act Article 5 indicators.
	// Empty means no *detectable* indicator matched — not a clearance,
	// since several Article 5 prohibitions leave no trace in a manifest.
	ProhibitedPractices []ProhibitedPracticeSignal `json:"prohibitedPractices,omitempty"`
	// TransparencyObligations (Wave 21) are EU AI Act Article 50
	// disclosure duties the system appears to attract. Like Article 5,
	// an empty list is not a clearance.
	TransparencyObligations []TransparencyObligation `json:"transparencyObligations,omitempty"`
}

// FinOpsRightsizing is one rightsizing suggestion for a detected
// FinOps finding. We only emit it when (a) the BOM shows no training
// signals (inference-only workload) and (b) the detected instance
// family is a training-class GPU with a known inference equivalent in
// the same cloud. Savings are computed from catalog prices and are a
// rough ceiling — the inference family typically has less raw compute,
// so the user must validate the swap is functionally equivalent.
type FinOpsRightsizing struct {
	Resource               string  `json:"resource"`
	Location               string  `json:"location,omitempty"`
	CurrentFamily          string  `json:"currentFamily"`
	CurrentCloud           string  `json:"currentCloud"`
	RecommendedFamily      string  `json:"recommendedFamily"`
	RecommendedAccelerator string  `json:"recommendedAccelerator,omitempty"`
	Rationale              string  `json:"rationale"`
	EstimatedSavingsLow    float64 `json:"estimatedSavingsMonthlyUsdLow"`
	EstimatedSavingsHigh   float64 `json:"estimatedSavingsMonthlyUsdHigh"`
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
	// Wave 12: declarative Annex IV § 1 fields. When present in
	// .aicap.yml they replace the [REQUIRES MANUAL INPUT] placeholders
	// in the rendered markdown so a fully-populated policy file means
	// the rendered Annex IV needs zero manual editing post-scan.
	ContactEmail     string   `json:"contactEmail,omitempty"`
	DataInputs       []string `json:"dataInputs,omitempty"`
	TrainingDatasets []string `json:"trainingDatasets,omitempty"`
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
	//
	// Retained alongside LiveVulns (Wave 16) because historical
	// proof_drills rows carry this shape in their persisted JSONB and
	// must keep deserialising. New code should read LiveVulns.
	LiveVulnIDs []string `json:"liveVulnIds,omitempty"`

	// LiveVulns (Wave 16) is the full advisory record behind each ID.
	// An identifier alone tells an auditor a problem exists; the fixed
	// version tells an engineer what to do about it, which is the
	// difference between a report that gets read and one that gets
	// filed.
	LiveVulns []LiveVuln `json:"liveVulns,omitempty"`

	// Source records where this finding came from: "catalog" for a
	// curated vulns.json entry, "osv" for one raised purely by a live
	// advisory. Auditors should be able to tell a considered risk
	// assessment from a machine-generated one.
	Source string `json:"source,omitempty"`
}

// LiveVuln is one advisory as reported by OSV.dev for a specific
// package version.
//
// Severity is deliberately carried as the label the advisory database
// itself publishes ("HIGH", "MODERATE") plus the raw CVSS vector, and
// never as a computed numeric score. Deriving a score from a vector
// requires implementing the CVSS specification, and a compliance report
// asserting a severity it calculated slightly wrong is worse than one
// quoting the source verbatim.
type LiveVuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary,omitempty"`
	// Severity is the advisory's own label, e.g. "HIGH", "MODERATE".
	Severity string `json:"severity,omitempty"`
	// CVSSVector is the raw vector string, e.g.
	// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". Quoted, not parsed.
	CVSSVector string `json:"cvssVector,omitempty"`
	// FixedVersion is the earliest version the advisory records as
	// fixed. Empty when the advisory has no fix published — which is
	// itself worth showing, since "no fix available" changes the
	// remediation decision.
	FixedVersion string `json:"fixedVersion,omitempty"`
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

// Attestation describes the provenance of a generated Annex IV document:
// whether it is recorded in the hosted audit ledger, or was produced
// locally and is therefore unverifiable by anyone but its author.
//
// This distinction is the whole point of the ledger. A document a party
// generated on its own machine and can silently regenerate is evidence
// of nothing to an auditor; one recorded in a hash chain held by a third
// party, verifiable without that party's cooperation, is evidence of
// something. Annex IV § 5 must state which of the two the reader is
// holding — claiming an "immutable audit trail" on a document that has
// no such trail would be precisely the kind of overstatement this
// product exists to prevent.
type Attestation struct {
	// Anchored is true when this render is being persisted into the
	// proof-drill ledger.
	Anchored bool
	// LedgerHash is the chain hash of the proof-drill row, when known
	// at render time.
	LedgerHash string
	// VerifyURL is where a third party can independently check the
	// record.
	VerifyURL string
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
	// Vulnerabilities (Wave 19) is the CycloneDX 1.5 vulnerabilities
	// array. AIcap already held live OSV advisories and emitted an SBOM
	// without them, which meant Dependency-Track and every other
	// consumer had to re-discover vulnerabilities AIcap had already
	// found. Omitted entirely when the risk register carries none.
	Vulnerabilities []CycloneDXVulnerability `json:"vulnerabilities,omitempty"`
}

// CycloneDXVulnerability is one advisory in the CycloneDX 1.5 shape.
type CycloneDXVulnerability struct {
	BOMRef string               `json:"bom-ref,omitempty"`
	ID     string               `json:"id"`
	Source *CycloneDXVulnSource `json:"source,omitempty"`
	// Ratings carries the severity exactly as the advisory database
	// published it. AIcap never computes a score from a CVSS vector —
	// that would mean implementing the CVSS spec, and a compliance
	// artefact asserting a severity it derived slightly wrong is worse
	// than one quoting its source.
	Ratings        []CycloneDXRating      `json:"ratings,omitempty"`
	Description    string                 `json:"description,omitempty"`
	Recommendation string                 `json:"recommendation,omitempty"`
	Advisories     []CycloneDXAdvisoryRef `json:"advisories,omitempty"`
	Affects        []CycloneDXAffects     `json:"affects,omitempty"`
}

type CycloneDXVulnSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type CycloneDXAdvisoryRef struct {
	URL string `json:"url"`
}

// CycloneDXRating carries a published severity. Score is deliberately
// absent: the OSV `severity` field holds a CVSS *vector*, not a number,
// and Vector is where that belongs.
type CycloneDXRating struct {
	Source   *CycloneDXVulnSource `json:"source,omitempty"`
	Severity string               `json:"severity,omitempty"`
	Method   string               `json:"method,omitempty"`
	Vector   string               `json:"vector,omitempty"`
}

// CycloneDXAffects links an advisory to the component it affects, by
// the component's bom-ref.
type CycloneDXAffects struct {
	Ref string `json:"ref"`
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
	Id          string   `json:"_id"`
	ModelId     string   `json:"modelId"`
	Tags        []string `json:"tags"`
	PipelineTag string   `json:"pipeline_tag"`
}

// --- Scan-to-scan drift (Wave 18) -----------------------------------------
//
// The ledger has stored consecutive proof drills since Wave 4, but nothing
// compared two of them: every scan was an isolated snapshot. Drift is that
// comparison. It is also the EU AI Act Article 72 hook — providers of
// high-risk systems must actively collect and review experience with the
// system over its lifetime, and a per-commit record of what changed is the
// evidence that obligation asks for.

// DriftEndpoint identifies one side of a comparison.
type DriftEndpoint struct {
	CommitSha  string `json:"commitSha,omitempty"`
	CryptoHash string `json:"cryptoHash,omitempty"`
	CreatedAt  string `json:"createdAt,omitempty"`
}

// VersionChange records a component moving between two concrete versions.
type VersionChange struct {
	Name        string `json:"name"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	FromVersion string `json:"fromVersion"`
	ToVersion   string `json:"toVersion"`
}

// DependencyDrift is the component-level delta between two scans.
type DependencyDrift struct {
	Added          []AIDependency  `json:"added,omitempty"`
	Removed        []AIDependency  `json:"removed,omitempty"`
	VersionChanged []VersionChange `json:"versionChanged,omitempty"`
}

// AdvisoryDelta reports advisories that appeared against a component
// between two scans. When the component's version is unchanged, this is
// the "nobody touched it and it became vulnerable" case — the one a
// point-in-time audit structurally cannot catch.
type AdvisoryDelta struct {
	Component string     `json:"component"`
	Version   string     `json:"version,omitempty"`
	Vulns     []LiveVuln `json:"vulns"`
}

// RiskDrift is the Article 9 register delta between two scans.
type RiskDrift struct {
	NewFindings      []RiskFinding   `json:"newFindings,omitempty"`
	ResolvedFindings []RiskFinding   `json:"resolvedFindings,omitempty"`
	NewAdvisories    []AdvisoryDelta `json:"newAdvisories,omitempty"`
}

// ComplianceChange records a posture transition and whether it was a
// regression.
type ComplianceChange struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Regressed bool   `json:"regressed"`
}

// DriftSummary is the headline an alerting rule or dashboard card reads
// without walking the detail.
type DriftSummary struct {
	DependenciesAdded   int `json:"dependenciesAdded"`
	DependenciesRemoved int `json:"dependenciesRemoved"`
	VersionsChanged     int `json:"versionsChanged"`
	NewFindings         int `json:"newFindings"`
	ResolvedFindings    int `json:"resolvedFindings"`
	NewAdvisories       int `json:"newAdvisories"`
	HighRiskAdded       int `json:"highRiskAdded"`
	// Regressed is deliberately broad — a worse posture, a new high-risk
	// component, or a new advisory against something already present.
	Regressed bool `json:"regressed"`
}

// Drift is the full comparison between two proof drills.
type Drift struct {
	From             DriftEndpoint     `json:"from"`
	To               DriftEndpoint     `json:"to"`
	Dependencies     DependencyDrift   `json:"dependencies"`
	Risk             RiskDrift         `json:"risk"`
	ComplianceChange *ComplianceChange `json:"complianceChange,omitempty"`
	Summary          DriftSummary      `json:"summary"`
}

// ProhibitedPracticeSignal is one Article 5 indicator: a detected
// component whose capability falls within the scope of an EU AI Act
// prohibited practice.
//
// It is deliberately not called a "violation" or a "finding". Article 5
// prohibitions turn on purpose, context, and deployment setting, none of
// which a static scan can observe — the same library is prohibited when
// pointed at employees and unremarkable in a consented study. Every
// signal therefore carries the text of what the cited paragraph actually
// prohibits and the question a human must answer, and its Status is
// "requires human assessment" rather than pass or fail.
type ProhibitedPracticeSignal struct {
	Component   string `json:"component"`
	Version     string `json:"version,omitempty"`
	Location    string `json:"location,omitempty"`
	Practice    string `json:"practice"`
	Article     string `json:"article"`
	Prohibition string `json:"prohibition"`
	AppliesWhen string `json:"appliesWhen"`
	Question    string `json:"question"`
	Status      string `json:"status"`
}

// TransparencyObligation is one EU AI Act Article 50 disclosure duty the
// scanned system appears to attract.
//
// Grouped per obligation rather than per component: a project with eight
// LLM libraries has one Article 50(1) duty, and reporting it eight times
// would bury the sentence the reader has to act on.
//
// EvidenceIsDetectable records whether this duty can be discharged by
// something a dependency scan could see at all. It matters because the
// honest reading of an empty EvidenceFound differs completely between
// the two cases: for Article 50(2) it means no watermarking library was
// found, which is informative; for Article 50(1) it means nothing,
// because that duty is discharged by interface copy.
type TransparencyObligation struct {
	ID          string `json:"id"`
	Article     string `json:"article"`
	Obligation  string `json:"obligation"`
	Requirement string `json:"requirement"`
	AppliesWhen string `json:"appliesWhen"`
	Question    string `json:"question"`
	// DischargedBy describes what actually satisfies the duty.
	DischargedBy         string   `json:"dischargedBy"`
	TriggeredBy          []string `json:"triggeredBy"`
	EvidenceFound        []string `json:"evidenceFound,omitempty"`
	EvidenceIsDetectable bool     `json:"evidenceIsDetectable"`
	Status               string   `json:"status"`
}
