// Remote catalog refresh (Wave 16).
//
// Detection quality in this scanner is almost entirely a function of how
// current three JSON files are: which libraries count as AI components,
// which string literals are model identifiers, and which model families
// exist. Shipping those only as embedded files ties catalog freshness to
// release cadence — and a compliance scanner that has not been released
// in three months reports a codebase using this quarter's models as
// having no AI components at all.
//
// pkg/finops already solved this shape for GPU pricing
// (AICAP_GPU_COSTS_URL / LoadCatalogFromURL). This mirrors it for the
// detection catalogs, deliberately using the same contract: one env var,
// fetched once at startup, embedded data left intact on any failure so a
// scan degrades to "slightly stale" rather than "empty".
//
// Bundle format — every key optional, so a publisher can refresh just
// the fast-moving part:
//
//	{
//	  "libraries":      { "<pkg>": {"risk": "...", "desc": "..."} },
//	  "models":         ["gpt-5", ...],
//	  "model_families": {"families": [{"name":..., "pattern":...}]},
//	  "licenses":       {"<model>": {"hf_id": "...", "license": "..."}}
//	}

package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"aicap/pkg/types"
)

// catalogBundle is the wire format for a remote catalog refresh.
// Pointer fields distinguish "absent" (keep embedded) from "present but
// empty" (an explicit, if unwise, instruction to clear the catalog).
type catalogBundle struct {
	Libraries     *map[string]types.LibraryMeta    `json:"libraries"`
	Models        *[]string                        `json:"models"`
	ModelFamilies *json.RawMessage                 `json:"model_families"`
	Licenses      *map[string]types.LicenseMapping `json:"licenses"`
}

// applyCatalogBundle replaces whichever catalogs the bundle carries.
// Returns the names of the catalogs actually replaced so the caller can
// log something specific.
func applyCatalogBundle(data []byte) ([]string, error) {
	var bundle catalogBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse catalog bundle: %w", err)
	}

	var applied []string
	if bundle.Libraries != nil {
		lowered := make(map[string]types.LibraryMeta, len(*bundle.Libraries))
		for name, meta := range *bundle.Libraries {
			lowered[lowerASCII(name)] = meta
		}
		targetAILibraries = lowered
		applied = append(applied, "libraries")
	}
	if bundle.Models != nil {
		targetModels = *bundle.Models
		applied = append(applied, "models")
	}
	if bundle.ModelFamilies != nil {
		// A bad pattern inside the bundle costs that one family, not the
		// refresh — same rule as the embedded catalog.
		if err := loadModelFamilies(*bundle.ModelFamilies); err != nil {
			return applied, fmt.Errorf("parse model families: %w", err)
		}
		applied = append(applied, "model_families")
	}
	if bundle.Licenses != nil {
		modelLicenseMap = *bundle.Licenses
		applied = append(applied, "licenses")
	}

	if len(applied) == 0 {
		return nil, fmt.Errorf("catalog bundle contained no known catalogs")
	}
	return applied, nil
}

// LoadCatalogsFromURL fetches a catalog bundle and replaces the embedded
// detection catalogs on success. On any failure — unreachable host,
// non-200, malformed JSON — it returns an error and leaves every
// embedded catalog untouched, so detection never gets worse than the
// binary shipped with. A blank url is a no-op.
//
// Intended to be called once at startup, before any scan runs. It is not
// safe to call concurrently with a scan in progress.
func LoadCatalogsFromURL(url string) ([]string, error) {
	if url == "" {
		return nil, nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetch catalog bundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch catalog bundle: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogBytes))
	if err != nil {
		return nil, fmt.Errorf("read catalog bundle: %w", err)
	}
	return applyCatalogBundle(data)
}

// maxCatalogBytes caps what we will read from the catalog endpoint. The
// real bundle is tens of kilobytes; anything approaching this limit is a
// misconfigured URL, not a catalog.
const maxCatalogBytes = 4 << 20 // 4 MiB

// lowerASCII lower-cases a package name. Catalog keys are ASCII package
// names, so this avoids pulling in Unicode case folding for a hot path
// that runs once per dependency lookup.
func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
