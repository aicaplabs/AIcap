package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"aicap/pkg/types"
)

// snapshotCatalogs restores every detection catalog after a test, since
// applyCatalogBundle replaces package-level state.
func snapshotCatalogs(t *testing.T) {
	t.Helper()
	libs, models, families, licenses := targetAILibraries, targetModels, modelFamilies, modelLicenseMap
	t.Cleanup(func() {
		targetAILibraries, targetModels, modelFamilies, modelLicenseMap = libs, models, families, licenses
	})
}

func TestApplyCatalogBundle_ReplacesOnlyWhatIsPresent(t *testing.T) {
	snapshotCatalogs(t)
	originalModels := len(targetModels)

	applied, err := applyCatalogBundle([]byte(`{
	  "libraries": {"NewAILib": {"risk": "High", "desc": "A library shipped after this binary"}}
	}`))
	if err != nil {
		t.Fatalf("applyCatalogBundle: %v", err)
	}
	if len(applied) != 1 || applied[0] != "libraries" {
		t.Fatalf("applied = %v, want [libraries]", applied)
	}

	// Keys are lower-cased on load so lookups stay case-insensitive.
	if _, ok := LookupLibrary("newailib"); !ok {
		t.Error("refreshed library not found via LookupLibrary")
	}
	// Catalogs absent from the bundle must be left alone.
	if len(targetModels) != originalModels {
		t.Errorf("models catalog changed (%d -> %d) though the bundle omitted it",
			originalModels, len(targetModels))
	}
}

func TestApplyCatalogBundle_RefreshesModelFamilies(t *testing.T) {
	snapshotCatalogs(t)

	if isTargetModelLiteral("futuremodel-9") {
		t.Fatal("test premise broken: futuremodel-9 already matches")
	}
	if _, err := applyCatalogBundle([]byte(`{
	  "model_families": {"families": [
	    {"name": "Future", "pattern": "futuremodel-[0-9]+", "vendor": "Acme", "license": "Proprietary (Acme)"}
	  ]}
	}`)); err != nil {
		t.Fatalf("applyCatalogBundle: %v", err)
	}
	if !isTargetModelLiteral("futuremodel-9") {
		t.Error("a model family shipped by remote refresh did not take effect")
	}
}

func TestApplyCatalogBundle_RejectsEmptyAndMalformed(t *testing.T) {
	snapshotCatalogs(t)

	if _, err := applyCatalogBundle([]byte(`{"unrelated": 1}`)); err == nil {
		t.Error("bundle with no known catalogs was accepted, want an error")
	}
	if _, err := applyCatalogBundle([]byte(`not json`)); err == nil {
		t.Error("malformed bundle was accepted, want an error")
	}
}

func TestLoadCatalogsFromURL_AppliesRemoteBundle(t *testing.T) {
	snapshotCatalogs(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"libraries": {"remotelib": {"risk": "Medium", "desc": "From the remote catalog"}}}`))
	}))
	defer srv.Close()

	applied, err := LoadCatalogsFromURL(srv.URL)
	if err != nil {
		t.Fatalf("LoadCatalogsFromURL: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("applied = %v, want one catalog", applied)
	}
	if _, ok := LookupLibrary("remotelib"); !ok {
		t.Error("remote library not loaded")
	}
}

func TestLoadCatalogsFromURL_FailureKeepsEmbeddedCatalog(t *testing.T) {
	snapshotCatalogs(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	before := len(targetAILibraries)
	if _, err := LoadCatalogsFromURL(srv.URL); err == nil {
		t.Error("non-200 response was accepted, want an error")
	}
	if len(targetAILibraries) != before {
		t.Error("embedded catalog was clobbered by a failed refresh — detection must never get worse than the shipped binary")
	}
	// The embedded catalog must still work.
	if _, ok := LookupLibrary("torch"); !ok {
		t.Error("embedded catalog no longer resolves torch after a failed refresh")
	}
}

func TestLoadCatalogsFromURL_BlankURLIsNoOp(t *testing.T) {
	applied, err := LoadCatalogsFromURL("")
	if err != nil || applied != nil {
		t.Errorf("LoadCatalogsFromURL(\"\") = (%v, %v), want (nil, nil)", applied, err)
	}
}

// Compile-time guard: the bundle type must stay in sync with the shapes
// the embedded catalogs use.
var _ = catalogBundle{
	Libraries: &map[string]types.LibraryMeta{},
	Licenses:  &map[string]types.LicenseMapping{},
}
