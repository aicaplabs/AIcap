package imagescan

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

// buildTar writes an in-memory tar archive from a list of (path, body)
// pairs. The body slice length sets the header Size, which the tar
// reader uses to enforce per-entry boundaries.
func buildTar(t *testing.T, entries []struct {
	Path string
	Body []byte
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.Path,
			Mode:     0o644,
			Size:     int64(len(e.Body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header for %s: %v", e.Path, err)
		}
		if _, err := tw.Write(e.Body); err != nil {
			t.Fatalf("write body for %s: %v", e.Path, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func TestScanLayer_PythonDistInfoMatchesAILibrary(t *testing.T) {
	body := []byte("Metadata-Version: 2.1\nName: openai\nVersion: 1.30.5\nSummary: OpenAI client\n\nBody")
	tarBytes := buildTar(t, []struct {
		Path string
		Body []byte
	}{
		{"usr/lib/python3.11/site-packages/openai-1.30.5.dist-info/METADATA", body},
	})

	deps := scanLayer(bytes.NewReader(tarBytes), "registry.example.com/myimage:v1", 2)
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "openai" {
		t.Errorf("expected name openai, got %q", deps[0].Name)
	}
	if deps[0].Version != "1.30.5" {
		t.Errorf("expected version 1.30.5, got %q", deps[0].Version)
	}
	if !strings.Contains(deps[0].Ecosystem, "Python dist-info") {
		t.Errorf("expected Python dist-info ecosystem, got %q", deps[0].Ecosystem)
	}
	if !strings.Contains(deps[0].Location, "registry.example.com/myimage:v1#layer2:") {
		t.Errorf("expected image#layer2: location, got %q", deps[0].Location)
	}
}

func TestScanLayer_PythonDistInfoSkipsNonAILibrary(t *testing.T) {
	body := []byte("Metadata-Version: 2.1\nName: numpy\nVersion: 1.26.0\n")
	tarBytes := buildTar(t, []struct {
		Path string
		Body []byte
	}{
		{"site-packages/numpy-1.26.0.dist-info/METADATA", body},
	})
	deps := scanLayer(bytes.NewReader(tarBytes), "img", 0)
	if len(deps) != 0 {
		t.Fatalf("non-AI lib should be skipped, got %d deps: %+v", len(deps), deps)
	}
}

func TestScanLayer_DetectsModelWeightByExtension(t *testing.T) {
	for _, ext := range []string{".safetensors", ".onnx", ".pt", ".gguf"} {
		t.Run(ext, func(t *testing.T) {
			tarBytes := buildTar(t, []struct {
				Path string
				Body []byte
			}{
				{"opt/models/checkpoint" + ext, []byte("fake-weights")},
			})
			deps := scanLayer(bytes.NewReader(tarBytes), "img", 1)
			if len(deps) != 1 {
				t.Fatalf("expected 1 model-weight dep, got %d", len(deps))
			}
			if deps[0].RiskLevel != "High" {
				t.Errorf("model weights are High risk; got %q", deps[0].RiskLevel)
			}
		})
	}
}

func TestScanLayer_DetectsSentinelFilenames(t *testing.T) {
	// pytorch_model.bin has the generic .bin extension which is on
	// the model list, but model.safetensors is doubly covered. We
	// also confirm the directory-scanner-style sentinel-name path.
	tarBytes := buildTar(t, []struct {
		Path string
		Body []byte
	}{
		{"opt/app/pytorch_model.bin", []byte("x")},
		{"opt/app/model.safetensors", []byte("y")},
	})
	deps := scanLayer(bytes.NewReader(tarBytes), "img", 0)
	if len(deps) != 2 {
		t.Fatalf("expected 2 sentinel model files, got %d", len(deps))
	}
}

func TestScanLayer_NodePackageJSONOnlyInsideNodeModules(t *testing.T) {
	pkgBody := []byte(`{"name":"openai","version":"4.20.0","main":"index.js"}`)
	tarBytes := buildTar(t, []struct {
		Path string
		Body []byte
	}{
		// Root-level package.json: should be ignored (the directory
		// scanner already catches this; we mustn't double-count).
		{"app/package.json", pkgBody},
		// Inside node_modules: detected.
		{"app/node_modules/openai/package.json", pkgBody},
	})
	deps := scanLayer(bytes.NewReader(tarBytes), "img", 0)
	if len(deps) != 1 {
		t.Fatalf("expected 1 node-modules finding, got %d (%+v)", len(deps), deps)
	}
	if !strings.Contains(deps[0].Ecosystem, "node_modules") {
		t.Errorf("expected node_modules ecosystem, got %q", deps[0].Ecosystem)
	}
	if deps[0].Version != "4.20.0" {
		t.Errorf("expected version 4.20.0, got %q", deps[0].Version)
	}
}

func TestScanLayer_SkipsWhiteoutMarkers(t *testing.T) {
	// OCI/Docker convention: a file named .wh.<X> in layer N+1 marks
	// <X> as deleted from earlier layers. The marker itself shouldn't
	// produce a finding.
	tarBytes := buildTar(t, []struct {
		Path string
		Body []byte
	}{
		{"opt/models/.wh.weights.safetensors", []byte("")},
	})
	deps := scanLayer(bytes.NewReader(tarBytes), "img", 0)
	if len(deps) != 0 {
		t.Fatalf("whiteout markers must not yield findings, got %+v", deps)
	}
}

func TestScanLayer_OversizedMetadataIgnored(t *testing.T) {
	// PEP 566 METADATA is tiny; if a layer claims 5 MB of METADATA,
	// we skip rather than read into memory.
	huge := bytes.Repeat([]byte("Name: openai\nVersion: 1.0\n"), 500_000)
	tarBytes := buildTar(t, []struct {
		Path string
		Body []byte
	}{
		{"site-packages/openai-1.0.dist-info/METADATA", huge},
	})
	deps := scanLayer(bytes.NewReader(tarBytes), "img", 0)
	if len(deps) != 0 {
		t.Fatalf("oversized METADATA must be skipped, got %+v", deps)
	}
}

func TestScanLayer_MissingNameInMetadataYieldsNothing(t *testing.T) {
	body := []byte("Metadata-Version: 2.1\nSummary: Mystery package\nVersion: 1.0\n")
	tarBytes := buildTar(t, []struct {
		Path string
		Body []byte
	}{
		{"site-packages/anon-1.0.dist-info/METADATA", body},
	})
	deps := scanLayer(bytes.NewReader(tarBytes), "img", 0)
	if len(deps) != 0 {
		t.Fatalf("metadata without Name: must be skipped, got %+v", deps)
	}
}

func TestParsePythonMetadata_StopsAtBlankLine(t *testing.T) {
	body := []byte("Name: torch\nVersion: 2.3.0\n\nName: ignored\nVersion: 999\n")
	name, version := parsePythonMetadata(body)
	if name != "torch" || version != "2.3.0" {
		t.Errorf("got (%q, %q); want (torch, 2.3.0) — must stop at blank line", name, version)
	}
}

func TestParsePythonMetadata_CaseInsensitiveKeys(t *testing.T) {
	body := []byte("NAME: TENSORFLOW\nversion: 2.16.1\n")
	name, version := parsePythonMetadata(body)
	if name != "TENSORFLOW" || version != "2.16.1" {
		t.Errorf("got (%q, %q); want preserved-case TENSORFLOW + 2.16.1", name, version)
	}
}

func TestIsPythonDistInfoMetadata(t *testing.T) {
	cases := map[string]bool{
		"usr/lib/python3.11/site-packages/openai-1.0.dist-info/METADATA":  true,
		"site-packages/torch-2.3.0.dist-info/METADATA":                    true,
		"site-packages/openai-1.0.dist-info/RECORD":                       false,
		"site-packages/openai-1.0.dist-info/metadata":                     false, // case-sensitive
		"site-packages/openai-1.0.egg-info/METADATA":                      false, // egg-info path
		"random/path/METADATA":                                            false,
	}
	for path, want := range cases {
		got := isPythonDistInfoMetadata(path)
		if got != want {
			t.Errorf("isPythonDistInfoMetadata(%q) = %v; want %v", path, got, want)
		}
	}
}

func TestIsNodePackageJSON(t *testing.T) {
	cases := map[string]bool{
		"node_modules/openai/package.json":            true,
		"app/node_modules/anthropic/package.json":     true,
		"node_modules/@scope/pkg/package.json":        true,
		"app/package.json":                            false,
		"random/path/package.json":                    false,
		"node_modules/openai/package-lock.json":       false,
	}
	for path, want := range cases {
		got := isNodePackageJSON(path)
		if got != want {
			t.Errorf("isNodePackageJSON(%q) = %v; want %v", path, got, want)
		}
	}
}

func TestFormatImageLocation(t *testing.T) {
	got := formatImageLocation("registry.example.com/foo:1.2", 7, "opt/app/model.safetensors")
	want := "registry.example.com/foo:1.2#layer7:opt/app/model.safetensors"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractStringField_HandlesWhitespace(t *testing.T) {
	body := `{
		"name"   :    "openai",
		"version" : "1.0.0"
	}`
	if got := extractStringField(body, "name"); got != "openai" {
		t.Errorf("name: got %q want openai", got)
	}
	if got := extractStringField(body, "version"); got != "1.0.0" {
		t.Errorf("version: got %q want 1.0.0", got)
	}
}
