package imagescan

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// makeLayer builds an in-memory v1.Layer from a list of tar entries.
// tarball.LayerFromOpener takes a function that returns a fresh
// io.ReadCloser each time — go-containerregistry may call the opener
// multiple times to compute the digest, size, and content.
func makeLayer(t *testing.T, entries []struct {
	Path string
	Body []byte
}) v1.Layer {
	t.Helper()
	tarBytes := buildTar(t, entries)
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(tarBytes)), nil
	}
	l, err := tarball.LayerFromOpener(opener)
	if err != nil {
		t.Fatalf("layer from opener: %v", err)
	}
	return l
}

func TestScanTarball_EndToEnd(t *testing.T) {
	// Build a synthetic two-layer image:
	//   layer 0 — installs the openai Python package
	//   layer 1 — copies a llama-3 .gguf model weight
	pythonMeta := []byte("Metadata-Version: 2.1\nName: openai\nVersion: 1.30.5\n")
	layer0 := makeLayer(t, []struct {
		Path string
		Body []byte
	}{
		{"usr/lib/python3.11/site-packages/openai-1.30.5.dist-info/METADATA", pythonMeta},
	})
	layer1 := makeLayer(t, []struct {
		Path string
		Body []byte
	}{
		{"opt/models/llama-3-8b.gguf", []byte("fake-weights")},
	})

	img, err := mutate.AppendLayers(empty.Image, layer0, layer1)
	if err != nil {
		t.Fatalf("append layers: %v", err)
	}

	tag, err := name.NewTag("imagescan/test:e2e")
	if err != nil {
		t.Fatalf("new tag: %v", err)
	}

	tmpDir := t.TempDir()
	tarballPath := filepath.Join(tmpDir, "image.tar")
	if err := tarball.WriteToFile(tarballPath, tag, img); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	res, err := ScanTarball(context.Background(), tarballPath)
	if err != nil {
		t.Fatalf("ScanTarball: %v", err)
	}

	if res.LayerCount != 2 {
		t.Errorf("expected 2 layers, got %d", res.LayerCount)
	}
	if res.Source != "tarball" {
		t.Errorf("expected source=tarball, got %q", res.Source)
	}
	if len(res.Dependencies) != 2 {
		t.Fatalf("expected 2 deps (openai + llama-3 weight), got %d: %+v", len(res.Dependencies), res.Dependencies)
	}

	// Confirm both findings round-trip with the expected metadata.
	gotPython := false
	gotModel := false
	for _, d := range res.Dependencies {
		if d.Name == "openai" && d.Version == "1.30.5" {
			gotPython = true
		}
		if strings.HasSuffix(d.Name, ".gguf") || strings.Contains(d.Name, "llama") {
			gotModel = true
		}
	}
	if !gotPython {
		t.Errorf("missing openai dep; got %+v", res.Dependencies)
	}
	if !gotModel {
		t.Errorf("missing model-weight dep; got %+v", res.Dependencies)
	}
}

func TestScanTarball_NonexistentPathReturnsError(t *testing.T) {
	_, err := ScanTarball(context.Background(), "/nonexistent/path/missing.tar")
	if err == nil {
		t.Fatal("expected error for missing tarball, got nil")
	}
}

func TestScanImage_AgainstLocalRegistry(t *testing.T) {
	// Build the same synthetic image as the tarball test, but push it
	// to an in-process registry (go-containerregistry's reference
	// implementation), then have ScanImage pull it back. This proves
	// the registry code path actually walks layers without any
	// daemon dependency.
	pythonMeta := []byte("Metadata-Version: 2.1\nName: transformers\nVersion: 4.41.0\n")
	layer := makeLayer(t, []struct {
		Path string
		Body []byte
	}{
		{"usr/lib/python3.11/site-packages/transformers-4.41.0.dist-info/METADATA", pythonMeta},
	})
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref, err := name.NewTag(u.Host + "/aicap/test:v1")
	if err != nil {
		t.Fatalf("new tag: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("push to local registry: %v", err)
	}

	res, err := ScanImage(context.Background(), ref.String())
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if res.Source != "registry" {
		t.Errorf("expected source=registry, got %q", res.Source)
	}
	if len(res.Dependencies) != 1 || res.Dependencies[0].Name != "transformers" {
		t.Errorf("expected transformers dep, got %+v", res.Dependencies)
	}
	if res.Digest == "" {
		t.Error("expected non-empty digest from registry pull")
	}
}

func TestScanRefs_AggregatesAndCollectsErrors(t *testing.T) {
	// One unreachable ref should produce an error string but not
	// suppress findings from a valid tarball passed in the same
	// call. This is the CI-friendliness contract: best-effort.
	pythonMeta := []byte("Name: torch\nVersion: 2.3.0\n")
	layer := makeLayer(t, []struct {
		Path string
		Body []byte
	}{
		{"site-packages/torch-2.3.0.dist-info/METADATA", pythonMeta},
	})
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	tag, _ := name.NewTag("imagescan/test:refs")
	tarPath := filepath.Join(t.TempDir(), "img.tar")
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("write: %v", err)
	}

	deps, scanned, errs := ScanRefs(
		context.Background(),
		[]string{"definitely-not-a-real-registry.invalid/x/y:z"},
		[]string{tarPath},
	)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error for the unreachable ref, got %d: %v", len(errs), errs)
	}
	if len(deps) != 1 || deps[0].Name != "torch" {
		t.Errorf("expected torch dep from the tarball, got %+v", deps)
	}
	if len(scanned) != 1 {
		t.Errorf("expected 1 scanned-image entry from the tarball, got %d", len(scanned))
	}
}

// drainTar is a sanity helper for the layer builder, confirming our
// in-memory tar entries are well-formed before we ship them through
// go-containerregistry. Keeps the assertion local rather than
// debugging via opaque crc mismatches deep in the registry stack.
func TestBuildTar_RoundTripsEntries(t *testing.T) {
	body := []byte("payload")
	raw := buildTar(t, []struct {
		Path string
		Body []byte
	}{{"a/b/c.txt", body}})

	tr := tar.NewReader(bytes.NewReader(raw))
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if hdr.Name != "a/b/c.txt" {
		t.Errorf("name %q want a/b/c.txt", hdr.Name)
	}
	got, _ := io.ReadAll(tr)
	if !bytes.Equal(got, body) {
		t.Errorf("body mismatch")
	}
}

