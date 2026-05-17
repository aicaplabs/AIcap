package imagescan

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"aicap/pkg/types"
)

// Result is the per-image output: provenance metadata (mirrored into
// types.ScannedImage on the BOM) plus the dependencies found across
// all layers. Callers merge Dependencies into bom.Dependencies and
// record the metadata in bom.ScannedImages.
type Result struct {
	Reference    string
	Digest       string
	Source       string // "registry" or "tarball"
	LayerCount   int
	Dependencies []types.AIDependency
}

// ScanImage pulls an image manifest + layers from a remote registry
// (no local Docker daemon required) and walks each layer's tar for
// AI artefacts. Auth is delegated to go-containerregistry's
// DefaultKeychain so the standard environments work out of the box:
// docker login state in ~/.docker/config.json, GitHub Actions
// `GITHUB_TOKEN`-derived ghcr.io creds, GCR / ACR / ECR via their
// respective helper binaries when on the PATH.
func ScanImage(ctx context.Context, ref string) (*Result, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", ref, err)
	}
	img, err := remote.Image(parsed,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return nil, fmt.Errorf("fetch image %q: %w", ref, err)
	}
	return walkImage(img, ref, "registry")
}

// ScanTarball reads an image saved with `docker save` (or `crane
// pull --format=tarball`) and walks its layers identically to
// ScanImage. The tarball path is preferred in CI flows that build
// images locally and want to scan *before* push — no registry round
// trip, no daemon, no network. Passing nil for the tag tells
// go-containerregistry to pick the first image in the manifest,
// which matches the typical single-tag `docker save` output.
func ScanTarball(ctx context.Context, path string) (*Result, error) {
	img, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return nil, fmt.Errorf("read image tarball %q: %w", path, err)
	}
	return walkImage(img, path, "tarball")
}

// walkImage is the shared per-image driver. It pulls layers in the
// order go-containerregistry returns them (base layer first, top
// layer last — matching Dockerfile build order), so layerIndex 0
// is the closest-to-base layer in every finding's Location.
func walkImage(img v1.Image, ref, source string) (*Result, error) {
	digest, err := img.Digest()
	if err != nil {
		// Digest computation can fail for malformed manifests; we
		// keep going with an empty digest rather than aborting,
		// because the layer walk itself is still meaningful.
		digest = v1.Hash{}
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read layers for %q: %w", ref, err)
	}

	result := &Result{
		Reference:  ref,
		Digest:     digest.String(),
		Source:     source,
		LayerCount: len(layers),
	}

	for i, layer := range layers {
		deps, err := scanOneLayer(layer, ref, i)
		if err != nil {
			// One bad layer doesn't taint the whole result —
			// container-image scanning is best-effort by
			// design (an attacker controlling a layer could
			// produce a tar bomb, and we'd rather skip and
			// flag than crash a CI pipeline).
			continue
		}
		result.Dependencies = append(result.Dependencies, deps...)
	}
	return result, nil
}

func scanOneLayer(layer v1.Layer, ref string, layerIndex int) ([]types.AIDependency, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return scanLayer(rc, ref, layerIndex), nil
}

// ScanRefs is the CLI-facing convenience: takes parallel lists of
// registry refs + tarball paths, runs each through the appropriate
// entry point, and returns flattened dependencies + per-image
// provenance entries ready to merge into an AIBOM. Failures are
// returned as a string slice so the caller (the CLI) can surface
// per-image errors without aborting the whole scan — one
// unreachable registry shouldn't drop the dependencies that the
// other images contributed.
func ScanRefs(ctx context.Context, refs []string, tarballs []string) ([]types.AIDependency, []types.ScannedImage, []string) {
	var deps []types.AIDependency
	var images []types.ScannedImage
	var errs []string

	for _, ref := range refs {
		res, err := ScanImage(ctx, ref)
		if err != nil {
			errs = append(errs, fmt.Sprintf("image %q: %v", ref, err))
			continue
		}
		deps = append(deps, res.Dependencies...)
		images = append(images, types.ScannedImage{
			Reference:    res.Reference,
			Digest:       res.Digest,
			Source:       res.Source,
			Layers:       res.LayerCount,
			FindingCount: len(res.Dependencies),
		})
	}
	for _, path := range tarballs {
		res, err := ScanTarball(ctx, path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("tarball %q: %v", path, err))
			continue
		}
		deps = append(deps, res.Dependencies...)
		images = append(images, types.ScannedImage{
			Reference:    res.Reference,
			Digest:       res.Digest,
			Source:       res.Source,
			Layers:       res.LayerCount,
			FindingCount: len(res.Dependencies),
		})
	}
	return deps, images, errs
}
