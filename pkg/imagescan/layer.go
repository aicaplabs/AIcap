// Package imagescan inspects OCI / Docker container-image layer
// filesystems for AI artefacts without requiring a running Docker
// daemon. It pulls layers either from a registry (remote.Image) or
// from a local docker-save tarball (tarball.Image), streams each
// layer's uncompressed tar, and emits the same types.AIDependency
// shape that the directory scanner produces — so risk-register
// enrichment, OWASP cross-referencing, and Annex IV rendering all
// work without any downstream changes.
package imagescan

import (
	"archive/tar"
	"bufio"
	"io"
	"path"
	"strings"

	"aicap/pkg/scanner"
	"aicap/pkg/types"
)

// modelWeightExts is the same set the directory scanner recognises
// via filepath.Ext. Kept in sync deliberately so a model file in a
// repo and the same model file baked into an image produce
// equivalent findings.
var modelWeightExts = map[string]bool{
	".safetensors": true,
	".onnx":        true,
	".pt":          true,
	".h5":          true,
	".gguf":        true,
	".bin":         true,
	".tflite":      true,
	".pb":          true,
	".mlmodel":     true,
	".ckpt":        true,
}

// Per-file read cap. PEP 566 METADATA files are typically <8 KB; an
// abusive layer entry that claims to be METADATA but is multi-megabyte
// is treated as malformed (we abort the read and skip). The cap
// applies only to entries we choose to read into memory — model-weight
// detection looks at the tar header and never reads the body.
const maxMetadataBytes = 256 * 1024

// scanLayer walks a single uncompressed-layer tar stream and emits
// AIDependency findings. The imageRef + layerIndex are baked into the
// Location field so auditors can trace each finding back to the layer
// it came from. scanLayer never returns an error: a malformed tar
// stream just truncates the layer's contribution.
func scanLayer(r io.Reader, imageRef string, layerIndex int) []types.AIDependency {
	var found []types.AIDependency
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return found
		}
		if err != nil {
			return found
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		// docker/OCI whiteout markers: a deleted file in a higher
		// layer. We could honour them to suppress findings from
		// lower layers, but the layer-by-layer audit trail is more
		// useful for compliance — a model that was *added then
		// deleted* is still an audit-relevant artefact.
		base := path.Base(hdr.Name)
		if strings.HasPrefix(base, ".wh.") {
			continue
		}

		if dep := detectModelWeight(hdr, imageRef, layerIndex); dep != nil {
			found = append(found, *dep)
			// Don't read the body — model files are huge. We
			// flagged the path and size from the header alone.
			continue
		}

		if isPythonDistInfoMetadata(hdr.Name) {
			if dep := readPythonDistInfo(tr, hdr, imageRef, layerIndex); dep != nil {
				found = append(found, *dep)
			}
			continue
		}

		if isNodePackageJSON(hdr.Name) {
			if dep := readNodePackageJSON(tr, hdr, imageRef, layerIndex); dep != nil {
				found = append(found, *dep)
			}
			continue
		}
	}
}

func detectModelWeight(hdr *tar.Header, imageRef string, layerIndex int) *types.AIDependency {
	base := path.Base(hdr.Name)
	ext := strings.ToLower(path.Ext(base))
	if !modelWeightExts[ext] {
		// Sentinel filenames that the directory scanner also
		// catches even when the extension isn't on the list.
		if base != "pytorch_model.bin" && base != "model.safetensors" {
			return nil
		}
	}
	return &types.AIDependency{
		Name:        base,
		Version:     "container-layer",
		Ecosystem:   "Container Image (layer model weight " + ext + ")",
		RiskLevel:   "High",
		Description: "Model weight file detected inside container image layer",
		Location:    formatImageLocation(imageRef, layerIndex, hdr.Name),
	}
}

// isPythonDistInfoMetadata matches the PEP 566 layout that pip
// installs every wheel into: `…/site-packages/<name>-<ver>.dist-info/METADATA`.
// We accept any depth + any site-packages parent so the same logic
// works for /usr/lib/python3.11/site-packages, virtualenv layouts,
// and conda's lib/pythonX.Y/site-packages.
func isPythonDistInfoMetadata(name string) bool {
	if path.Base(name) != "METADATA" {
		return false
	}
	parent := path.Base(path.Dir(name))
	return strings.HasSuffix(parent, ".dist-info")
}

func isNodePackageJSON(name string) bool {
	if path.Base(name) != "package.json" {
		return false
	}
	// Only inside node_modules/ — root-level package.json copies
	// are picked up by the directory scanner already and shouldn't
	// fire from container layers (we'd double-report).
	return strings.Contains(name, "/node_modules/") || strings.HasPrefix(name, "node_modules/")
}

func readPythonDistInfo(tr *tar.Reader, hdr *tar.Header, imageRef string, layerIndex int) *types.AIDependency {
	if hdr.Size <= 0 || hdr.Size > maxMetadataBytes {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(tr, maxMetadataBytes))
	if err != nil {
		return nil
	}
	name, version := parsePythonMetadata(body)
	if name == "" {
		return nil
	}
	meta, ok := scanner.LookupLibrary(name)
	if !ok {
		return nil
	}
	if version == "" {
		version = "unknown"
	}
	return &types.AIDependency{
		Name:        strings.ToLower(name),
		Version:     version,
		Ecosystem:   "Container Image (Python dist-info)",
		RiskLevel:   meta.Risk,
		Description: meta.Desc + " (installed in container image)",
		Location:    formatImageLocation(imageRef, layerIndex, hdr.Name),
	}
}

// parsePythonMetadata reads the RFC 822-style header block at the
// top of a PEP 566 METADATA file. The first blank line ends the
// header; multi-line continuations (a leading space on the next
// line) are not relevant for Name/Version so we don't unfold them.
func parsePythonMetadata(body []byte) (name, version string) {
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 0, 64*1024), maxMetadataBytes)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		k, v, ok := splitHeader(line)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "name":
			name = strings.TrimSpace(v)
		case "version":
			version = strings.TrimSpace(v)
		}
		if name != "" && version != "" {
			return name, version
		}
	}
	return name, version
}

func splitHeader(line string) (key, value string, ok bool) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return "", "", false
	}
	return line[:idx], line[idx+1:], true
}

// readNodePackageJSON pulls name+version from a node_modules/.../package.json
// inside an image layer. Same JSON shape as the directory scanner's
// parsePackageJson, just from a tar stream.
func readNodePackageJSON(tr *tar.Reader, hdr *tar.Header, imageRef string, layerIndex int) *types.AIDependency {
	if hdr.Size <= 0 || hdr.Size > maxMetadataBytes {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(tr, maxMetadataBytes))
	if err != nil {
		return nil
	}
	name, version := parseNodePackageJSON(body)
	if name == "" {
		return nil
	}
	meta, ok := scanner.LookupLibrary(name)
	if !ok {
		return nil
	}
	if version == "" {
		version = "unknown"
	}
	return &types.AIDependency{
		Name:        name,
		Version:     version,
		Ecosystem:   "Container Image (Node.js node_modules)",
		RiskLevel:   meta.Risk,
		Description: meta.Desc + " (installed in container image)",
		Location:    formatImageLocation(imageRef, layerIndex, hdr.Name),
	}
}

// parseNodePackageJSON does a tiny tolerant lookup for "name" and
// "version" top-level string keys. We deliberately don't pull in a
// full JSON parser dependency just for two fields, and we don't use
// encoding/json because some real-world package.json files in the
// wild have trailing-comma quirks from build tools.
func parseNodePackageJSON(body []byte) (name, version string) {
	s := string(body)
	name = extractStringField(s, "name")
	version = extractStringField(s, "version")
	return name, version
}

// extractStringField finds `"key" : "value"` at any indentation. It
// only walks top-level structure heuristically by stopping at the
// first match — nested dependency objects also use "name"/"version"
// keys, but the top-level keys always appear first in the standard
// shape npm emits, so first-match is good enough for the package.json
// files pip-style tooling will land in node_modules.
func extractStringField(s, key string) string {
	needle := `"` + key + `"`
	idx := strings.Index(s, needle)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(needle):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = rest[colon+1:]
	openQuote := strings.IndexByte(rest, '"')
	if openQuote < 0 {
		return ""
	}
	rest = rest[openQuote+1:]
	closeQuote := strings.IndexByte(rest, '"')
	if closeQuote < 0 {
		return ""
	}
	return rest[:closeQuote]
}

// formatImageLocation is the canonical "where did this finding come
// from" string for image-scan results: `<image-ref>#layer<N>:<path>`.
// The directory scanner's Location values are file paths; image-scan
// values are obviously distinguishable because they always start
// with the image reference.
func formatImageLocation(imageRef string, layerIndex int, entryPath string) string {
	var b strings.Builder
	b.WriteString(imageRef)
	b.WriteString("#layer")
	b.WriteString(itoa(layerIndex))
	b.WriteString(":")
	b.WriteString(entryPath)
	return b.String()
}

// itoa is a tiny dependency-free positive-int formatter; layerIndex
// is always small so we avoid the strconv import for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
