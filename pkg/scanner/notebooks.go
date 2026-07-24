// Jupyter notebook scanning (Wave 16).
//
// Notebooks were invisible to the scanner until now: `.ipynb` matched no
// parser, so a repository whose model calls, API keys, and `%pip install`
// lines all lived in notebooks scanned clean. That is the worst possible
// blind spot for an AI-BOM tool — notebooks are where ML code actually
// lives, and they routinely carry hardcoded model identifiers and pasted
// API keys that never appear in a manifest.
//
// A notebook is JSON: an object with a `cells` array, each cell carrying
// a `cell_type` and a `source` that is either a string or an array of
// line strings. We decode it, concatenate the code cells, and hand the
// lines to the same detector `.py` files use (scanPythonLines), so the
// two can never drift apart.
//
// Outputs are deliberately NOT scanned. A cell's stored output can be
// megabytes of base64 image data or a printed dataframe, and a model
// name appearing in printed output is evidence of a run, not of a
// dependency. Inputs only.

package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"aicap/pkg/types"
)

// maxNotebookBytes caps the notebook we will decode. Notebooks with
// embedded plot images routinely reach tens of megabytes, and there is
// no value in decoding those to read a handful of code cells. Skipping
// an oversized notebook is safer than stalling a CI run on it.
const maxNotebookBytes = 8 << 20 // 8 MiB

// notebook mirrors the subset of the nbformat 4 schema we read.
type notebook struct {
	Cells []struct {
		CellType string          `json:"cell_type"`
		Source   json.RawMessage `json:"source"`
	} `json:"cells"`
}

// pipInstallRe matches the notebook install magics — `!pip install x`,
// `%pip install x`, `%conda install x`, and the `python -m pip install`
// spelling. Notebook authors install this way constantly, and those
// packages are real dependencies of the system even though they appear
// in no manifest file.
var pipInstallRe = regexp.MustCompile(`^\s*[!%]?\s*(?:python\s+-m\s+)?(?:pip|pip3|conda|uv\s+pip)\s+install\s+(.+)$`)

// notebookSource flattens a cell's `source` field, which nbformat allows
// to be either a single string or an array of per-line strings.
func notebookSource(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var asArray []string
	if err := json.Unmarshal(raw, &asArray); err == nil {
		out := make([]string, 0, len(asArray))
		for _, s := range asArray {
			out = append(out, strings.TrimRight(s, "\r\n"))
		}
		return out
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return strings.Split(strings.ReplaceAll(asString, "\r\n", "\n"), "\n")
	}
	return nil
}

// parsePipInstallMagic extracts AI dependencies from a notebook install
// magic. Flags (`-q`, `--upgrade`, `-U`) are skipped; everything else is
// treated as a PEP 508 requirement and looked up in the AI catalog.
func parsePipInstallMagic(line, location string) []types.AIDependency {
	m := pipInstallRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return nil
	}

	var found []types.AIDependency
	for _, token := range strings.Fields(m[1]) {
		if strings.HasPrefix(token, "-") {
			continue
		}
		pkgName, version, ok := parseRequirementSpec(token)
		if !ok {
			continue
		}
		meta, exists := targetAILibraries[pkgName]
		if !exists {
			continue
		}
		found = append(found, types.AIDependency{
			Name:        pkgName,
			Version:     version,
			Ecosystem:   "Notebook (pip magic)",
			RiskLevel:   meta.Risk,
			Description: meta.Desc + " (installed from a notebook cell)",
			Location:    location,
		})
	}
	return found
}

// parseJupyterNotebook walks a notebook's code cells and returns the AI
// dependencies, hardcoded model identifiers, exposed secrets, and
// notebook-installed packages found in them.
//
// Locations are reported as `path#cellN:line` so an auditor can navigate
// to the exact cell — notebooks have no meaningful whole-file line
// numbering, so a bare `path:42` would be unusable.
func parseJupyterNotebook(filePath string) []types.AIDependency {
	info, err := os.Stat(filePath)
	if err != nil || info.Size() > maxNotebookBytes {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var nb notebook
	if err := json.Unmarshal(data, &nb); err != nil {
		// Not a notebook we can read (nbformat 3, corrupt, or a `.ipynb`
		// that isn't JSON). Silently skip — a parse failure is not a
		// finding.
		return nil
	}

	var found []types.AIDependency
	// Shared across cells so one `import torch` repeated in five cells
	// yields one dependency.
	detectedImports := map[string]bool{}
	installedSeen := map[string]bool{}

	for cellIdx, cell := range nb.Cells {
		if cell.CellType != "code" {
			continue
		}
		lines := notebookSource(cell.Source)
		if len(lines) == 0 {
			continue
		}

		cellNum := cellIdx + 1
		locate := func(lineNum int) string {
			return fmt.Sprintf("%s#cell%d:%d", filePath, cellNum, lineNum)
		}

		found = append(found, scanPythonLines(lines, pythonScanContext{
			importEcosystem:  "Notebook (.ipynb import)",
			literalEcosystem: "Notebook (.ipynb)",
			sourceLabel:      "a Jupyter notebook cell",
			locate:           locate,
		}, detectedImports)...)

		for lineIdx, line := range lines {
			for _, dep := range parsePipInstallMagic(line, locate(lineIdx+1)) {
				if installedSeen[dep.Name] {
					continue
				}
				installedSeen[dep.Name] = true
				found = append(found, dep)
			}
		}
	}

	return found
}
