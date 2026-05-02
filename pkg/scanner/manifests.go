// Additional dependency-manifest parsers (Wave 7c).
//
// The original analysis flagged that AIcap only handled `requirements.txt`
// and `package.json`. Subsequent waves added `pyproject.toml`, `go.mod`,
// `Dockerfile`, and Terraform `.tf` parsing. This file fills in the
// remaining lockfile / alternative-manifest formats so projects using
// Poetry-locked, Pipenv-locked, pnpm/yarn-locked, or Conda-managed deps
// still get a full AI-BOM:
//
//   poetry.lock         TOML, [[package]] blocks (Poetry's resolved tree)
//   Pipfile.lock        JSON with default + develop sections (Pipenv)
//   pnpm-lock.yaml      YAML, packages: map keyed by /name@version
//   yarn.lock           Custom format ("name@range:" → "name@actual"
//                       resolution blocks)
//   environment.yml     YAML, dependencies: list (Conda)
//
// All parsers share the same contract as parseRequirementsTxt: read the
// file, extract (name, version) pairs, look up name in targetAILibraries,
// emit AIDependency findings only for matches. Unknown deps are silently
// dropped — this is a scanner for AI components, not a generic SBOM tool.
//
// Lockfile parsers intentionally use simple line-based scanning rather
// than full TOML/YAML parsers. Reasons:
//   1. Zero new dependencies (all stdlib).
//   2. Lockfile shapes are stable and well-known — no risk of upstream
//      schema drift breaking us.
//   3. We only need name+version, not the full dependency graph.

package scanner

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"aicap/pkg/types"
)

// emitIfAI is a small helper used by every parser below to keep the
// "is this dep one we care about?" lookup in one place. Returns nil
// when the package isn't in our AI-library catalog so callers can
// just append the result.
func emitIfAI(name, version, ecosystem, filePath string) *types.AIDependency {
	lower := strings.ToLower(name)
	meta, ok := targetAILibraries[lower]
	if !ok {
		return nil
	}
	return &types.AIDependency{
		Name:        lower,
		Version:     version,
		Ecosystem:   ecosystem,
		RiskLevel:   meta.Risk,
		Description: meta.Desc,
		Location:    filePath,
	}
}

// --- Poetry: poetry.lock --------------------------------------------------

// poetryPackageHeader is the start-of-block marker. We then look for the
// next `name = "..."` and `version = "..."` lines in the same [[package]]
// stanza. Toml's spec allows attributes in any order so we scan until the
// next [[package]] or end-of-file rather than assuming a fixed layout.
var (
	poetryPkgHeader  = regexp.MustCompile(`^\s*\[\[package\]\]\s*$`)
	poetryNameLine   = regexp.MustCompile(`(?i)^\s*name\s*=\s*"([^"]+)"`)
	poetryVerLine    = regexp.MustCompile(`(?i)^\s*version\s*=\s*"([^"]+)"`)
)

func parsePoetryLock(filePath string) []types.AIDependency {
	var found []types.AIDependency
	body, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}
	var name, version string
	flush := func() {
		if name != "" {
			if dep := emitIfAI(name, version, "Python (Poetry lock)", filePath); dep != nil {
				found = append(found, *dep)
			}
		}
		name, version = "", ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	inPkg := false
	for scanner.Scan() {
		line := scanner.Text()
		if poetryPkgHeader.MatchString(line) {
			flush()
			inPkg = true
			continue
		}
		if !inPkg {
			continue
		}
		if m := poetryNameLine.FindStringSubmatch(line); m != nil {
			name = m[1]
			continue
		}
		if m := poetryVerLine.FindStringSubmatch(line); m != nil {
			version = m[1]
		}
	}
	flush()
	return found
}

// --- Pipenv: Pipfile.lock -------------------------------------------------

// Pipfile.lock is JSON. Schema:
//   {
//     "default": { "torch": { "version": "==2.1.0", ... }, ... },
//     "develop": { ... }
//   }
// Versions arrive as "==X.Y.Z" — we strip the operator before storing.
func parsePipfileLock(filePath string) []types.AIDependency {
	var found []types.AIDependency
	body, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(body, &lock); err != nil {
		return found
	}
	emit := func(deps map[string]struct {
		Version string `json:"version"`
	}) {
		for name, info := range deps {
			version := strings.TrimLeft(info.Version, "=<>~!^ ")
			if version == "" {
				version = "unknown"
			}
			if dep := emitIfAI(name, version, "Python (Pipfile lock)", filePath); dep != nil {
				found = append(found, *dep)
			}
		}
	}
	emit(lock.Default)
	emit(lock.Develop)
	return found
}

// --- pnpm: pnpm-lock.yaml -------------------------------------------------

// pnpm-lock.yaml stores resolved packages keyed by /name@version under
// the top-level `packages:` map. We pattern-match those keys directly —
// pulling in a YAML parser is overkill for two regex-extractable fields.
//
// Example:
//   packages:
//     /openai@4.52.5:
//       resolution: {...}
var pnpmPackageKey = regexp.MustCompile(`^\s+/([@\w.\-/]+)@([\w.\-]+):`)

func parsePnpmLock(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // pnpm lockfiles can be large
	for scanner.Scan() {
		m := pnpmPackageKey.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		// pnpm's scoped-package key looks like /@scope/name@version —
		// keep the @scope/name as the package name; only the trailing
		// @version is the version separator.
		name, version := m[1], m[2]
		if dep := emitIfAI(name, version, "Node.js (pnpm lock)", filePath); dep != nil {
			found = append(found, *dep)
		}
	}
	return found
}

// --- Yarn: yarn.lock ------------------------------------------------------

// yarn.lock has a bespoke (non-YAML, non-TOML) format. Each block looks
// like:
//   "openai@^4.0.0":
//     version "4.52.5"
//     resolved "https://..."
//
// We track the most-recent quoted package header, then capture its
// `version "..."` line. Unquoted headers (rare; older yarn versions)
// also work because the regex tolerates an optional leading quote.
var (
	yarnPkgHeader  = regexp.MustCompile(`^"?([@\w.\-/]+)@`)
	yarnVersionRow = regexp.MustCompile(`^\s+version\s+"([^"]+)"`)
)

func parseYarnLock(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var pendingName string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if pendingName == "" {
				continue
			}
			if m := yarnVersionRow.FindStringSubmatch(line); m != nil {
				if dep := emitIfAI(pendingName, m[1], "Node.js (yarn lock)", filePath); dep != nil {
					found = append(found, *dep)
				}
				pendingName = ""
			}
			continue
		}
		// New top-level block. Capture the package name from the first
		// "name@range" portion of the header (yarn v1 supports
		// comma-separated multi-range headers, but the leading name is
		// always the package).
		if m := yarnPkgHeader.FindStringSubmatch(line); m != nil {
			pendingName = m[1]
		}
	}
	return found
}

// --- Conda: environment.yml -----------------------------------------------

// Conda environments are YAML with a `dependencies:` list. Entries are
// either bare strings ("python=3.11") or sub-mapped pip blocks
// ("- pip:\n    - torch==2.1.0"). Both are name-bearing for our purposes.
//
// Sample:
//   dependencies:
//     - numpy=1.26.0
//     - pip:
//         - torch==2.1.0
//         - transformers==4.30.0
var (
	condaDepLine = regexp.MustCompile(`^\s*-\s+([a-zA-Z0-9_\-\.]+)\s*[=<>~!]+([a-zA-Z0-9_\-\.]+)`)
)

func parseCondaEnv(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()
	inDeps := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		// Section toggle. Conda only has one dependencies: block per
		// environment file at the top level; a subsequent unindented
		// key (e.g. `name:` further down) takes us out.
		if strings.HasPrefix(trimmed, "dependencies:") {
			inDeps = true
			continue
		}
		if !inDeps {
			continue
		}
		// Bail out of the deps section when we hit another top-level
		// key (column 0, ends in colon, no leading dash).
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") &&
			strings.Contains(trimmed, ":") {
			inDeps = false
			continue
		}
		if m := condaDepLine.FindStringSubmatch(line); m != nil {
			if dep := emitIfAI(m[1], m[2], "Python (Conda environment.yml)", filePath); dep != nil {
				found = append(found, *dep)
			}
		}
	}
	return found
}
