package scanner

import (
	"strings"
	"testing"
)

// nbWithCells builds a minimal nbformat-4 notebook around the given code
// cell bodies. Each body is stored as an array of line strings, which is
// how Jupyter actually writes them.
func nbWithCells(t *testing.T, cells ...string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`{"nbformat":4,"nbformat_minor":5,"cells":[`)
	for i, body := range cells {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"cell_type":"code","metadata":{},"source":[`)
		for j, line := range strings.Split(body, "\n") {
			if j > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`"`)
			sb.WriteString(strings.ReplaceAll(line, `"`, `\"`))
			sb.WriteString(`\n"`)
		}
		sb.WriteString(`]}`)
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func TestParseJupyterNotebook_DetectsImportsAndModels(t *testing.T) {
	path := createTempFile(t, "analysis.ipynb", nbWithCells(t,
		"import torch\nfrom transformers import AutoModel",
		"MODEL = \"gpt-4o\"",
	))

	deps := parseJupyterNotebook(path)

	names := map[string]depSnapshot{}
	for _, d := range deps {
		names[d.Name] = depSnapshot{version: d.Version, ecosystem: d.Ecosystem, location: d.Location}
	}
	if _, ok := names["torch"]; !ok {
		t.Errorf("torch not detected in notebook: %#v", deps)
	}
	if _, ok := names["transformers"]; !ok {
		t.Errorf("transformers not detected in notebook: %#v", deps)
	}
	model, ok := names["Hardcoded Model"]
	if !ok {
		t.Fatalf("hardcoded model not detected in notebook: %#v", deps)
	}
	if model.version != "gpt-4o" {
		t.Errorf("model version = %q, want gpt-4o", model.version)
	}
	// The model literal is in the second cell — the location must say so,
	// since a flat line number is meaningless in a notebook.
	if !strings.Contains(model.location, "#cell2:") {
		t.Errorf("location = %q, want a #cell2: reference", model.location)
	}
}

func TestParseJupyterNotebook_DeduplicatesImportsAcrossCells(t *testing.T) {
	path := createTempFile(t, "repeat.ipynb", nbWithCells(t,
		"import torch",
		"import torch",
		"import torch",
	))

	deps := parseJupyterNotebook(path)
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1 (torch imported in three cells is one dependency): %#v", len(deps), deps)
	}
}

func TestParseJupyterNotebook_DetectsPipInstallMagic(t *testing.T) {
	path := createTempFile(t, "install.ipynb", nbWithCells(t,
		"!pip install -q openai==1.40.0 pandas\n%pip install transformers",
	))

	deps := parseJupyterNotebook(path)

	byName := map[string]string{}
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	if byName["openai"] != "1.40.0" {
		t.Errorf("openai version = %q, want 1.40.0 (from !pip install)", byName["openai"])
	}
	if _, ok := byName["transformers"]; !ok {
		t.Errorf("transformers not detected from %%pip install: %#v", deps)
	}
	if _, ok := byName["pandas"]; ok {
		t.Errorf("pandas should not be reported — it is not an AI library")
	}
}

func TestParseJupyterNotebook_SkipsMarkdownCellsAndOutputs(t *testing.T) {
	// A markdown cell mentioning a model, and a code cell whose *output*
	// contains one. Neither is a dependency.
	raw := `{"nbformat":4,"cells":[
	  {"cell_type":"markdown","source":["We evaluated gpt-4o here.\n"]},
	  {"cell_type":"code","source":["print(result)\n"],
	   "outputs":[{"output_type":"stream","text":["model: gpt-4o\n"]}]}
	]}`
	path := createTempFile(t, "doc.ipynb", raw)

	deps := parseJupyterNotebook(path)
	if len(deps) != 0 {
		t.Fatalf("got %d deps, want 0 (markdown prose and cell outputs are not dependencies): %#v", len(deps), deps)
	}
}

func TestParseJupyterNotebook_SourceAsPlainString(t *testing.T) {
	// nbformat allows `source` to be a single string rather than an array.
	raw := `{"nbformat":4,"cells":[{"cell_type":"code","source":"import torch\nMODEL='claude-3-opus'\n"}]}`
	path := createTempFile(t, "string-source.ipynb", raw)

	deps := parseJupyterNotebook(path)
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2 (torch import + hardcoded model): %#v", len(deps), deps)
	}
}

func TestParseJupyterNotebook_MalformedIsNotAFinding(t *testing.T) {
	path := createTempFile(t, "broken.ipynb", `{"cells": [ this is not json`)
	if deps := parseJupyterNotebook(path); len(deps) != 0 {
		t.Errorf("got %d deps from unparseable notebook, want 0", len(deps))
	}
}

func TestPerformScan_IncludesNotebooks(t *testing.T) {
	dir := createTempDir(t, map[string]string{
		"notebooks/train.ipynb": nbWithCells(t, "import torch"),
	})

	bom := PerformScan(dir)

	found := false
	for _, d := range bom.Dependencies {
		if d.Name == "torch" {
			found = true
		}
	}
	if !found {
		t.Errorf("PerformScan missed a notebook dependency: %#v", bom.Dependencies)
	}
}

// depSnapshot is a tiny local record so the assertions above stay readable.
type depSnapshot struct {
	version   string
	ecosystem string
	location  string
}
