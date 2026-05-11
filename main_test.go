package main

import (
	"reflect"
	"testing"
)

func TestParseCLIArgs_DirectoryOnly(t *testing.T) {
	dir, refs, tarballs, cdx := parseCLIArgs([]string{"./repo"})
	if dir != "./repo" {
		t.Errorf("dir=%q want ./repo", dir)
	}
	if len(refs) != 0 || len(tarballs) != 0 || cdx {
		t.Errorf("unexpected flags: refs=%v tarballs=%v cdx=%v", refs, tarballs, cdx)
	}
}

func TestParseCLIArgs_DefaultsScanDirToDot(t *testing.T) {
	dir, _, _, _ := parseCLIArgs(nil)
	if dir != "." {
		t.Errorf("dir=%q want .", dir)
	}
}

func TestParseCLIArgs_RepeatedImageFlags(t *testing.T) {
	dir, refs, tarballs, cdx := parseCLIArgs([]string{
		"./src",
		"--image", "ghcr.io/foo/bar:1",
		"--image-tar", "/tmp/local.tar",
		"--image", "registry.example.com/baz:latest",
		"--cyclonedx",
	})
	if dir != "./src" {
		t.Errorf("dir=%q want ./src", dir)
	}
	wantRefs := []string{"ghcr.io/foo/bar:1", "registry.example.com/baz:latest"}
	if !reflect.DeepEqual(refs, wantRefs) {
		t.Errorf("refs=%v want %v", refs, wantRefs)
	}
	wantTar := []string{"/tmp/local.tar"}
	if !reflect.DeepEqual(tarballs, wantTar) {
		t.Errorf("tarballs=%v want %v", tarballs, wantTar)
	}
	if !cdx {
		t.Error("expected --cyclonedx to be true")
	}
}

func TestParseCLIArgs_UnknownFlagsIgnored(t *testing.T) {
	// Forward-compat: an older binary called by a newer action.yml
	// must not abort on unrecognised flags.
	dir, _, _, _ := parseCLIArgs([]string{"--future-flag", "value", "./src"})
	if dir != "./src" {
		t.Errorf("dir=%q want ./src", dir)
	}
}

func TestParseCLIArgs_MissingFlagValueIsTolerated(t *testing.T) {
	// --image at the very end with no value should not panic; the
	// flag is simply dropped.
	_, refs, _, _ := parseCLIArgs([]string{"./src", "--image"})
	if len(refs) != 0 {
		t.Errorf("trailing --image with no value should be ignored, got refs=%v", refs)
	}
}
