#!/usr/bin/env bash
# Build the release binary reproducibly and print its SHA-256.
#
#   scripts/build-release.sh [git-ref] [output-path]
#
# Defaults: ref = HEAD, output = ./aicap-linux-amd64
#
# The digest printed here is the one action.yml pins (AICAP_SHA256), so
# anyone must be able to reproduce it from the tagged source. Two things
# make that true, and both were learned the hard way:
#
#   * It builds from `git archive` with line-ending conversion OFF, not
#     from the working tree. The binary embeds JSON catalogs, the OpenAPI
#     document and the SQL migrations. On a Windows checkout with
#     core.autocrlf those files have CRLF line endings, the embedded bytes
#     differ, and the binary gets a digest nobody on Linux can reproduce.
#   * -buildvcs=false, so the digest does not depend on the commit — which
#     lets the commit that records the digest in action.yml be the one that
#     gets tagged. -trimpath removes the build directory from the binary.
#
# Requires the Go toolchain named in go.mod (the `toolchain` line); a
# different patch release produces a different binary.
set -euo pipefail

ref="${1:-HEAD}"
out="${2:-aicap-linux-amd64}"

repo_root="$(git rev-parse --show-toplevel)"
case "$out" in
  /*|[A-Za-z]:*) ;;
  *) out="$PWD/$out" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git -C "$repo_root" -c core.autocrlf=false -c core.eol=lf archive "$ref" | tar -x -C "$work"

(
  cd "$work"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$out" .
)

digest="$(sha256sum "$out" | cut -c1-64)"
echo "built   $out"
echo "ref     $ref ($(git -C "$repo_root" rev-parse --short "$ref"))"
echo "go      $(cd "$work" && go version | cut -d' ' -f3)"
echo "sha256  $digest"

pinned="$(git -C "$repo_root" show "$ref:action.yml" | sed -n 's/^ *AICAP_SHA256: *\([0-9a-f]\{64\}\) *$/\1/p')"
if [ "$pinned" = "$digest" ]; then
  echo "pin     matches action.yml at $ref"
else
  echo "pin     action.yml at $ref pins ${pinned:-nothing} — update AICAP_SHA256 to the digest above"
  exit 1
fi
