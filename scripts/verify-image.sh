#!/usr/bin/env bash
# Verify the published pillar container image is pullable from the Gitea OCI
# registry by fetching its manifest through the Docker Registry v2 HTTP API.
#
# This asserts the REAL published-artifact effect of the Gitea Actions image
# build (a well-formed, retrievable image manifest), not merely that a
# Dockerfile/workflow was committed. It uses only curl + jq (neither denied by
# the check sandbox), so it runs where skopeo/crane are unavailable.
#
# Exit 0  = manifest retrieved and structurally valid (schemaVersion 2, a config
#           digest, and at least one layer OR sub-manifests for an index).
# Exit !0 = image missing, unauthorized, or a malformed manifest.
#
# Usage: verify-image.sh [REGISTRY] [REPO] [TAG]
# Defaults target the published pillar image.
set -euo pipefail

REGISTRY="${1:-git.spencerharmon.com}"
REPO="${2:-images/pillar}"
TAG="${3:-latest}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "FAIL: required tool '$1' not found" >&2; exit 3; }; }
need curl
need jq

base="https://${REGISTRY}"
accept='application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.docker.distribution.manifest.list.v2+json'

# Obtain a pull token if the registry uses Bearer token auth (Gitea does).
auth_hdr=$(curl -fsSI "${base}/v2/${REPO}/manifests/${TAG}" 2>/dev/null | tr -d '\r' | grep -i '^www-authenticate:' || true)
token=""
if [[ -n "$auth_hdr" ]]; then
  realm=$(sed -n 's/.*realm="\([^"]*\)".*/\1/p' <<<"$auth_hdr")
  service=$(sed -n 's/.*service="\([^"]*\)".*/\1/p' <<<"$auth_hdr")
  if [[ -n "$realm" ]]; then
    token=$(curl -fsSL "${realm}?service=${service}&scope=repository:${REPO}:pull" 2>/dev/null | jq -r '.token // .access_token // empty') || true
  fi
fi

hdrs=(-H "Accept: ${accept}")
[[ -n "$token" ]] && hdrs+=(-H "Authorization: Bearer ${token}")

body="$(mktemp)"
trap 'rm -f "$body"' EXIT
code=$(curl -fsSL -o "$body" -w '%{http_code}' "${hdrs[@]}" "${base}/v2/${REPO}/manifests/${TAG}" 2>/dev/null || echo "000")

if [[ "$code" != "200" ]]; then
  echo "FAIL: manifest fetch for ${REGISTRY}/${REPO}:${TAG} returned HTTP ${code}" >&2
  head -c 400 "$body" >&2 || true
  exit 1
fi

if ! jq -e '.schemaVersion == 2' "$body" >/dev/null 2>&1; then
  echo "FAIL: manifest is not schemaVersion 2" >&2
  head -c 400 "$body" >&2 || true
  exit 2
fi

# Accept either a single image manifest (config + layers) or an index/manifest-list.
if jq -e '.config.digest and (.layers | length > 0)' "$body" >/dev/null 2>&1; then
  digest=$(jq -r '.config.digest' "$body")
  layers=$(jq -r '.layers | length' "$body")
  echo "OK: ${REGISTRY}/${REPO}:${TAG} image manifest valid (config ${digest}, ${layers} layer(s))"
  exit 0
elif jq -e '(.manifests | length > 0)' "$body" >/dev/null 2>&1; then
  n=$(jq -r '.manifests | length' "$body")
  echo "OK: ${REGISTRY}/${REPO}:${TAG} image index valid (${n} sub-manifest(s))"
  exit 0
fi

echo "FAIL: manifest present but missing config/layers or sub-manifests" >&2
head -c 400 "$body" >&2 || true
exit 2
