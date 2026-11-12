#!/bin/sh
# Build with real metadata; this script never creates a tag or publishes.
set -eu

if [ "$#" -gt 2 ]; then
    echo 'Usage: sh scripts/build-release.sh [VERSION] [OUTPUT]' >&2
    exit 2
fi
release_version=${1:-0.1.0-rc.1}
output=${2:-bin/veyl}
if ! printf '%s\n' "$release_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then
    echo 'Version must be a numeric release or release candidate, without a leading v.' >&2
    exit 2
fi

# Resolve the checkout itself, not an unrelated caller-provided environment SHA.
commit=$(git rev-parse --verify HEAD 2>/dev/null) || commit=unknown
built=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
package=github.com/poizdev/veyl/internal/app
mkdir -p -- "$(dirname -- "$output")"
go build -buildvcs=false -trimpath \
    -ldflags "-X $package.version=$release_version -X $package.buildCommit=$commit -X $package.buildDate=$built" \
    -o "$output" ./cmd/veyl
