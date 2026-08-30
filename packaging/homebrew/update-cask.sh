#!/bin/sh
# Emit the cask for a published release, with the real hash filled in.
#
#   ./packaging/homebrew/update-cask.sh v0.1.2 > ~/homebrew-rpgp/Casks/rpgp.rb
#
# Run after the release is published and the notarised macOS zip is attached —
# the hash has to be of the artifact users will actually download, which is the
# stapled one, not the zip CI produced.
#
# By hand rather than from CI: updating the tap from here would need a token
# with write access to another repository, and a two-line change once a release
# does not justify holding one. The tap is a git repo; commit and push it.
set -eu

TAG="${1:-}"
[ -n "$TAG" ] || { echo "usage: $0 <tag>   e.g. $0 v0.1.2" >&2; exit 1; }
case "$TAG" in v*) ;; *) echo "error: tag should start with v, got '$TAG'" >&2; exit 1 ;; esac
VERSION="${TAG#v}"

URL="https://github.com/jzbz/rpgp/releases/download/$TAG/rpgp-$TAG-macos-universal.zip"

echo "fetching $URL" >&2
TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT
if ! curl -sSLf --max-time 300 -o "$TMP" "$URL"; then
    echo "error: could not download $URL" >&2
    echo "  A draft release's assets are not public — publish it first." >&2
    exit 1
fi

# sha256sum on Linux, shasum on macOS: this runs on whichever machine is to hand.
if command -v sha256sum >/dev/null 2>&1; then
    SUM=$(sha256sum "$TMP" | awk '{print $1}')
else
    SUM=$(shasum -a 256 "$TMP" | awk '{print $1}')
fi
echo "  sha256 $SUM" >&2

# Cross-check against the release's own signed checksum file where it exists, so
# a corrupted or substituted download cannot quietly become the cask's pinned
# hash. This is the one place the project's own signing discipline can reach a
# Homebrew user at all — the cask itself carries no signature.
SUMS_URL="https://github.com/jzbz/rpgp/releases/download/$TAG/SHA256SUMS"
if curl -sSLf --max-time 60 "$SUMS_URL" -o "$TMP.sums" 2>/dev/null; then
    NAME="rpgp-$TAG-macos-universal.zip"
    WANT=$(awk -v n="$NAME" '$2 == n || $2 == "*" n {print $1}' "$TMP.sums" | head -1)
    rm -f "$TMP.sums"
    if [ -n "$WANT" ] && [ "$WANT" != "$SUM" ]; then
        echo "error: hash does not match SHA256SUMS for $NAME" >&2
        echo "  downloaded: $SUM" >&2
        echo "  SHA256SUMS: $WANT" >&2
        exit 1
    fi
    [ -n "$WANT" ] && echo "  matches SHA256SUMS" >&2
fi

sed -e "s/^  version \".*\"$/  version \"$VERSION\"/" \
    -e "s/^  sha256 \".*\"$/  sha256 \"$SUM\"/" \
    "$(dirname "$0")/rpgp.rb"
