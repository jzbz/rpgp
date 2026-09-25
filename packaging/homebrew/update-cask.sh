#!/bin/sh
# Emit the cask for a published release, with the real hash filled in.
#
#   ./packaging/homebrew/update-cask.sh v0.1.2 > ~/zx/dev/homebrew-tap/Casks/rpgp.rb
#
# Run after the release is published, its SHA256SUMS signed and the notarised
# macOS zip attached — the hash has to be of the artifact users will actually
# download, which is the stapled one, not the zip CI produced.
#
# No cask comes out until SHA256SUMS.asc is a good signature by the release key
# over SHA256SUMS and the zip's line in that file matches the download. So this
# needs gpg with the release key's public half already in its keyring, as it is
# on the machine holding the key. It imports nothing and fetches no key; on any
# other machine, import the key the way the top-level README.md's "Verifying a
# download" says and check its fingerprint first.
#
# By hand rather than from CI: updating the tap from here would need a token
# with write access to another repository, and a two-line change once a release
# does not justify holding one. The tap is a git repo; commit and push it.
set -eu

# The release key, in full: the one key whose signature over SHA256SUMS counts.
# A 16-digit key ID is short enough to forge.
SIGNER=252B901C88853CF9F9392559249738C8641C3359

TAG="${1:-}"
[ -n "$TAG" ] || { echo "usage: $0 <tag>   e.g. $0 v0.1.2" >&2; exit 1; }
case "$TAG" in v*) ;; *) echo "error: tag should start with v, got '$TAG'" >&2; exit 1 ;; esac
VERSION="${TAG#v}"

BASE="https://github.com/jzbz/rpgp/releases/download/$TAG"
NAME="rpgp-$TAG-macos-universal.zip"

if ! command -v gpg >/dev/null 2>&1; then
    echo "error: gpg not found. No cask is written without checking SHA256SUMS.asc," >&2
    echo "  which needs gpg with key $SIGNER in its keyring." >&2
    exit 1
fi

DIR=$(mktemp -d) || exit 1
trap 'rm -rf "$DIR"' EXIT

# Every file is required, and a failed download stops the run. A check that is
# skipped when SHA256SUMS or its signature will not download is one that anyone
# able to delete a release asset can turn off.
fetch() {
    echo "fetching $BASE/$1" >&2
    if ! curl -sSLf --max-time "$2" -o "$DIR/$1" "$BASE/$1"; then
        echo "error: could not download $BASE/$1" >&2
        echo "  The zip, SHA256SUMS and SHA256SUMS.asc are all required, and a" >&2
        echo "  draft release's assets are not public — publish it first." >&2
        exit 1
    fi
}

fetch SHA256SUMS 60
fetch SHA256SUMS.asc 60

# Signature first, sums second, the order the top-level README.md gives anyone
# checking a download, but judged from gpg's status lines: its exit status and
# its "Good signature" hold for a good signature by any key in the keyring.
# Exactly one GOODSIG, none of BADSIG, ERRSIG, EXPSIG, EXPKEYSIG or REVKEYSIG,
# and one VALIDSIG whose last field is the release key's fingerprint. That
# field names the primary key even when a subkey made the signature, so a
# signing subkey added later still passes. --no-auto-key-retrieve and
# --no-auto-key-import hold gpg to the keyring as it stands, whatever gpg.conf
# says: a key the signature names or carries is neither fetched nor imported.
gpg --batch --no-auto-key-retrieve --no-auto-key-import --status-fd 1 \
    --verify "$DIR/SHA256SUMS.asc" "$DIR/SHA256SUMS" \
    >"$DIR/status" 2>"$DIR/gpg.log" || true
if ! awk -v fpr="$SIGNER" '
        $1 != "[GNUPG:]" { next }
        $2 == "GOODSIG" { good++ }
        $2 == "BADSIG" || $2 == "ERRSIG" || $2 == "EXPSIG" ||
            $2 == "EXPKEYSIG" || $2 == "REVKEYSIG" { bad++ }
        $2 == "VALIDSIG" { valid++; if ($NF == fpr) ours++ }
        END { exit !(good == 1 && bad == 0 && valid == 1 && ours == 1) }
    ' "$DIR/status"; then
    echo "error: SHA256SUMS.asc is not one good signature over SHA256SUMS by" >&2
    echo "  $SIGNER. gpg reported:" >&2
    sed 's/^/  /' "$DIR/gpg.log" >&2
    grep -E '^\[GNUPG:\] (GOODSIG|BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|VALIDSIG) ' \
        "$DIR/status" | sed 's/^/  /' >&2 || true
    # ERRSIG's rc 9 is a missing key, and its last field the fingerprint of the
    # key that made the signature. Only a hint: the verdict is already given.
    if awk -v fpr="$SIGNER" '$1 == "[GNUPG:]" && $2 == "ERRSIG" && $8 == 9 &&
            $NF == fpr { found = 1 } END { exit !found }' "$DIR/status"; then
        echo "  The release key is not in this keyring, and this fetches no key:" >&2
        echo "  import it as the top-level README.md's \"Verifying a download\"" >&2
        echo "  says, check its fingerprint, and run this again." >&2
    fi
    exit 1
fi
echo "  SHA256SUMS signed by $SIGNER" >&2

fetch "$NAME" 300

# sha256sum on Linux, shasum on macOS: this runs on whichever machine is to hand.
if command -v sha256sum >/dev/null 2>&1; then
    SUM=$(sha256sum "$DIR/$NAME" | awk '{print $1}')
else
    SUM=$(shasum -a 256 "$DIR/$NAME" | awk '{print $1}')
fi
echo "  sha256 $SUM" >&2

# The zip's line from the SHA256SUMS just verified — the same bytes, not a second
# download — so a corrupted or substituted zip cannot quietly become the cask's
# pinned hash. This is the one place the project's own signing discipline can
# reach a Homebrew user at all; the cask itself carries no signature. Exactly one
# line, or no cask: the zip's name carries the tag, so a signed SHA256SUMS lifted
# from another release has no line for it, and reading a missing line as nothing
# to compare would let that swap through.
WANT=$(awk -v n="$NAME" '$2 == n || $2 == "*" n { c++; h = $1 }
    END { if (c == 1) print h }' "$DIR/SHA256SUMS")
if [ -z "$WANT" ]; then
    echo "error: the signed SHA256SUMS does not list $NAME exactly once" >&2
    exit 1
fi
if [ "$WANT" != "$SUM" ]; then
    echo "error: hash does not match the signed SHA256SUMS for $NAME" >&2
    echo "  downloaded: $SUM" >&2
    echo "  SHA256SUMS: $WANT" >&2
    exit 1
fi
echo "  matches the signed SHA256SUMS" >&2

sed -e "s/^  version \".*\"$/  version \"$VERSION\"/" \
    -e "s/^  sha256 \".*\"$/  sha256 \"$SUM\"/" \
    "$(dirname "$0")/rpgp.rb"
