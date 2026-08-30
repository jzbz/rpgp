#!/bin/sh
# Sign, notarise and staple the macOS bundle, on the machine that holds the key.
#
# CI builds rPGP.app and stops there: the Developer ID key is not on the runner
# and is not going to be. That is not caution for its own sake. A leaked
# Developer ID key cannot be quietly rotated — Apple does not let you revoke one
# from the account portal (it is an email to product-security@apple.com), and a
# revocation stops every already-shipped copy from launching on every machine
# that has one, including correctly notarised ones. Expiry is survivable;
# revocation is not. So the key stays where the PGP key stays.
#
#   ./packaging/macos-sign.sh rpgp-v0.1.2-macos-universal.zip
#
# Takes the unsigned zip CI produced (or an unpacked rPGP.app) and leaves a
# signed, notarised, stapled zip beside it, verified the way a stranger's Mac
# will verify it.
#
# One-time setup on this machine — see the block printed by --setup.
set -eu

PROFILE="${RPGP_NOTARY_PROFILE:-rpgp-notary}"

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

if [ "${1:-}" = "--setup" ]; then
    cat <<'SETUP'
One-time setup on the signing Mac
---------------------------------

1. Developer ID Application certificate, in this Mac's keychain.

   In Keychain Access it must appear under "My Certificates" with a disclosure
   triangle — the triangle means the private key is present. Under plain
   "Certificates" with no triangle means the key is on some other machine, and
   Apple will not re-issue it; you would have to create a new certificate from
   a fresh CSR. Note the cap: five unexpired Developer ID Application
   certificates per team.

   Check what this Mac has:

       security find-identity -v -p codesigning

   You want a line reading "Developer ID Application: <name> (<TEAMID>)".
   "Apple Development" is a different certificate and will notarise-reject.

2. An App Store Connect API key, stored as a notarytool profile.

   Create it at App Store Connect > Users and Access > Integrations > App Store
   Connect API. It must be a TEAM key, not an Individual one: an Individual key
   cannot drive notarytool. Start at the Developer role. Download the .p8 once —
   Apple will not let you download it again — and note the Issuer ID and Key ID
   from the same page.

   Then store it in the keychain so nothing needs to sit in this script or in
   your shell history:

       xcrun notarytool store-credentials rpgp-notary \
         --key ~/path/to/AuthKey_XXXXXXXXXX.p8 \
         --key-id XXXXXXXXXX \
         --issuer aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

   An API key is preferred over an Apple ID plus app-specific password because
   it is a machine credential: it does not carry your account's privileges, and
   revoking it is one click that breaks nothing already shipped.

3. Nothing else. This bundle needs no entitlements file — see the comment above
   the codesign call.
SETUP
    exit 0
fi

INPUT="${1:-}"
[ -n "$INPUT" ] || die "usage: $0 <unsigned .zip | rPGP.app>   (or --setup)"
[ -e "$INPUT" ] || die "no such file: $INPUT"

command -v xcrun >/dev/null 2>&1 || die "xcrun not found — this must run on macOS with the command line tools installed"

# ---------------------------------------------------------------- preflight
# All of it before anything is modified, because the failures here are the ones
# that otherwise surface ten minutes into a notarisation wait.
step "Preflight"

IDENTITY="${RPGP_SIGN_IDENTITY:-}"
if [ -z "$IDENTITY" ]; then
    IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null \
        | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -1)
fi
[ -n "$IDENTITY" ] || die "no 'Developer ID Application' identity in the keychain.
  Found instead:
$(security find-identity -v -p codesigning 2>&1 | sed 's/^/    /')
  Run '$0 --setup' for what this needs."

case "$IDENTITY" in
    "Developer ID Application: "*) ;;
    *) die "'$IDENTITY' is not a Developer ID Application certificate.
  Apple Development and Apple Distribution certificates are for other purposes
  and notarisation will reject a bundle signed with one." ;;
esac
echo "  identity:  $IDENTITY"

xcrun notarytool history --keychain-profile "$PROFILE" >/dev/null 2>&1 \
    || die "notarytool profile '$PROFILE' is missing or its credentials are rejected.
  Run '$0 --setup' for how to create it, or set RPGP_NOTARY_PROFILE."
echo "  notary:    profile '$PROFILE' authenticates"

# The login keychain unlocks with the password at console login and stays locked
# in an SSH session, so this is the normal state when signing remotely. Checked
# here rather than left to codesign, which fails partway through with an error
# about the identity rather than about the lock.
if ! security show-keychain-info 2>&1 | grep -qi "no-timeout\|timeout"; then
    die "the login keychain is locked, so codesign cannot reach the private key.
  Unlock it and run this again:

      security unlock-keychain

  This is the usual state over SSH: the keychain unlocks with your password
  when you log in at the console, not when you connect remotely."
fi
echo "  keychain:  unlocked"

# ------------------------------------------------------------------- unpack
WORK=$(mktemp -d) || die "could not create a working directory"
trap 'rm -rf "$WORK"' EXIT

case "$INPUT" in
    *.zip)
        step "Unpacking $INPUT"
        # ditto, not unzip: it is the only extractor that restores a bundle's
        # metadata faithfully, and it is what Archive Utility uses.
        ditto -x -k "$INPUT" "$WORK" || die "could not unpack $INPUT"
        APP=$(find "$WORK" -maxdepth 1 -name '*.app' | head -1)
        [ -n "$APP" ] || die "no .app inside $INPUT"
        OUTDIR=$(cd "$(dirname "$INPUT")" && pwd)
        BASE=$(basename "$INPUT" .zip)
        ;;
    *.app)
        APP="$WORK/$(basename "$INPUT")"
        cp -R "$INPUT" "$APP" || die "could not copy $INPUT"
        OUTDIR=$(cd "$(dirname "$INPUT")" && pwd)
        BASE=$(basename "$INPUT" .app)
        ;;
    *) die "expected a .zip or a .app, got: $INPUT" ;;
esac
echo "  bundle:    $(basename "$APP")"
echo "  arches:    $(lipo -archs "$APP/Contents/MacOS/rpgp" 2>/dev/null || echo '?')"

# Anything the download picked up would be sealed into the signature.
xattr -cr "$APP"

# --------------------------------------------------------------------- sign
# One invocation, and deliberately no --deep. Apple deprecates --deep for
# signing: it applies one identity and one set of options to whatever it finds,
# which is the wrong model. Nested code is meant to be signed inside-out, first.
# This bundle has none — Contents/ holds the binary, the .icns and Info.plist,
# and every library the binary links is a system framework — so a single call is
# the whole job. (--deep IS still correct for verifying, below.)
#
# --options runtime enables the hardened runtime, which notarisation requires.
# --timestamp gets a secure timestamp from Apple, which is what keeps already
# shipped copies working after the certificate expires.
#
# No --entitlements. Every entitlement weakens the hardened runtime and this app
# needs none: it does not JIT (wgpu talks to Metal, which compiles shaders out
# of process), it loads no third-party libraries into itself, and it is not
# sandboxed. allow-jit, allow-unsigned-executable-memory and
# disable-library-validation are all cargo-cult here, and the middle one would
# be a poor thing to put on a program that holds secret keys.
step "Signing"
codesign --sign "$IDENTITY" \
         --force --timestamp --options runtime \
         --verbose "$APP" 2>&1 | sed 's/^/  /'

codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | sed 's/^/  /' \
    || die "the signature did not verify immediately after signing"

# ----------------------------------------------------------------- notarise
# The zip submitted here is scaffolding, never the artifact that ships: the
# ticket is stapled into the .app afterwards, so this zip is already stale by
# the time notarisation returns.
step "Notarising (this usually takes a few minutes)"
SUBMIT="$WORK/submit.zip"
ditto -c -k --keepParent "$APP" "$SUBMIT"

set +e
OUT=$(xcrun notarytool submit "$SUBMIT" --keychain-profile "$PROFILE" --wait 2>&1)
RC=$?
set -e
echo "$OUT" | sed 's/^/  /'

ID=$(echo "$OUT" | sed -n 's/.*id: \([0-9a-f-][0-9a-f-]*\).*/\1/p' | head -1)
if [ $RC -ne 0 ] || ! echo "$OUT" | grep -q "status: Accepted"; then
    if [ -n "$ID" ]; then
        step "Notarisation log for $ID"
        xcrun notarytool log "$ID" --keychain-profile "$PROFILE" 2>&1 | sed 's/^/  /'
    fi
    die "notarisation did not return Accepted — see the log above"
fi

# ------------------------------------------------------------------- staple
# The .app, never the zip: stapling an archive is not a weaker form of
# stapling, it is unsupported. The ticket is keyed by cdhash rather than by
# container, which is why stapling the bundle works after submitting a zip of
# it, and why a universal binary gets an entry per architecture.
#
# Stapling is what makes the app open on a Mac that is offline or that cannot
# reach Apple: without it Gatekeeper has to ask, and a machine behind a captive
# portal or a firewall gets the same refusal as an unsigned build.
step "Stapling the ticket into the bundle"
xcrun stapler staple "$APP" 2>&1 | sed 's/^/  /'

# The order matters and is the step most often missed: the zip that ships has
# to be made AFTER stapling. Re-using the submission zip ships an unstapled app.
step "Re-packing"
FINAL="$OUTDIR/${BASE%-unsigned}.zip"
rm -f "$FINAL"
ditto -c -k --keepParent "$APP" "$FINAL"

# ------------------------------------------------------------------- verify
# The checks a stranger's Mac will make, run here so a bad bundle is caught now
# rather than by the first person to download it.
step "Verifying"
echo "  --- stapler validate (is the ticket actually in the bundle?) ---"
xcrun stapler validate "$APP" 2>&1 | sed 's/^/    /'
echo "  --- codesign (is the seal intact, including nested content?) ---"
codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | sed 's/^/    /'
echo "  --- spctl (what Gatekeeper decides) ---"
spctl -a -vvv -t exec "$APP" 2>&1 | sed 's/^/    /'

if ! spctl -a -t exec "$APP" >/dev/null 2>&1; then
    die "Gatekeeper still rejects the bundle — do not ship this"
fi

printf '\n'
printf 'done: %s\n' "$FINAL"
printf '  shasum: %s\n' "$(shasum -a 256 "$FINAL" | awk '{print $1}')"
printf '\nVerify it elsewhere before shipping — on a Mac that has never held the\n'
printf 'signing key, quarantine it the way a download would and open it:\n\n'
# shellcheck disable=SC2016  # deliberately literal: this is text to paste, not to run here
printf '  xattr -w com.apple.quarantine "0083;00000000;Safari;$(uuidgen)" rPGP.app\n'
printf '  spctl -a -vvv -t exec rPGP.app && open rPGP.app\n'
