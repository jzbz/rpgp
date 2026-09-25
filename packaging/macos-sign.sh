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
# Takes the unsigned zip CI produced (or an unpacked rPGP.app), signs,
# notarises and staples the bundle, zips it again, and checks that new zip the
# way a stranger's Mac will check it. Only once every check has passed does it
# replace CI's zip, under the same name: the name the draft release, SHA256SUMS
# and the Homebrew cask all expect. Until then the input is left exactly as it
# was, so a run that fails can simply be run again. An rPGP.app gives rPGP.zip
# beside it.
#
# One-time setup on this machine — see the block printed by --setup.
set -eu

PROFILE="${RPGP_NOTARY_PROFILE:-rpgp-notary}"

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

# Run a command, indent what it says, and KEEP ITS EXIT STATUS.
#
# `cmd | sed` reports sed's status, not cmd's, so `set -e` never sees a failure
# and an `|| die` after it is unreachable. That is not hypothetical: the first
# real run of this script had codesign fail with errSecInternalComponent, print
# "code object is not signed at all", and carry on to spend four minutes
# notarising an unsigned bundle before Apple rejected it.
run() {
    _out=$("$@" 2>&1); _rc=$?
    [ -n "$_out" ] && printf '%s\n' "$_out" | sed 's/^/  /'
    return $_rc
}

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

   Renewing is making a new certificate, from a new CSR, and the old one stays
   valid until it expires. Leave it to expire: revoking it would stop every
   copy it signed from launching. Until then this Mac holds two identities
   under the same name, and the script stops rather than pick one. Choose the
   newer (Keychain Access shows each certificate's expiry date, and its SHA-1
   under Fingerprints) and name it by the 40-digit hash that find-identity
   prints beside it:

       RPGP_SIGN_IDENTITY=<SHA-1> ./packaging/macos-sign.sh <zip>

   RPGP_SIGN_IDENTITY takes that hash or the identity's whole name, and only
   ever a Developer ID Application identity.

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

# The identity is picked by its certificate's SHA-1, and codesign is handed
# that hash, never a name. A Developer ID Application certificate is not
# renewed in place: the new one comes from a new CSR, the old one stays valid
# until it expires, and both carry the same name, "Developer ID Application:
# <name> (<TEAMID>)". codesign refuses a name that matches two identities, and
# no name can tell those two apart; a hash can. So where more than one would
# do, this stops and lists them rather than guess, before anything is unpacked.
#
# find-identity -v lists the valid identities whose private key is on this
# Mac, one per line:
#
#   1) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID Application: ..."
#
# The same certificate in two keychains can be listed twice, which codesign
# treats as harmless. So does this: DEVIDS holds one "HASH NAME" line per
# distinct certificate, and only Developer ID Application ones, which is what
# keeps an Apple Development or Apple Distribution certificate out whichever
# way it is named.
IDENTITIES=$(security find-identity -v -p codesigning 2>&1) \
    || die "security find-identity failed:
$(printf '%s\n' "$IDENTITIES" | sed 's/^/    /')"
DEVIDS=$(printf '%s\n' "$IDENTITIES" \
    | sed -n 's/^ *[0-9][0-9]*) \([0-9A-Fa-f]\{40\}\) "\(Developer ID Application: .*\)"$/\1 \2/p' \
    | awk '{ print toupper(substr($0, 1, 40)) substr($0, 41) }' | sort -u)

# RPGP_SIGN_IDENTITY narrows the choice: forty hex digits are a SHA-1, as they
# are to codesign, and anything else has to be an identity's whole name.
# Keychain Access shows a SHA-1 in pairs, "3E 1F 5A ...", so spaces, and the
# colons other tools put there, are left out when looking for one.
WANT="${RPGP_SIGN_IDENTITY:-}"
HEX=$(printf '%s' "$WANT" | tr -d ' :')
if [ -z "$WANT" ]; then
    MATCHES=$DEVIDS
elif [ ${#HEX} -eq 40 ] && [ -z "$(printf '%s' "$HEX" | tr -d '0-9A-Fa-f')" ]; then
    WANT=$(printf '%s' "$HEX" | tr 'a-f' 'A-F')
    MATCHES=$(printf '%s\n' "$DEVIDS" \
        | WANT="$WANT" awk 'substr($0, 1, 40) == ENVIRON["WANT"]')
else
    MATCHES=$(printf '%s\n' "$DEVIDS" \
        | WANT="$WANT" awk 'substr($0, 42) == ENVIRON["WANT"]')
fi

case $(printf '%s' "$MATCHES" | awk 'END { print NR }') in
    1)
        IDENTITY=${MATCHES%% *}
        IDENTITY_NAME=${MATCHES#* }
        ;;
    0)
        [ -z "$WANT" ] || die "RPGP_SIGN_IDENTITY names no Developer ID Application identity on this Mac:
    '$RPGP_SIGN_IDENTITY'
  It takes the SHA-1, or the whole name, of an identity whose name starts
  'Developer ID Application: '. Found:
$(printf '%s\n' "$IDENTITIES" | sed 's/^/    /')
  Apple Development and Apple Distribution certificates are for other purposes
  and notarisation will reject a bundle signed with one."
        die "no 'Developer ID Application' identity in the keychain.
  Found instead:
$(printf '%s\n' "$IDENTITIES" | sed 's/^/    /')
  Run '$0 --setup' for what this needs."
        ;;
    *)
        die "more than one Developer ID Application identity would do, and this will not
  guess between them:
$(printf '%s\n' "$MATCHES" | sed 's/^/    /')
  A renewed certificate leaves two until the old one expires. Choose the newer
  (Keychain Access shows each one's expiry date, and its SHA-1 under
  Fingerprints) and run this again with its hash:

      RPGP_SIGN_IDENTITY=<SHA-1> $0 $INPUT"
        ;;
esac
echo "  identity:  $IDENTITY_NAME"
echo "             SHA-1 $IDENTITY"

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
# PARTIAL is the new zip before it has passed its checks; see Re-packing.
PARTIAL=
trap 'rm -rf "$WORK"; [ -z "$PARTIAL" ] || rm -f "$PARTIAL"' EXIT

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
#
# The keychain advice on failure is for errSecInternalComponent alone. Given
# for every failure, it pointed one with another cause, a timestamp server that
# did not answer or a certificate name that matched two identities, at the
# command that wants the login password on the command line. codesign's own
# message is printed either way.
step "Signing"
if ! run codesign --sign "$IDENTITY" \
                  --force --timestamp --options runtime \
                  --verbose "$APP"; then
    case "$_out" in
        *errSecInternalComponent*) ;;
        *) die "codesign failed; what it said is above." ;;
    esac
    die "codesign failed.

  errSecInternalComponent almost always means codesign could not use the
  private key without asking, and could not ask: over SSH there is no way to
  show the keychain's 'allow access' prompt. Two ways round it —

    1. Run this from Terminal ON the Mac, once. macOS asks whether codesign may
       use the key; choose 'Always Allow'. Afterwards SSH runs work too.

    2. Or authorise it without the prompt, which needs your login password on
       the command line:

           security set-key-partition-list -S apple-tool:,apple:,codesign: \\
             -s -k '<login password>' ~/Library/Keychains/login.keychain-db"
fi

run codesign --verify --deep --strict --verbose=2 "$APP" \
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
run xcrun stapler staple "$APP" || die "stapling failed"

# The order matters and is the step most often missed: the zip that ships has
# to be made AFTER stapling. Re-using the submission zip ships an unstapled app.
#
# Made under a hidden name beside where it is going, and moved there only
# once every check below has passed. For CI's zip that place is the input
# itself, so writing straight to it would destroy the input before anything
# was known about the result, and leave a rejected zip under the name the
# release expects. Beside it rather than in $WORK so that the move is a rename
# within one volume: the zip under the shipping name is only ever the old one
# or the whole new one.
step "Re-packing"
FINAL="$OUTDIR/$BASE.zip"
PARTIAL="$OUTDIR/.$BASE.zip.partial"
rm -f "$PARTIAL"
ditto -c -k --keepParent "$APP" "$PARTIAL" || die "could not write $PARTIAL"

# ------------------------------------------------------------------- verify
# The checks a stranger's Mac will make, run here so a bad bundle is caught now
# rather than by the first person to download it. They run on the zip that
# will ship, unpacked afresh, not on the bundle it was made from, so a re-pack
# that lost the ticket or broke the seal is caught too. Each one stops the run
# through run(), because a check piped straight into sed has its failure
# swallowed like any other; and when one does, the input has not been touched.
#
# spctl's exit status alone is not enough: on a Mac where Gatekeeper
# assessments have been turned off it accepts anything, with an override where
# the source would be. So its verdict has to name the source as well,
# "Notarized Developer ID". Neither says the ticket is in the bundle, since
# online Gatekeeper fetches it from Apple instead; stapler validate is the
# check for that, which is why it has to be able to stop the run too.
step "Verifying the zip that will ship"
mkdir "$WORK/check"
ditto -x -k "$PARTIAL" "$WORK/check" || die "could not unpack $PARTIAL"
SHIP="$WORK/check/$(basename "$APP")"
[ -d "$SHIP" ] || die "$PARTIAL does not hold $(basename "$APP")"
KEPT="Nothing was written to $FINAL."

echo "  --- stapler validate (is the ticket actually in the bundle?) ---"
run xcrun stapler validate "$SHIP" \
    || die "the zip that would ship has no valid stapled ticket.
  $KEPT"
echo "  --- codesign (is the seal intact, including nested content?) ---"
run codesign --verify --deep --strict --verbose=2 "$SHIP" \
    || die "the signature in the zip that would ship does not verify.
  $KEPT"
echo "  --- spctl (what Gatekeeper decides) ---"
run spctl -a -vvv -t exec "$SHIP" \
    || die "Gatekeeper rejects the bundle — do not ship this.
  $KEPT"
case "$_out" in
    *"source=Notarized Developer ID"*) ;;
    *) die "Gatekeeper let the bundle through, but not as notarised Developer ID;
  what it said instead is above. Do not ship this.
  $KEPT" ;;
esac

mv -f "$PARTIAL" "$FINAL" || die "could not move $PARTIAL to $FINAL"
PARTIAL=

printf '\n'
printf 'done: %s\n' "$FINAL"
printf '  shasum: %s\n' "$(shasum -a 256 "$FINAL" | awk '{print $1}')"
printf '\nVerify it elsewhere before shipping — on a Mac that has never held the\n'
printf 'signing key, quarantine it the way a download would and open it:\n\n'
# shellcheck disable=SC2016  # deliberately literal: this is text to paste, not to run here
printf '  xattr -w com.apple.quarantine "0083;00000000;Safari;$(uuidgen)" rPGP.app\n'
printf '  spctl -a -vvv -t exec rPGP.app && open rPGP.app\n'
