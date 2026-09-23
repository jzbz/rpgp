# rPGP

[![CI](https://github.com/jzbz/rpgp/actions/workflows/ci.yml/badge.svg)](https://github.com/jzbz/rpgp/actions/workflows/ci.yml)

An OpenPGP certificate manager for Linux, macOS and Windows, in the spirit of
KDE's Kleopatra: a window that lists your certificates and lets you generate,
import, export, sign, encrypt, decrypt and verify without touching a command
line.

Rust throughout, Slint for the GUI, Sequoia for the OpenPGP implementation. No
webview, no Qt, no C++, no `gpg` subprocess.

**Status: feature-complete against Kleopatra's common workflows, and young.**
Generating, importing, exporting, certifying, revoking, looking up, publishing,
and signing, encrypting, decrypting and verifying both files and text all work
from the window — including on a smartcard. Nothing here has been used in anger
by anyone but its author.

## Layout

| Crate | Contents |
| --- | --- |
| `crates/rpgp-core` | Certificate store, key generation, encrypt/decrypt/sign/verify, certification, web-of-trust, revocation and key lifecycle. No GUI types. |
| `crates/rpgp-gui` | Slint front end. Binary is `rpgp`. |

The GUI depends only on `rpgp-core`'s own types — no `sequoia_openpgp` type
reaches a Slint callback — so the OpenPGP layer stays replaceable.

Inside `crates/rpgp-gui/ui`:

| File | Contents |
| --- | --- |
| `theme.slint` | Colour, spacing and type tokens, plus the icon paths. |
| `widgets.slint` | Buttons, fields, pills, dialogs — the app's own controls. |
| `dialogs.slint` | New key pair, Sign / Encrypt, Decrypt / Verify, Certify, Revoke, Lifecycle, Lookup, Details, Notepad, About. |
| `app-window.slint` | The shell that assembles them. |
| `types.slint` | Structs shared with Rust. |

## Look and feel

The app follows the system light/dark setting but not the system *widget
style*: Slint would otherwise give macOS `cupertino` controls and Linux
`fluent` ones, which reads as two different products. `build.rs` pins the
style, so the only platform character left is the window frame, the UI font
and the scrollbars.

Everything else is drawn by the design system in `theme.slint` and
`widgets.slint`. Only `ListView` comes from std-widgets, for virtualised
scrolling. Icons are [Lucide](https://lucide.dev/) SVGs, vendored under
`ui/icons` and recoloured through `Image`'s `colorize`, so one file serves
every tone in both themes.

Long operations run on a worker thread and report back through the event loop,
so generating an RSA-4096 key does not freeze the window.

## Build and run

Needs the Cap'n Proto compiler (`capnp`) installed.

```bash
cargo run -p rpgp-gui
```

```bash
cargo test --workspace
```

Some tests are `#[ignore]`d because they need the network, a smartcard, or a
PIN prompt. Run them with `-- --ignored`.

To try the app with content in it, seed a throwaway store. It writes only
inside the `XDG_DATA_HOME` you give it:

```bash
XDG_DATA_HOME=/tmp/rpgp-demo cargo run -p rpgp-core --example seed-demo-store && XDG_DATA_HOME=/tmp/rpgp-demo cargo run -p rpgp-gui
```

## Installing

A [release](https://github.com/jzbz/rpgp/releases) carries a Flatpak bundle for
`x86_64` and `aarch64`, a universal `.app` for macOS, and one self-contained
`.exe` for Windows. The macOS bundle is signed with a Developer ID and notarised
by Apple, so it opens on first launch rather than having to be talked past
Gatekeeper; the Windows executable is not signed, so SmartScreen warns on first
run and then lets you through.

```bash
brew install --cask jzbz/tap/rpgp                  # macOS, from the tap
flatpak install ./rpgp-*.flatpak                   # Linux, from the bundle
winget install rPGP.rPGP                           # Windows
```

The cask lives in `github.com/jzbz/homebrew-tap`, a tap of this project's own;
`packaging/homebrew/README.md` says why that rather than homebrew-cask. Whatever
the route, the signed `SHA256SUMS` on the release is worth checking first.

## Verifying a download

A [release](https://github.com/jzbz/rpgp/releases) carries the Flatpak bundles,
a `SHA256SUMS` listing them, and a `SHA256SUMS.asc` signing that list. Fetch the
signing key once, from GitHub:

```bash
curl -sL https://github.com/jzbz.gpg | gpg --import
```

or from a keyserver, which is the better of the two — it does not come from the
same host as the release:

```bash
gpg --locate-keys jz@jz.bz
```

Either way the fingerprint below is what to trust, not where you got it. Then
check the signature before the files:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS && sha256sum -c --ignore-missing SHA256SUMS
```

`gpg --verify` has to report a *Good signature* from
`252B 901C 8885 3CF9 F939  2559 2497 38C8 641C 3359`; any other key, or none, and
the rest is meaningless. `--ignore-missing` checks whichever bundle you actually
downloaded and stays quiet about the other architecture.

A freshly imported key also draws *"WARNING: This key is not certified with a
trusted signature"*. That is expected and is not a failed check: it says the key
carries no web-of-trust path from anything you already trust, which a key you
just fetched never does. The signature is still good. Compare the fingerprint
gpg prints against the one above and move on, or sign the key locally
(`gpg --lsign-key jz@jz.bz`) to silence it on later releases.

The order is the whole point. `SHA256SUMS` sits in the same release as the files
it describes, so by itself it catches a truncated download and nothing else —
anyone able to replace a bundle could replace the list beside it just as easily.
The signature is what turns it into a check, and it is made by hand: the key
never goes near CI, so a compromised workflow can publish a bundle but cannot
sign for one.

None of which needs `gpg`, incidentally. Import the signing key into rPGP, open
**Decrypt / Verify**, give it `SHA256SUMS.asc`, and it will ask for the file that
goes with it. Circular for the download you have not verified yet, and perfectly
sound for every release after that.

## Stack decisions

### GUI: Slint on winit, rendering through wgpu

`slint` is pulled in with `default-features = false`, because two of its
defaults are unwanted. `backend-default` compiles in the Qt backend whenever
`qmake` is on the build machine's `PATH` and then *prefers it at runtime*, so a
default build renders through Qt on one developer's machine and winit on
another. And `renderer-femtovg` is FemtoVG over OpenGL, which is deprecated on
macOS; `renderer-femtovg-wgpu` is the same renderer over Vulkan and Metal.
`renderer-skia` is never enabled — it needs a C++ toolchain.

A machine with no usable GPU falls back to the software renderer
automatically. Slint left alone would abort instead; how that is handled, and
two approaches that do not work, are documented above `configure_renderer` in
`main.rs`.

### OpenPGP: Sequoia with the RustCrypto backend

`sequoia-openpgp` defaults to Nettle (C). This build selects `crypto-rust`,
which demands two explicit opt-ins — `allow-experimental-crypto`, because the
backend is not one of Sequoia's mature ones, and `allow-variable-time-crypto`,
because it does not guarantee constant-time operation everywhere.

Both are real warnings rather than paperwork: this build is more exposed to
timing side channels than a Nettle or OpenSSL build. On a desktop where an
attacker is not co-resident that is an acceptable trade for a single-language
build. It would not be on a shared host.

`compression-bzip2` is off, as it links C bzip2. The cost is that
BZip2-compressed messages cannot be read; nothing modern produces them.

### What is *not* pure Rust

| Library | Via | Why |
| --- | --- | --- |
| `libsqlite3` | `sequoia-cert-store` → `rusqlite` | cert-d keeps a SQLite index for lookup by e-mail and subkey. Not optional in that crate. |
| `fontconfig` | `i-slint-core` | System font discovery on Linux. |
| `libwayland` | `winit`, `smithay-clipboard` | Loaded at runtime on a Wayland session. |

Building also needs the Cap'n Proto compiler (`capnp`), for `sequoia-ipc`.

## Certifying and trust

Two different questions get asked about a certificate, and rPGP shows both
because confusing them is how people end up trusting the wrong key:

- **Validity** — is the certificate internally sound? Self-signatures check
  out, not expired, not revoked. This is the `valid` / `expired` / `revoked`
  pill, and it says nothing about who the certificate belongs to.
- **Authentication** — does the name on it belong to the person you think? This
  is the `verified` / `partly verified` pill, computed by `sequoia-wot` from the
  certifications in the store. A perfectly valid certificate from a stranger is
  unauthenticated, and a key you confirmed years ago stays authenticated after
  it expires.

Certifying is done from a certificate's details pane. A certification always
names one *user ID* — OpenPGP has no way to vouch for a certificate as a whole
— so the dialog lists them and you tick the ones you actually checked. The
options map onto OpenPGP as follows:

| Dialog | What it writes |
| --- | --- |
| Confidence: Full / Partial | trust amount 120 / 60; anything but Full becomes a trust signature |
| Publishable | an exportable certification, shareable and included in exports |
| *(unticked)* | a local certification, never written out by `export_file` |
| Trusted introducer | a trust signature of depth 1: keys *they* certify count here too |

Trust roots are where authentication starts. Every key you **generate here** is
a root automatically — the alternative is a fresh install where nothing
authenticates until the user finds a checkbox — and any other certificate can be
marked one by hand from its details pane.

A secret key that arrives by **import** is deliberately not a root. Holding the
secret half is what the rule used to test, and importing is how someone else's
key can satisfy it: a file containing a keypair *they* generated would otherwise
buy them a trust root in your store, and with it a `verified` badge on whatever
identities that key had certified. The key still works for decrypting and
signing — it simply does not vouch for anyone until you say so. Restoring your
own backup is the same story: tick Trust root once, and it stays.

The graph is rebuilt on every store reload rather than cached. At five thousand
certificates that rebuild is about 53ms of a 127ms read — a caching layer would
have to be invalidated by every certification, revocation and trust-root change,
and taking the read off the event loop was the cheaper answer to the same
complaint. A keyring well past that size will still want the cache.

## Encrypting with a password

A message can be encrypted to certificates, to passwords, or to both at once —
the session key is wrapped separately for each, so any one of them opens it.
Encrypting to a password alone is what `gpg -c` produces, and rPGP now reads
that too: the decryption helper tries the supplied passphrase against the
symmetric envelopes before concluding a message was not meant for us.

That is one field doing two jobs on the way in and two on the way out. In Sign
/ Encrypt the passphrase that unlocks *your signing key* and the password that
*anyone* will need are deliberately separate fields, because confusing them
would hand out the wrong secret.

Reading such a message costs whatever its sender decided it should. The packet
names the password-hashing parameters, and Argon2's are a memory size and a
pass count that the recipient pays once for every (envelope × candidate
password) — before the password is checked, so a wrong guess costs as much as a
right one. rPGP spends at most what RFC 9580's own recommended parameters ask
for: 2 GiB hashed once per attempt, and four such attempts for the whole
message however many envelopes it carries or encryption layers it nests. An
envelope priced above that is passed over, and if nothing else opens the
message the failure says so rather than reporting a wrong password, because
from the outside the two look identical. Nothing in ordinary use comes near the
limit: GnuPG and the library rPGP is built on both hash passwords with iterated
SHA-256, whose cost its own encoding already bounds.

## Revocation

Revocation is one-way and public: the signature becomes part of the certificate,
and anyone who already has a copy keeps it forever. Three separate things can be
retracted, and the UI keeps them apart:

- **Your own key**, from its details pane. Pick a reason and optionally leave a
  note. Choosing *secret key may be compromised* makes it a **hard** revocation,
  which also invalidates signatures the key made in the past — including every
  certification it ever issued, so anyone it had authenticated drops back to
  unverified.
- **A certification you made**, without touching the other person's key. Only
  your endorsement is withdrawn.
- **Someone else's key**, by importing the revocation certificate they
  published. The Import button takes it: a revocation is a bare signature rather
  than a certificate, so it falls through `CertParser` to `apply_revocation_file`.

A revoked certificate is then refused for anything **new**: encrypting to it,
signing with it, certifying it or vouching with it, changing its expiry, adding
a user ID. Soft reasons are refused alongside hard ones, because *replaced by a
newer key* still says the owner has stopped using this one. Two things are
deliberately left out of that. Reading is one — a revoked key still opens what
it was sent, and whether its old signatures still verify is the reason's
business rather than the refusal's, a soft revocation leaving them standing
where a hard one does not, exactly as the first bullet above says. Withdrawing
a certification is the other: taking back what a key already said is not new
use of it, so it does not go through the refusal at all. The refusal needs a
check of its own because Sequoia's per-key filters cannot express it:
`revoked(false)` asks a *subkey* about its own revocation, and revoking a
certificate as a whole leaves its subkeys unmarked.

That second exemption preserves only what already worked. The key signing the
withdrawal still has to be one the certificate offers for certification, and
`revoked(false)` asked of the *primary* key does consult the certificate — so a
key generated here, which certifies with its primary and has no certification
subkey, cannot withdraw its certifications once it has been revoked: the attempt
reports that there is no usable secret key. What survives is the shape that
filter does not catch, a certification *subkey*, held locally or on a card.
**Withdraw first, revoke second**, therefore — and the order matters most
after a soft revocation, where every certification the key made still stands
and withdrawing them is the only remedy there is.

The list says the same thing rather than something of its own. The capability
letters on a row — `C`, `S`, `E` — are what this app will *do* with the
certificate, not an inventory of the flags on its keys, so a revoked
certificate shows none of them and the recipient, signer and certifier pickers
never offer it. The same rule is why a certificate you accept SHA-1 from shows
none either: that acceptance is for checking signatures, and every operation
judges the certificate strictly.

A **revocation certificate** is now written at key generation, to
`$XDG_DATA_HOME/rpgp/revocations/<fingerprint>.rev`, and can be exported from
the details pane. It is the way back if the secret key or its passphrase is
lost: applying it needs neither, because it was signed while the key was in
hand. It cannot be recreated afterwards, which is why it is written once, at
the only moment the key is certainly available. If that write fails, on a full
disk say, the key is kept all the same and the status line says it has no
revocation certificate; the details pane then offers none to export, and the
key can still be revoked from there for as long as you hold it and its
passphrase.

One timing rule runs through all of this. OpenPGP gives the newest signature of
a kind the last word — a key's expiry is read off its newest self-signature, a
soft revocation stands only until a newer one, a certification counts until
the same certifier makes a newer certification or withdrawal — and its
timestamps have one-second granularity. So every signature rPGP makes to
replace another is dated at least a second after the newest one it replaces:
an expiry change, a revocation of a key, a subkey or a user ID, a
certification, a withdrawal. Where that one was made in the current second, as
it is when you certify and immediately change your mind, the operation waits
for the next second rather than dating its signature ahead of the clock, so the
change counts as soon as the status bar reports it. Where it is dated more than
a few seconds ahead, a clock is wrong — this machine's, or the one that made
it — and the operation is refused with that signature's date, rather than
signing something that would count nowhere until then, or never at all. A hard
revocation is the exception: nothing dated after one undoes it, so it is never
held up.

A user ID you retire can be brought back: adding the same name again binds it
anew, and the newer binding supersedes the retirement. Anyone holding a copy of
the key from between the two still sees it retired.

## Smartcards and YubiKeys

Card keys are reached **through the user's `gpg-agent`**, not by talking to the
reader. That is not a preference: `scdaemon` holds the card with an exclusive
PC/SC transaction, so a second process asking the reader directly gets
`SCARD_E_SHARING_VIOLATION`. It is why Kleopatra goes through gpg-agent too.

Two things follow, both good. **rPGP never sees a PIN** — the agent runs the
user's own `pinentry`. And there is no PC/SC dependency.

Signing, certifying and decrypting all work on a card. Where the agent puts its
prompt is the agent's business: `sequoia-gpg-agent` builds those options from
`GPG_TTY`, `TERM` and `DISPLAY` when a crypto operation opens its connection.
The connection that only lists keys deliberately sets none, for the reason in
the note above `connect` in `agent.rs`.

## Keyservers

Lookup tries the Web Key Directory before a keyserver, and publishing uploads
to `keys.openpgp.org`. `RPGP_KEYSERVER` overrides the server, for an internal
one or for testing against a local stand-in rather than uploading to public
infrastructure.

An internal keyserver's certificate usually comes from the organisation's own
CA, and that works wherever the CA is in the **operating system's certificate
store**, where curl and gpg look for it too. A server's certificate is checked
against Mozilla's roots, compiled in, and against the system's anchors beside
them: the distribution's CA bundle and certificate directories on Linux, the
certificates the user, administrator and system trust settings mark as trusted
on macOS, and the Trusted Root Certification Authorities store as the current
user sees it on Windows. Only the anchors come from the system. The check is
rustls's own, so the system opens no connection for revocation data, or for
anything else, that the network guard described below would not see. The store
is read once, at the first lookup or upload, so a CA installed or removed while
rPGP is running takes effect at its next start, and one removed stays trusted
until then.

`SSL_CERT_FILE`, a file of PEM certificates, and `SSL_CERT_DIR`, directories of
them separated as in `PATH`, replace the system store when either is set, on
every platform. Mozilla's roots stay either way, so `SSL_CERT_FILE` naming a
private CA alone trusts that CA and the public roots, and nothing else.

The cost is trusting whatever the store holds. On a managed network that
inspects TLS, the inspecting CA is in the store: lookups there work where they
used to fail, and that CA can read and rewrite what a WKD host or a keyserver
sends, as it already can for curl and gpg on the same machine. Where that is not
wanted, pointing `SSL_CERT_FILE` at a file holding only the CAs you mean to
trust, or an empty one, leaves the rest of the store out.

The Flatpak sees none of the host's store. Its `/etc/ssl` and `/etc/pki` are the
freedesktop runtime's own, holding that runtime's copy of Mozilla's roots and
nothing added on the host; the runtime hands the host's trust on through
p11-kit, but only to software that asks p11-kit for it, and rPGP reads the PEM
files instead. A private CA reaches the Flatpak through `SSL_CERT_FILE`, from a
place the sandbox can read:

```bash
mkdir -p ~/.var/app/app.rpgp.rpgp/config
cp corp-ca.pem ~/.var/app/app.rpgp.rpgp/config/
flatpak override --user \
  --env=SSL_CERT_FILE=$HOME/.var/app/app.rpgp.rpgp/config/corp-ca.pem \
  app.rpgp.rpgp
```

What a WKD host serves is kept only where it **carries the address that was
asked for**, and only that identity is kept on it — both are requirements of
the specification, and neither was applied. A domain serving
`alice@evil.example` could answer with `Bob <bob@bank.example>`, and the result
was listed as coming from the web key directory, which is the strongest
provenance this app shows; an import then stored every user ID on it, and the
certify dialog offers those pre-ticked. Which of the two WKD URLs is fetched is
decided by whether `openpgpkey.<domain>` **resolves**, not by trying the
delegated host and moving on when it does not answer with a key: a 404 there is
an answer, and treating it as a failure handed every unpublished address at a
delegating domain to whoever runs the apex web site. A domain that wildcards
its DNS and publishes by the direct method loses WKD by this rule, which the
specification puts on the site; the lookup falls through to the keyserver as it
does for any address with no WKD key.

A keyserver reply is held to the weaker half of the same rule: it must be an
answer to the question. `RPGP_KEYSERVER` may name any HKP server, verifying or
not, and a fingerprint query answered with an unrelated certificate used to be
listed as found. A certificate answers for a fingerprint or key ID only where
it is that certificate's own primary key or a subkey it has signed for, since
appending a key packet to somebody else's certificate takes no signature at
all. What this cannot settle is whose a properly bound subkey is, as two
certificates may bind one key. A free-text name search is left as the server
returned it.

A lookup is the least trusted fetch the app makes: a WKD URL is built from the
domain half of whatever address was typed, and a redirect names whatever the
server chooses. So neither is allowed to reach this machine or its network. An
address written as an address is refused before a URL is built, and a *name* is
resolved by a guard that hands reqwest only the addresses it approved — which
also means no second DNS answer can arrive between the check and the connection.
Without this, `alice@127.0.0.1:8080` was a port probe and `evil.example` with an
A record of 127.0.0.1 was the same probe wearing a name.

"This machine or its network" is loopback, RFC1918, link-local and the rest of
the usual list, and also shared address space, 100.64.0.0/10: a carrier's NAT
puts the subscriber's own network there, and so does Tailscale, whose tailnet
addresses were refused on the IPv6 side as unique-local and not refused at all
on the IPv4 side. An IPv6 address that carries an IPv4 one inside it is judged
by the address inside — IPv4-mapped, the well-known NAT64 prefix, 6to4 and
Teredo — while local-use NAT64 and site-local are refused outright. Proxy
environment variables are ignored, for the same reason: `HTTPS_PROXY` would put
the target name in a `CONNECT` line for the proxy to resolve on the far side,
which is the guard switched off, and it broke ordinary lookups besides, since a
proxy named by a host that resolves privately was itself refused.

The server named by `RPGP_KEYSERVER` is the one exception, because an internal
keyserver is precisely a name that resolves to a private address and that is
what the variable is for. It is exempt only on the fetches this app aims at it,
and the exemption is decided from a hostname, because a hostname is all a
resolver is handed. So a WKD address whose domain happens to be that host does
not inherit it, nor does a redirect naming that host from anywhere else; on the
keyserver's own fetches a redirect to another port on that host is refused in
the redirect policy, which is the one place the port is visible. Nothing else is
exempt, including a redirect away from that server.

Publishing cannot be undone — a keyserver has no delete — so the dialog says so,
names the key it is about to upload, and uses the same danger styling as
revocation. Only your own keys are offered, and the upload refuses any other.
Only the public half is ever sent, and no local certification goes with it:
`publish` serialises the certificate rather than the transferable secret key,
and uses `export_to_vec`, which omits signatures marked non-exportable. A test
asserts on the upload body itself, parsing it back to check both properties.

## Where outputs go

Sign / Encrypt and Decrypt put their output beside the input: `notes.txt` is
encrypted to `notes.txt.asc` or signed as `notes.txt.sig`, and `notes.txt.asc`
decrypts to `notes.txt`. A file already at that name is never overwritten: the
output steps aside to the next free name, `notes (1).txt` for a decrypted
`notes.txt`.

The Flatpak asks instead. Run opens a save dialog with that name filled in, and
the output goes wherever you choose there. The sandbox is given only the files
you pick in the desktop's file chooser, and the portal standing between it and
your files keeps anything else written beside one of them to itself: it reaches
your disk only as a hidden `.xdp-` file, never under the name you would look
for.

While an encrypt or decrypt runs, its output is written to a `.part` file
beside it and renamed into place only once it is complete, so one that fails
leaves nothing behind, and a file you chose to replace stays as it was. One cut
off before it can clear up, by a crash or by closing the window while it runs,
can leave its `.part` file behind, as a hidden `.xdp-` file in the Flatpak;
after a decrypt that file holds the plaintext written so far, and it can be
deleted. On Linux and macOS a decrypted file can be read by you alone: it is
`0600` from the moment it is created, whatever your umask. On Windows it takes
the permissions of the folder it lands in, as any new file does. Encrypted
files and signatures are meant to be passed on, so they get the permissions any
new file of yours gets.

## Where certificates live

Public certificates go in a [pgp-cert-d][certd] directory, the same layout `sq`
uses, so they are shared with other Sequoia tooling rather than locked in this
app:

    $XDG_DATA_HOME/pgp.cert.d          (override with RPGP_CERT_STORE)

That sharing is a property of a native build. The Flatpak keeps its store inside
`~/.var/app/app.rpgp.rpgp/data` and shares it with nothing: `XDG_DATA_HOME`
points into the sandbox there, and Flathub does not grant access to the real one
without an exception. Point `RPGP_CERT_STORE` at a path both can reach if you
want one store across both.

Every time the list is read, at Refresh and after each change made here, each
certificate in it is checked against its file, so a certificate that `sq` or a
second rPGP window has changed or deleted there shows up as it now is.

Secret keys do **not** go there — cert-d is a store of public certificates, and
a transferable secret key in it would be readable by every tool that scans the
directory. They live in their own directory, one binary TSK per file:

    $XDG_DATA_HOME/rpgp/secrets/<fingerprint>.pgp

Those files are `0600` in a `0700` directory, tightened every time the store is
opened rather than only when a key is written, so a store created by an earlier
build is repaired rather than left exposed. The `rpgp` directory above it, which
holds the revocation certificates and the lists of trust roots, of imported keys
and of certificates you accept SHA-1 from, is `0700` too. A key generated with a
passphrase is encrypted with it. A key generated **without** one is not, and
then the file permissions are all that protects it.

Two rPGP windows can share one store. Each change to a key or a list is made
under a lock file in the `rpgp` directory, so the two take turns rather than
undo each other's changes, and each file is replaced whole, so a crash or a full
disk part-way through leaves the previous version rather than a damaged one.

[certd]: https://www.ietf.org/archive/id/draft-nwjw-openpgp-cert-d-02.html

## What protects a key in memory

A key is decrypted for the span of a single operation and then dropped. Sequoia
keeps it sealed in RAM even while it is unlocked, and zeroes it on drop, so a
partial read of the process — the class of attack Spectre and coldboot fall
into — yields nothing useful.

That sealing does not survive a *complete* read of the address space, because
the key it is sealed with lives in that same space. What rPGP does about that
differs by platform, and the gap is wide enough to spell out:

**Linux.** The process is marked non-dumpable. That suppresses the core dump and
also revokes `ptrace`, including from another process of the same user, so `gdb`
will not attach and a crash leaves nothing in `coredumpctl`.

**macOS.** `RLIMIT_CORE` is set, though that half has not been tested — the
hardening tests are Linux-only. There is no equivalent of the non-dumpable flag,
so debugger attach is denied at signing time rather than by the process itself:
the released bundle is codesigned with the hardened runtime and no entitlements
file, so it carries no `get-task-allow` and `task_for_pid` fails for a debugger
run by the same user. `packaging/macos-sign.sh` is what applies it. A macOS
binary you built yourself is unsigned and gets none of that — assume a debugger
can attach to that one.

Keeping passphrases off the accessibility bus is not platform-specific and
applies to both. The bus publishes the contents of an ordinary text field
verbatim and does not exempt password fields.

Set `RPGP_ALLOW_DEBUG=1` to turn off the core-dump and debugger restrictions
when you need a backtrace.

None of this is a privilege boundary. Key material passes through the GUI
process, so root, or anything holding `CAP_SYS_PTRACE`, can still read it while
an operation is in flight — and the passphrase you type cannot be scrubbed at
all, because Slint's own string type keeps unzeroed copies, including an undo
buffer. Only the smartcard path avoids this entirely, by never seeing the key.

## Coming from GnuPG

rPGP does not read `~/.gnupg`, and nothing it does will disturb it. Public certificates need no export at all: point Import at
`~/.gnupg/pubring.kbx`. Secret keys still need exporting, since GnuPG keeps
them in gpg-agent's own format:

```bash
gpg --export --armor > /tmp/rpgp-public.asc && gpg --export-secret-keys --armor > /tmp/rpgp-secret.asc
```

Import both with the Import button. Public certificates land in cert-d and
secret keys in the secrets directory; a file containing both is handled in one
pass.

Three caveats:

- **This copies secret key material.** The keys then exist twice, under two
  different protections: gpg-agent's, and rPGP's weaker on-disk one. Delete
  `/tmp/rpgp-secret.asc` afterwards, and understand that rPGP's copy is only as
  safe as the passphrase on it.
- **Smartcard keys cannot come across.** `--export-secret-keys` emits a stub for
  a key that lives on a YubiKey. Those need the gpg-agent route below.
- **Ownertrust does not come across.** rPGP has no trust model yet, so
  `--export-ownertrust` has nowhere to go.

Reading `~/.gnupg` in place is possible but not built:

- `pubring.kbx` **can be imported directly.** It is GnuPG's Keybox container
  rather than an OpenPGP keyring, so `CertParser` cannot read it, but
  `sequoia-ipc`'s `keybox` module can. Point Import at it — the file is
  recognised by its magic bytes rather than its name — and every public
  certificate comes across. X.509 records in the same file are skipped.
- Secret keys under `private-keys-v1.d` are in gpg-agent's own S-expression
  format, not OpenPGP. The only sound way to use them is to ask gpg-agent, via
  `sequoia-keystore`'s gpg-agent backend — which would also solve smartcards and
  would mean rPGP never holds key material at all.
- A pre-2.1 `~/.gnupg/pubring.gpg` *is* a plain OpenPGP keyring and imports
  as-is today.

## Licence

MIT — see [LICENSE](LICENSE).

Two dependencies add obligations MIT does not, both relevant only when
shipping binaries: Slint's royalty-free terms require the attribution in the
About box, and `sequoia-openpgp` is LGPL-2.0-or-later linked statically.

The bundled fonts (Geo, Source Code Pro) are SIL Open Font License 1.1, which
requires its text to ship with them; it sits beside them in
`crates/rpgp-gui/ui/fonts`. Icons are Lucide, ISC, likewise.
