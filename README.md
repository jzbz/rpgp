# rPGP

[![CI](https://github.com/jzbz/rpgp/actions/workflows/ci.yml/badge.svg)](https://github.com/jzbz/rpgp/actions/workflows/ci.yml)

An OpenPGP certificate manager for Linux and macOS, in the spirit of KDE's
Kleopatra: a window that lists your certificates and lets you generate, import,
export, sign, encrypt, decrypt and verify without touching a command line.

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
| `libwayland` | `winit` | Loaded at runtime on a Wayland session. |

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

The graph is rebuilt on every store reload rather than cached, which is fine
for the sizes tested and will need revisiting for a keyring of thousands.

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

A **revocation certificate** is now written at key generation, to
`$XDG_DATA_HOME/rpgp/revocations/<fingerprint>.rev`, and can be exported from
the details pane. It is the way back if the secret key or its passphrase is
lost: applying it needs neither, because it was signed while the key was in
hand. It cannot be recreated afterwards, which is why it is written once, at
the only moment the key is certainly available.

One timing wrinkle worth knowing. A revocation only supersedes a certification
made *strictly earlier*, and OpenPGP timestamps have one-second granularity, so
certifying and immediately changing your mind would otherwise leave the
certification standing. `revoke_certification` dates the revocation one second
past the certification it retracts — which means it takes effect a second
later, and the status bar says so.

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

Publishing cannot be undone — a keyserver has no delete — so the dialog says so
and uses the same danger styling as revocation. Only the public half is ever
sent, and no local certification goes with it: `publish` serialises the
certificate rather than the transferable secret key, and uses `export_to_vec`,
which omits signatures marked non-exportable. A test asserts on the upload body
itself, parsing it back to check both properties.

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

Secret keys do **not** go there — cert-d is a store of public certificates, and
a transferable secret key in it would be readable by every tool that scans the
directory. They live in their own directory, one binary TSK per file:

    $XDG_DATA_HOME/rpgp/secrets/<fingerprint>.pgp

Those files are `0600` in a `0700` directory, tightened every time the store is
opened rather than only when a key is written, so a store created by an earlier
build is repaired rather than left exposed. A key generated with a passphrase is
encrypted with it. A key generated **without** one is not, and then the file
permissions are all that protects it.

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

**macOS.** Only `RLIMIT_CORE` is set, and that has not been tested on macOS.
There is no equivalent of the non-dumpable flag, so a debugger run by the same
user can still attach to a running rPGP and read key material out of it. The
supported answer is codesigning the release with the hardened runtime and
without the `get-task-allow` entitlement — not done yet. Until it is, assume the
macOS build offers none of this paragraph.

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
