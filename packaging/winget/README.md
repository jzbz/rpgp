# winget

Manifests for the Microsoft winget community repository. They do not live here
in any operational sense — winget reads them from `microsoft/winget-pkgs` — but
the first submission has to come from somewhere, and a security tool's package
metadata is worth writing deliberately rather than generating blind.

## What ships

The Windows artifact is a single `.exe` with no installer, so `InstallerType` is
`portable`: winget copies it onto a PATH directory and registers an alias. That
is why `Commands: [rpgp]` matters more than it looks. winget picks the alias in
this order — manifest `Commands[0]`, the `--rename` argument, `PortableCommandAlias`
(archives only), then the file's own name. Without the `Commands` entry the alias
becomes the asset name, `rpgp-v0.1.2-x86_64`, and it would change every release.

Portable also means no Start Menu entry. That is the trade for shipping one file.

## The order matters

winget validation downloads the asset and checks its hash, so **the GitHub release
must be published, not a draft**. release.yml deliberately creates a draft, so the
winget step comes after the release is complete and public — after the signature
over SHA256SUMS, not before.

## First submission

Once v0.1.2 is published, from any machine (Komac is Rust and runs on Linux):

    komac new rPGP.rPGP \
      --urls https://github.com/jzbz/rpgp/releases/download/v0.1.2/rpgp-v0.1.2-x86_64.exe \
      --submit

Komac computes the hash, fills the schema, forks `microsoft/winget-pkgs` and opens
the pull request. The Microsoft CLA is a one-time checkbox on that PR.

`manifest/` here holds what the result should look like, for review before it is
sent and as a reference if a later version needs hand-editing.

## Later releases

Two options, and they differ in where a credential lives.

By hand, per release, from the machine that already holds the signing keys:

    komac update rPGP.rPGP --version 0.1.3 \
      --urls https://github.com/jzbz/rpgp/releases/download/v0.1.3/rpgp-v0.1.3-x86_64.exe \
      --submit

Or automatically, via `.github/workflows/winget.yml`, which fires when a release is
published. That needs a classic personal access token with `public_repo` scope in
this repository's secrets, because the action opens a pull request against a fork
under your account. It cannot sign anything and cannot touch this repository's
contents, but it is a credential in CI, which is the thing this project otherwise
avoids — hence it is opt-in: the workflow is dispatch-only until that secret
exists, and does nothing without it.

## What a winget user actually trusts

Not the PGP signature. winget pins `InstallerSha256`, verifies it client-side, and
refuses to install on a mismatch — but nothing in that chain reads SHA256SUMS.asc
or knows about key 249738C8641C3359. A winget user is trusting Microsoft's
validation pipeline, its moderators, and TLS to GitHub.

That is not an argument against winget. `winget install` has no Mark-of-the-Web
and no SmartScreen prompt, so it is the least unpleasant way to get an unsigned
exe onto a Windows machine, and it is strictly better than the browser download it
replaces. It is an argument for keeping the signed checksum file prominent in the
README: it is the artefact that survives a compromise of any of the above, and it
lets anyone audit a packager's hash line years later.
