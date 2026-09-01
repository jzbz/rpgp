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

## Submitting

By hand, per release, and deliberately so — see below. From any machine, once the
release is published (Komac is Rust and runs on Linux):

    komac update rPGP.rPGP --version 0.1.3 \
      --urls https://github.com/jzbz/rpgp/releases/download/v0.1.3/rpgp-v0.1.3-x86_64.exe \
      --submit

Komac computes the hash, fills the schema, forks `microsoft/winget-pkgs` and opens
the pull request. Use `komac new` instead of `update` for a package winget has
never seen. The Microsoft CLA is a one-time checkbox on that PR.

`manifest/` here holds what was actually submitted, for review before it is sent
and as the starting point for the next version. Keep `InstallerSha256` in step
with the release's signed `SHA256SUMS` rather than recomputing it: pinning the
hash that signature covers is the only thread connecting a winget install back to
key 249738C8641C3359.

## Why there is no workflow for this

There was one, and it never ran. `winget.yml` fired on every published release,
found no `WINGET_PAT`, skipped itself and reported success — three releases across
this project and Azzurro, each with a green check for having done nothing.

Setting the token would have been worse than leaving it unset. The job called a
third-party action and would have handed it that credential, which is the one
thing `ci.yml` opens by saying this project does not do: a third-party action runs
with the same access to the workflow as anything else in it. On a project about
handling secret keys that is not a footnote, and the workflow was a trap primed to
spring the day somebody decided to finish the automation.

So the submission is a command, run by a person, from the machine that already
holds the signing keys. At this release cadence that is a smaller cost than a
credential in CI, and it puts the person who signed the checksums in the same
place as the person who pins the hash.

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
