# winget

Manifests for the Microsoft winget community repository. They do not live here
in any operational sense — winget reads them from `microsoft/winget-pkgs` — but
the first submission has to come from somewhere, and a security tool's package
metadata is worth writing deliberately rather than generating blind.

## What ships

A release carries two Windows files: the bare `rpgp-vX.Y.Z-x86_64.exe`, which is
the whole program, and `rpgp-vX.Y.Z-x86_64-setup.exe`, a per-user Inno Setup
installer that release.yml builds around that same exe (`packaging/windows/`).
From the release after 0.1.3, winget installs the second one, as
`InstallerType: inno` with `Scope: user`. It asks for no administrator rights,
puts rpgp.exe in `%LOCALAPPDATA%\Programs\rPGP`, and adds rPGP to the Start
Menu and to Apps & Features. `winget uninstall` runs its uninstaller, which
takes all of that away again provided rPGP is closed first, and leaves the keys
where they are either way. With rPGP still running, the uninstaller also leaves
rpgp.exe and its folder behind, to be deleted by hand once rPGP is closed
(`packaging/windows/README.md`). The bare exe is still on every release for
whoever downloads it directly; winget simply no longer installs it.

Up to 0.1.3 winget installed the bare exe as `InstallerType: portable`: it
copied the file and registered `rpgp` as a command. That gave no Start Menu
entry, and nothing in winget can give a portable package one. No manifest schema
from 1.6 to 1.28 has a field for a shortcut, winget's own code creates none, and
the request for it (microsoft/winget-cli#2299) has been open since 2022. The
entry has to come from an installer, and an installer is also what removes it
on uninstall.

The `rpgp` command comes with it in a different form. `Commands: [rpgp]` was what
made winget register the portable package's alias; for an installer winget does
nothing with it beyond search, so it stays in the manifest for that. The setup
exe registers an App Paths entry for `rpgp.exe` under HKCU instead, which is
what Win+R and `start rpgp` look up from a normal, not elevated, Run box or
prompt. It does not put `rpgp` on PATH, and a terminal that runs plain `rpgp`
will not find it.

From then on the manifest lists only the installer. Keeping the portable entry
beside it would have let existing users go on upgrading without the step below,
still with no Start Menu entry and without knowing it was missing, and left two
ways of installing one package to support indefinitely; winget can move nobody
from one to the other except by hand either way.

## Moving from the portable package

Every winget install of 0.1.3 or earlier is the portable package, and winget
will not upgrade a portable install to an installer. `winget upgrade jzbz.rPGP`
refuses, saying the install technology is different and that the package has to
be uninstalled and installed again; since winget 1.29.280 (1.29.160 in preview)
it ends with error 0x8A15008E, and `winget upgrade --all` counts it among the
packages it could not upgrade, where older winget skips it without a word.
Neither `--force` nor `--uninstall-previous` gets past that check. So, by hand,
once, with rPGP closed, since a running rpgp.exe cannot be deleted:

    winget uninstall jzbz.rPGP
    winget install jzbz.rPGP

The keys are not touched. Uninstalling the portable package removes the exe
winget copied, the `rpgp` command and winget's own entry for it, and nothing
else: certificates live in `%APPDATA%\pgp.cert.d` and secret keys in
`%LOCALAPPDATA%\rpgp`, outside anything winget or the installer owns, and the
rPGP that the second command installs opens them as they were.

Running the setup exe by hand on top of a winget portable install is the one
thing not to do. It leaves two copies, with the Start Menu pointing at one, the
`rpgp` command at the other, and winget still tracking the old one.

## The identifier

`jzbz.rPGP`. The first submission went in as `rPGP.rPGP`, naming the project
rather than the account, and winget's moderators asked for `jzbz.rPGP` instead:
the publisher segment is the account that publishes, and it keeps the package
apart from the unrelated `rpgp/rpgp` OpenPGP library. The identifier is
effectively permanent once a version is merged, since changing it later means a
new package and an orphaned old one that silently stops updating, so it changed
before the first merge rather than after. In winget-pkgs the manifests live at
`manifests/j/jzbz/rPGP/<version>/`.

## The order matters

winget validation downloads the asset and checks its hash, so **the GitHub release
must be published, not a draft**. release.yml deliberately creates a draft, so the
winget step comes after the release is complete and public — after the signature
over SHA256SUMS, not before.

## Submitting

By hand, per release, and deliberately so — see below. From any machine, once the
release is published (Komac is Rust and runs on Linux), with one URL, the setup
exe's, and a dry run first:

    komac update jzbz.rPGP --version 0.1.4 \
      --urls https://github.com/jzbz/rpgp/releases/download/v0.1.4/rpgp-v0.1.4-x86_64-setup.exe \
      --dry-run

Komac downloads the installer, reads what it needs from it, computes the hash
and fills the schema; with `--submit` in place of `--dry-run` it then forks
`microsoft/winget-pkgs` and opens the pull request. Use `komac new` instead of
`update` for a package winget has never seen. The Microsoft CLA is a one-time
checkbox on that PR.

Not every Komac can do this one. The setup exe is built by Inno Setup 7, and
Komac 2.16.0, the latest release as of 2026-10-02, reads Inno installers through
the `inno` crate 0.4.2, which refuses anything newer than Inno Setup 6.7. Support
for 7 came in `inno` 0.6.0, which Komac's main branch already uses; 0.6.0 reads
this installer's privileges as lowest, which Komac turns into `Scope: user`, and
its ProductCode as `jzbz.rPGP_is1`. 2.16.0's `update` also keeps the previous
manifest's `InstallerType` when that was `portable`, so it would have filed the
setup exe as a portable package even if it could read it. Use a Komac newer
than 2.16.0, or one built from its main branch.

The first manifest after the change has to read as follows, in whatever order
Komac writes it; the dry run shows it:

- one installer, `Architecture: x64`, and `InstallerType: inno`, with no
  `portable` left anywhere, at the top of the file or under the installer;
- `Scope: user`, and no `ElevationRequirement`, since the installer never asks
  for one;
- `ProductCode: jzbz.rPGP_is1`, which is `AppId` in `packaging/windows/rpgp.iss`
  with the `_is1` Inno adds, and how winget recognises the installed copy;
- `InstallerUrl` the setup exe, and `InstallerSha256` the setup exe's line in the
  release's signed `SHA256SUMS`, checked as below;
- `Commands: [rpgp]` and `UpgradeBehavior: install`, both kept;
- if Komac writes them, `AppsAndFeaturesEntries` naming `rPGP`, publisher
  `Jonathan Zeppettini`, the version being submitted and the same ProductCode,
  and `InstallationMetadata` with
  `DefaultInstallLocation: '%LocalAppData%\Programs\rPGP'`.

If the dry run shows anything else, run it again with `--output <dir>` in place
of `--dry-run`, correct the manifests there by hand, and send that directory
with `komac submit <dir>`, which submits manifests as they stand and analyses
no installer. Expect the pull request to get the bot's
`Manifest-Metadata-Consistency` label for the change of installer type, for a
moderator to clear.

The hash comes from the signed file, not from Komac. In a directory holding the
release's `SHA256SUMS` and `SHA256SUMS.asc`:

    gpg --verify SHA256SUMS.asc SHA256SUMS
    awk '$2 == "rpgp-v0.1.4-x86_64-setup.exe" { print toupper($1) }' SHA256SUMS

The first has to report a good signature from
`252B 901C 8885 3CF9 F939  2559 2497 38C8 641C 3359`; the second prints the value
`InstallerSha256` must equal, in the upper case Komac writes. The setup exe's
line is the one that matters to winget. The installed rpgp.exe is the bare
exe's bytes exactly, which release.yml checks by installing the setup on its
runner, so the bare exe's line vouches for what ends up on disk as well.

`manifest/` here holds what was actually submitted, for review before it is sent
and as the starting point for the next version. Until the next submission that is
still 0.1.3's portable manifest; replace it with what goes in. Keep
`InstallerSha256` in step with the release's signed `SHA256SUMS` rather than
recomputing it: pinning the hash that signature covers is the only thread
connecting a winget install back to key 249738C8641C3359.

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

That is not an argument against winget. winget does give what it downloads a
Mark-of-the-Web, marked as from the Internet the way a browser marks it, but
once the file matches the manifest's hash and the source is a trusted one, as
the community repository is, it rewrites the mark to the Trusted zone before
running the installer, so the unsigned setup exe starts without a SmartScreen
prompt. That makes it the least unpleasant way to get unsigned code onto a
Windows machine, and strictly better than the browser download it replaces. The
exception is Smart App Control: on a Windows 11 machine where it is enforcing,
unsigned code from an unknown publisher is blocked whatever the mark says,
through winget or not. What all this is an argument for is keeping the signed
checksum file prominent in the README: it is the artefact that survives a
compromise of any of the above, and it lets anyone audit a packager's hash line
years later.
