# Homebrew

A cask, in a tap of our own, until homebrew-cask will take it.

## Why a tap first

homebrew-cask applies a notability bar, tripled for a self-submission because
the PR author would own the project: 225 stars, 90 forks or 90 watchers, any one
of which suffices — plus a 30-day minimum repository age. A tap has none of
that. It is a git repository named `homebrew-<something>` under your account,
and `brew` finds it by name.

## What a tap does not escape

Gatekeeper. `brew` applies `com.apple.quarantine` to a cask's app on install
regardless of which tap it came from; `--no-quarantine` was removed in Homebrew
4.7 and the `quarantine` stanza no longer exists in the DSL. An unsigned app
would therefore install cleanly and then refuse to open, which is a worse
experience than not offering it at all.

So the cask is only worth publishing once `packaging/macos-sign.sh` has produced
a notarised, stapled zip. The 2026-09-01 deadline that disables unsigned casks
applies only to the main repository, not to a tap — but Gatekeeper applies
everywhere.

## The tap

`github.com/jzbz/homebrew-tap` — one tap for everything published this way,
rather than one per app. A tap is a public repository named `homebrew-<name>`
with a `Casks/` directory, and that is the whole of it: no registration, no
review, no Homebrew involvement. Nothing about it is per-project, so Azzurro's
cask sits beside this one and a third app would need no new repository at all.

    brew tap jzbz/tap
    brew install --cask rpgp

or in one step, without tapping first:

    brew install --cask jzbz/tap/rpgp

## Per release

After the release is published and the notarised zip is attached:

    ./packaging/homebrew/update-cask.sh v0.1.2 > ~/zx/dev/homebrew-tap/Casks/rpgp.rb
    cd ~/zx/dev/homebrew-tap && git commit -S -m "rpgp 0.1.2" Casks/rpgp.rb && git push

Name the file rather than reaching for `git commit -a`: the tap is shared now,
and a bump for one app has no business carrying another app's in-flight change.

The script downloads the published asset, hashes it, and — where the release
carries a SHA256SUMS — refuses to emit a cask whose hash disagrees with it. That
cross-check is the only point at which this project's signing discipline touches
a Homebrew user, because the cask itself carries no signature: a cask user
trusts the tap's git history and Apple's notary, not key 249738C8641C3359.

There is no bot. BrewTestBot autobumps casks in the official repositories only,
so a tap is a hand-written commit each release — two lines, but they are yours.

## Moving to homebrew-cask later

When the project clears the notability bar, the cask can be submitted upstream
and this one file deleted from the tap — the tap itself stays, because it holds
other apps. Users who tapped will keep working either way; `brew` prefers the
official cask once both exist, and the fully qualified `jzbz/tap/rpgp` goes on
resolving until the file is removed.
