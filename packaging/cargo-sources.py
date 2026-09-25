#!/usr/bin/env python3
"""Generate cargo-sources.json for the Flatpak build from Cargo.lock.

Flathub builds without network access, so every crate has to be declared as a
source up front. Cargo.lock already records the sha256 of each .crate file, so
this needs nothing but the lockfile — no downloads, and nothing to trust beyond
what cargo already verifies on every build.

Only crates.io packages are written as sources, and anything else in the
lockfile is an error naming it: a git dependency, a git [patch] or a crate from
another registry. Left out, or written as a crates.io archive, any of them
would fail the offline build much later, in `cargo --offline fetch`, with
nothing there to say that this script is why.

    python3 packaging/cargo-sources.py > packaging/cargo-sources.json
"""

import json
import sys
import tomllib
from pathlib import Path

CRATES_IO = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
# How Cargo.lock names crates.io, whichever protocol fetched the index. It is
# the only source the config below redirects to the vendored crates.
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
# Where the build expects the vendored registry to appear.
VENDOR = "cargo/vendor"


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    lock = tomllib.loads((root / "Cargo.lock").read_text())

    sources = []
    vendored = {}
    unsupported = []
    for package in lock["package"]:
        name, version = package["name"], package["version"]
        source = package.get("source")
        if source is None:
            # No source means a path dependency: the workspace's own crates,
            # which arrive with the git source rather than from the registry.
            continue
        if source != CRATES_IO_SOURCE:
            # A git source has no .crate at static.crates.io and no checksum
            # in the lockfile, and another registry's crates are not what the
            # config below replaces.
            unsupported.append(f"  {name} {version}, from {source}")
            continue
        checksum = package.get("checksum")
        if checksum is None:
            unsupported.append(f"  {name} {version}, from crates.io with no checksum")
            continue
        sources.append(
            {
                "type": "archive",
                "archive-type": "tar-gzip",
                "url": CRATES_IO.format(name=name, version=version),
                "sha256": checksum,
                "dest": f"{VENDOR}/{name}-{version}",
            }
        )
        vendored[f"{name}-{version}"] = {"package": checksum, "files": {}}

    if unsupported:
        print(
            "cargo-sources.py: Cargo.lock has packages this cannot vendor for the Flatpak:",
            *unsupported,
            "Only crates.io packages are written as sources. A git or other-registry",
            "source needs a source entry of its own and a [source] replacement in the",
            "cargo config written here, the way flatpak-cargo-generator writes them.",
            sep="\n",
            file=sys.stderr,
        )
        return 1

    # cargo needs a .cargo-checksum.json beside each vendored crate, and a
    # config telling it to use the directory instead of the network.
    for entry, meta in vendored.items():
        sources.append(
            {
                "type": "inline",
                "contents": json.dumps(meta),
                "dest": f"{VENDOR}/{entry}",
                "dest-filename": ".cargo-checksum.json",
            }
        )

    config = (
        "[source.crates-io]\n"
        'replace-with = "vendored-sources"\n\n'
        "[source.vendored-sources]\n"
        f'directory = "{VENDOR}"\n'
    )
    sources.append(
        {
            "type": "inline",
            "contents": config,
            "dest": "cargo",
            "dest-filename": "config.toml",
        }
    )

    json.dump(sources, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
