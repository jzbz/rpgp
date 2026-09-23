//! On-disk certificate storage.
//!
//! Public certificates live in a [pgp-cert-d] directory, the same layout `sq`
//! uses, so certificates are shared with other Sequoia tooling instead of being
//! locked inside this app — in a native build. Inside a Flatpak sandbox
//! `XDG_DATA_HOME` points at the app's own directory, so the store is private
//! there unless `RPGP_CERT_STORE` says otherwise. The default location is
//! `$XDG_DATA_HOME/pgp.cert.d`; set `RPGP_CERT_STORE` to override it.
//!
//! Secret keys are *not* stored there. cert-d is a store of public
//! certificates, and mixing transferable secret keys into it would leak them to
//! every tool that reads the directory. For now they go in a separate
//! `$XDG_DATA_HOME/rpgp/secrets` directory, one binary TSK per file.
//!
//! Those files are `0600` inside a `0700` directory, tightened on every open
//! rather than only on create. A key generated with a passphrase is encrypted
//! with it; a key generated without one is not, and then the permissions are
//! the only thing protecting it — the same trade GnuPG makes. The `rpgp`
//! directory above them, which holds the revocation certificates and the
//! bookkeeping lists, is `0700` too.
//!
//! Two rPGP windows can share one store, and most of what the store writes
//! for itself is read, merged and written back. Every such write takes an
//! advisory lock beside the secrets directory first, as cert-d does for the
//! public certificates with a lock of its own; see [`StoreLock`].
//!
//! On Windows the same two properties are enforced with a DACL naming only the
//! current user, applied by the call that creates the file; see [`windows_acl`].
//! One difference is worth knowing rather than glossing: a restrictive
//! directory means less there than a `0700` directory does on Unix, because
//! "bypass traverse checking" lets anyone who knows a file's full path reach it
//! regardless of its parents. The per-file ACL is the control on Windows; the
//! directory is defence in depth.
//!
//! In use, a key is decrypted for the span of a single operation and dropped.
//! Sequoia holds it sealed in RAM even while unlocked and zeroes it on drop,
//! and on Linux the GUI process refuses core dumps and debugger attach (see
//! `rpgp-gui`'s `hardening` module; on macOS the attach half comes from the
//! hardened runtime the release is codesigned with, in
//! `packaging/macos-sign.sh`). None of that is a privilege boundary:
//! key material does pass through this process, so root — or anything holding
//! `CAP_SYS_PTRACE` — can still read it.
//!
//! `sequoia-keystore` is not the fix it appears to be, which is why this is
//! still the design. Its default IPC policy silently degrades to a thread in
//! the caller's own address space, with no API to detect that it happened;
//! and forced into a real separate process it still runs as the same user,
//! authenticates over loopback with a cookie file that user can read, and
//! exposes an RPC that hands back the secret key. Smartcards go through
//! gpg-agent instead (see [`crate::agent`]), which is a boundary that means
//! something only because the key never leaves the card.
//!
//! [pgp-cert-d]: https://www.ietf.org/archive/id/draft-nwjw-openpgp-cert-d-02.html

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sequoia_cert_store::store::StoreError;
use sequoia_cert_store::{CertStore, LazyCert, Store as _, StoreUpdate as _};
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;

use crate::error::{Error, Result};

pub struct Store {
    certs: CertStore<'static>,
    /// Kept for [`Store::reopen`] and for finding a certificate's file.
    cert_dir: PathBuf,
    secrets_dir: PathBuf,
    /// Fingerprints the user has explicitly designated as trust roots, one per
    /// line. Keys generated here are roots implicitly — see
    /// [`Store::implicit_roots`].
    roots_path: PathBuf,
    /// Revocation certificates made at key-generation time, kept against the
    /// day the secret key or its passphrase is gone.
    revocations_dir: PathBuf,
    /// Fingerprints of secret keys that arrived from outside, one per line.
    /// These are *not* implicit trust roots — see [`Store::implicit_roots`].
    imported_secrets_path: PathBuf,
    /// Fingerprints the user has allowed SHA-1 for, one per line. Kept apart
    /// from every other list here because it grants nothing: see
    /// [`Store::sha1_policy`] and the [`crate::sha1`] module.
    sha1_path: PathBuf,
    /// The file [`StoreLock`] locks. Beside the lists, so that two stores
    /// sharing those — which two secrets directories in one parent do — share
    /// the lock too.
    lock_path: PathBuf,
}

/// A certificate in the store, borrowed rather than copied.
///
/// Behaves as a `&Cert` through [`Deref`](std::ops::Deref): every method a
/// caller used on the owned `Cert` still resolves. It exists so [`Store::certs`]
/// can hand back the whole keyring without deep-copying it.
#[derive(Clone)]
pub struct CertRef(Arc<LazyCert<'static>>);

impl std::ops::Deref for CertRef {
    type Target = Cert;

    fn deref(&self) -> &Cert {
        // Infallible here: `Store::certs` resolves every LazyCert before
        // wrapping it, and `to_cert` memoises that result, so the only way to
        // hold a CertRef is to have already parsed successfully.
        self.0
            .to_cert()
            .expect("CertRef holds a LazyCert that Store::certs already resolved")
    }
}

impl std::fmt::Debug for CertRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertRef({})", self.fingerprint().to_hex())
    }
}

impl Store {
    /// Open the default store, creating both directories if they are missing.
    pub fn open_default() -> Result<Self> {
        let cert_dir = match std::env::var_os("RPGP_CERT_STORE") {
            Some(dir) => PathBuf::from(dir),
            None => dirs::data_dir()
                .ok_or(Error::NoStoreDir)?
                .join("pgp.cert.d"),
        };
        // data_local_dir, not data_dir, and only the secrets differ: on Windows
        // the two are Local and Roaming AppData respectively, and a roaming
        // profile copies its contents to a domain file server at every logon.
        // Secret key material and revocation certificates are exactly what
        // should not be replicated onto a share the user does not control.
        // Public certificates stay on data_dir, which is where other cert-d
        // tooling looks and where nothing secret lives.
        //
        // On Linux and macOS the two functions return the same path, so this
        // changes nothing there: $XDG_DATA_HOME and ~/Library/Application
        // Support respectively.
        let secrets_dir = dirs::data_local_dir()
            .ok_or(Error::NoStoreDir)?
            .join("rpgp")
            .join("secrets");
        Self::open(cert_dir, secrets_dir)
    }

    /// Open a store, creating both directories if they are missing.
    ///
    /// The directory holding `secrets_dir` is the store's as well: the
    /// revocation certificates, the bookkeeping lists and the lock live there,
    /// and it is restricted to the current user like `secrets_dir` itself. So
    /// `secrets_dir` wants a parent of its own, as [`Store::open_default`]
    /// gives it with `rpgp/secrets`, never one shared with anything else such
    /// as the home directory.
    pub fn open(cert_dir: impl AsRef<Path>, secrets_dir: impl AsRef<Path>) -> Result<Self> {
        let cert_dir = cert_dir.as_ref();
        let secrets_dir = secrets_dir.as_ref();

        fs::create_dir_all(cert_dir)
            .map_err(|e| Error::io(format!("creating {}", cert_dir.display()), e))?;
        fs::create_dir_all(secrets_dir)
            .map_err(|e| Error::io(format!("creating {}", secrets_dir.display()), e))?;

        // Held for the sweep and the repair below, so that neither meets a
        // file that a writer taking the lock is still making.
        let lock_path = secrets_dir.with_file_name("write.lock");
        let held = StoreLock::acquire(&lock_path)?;

        // The directory above the secrets. create_dir_all made it with the
        // default mode, and on a group-writable umask anyone in the group could
        // then rename a list of their own over trust-roots, or unlink
        // imported-secrets and with it the record that a stranger's key is no
        // trust root, whatever mode the files themselves had. Restricted under
        // the lock like the rest of the repair, because on Windows restricting
        // a directory carries the new ACL down to everything in it, a list
        // another window is replacing included. Of what the store keeps in it,
        // only the secrets directory, restricted below, and the lock file are
        // made before this, and the lock file holds nothing: on Unix it is
        // private from the start, and on Windows it takes the directory's ACL.
        // A bare relative name has no parent to speak of, and the current
        // directory is not this function's to lock down.
        let data_dir = secrets_dir
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(data_dir) = data_dir {
            restrict(data_dir, 0o700)?;
        }

        // Staging files a crash left behind. Swept before the repair, so that
        // one this cannot remove is still tightened with the rest.
        let revocations_dir = secrets_dir.with_file_name("revocations");
        remove_leftover_staging(&held, secrets_dir, |name| {
            name.contains(".pgp.") && name.ends_with(".tmp")
        });
        remove_leftover_staging(&held, &revocations_dir, |name| {
            name.contains(".rev.") && name.ends_with(".tmp")
        });
        if let Some(data_dir) = data_dir {
            // Matched by name, list by list: this directory is whatever the
            // caller chose, and what else is in it is not the store's.
            remove_leftover_staging(&held, data_dir, |name| {
                BOOKKEEPING.iter().any(|list| is_staging_for(name, list))
            });
        }

        // Secret key material, and the revocation certificates that could
        // retire a key, must not be world-readable. Tighten on every open, not
        // only on create: a store made by an earlier version is already
        // exposed, and the user has no way to know it.
        //
        // A file listed here can be gone by the time it is reached. Every
        // write of this store holds the lock, but an older build or a file
        // manager does not, and a file that no longer exists exposes nothing,
        // so that is no reason to refuse to open. The directories themselves
        // still have to be restricted, or the open fails.
        restrict(secrets_dir, 0o700)?;
        for path in existing_files(secrets_dir) {
            restrict_if_present(&path, 0o600)?;
        }
        // The revocations directory too, when there is one. Anyone holding a
        // revocation certificate can retire the key it belongs to, and the
        // module doc has always claimed these are tightened on open — until
        // now it was only the secrets that were.
        if revocations_dir.is_dir() {
            restrict(&revocations_dir, 0o700)?;
            for path in existing_files(&revocations_dir) {
                restrict_if_present(&path, 0o600)?;
            }
        }

        // The bookkeeping files beside the secrets directory. None holds key
        // material, but trust-roots is the list of keys this user has decided
        // to trust — anyone able to write it can make a stranger's certificate
        // authenticate as fully trusted — and earlier builds created them with
        // the default mode, in a directory nothing restricted, so they landed
        // world-readable and group-writable on a typical umask.
        for list in BOOKKEEPING {
            let path = secrets_dir.with_file_name(list);
            if path.is_file() {
                restrict_if_present(&path, 0o600)?;
            }
        }
        drop(held);

        Ok(Store {
            certs: CertStore::open(cert_dir)?,
            cert_dir: cert_dir.to_path_buf(),
            secrets_dir: secrets_dir.to_path_buf(),
            roots_path: secrets_dir.with_file_name("trust-roots"),
            imported_secrets_path: secrets_dir.with_file_name("imported-secrets"),
            sha1_path: secrets_dir.with_file_name("sha1-accepted"),
            revocations_dir,
            lock_path,
        })
    }

    /// Take the store's write lock; see [`StoreLock`].
    fn lock(&self) -> Result<StoreLock> {
        StoreLock::acquire(&self.lock_path)
    }

    /// Remove a certificate from the store.
    ///
    /// Neither cert-d nor `sequoia-cert-store` offers a removal call, so this
    /// unlinks the file itself. The copy cert-d parsed earlier stays in this
    /// handle's cache until something looks the certificate up by fingerprint
    /// and finds the file gone, which [`Store::certs`] does for every
    /// certificate it lists, so the next listing from this same store leaves
    /// it out. This used to say that the index pruned the entry on its next
    /// scan and that scans were rate-limited, so a reopened store was needed
    /// to see the deletion. Neither was so: a scan never removes the entry of
    /// a file that has gone, the listing never consults the index, and waiting
    /// never helped. The certificate's entries in the index do stay behind,
    /// but they stay in a reopened store's index as well, which is read back
    /// from the same SQLite file.
    ///
    /// The pre-made revocation certificate is deliberately left behind. If the
    /// key ever reached a keyserver, that file is the only way to retract it,
    /// and it cannot be regenerated once the secret key is gone — so the moment
    /// the key is deleted is exactly when it stops being redundant. Ask for it
    /// with [`Store::revocation_path`] before deleting if it should go too.
    ///
    /// The certificate's entries in trust-roots and sha1-accepted are removed
    /// with it, and before anything is unlinked. Both lists are keyed by
    /// fingerprint alone, so an entry left behind applies again when the same
    /// certificate is next imported: a trust root once more, with everything
    /// it certified authenticated, while the import reports it unverified. The
    /// SHA-1 entry used to be left for good, and the trust-root entry was
    /// removed last, so a delete that failed there had already unlinked the
    /// certificate, and once the list stopped showing it there was nothing to
    /// retry the delete from. Removed first, a delete that fails after them
    /// leaves a certificate trusted less rather than more, and ticking the
    /// boxes again puts them back.
    ///
    /// Its entry in imported-secrets is kept. That entry only ever withholds
    /// trust-root status, so keeping it is the safe direction; removed before
    /// the secret key, it would let a failed unlink leave an imported key a
    /// trust root.
    pub fn delete(&self, fingerprint: &str, secret_too: bool) -> Result<()> {
        // Held throughout, so that no secret key can arrive from another
        // writer between the guard looking for one and the unlinks below.
        let held = self.lock()?;
        if self.has_secret(fingerprint) && !secret_too {
            return Err(Error::invalid(
                "this certificate has a secret key; deleting it needs to be confirmed",
            ));
        }

        // The entries first; see above. A list the certificate is not on is
        // left as it was rather than written again.
        update_list(&held, &self.roots_path, fingerprint, false)?;
        update_list(&held, &self.sha1_path, fingerprint, false)?;

        // Then the secret. If this fails halfway, a store still holding the
        // public certificate is the recoverable direction to fail in.
        if secret_too {
            let path = self.secret_path(fingerprint);
            remove_if_present(&path)?;
            // And whatever a crashed write of this key left beside it, which
            // can be a whole copy of the key. With the lock held no write that
            // takes it is in progress, so every staging file of this key is a
            // leftover, or an older build's, which takes no lock: a write of a
            // key being deleted is better failed than completed. A leftover
            // that cannot be removed fails the delete, though the sweep on
            // open lets one be: the user asked for this key to be gone, and a
            // copy of it still on disk is what they need to hear about. The
            // public certificate then stays, as above, and the next open tries
            // the leftover again.
            if let Some(target) = path.file_name().and_then(|name| name.to_str()) {
                for leftover in
                    staging_files(&self.secrets_dir, |name| is_staging_for(name, target))
                {
                    remove_if_present(&leftover)?;
                }
            }
        }
        remove_if_present(&self.cert_path(fingerprint))
    }

    /// A second handle on the same directories, with caches of its own.
    ///
    /// Not needed to see a deletion, or anything else written to the store
    /// since this handle was opened: [`Store::certs`] and the lookups check
    /// what they hand out against the files.
    pub fn reopen(&self) -> Result<Store> {
        Store::open(&self.cert_dir, &self.secrets_dir)
    }

    /// Where cert-d keeps `fingerprint`.
    ///
    /// The layout is the lowercase hex fingerprint split after the first two
    /// characters, which holds for both 40-character v4 fingerprints and
    /// 64-character v6 ones.
    fn cert_path(&self, fingerprint: &str) -> PathBuf {
        let fingerprint = hex_only(fingerprint).to_lowercase();
        let (prefix, rest) = fingerprint.split_at(2.min(fingerprint.len()));
        self.cert_dir.join(prefix).join(rest)
    }

    /// Where the revocation certificate for `fingerprint` lives.
    pub fn revocation_path(&self, fingerprint: &str) -> PathBuf {
        // Normalised like `secret_path`; same reasoning.
        self.revocations_dir
            .join(format!("{}.rev", hex_only(fingerprint).to_uppercase()))
    }

    pub fn has_revocation(&self, fingerprint: &str) -> bool {
        self.revocation_path(fingerprint).exists()
    }

    /// Keep a revocation certificate. Written once, at key generation.
    ///
    /// Staged and renamed into place like everything else the store writes.
    /// It used to be written straight to its path, so a write that failed
    /// part-way — a full disk, a quota — or a crash before the data reached
    /// the disk left an empty or truncated file there. `has_revocation` takes
    /// any file for a certificate, so the details pane offered that one for
    /// export and the delete dialog promised it would retract the key, which
    /// is found out only on the day it is needed. A write that fails now
    /// leaves no file, and the delete dialog says there is no certificate.
    pub fn save_revocation(&self, fingerprint: &str, armored: &[u8]) -> Result<()> {
        let held = self.lock()?;
        fs::create_dir_all(&self.revocations_dir)
            .map_err(|e| Error::io(format!("creating {}", self.revocations_dir.display()), e))?;
        restrict(&self.revocations_dir, 0o700)?;

        // Anyone holding this file can retire the key it belongs to.
        write_private_atomic(&held, &self.revocation_path(fingerprint), armored)
    }

    /// Fingerprints the user has explicitly marked as trust roots.
    pub fn trust_roots(&self) -> Result<BTreeSet<String>> {
        read_list(&self.roots_path)
    }

    pub fn set_trust_root(&self, fingerprint: &str, root: bool) -> Result<()> {
        let held = self.lock()?;
        update_list(&held, &self.roots_path, fingerprint, root)
    }

    /// Fingerprints the user has allowed SHA-1 signatures from.
    ///
    /// Read [`crate::sha1`] before using this for anything: the list widens
    /// what *verifies*, and must never widen what is *trusted*. It is not a
    /// weaker cousin of [`Store::trust_roots`] and the two are never combined.
    pub fn sha1_accepted(&self) -> Result<BTreeSet<String>> {
        read_list(&self.sha1_path)
    }

    pub fn set_sha1_accepted(&self, fingerprint: &str, accepted: bool) -> Result<()> {
        let held = self.lock()?;
        update_list(&held, &self.sha1_path, fingerprint, accepted)
    }

    /// The user's SHA-1 opt-in, resolved against the store.
    ///
    /// Not a policy sequoia is handed, despite the name: [`crate::Sha1Policy`]
    /// is the list of opted-in certificates, and hands out a policy per
    /// question asked of it. Empty until the user names a certificate, which
    /// is the default and stays the default until someone acts.
    ///
    /// An opted-in fingerprint that no longer resolves to a certificate is
    /// skipped rather than treated as an error: [`Store::delete`] takes the
    /// line out, but cert-d is shared, and a certificate deleted with another
    /// tool leaves it behind. A stale entry should cost the user a silently
    /// strict verification, not a failed one.
    ///
    /// What comes back is then checked against the line that asked for it,
    /// because [`Store::lookup`] answers a broader question than this one is
    /// asking. It resolves a key to whichever certificate carries it, subkeys
    /// included — verification has to find a certificate from the subkey that
    /// signed — so where no certificate's own fingerprint matches, it hands
    /// back one that merely binds that key as a subkey. Taking that answer
    /// here would move the opt-in onto a certificate the user never named, and
    /// binding somebody else's key as a subkey of your own takes none of their
    /// secret key material.
    ///
    /// One behaviour falls out of that check and is worth stating: a line
    /// written as a key ID rather than a full fingerprint is ignored, where it
    /// used to resolve, because no certificate's fingerprint can equal one.
    /// Nothing here writes such a line — [`Store::set_sha1_accepted`] stores
    /// the full fingerprint the GUI hands it — so this costs a hand-edited
    /// file a silently strict verification, which is what a stale line costs
    /// too.
    pub fn sha1_policy(&self) -> Result<crate::Sha1Policy> {
        let mut policy = crate::Sha1Policy::strict();
        for fingerprint in self.sha1_accepted()? {
            if let Ok(cert) = self.lookup(&fingerprint)
                && cert
                    .fingerprint()
                    .to_hex()
                    .eq_ignore_ascii_case(&fingerprint)
            {
                policy.accept(&cert);
            }
        }
        Ok(policy)
    }

    /// The roots the web of trust is actually evaluated against: the explicit
    /// list plus every certificate whose secret key you *generated here*.
    ///
    /// Own keys are included automatically because the alternative — a fresh
    /// install where nothing authenticates until the user finds a checkbox — is
    /// the wrong default, and because a key you generated is one you already
    /// trust by definition.
    ///
    /// Imported secret keys are excluded, and that distinction is the whole
    /// point of [`Store::imported_secrets`]. "I hold the secret half" used to
    /// be the test, but importing is how a stranger's key can satisfy it:
    /// anyone who persuades you to open a file containing a keypair *they*
    /// generated got a trust root out of it, and with it a `verified` badge on
    /// whatever identities that key had certified. Holding a secret you did not
    /// choose to hold says nothing about trusting it. An imported key can still
    /// be made a root deliberately, with the checkbox in its details pane.
    pub fn effective_roots(&self) -> Result<BTreeSet<String>> {
        let mut roots = self.trust_roots()?;
        roots.extend(self.implicit_roots()?);
        Ok(roots)
    }

    /// What [`Store::effective_roots`] adds to the explicit list: every secret
    /// key held here that was not imported.
    ///
    /// Asked for on its own by the GUI's reload, which needs the two halves
    /// apart and makes their union itself, so effective_roots has to stay
    /// exactly that union for the two to agree. The halves are for the details
    /// pane, whose Trust root checkbox has to tell a key that is a root
    /// whatever the list says from one that is a root only while the list
    /// names it. Ticking the first changes nothing; ticking the second is how
    /// an imported key is made a root. The checkbox used to answer that from
    /// the secret half alone, which drew every imported key as a root it was
    /// not and left no way to make it one.
    pub fn implicit_roots(&self) -> Result<BTreeSet<String>> {
        let imported = self.imported_secrets()?;
        Ok(self
            .secret_fingerprints()?
            .into_iter()
            .filter(|fp| !imported.contains(fp))
            .collect())
    }

    /// Fingerprints of secret keys that came from outside this installation.
    ///
    /// Absent entries mean "generated here", so a store written before this
    /// distinction existed keeps every root it had; only keys imported from
    /// now on are held back.
    pub fn imported_secrets(&self) -> Result<BTreeSet<String>> {
        read_list(&self.imported_secrets_path)
    }

    /// Record a secret key as having arrived from outside.
    ///
    /// Only marks a key we do not already hold: re-importing a backup of a key
    /// you generated here must not demote it, and applying a revocation or an
    /// expiry edit rewrites the same file without changing where it came from.
    fn mark_imported_secret(&self, held: &StoreLock, fingerprint: &str) -> Result<()> {
        update_list(held, &self.imported_secrets_path, fingerprint, true)
    }

    /// Store a secret key that arrived from outside, rather than one generated
    /// here. Identical to [`Store::insert_secret`], down to the error it
    /// returns when cert-d refuses the public half, except that the key does
    /// not become an implicit trust root.
    ///
    /// The lock is taken before looking for the key and held through the mark
    /// and the write. Looked for first, the key could be deleted by another
    /// writer while this one waited for the lock, and then written back
    /// unmarked though it came from outside — and an imported key with no mark
    /// is a trust root.
    ///
    /// The mark comes first for the same reason: before the secret key is
    /// written, and so before the public half goes to cert-d once the lock is
    /// released. It used to follow the write, so a mark that failed — a full
    /// disk is enough — or a crash between the two left the key held and
    /// unmarked: a trust root, and one a retry would find already held and so
    /// never mark. A mark whose key then fails to arrive costs nothing. It
    /// only ever withholds root status, and this store holds no secret key for
    /// it to withhold it from. Even so, a certificate with no secret key in it,
    /// which write_secret refuses, is turned away before the mark, so that an
    /// import refused for that leaves nothing behind.
    pub fn insert_imported_secret(&self, cert: &Cert) -> Result<()> {
        // write_secret refuses this too, but only after the mark; see above.
        if !cert.is_tsk() {
            return Err(Error::invalid("certificate carries no secret key material"));
        }
        let held = self.lock()?;
        let fingerprint = cert.fingerprint().to_hex();
        if !self.has_secret(&fingerprint) {
            self.mark_imported_secret(&held, &fingerprint)?;
        }
        let merged = self.write_secret(&held, cert)?;
        drop(held);
        self.insert_public_half(&merged)
    }

    /// The fingerprint of every secret key on disk, read from the filenames.
    ///
    /// The names are what `secret_path` writes, so the directory listing
    /// answers "do we hold this secret half?" without opening anything — which
    /// is the same question `has_secret` answers with a stat, and the reason
    /// this exists: callers that need the answer for *every* certificate were
    /// paying a syscall and four allocations each to re-derive a set the
    /// directory already spells out.
    ///
    /// Deliberately not built from [`Store::secret_certs`]: that skips files
    /// that will not parse, so a damaged key would silently report as absent
    /// here while `has_secret` still finds it. Listing names keeps the two
    /// answers identical, and `damaged_secret_files` remains how a broken file
    /// is surfaced.
    pub fn secret_fingerprints(&self) -> Result<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        let entries = match fs::read_dir(&self.secrets_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(Error::io(
                    format!("reading {}", self.secrets_dir.display()),
                    e,
                ));
            }
        };
        for entry in entries {
            let path = entry
                .map_err(|e| Error::io(format!("reading {}", self.secrets_dir.display()), e))?
                .path();
            if !path.extension().is_some_and(|e| e == "pgp") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.insert(stem.to_uppercase());
            }
        }
        Ok(out)
    }

    /// Every public certificate in the store, parsed.
    ///
    /// cert-d hands back `LazyCert`s that are only parsed on demand; the GUI
    /// needs every field of every row, so they are all resolved here.
    ///
    /// Resolved, not copied. The parse is memoised inside each `LazyCert`, so
    /// once it has happened the certificate is simply there to borrow — but
    /// this used to hand back a deep clone of every one of them, primary key,
    /// user IDs, subkeys and every certification signature included. Measured
    /// on a thousand-certificate store that copy was about three quarters of
    /// this call, and a reload makes the call twice. Nothing downstream wants
    /// ownership: [`CertRef`] derefs to `&Cert`, so callers read exactly what
    /// they read before.
    ///
    /// Each certificate is checked against its file before it is handed out.
    /// cert-d's own listing reads a file only the first time it meets it: after
    /// that it hands back the copy it parsed then, and never looks at the file
    /// again. So a certificate that another process changed — `sq`, which
    /// shares this directory, or a second rPGP window adding a revocation or
    /// withdrawing a certification — kept its old badges however often the
    /// list was refreshed, and one that was deleted, by another process or by
    /// [`Store::delete`] here, stayed in the list. Only a lookup of that one
    /// certificate on its own, which selecting its row or verifying a message
    /// it signed makes, brought it up to date; an introducer in the middle of
    /// a trust path, or a row nobody selected, stayed as first read until the
    /// app was restarted. Looking each one up again by fingerprint goes
    /// through cert-d's load, which compares the file's modification time and
    /// size with the copy it holds, reads the file again only when they
    /// differ, and drops the copy when the file has gone. That costs an open
    /// and a stat per certificate: on Linux, `benches/reload.rs` puts it at
    /// about a microsecond and a half each, 7ms at five thousand certificates
    /// against the 127ms the whole of a reload's core takes there. It is what
    /// makes a reload a read of the disk rather than of this handle's memory,
    /// without the full parse of every certificate that reopening the store
    /// would cost.
    pub fn certs(&self) -> Result<Vec<CertRef>> {
        let mut out = Vec::new();
        for listed in self.certs.certs() {
            let lazy = match self.certs.lookup_by_cert_fpr(&listed.fingerprint()) {
                Ok(current) => current,
                // Deleted since cert-d first read it, and now dropped from its
                // cache as well.
                Err(e) if is_not_found(&e) => continue,
                // A file that is there and cannot be read now. This listing
                // shows the copy last read. Where the file would not open,
                // load has dropped that copy as well, and the next listing
                // leaves the certificate out, since cert-d's listing passes
                // over a file it cannot open, as a store opened afresh would.
                // Where the file opens but no longer parses, load keeps the
                // copy, and every listing shows it until the file parses
                // again.
                Err(_) => listed,
            };
            // Resolved eagerly, so an unparseable certificate still fails the
            // whole call here rather than surfacing later as a panic in Deref.
            lazy.to_cert()?;
            out.push(CertRef(lazy));
        }
        Ok(out)
    }

    /// Look a certificate up by full fingerprint or key ID, as typed by a user.
    pub fn lookup(&self, handle: &str) -> Result<Cert> {
        let handle: sequoia_openpgp::KeyHandle = handle
            .parse()
            .map_err(|_| Error::invalid(format!("{handle} is not a fingerprint or key ID")))?;
        // Prefer the certificate whose *own* fingerprint matches the handle.
        //
        // lookup_by_cert_or_subkey answers "which certificates carry this key
        // anywhere", and the same key can be attached to more than one
        // certificate, so taking the first of those could hand back a
        // certificate whose own fingerprint is not the one asked for — and
        // certify, revoke and the details pane all pass a fingerprint
        // precisely when they mean one particular certificate.
        //
        // The subkey-tolerant search still has to happen, though: a
        // certification or a revocation names the *key* that made it, which
        // may well be a subkey, and the certificate has to be found from it.
        // So the search is kept and the choice is made afterwards, primary
        // match first. Verification is not one of those callers — it wants
        // every certificate that could have made the signature rather than
        // the best guess at one, and goes through [`Store::lookup_all`].
        let found = self.certs.lookup_by_cert_or_subkey(&handle)?;
        let chosen = found
            .iter()
            .find(|c| sequoia_openpgp::KeyHandle::from(c.fingerprint()).aliases(&handle))
            .cloned()
            .or_else(|| found.into_iter().next())
            .ok_or_else(|| Error::NoSuchCert(handle.to_string()))?;
        Ok(chosen.to_cert()?.clone())
    }

    /// Every certificate in the store that carries the key a handle names.
    ///
    /// [`Store::lookup`] answers "which certificate did the user mean"; this
    /// answers "which certificates could have made this signature", and only
    /// a verifier asks the second question. It has to be asked, because the
    /// same key can hang off more than one certificate and nothing stops that
    /// being somebody else's doing: cert-d indexes every key packet it parses
    /// without looking at the binding, so a certificate carrying a stranger's
    /// signing subkey — bound for encryption, which needs no back-signature,
    /// or not bound at all — is indexed under that subkey like any other.
    /// Handed only the first of those, a verifier finds the key in the wrong
    /// certificate, rejects it as not signing-capable, and reports a genuine
    /// signature as bad. Handed all of them it tries each in turn and stops at
    /// the first that checks out, so the extra candidates cost nothing.
    ///
    /// Unlike `lookup`, a handle no certificate carries is not an error: the
    /// question was which certificates carry the key, and none is an answer.
    /// A candidate that will not parse is dropped rather than failing the
    /// call, for the same reason the list exists — one certificate must not be
    /// able to speak for another, and a stranger's unparseable certificate
    /// keeping the owner's out of the list would be that failure by another
    /// route.
    pub fn lookup_all(&self, handle: &str) -> Result<Vec<Cert>> {
        let handle: sequoia_openpgp::KeyHandle = handle
            .parse()
            .map_err(|_| Error::invalid(format!("{handle} is not a fingerprint or key ID")))?;
        let found = match self.certs.lookup_by_cert_or_subkey(&handle) {
            Ok(found) => found,
            // Told apart from a store that could not be read, which is a real
            // failure and still propagates.
            Err(e) if is_not_found(&e) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        Ok(found
            .iter()
            .filter_map(|c| c.to_cert().ok().cloned())
            .collect())
    }

    /// Insert or merge a public certificate.
    ///
    /// Secret key material is stripped first: `update` writes to cert-d, which
    /// is world-readable by design.
    ///
    /// An error is returned only when cert-d does not hold what it was handed.
    /// cert-d writes in two steps, the certificate's file and then an entry in
    /// its SQLite index, and reports a failure of the second — a full disk is
    /// enough — after the first has already put the certificate in place. That
    /// used to come back as a failure, so a certification, a withdrawal or an
    /// import that had been made was reported as one that had not, and the
    /// obvious retry made a second certification beside the first. So a
    /// failed write is followed by a read of the file, and if merging the
    /// certificate into what is there would add nothing, the write is taken to
    /// have landed. The index notices on its next scan that the directory has
    /// changed since it last looked, and catches up by itself.
    pub fn insert(&self, cert: &Cert) -> Result<()> {
        self.insert_through(cert, |public| self.certs.update(public))
    }

    /// [`Store::insert`], with the write to cert-d handed in, so that a test
    /// can fail it after it has written, as the index can.
    fn insert_through(
        &self,
        cert: &Cert,
        update: impl FnOnce(Arc<LazyCert<'static>>) -> anyhow::Result<()>,
    ) -> Result<()> {
        let public = || cert.clone().strip_secret_key_material();
        let Err(e) = update(Arc::new(LazyCert::from(public()))) else {
            return Ok(());
        };
        // Stripped a second time rather than kept from the first, so that a
        // write that succeeds, as nearly all do, costs one copy of the
        // certificate and not two: an import of thousands makes this call for
        // each of them.
        if self.holds_all_of(&public()) {
            return Ok(());
        }
        Err(e.into())
    }

    /// Whether cert-d's copy of `cert` already carries everything `cert`
    /// does.
    ///
    /// Read by fingerprint, which goes to the file rather than to the index,
    /// and reads the file again whenever it has changed since this handle last
    /// did. Anything short of a copy that merging `cert` into leaves exactly as
    /// it was is a no, a copy that cannot be read included, so a doubt keeps
    /// the error.
    fn holds_all_of(&self, cert: &Cert) -> bool {
        let Ok(stored) = self.certs.lookup_by_cert_fpr(&cert.fingerprint()) else {
            return false;
        };
        let Ok(stored) = stored.to_cert() else {
            return false;
        };
        stored
            .clone()
            .merge_public(cert.clone())
            .is_ok_and(|merged| merged == *stored)
    }

    /// Store a transferable secret key, and its public half in cert-d.
    ///
    /// When the secret key is written and cert-d then refuses the public half,
    /// the error is [`Error::PublicCertNotUpdated`], which says so, rather than
    /// cert-d's own; see that variant.
    pub fn insert_secret(&self, cert: &Cert) -> Result<()> {
        let held = self.lock()?;
        let merged = self.write_secret(&held, cert)?;
        // The public half goes to cert-d once the lock is released. cert-d
        // takes a lock of its own and merges against its own copy, so it needs
        // nothing from this one, and waiting on it with this one held is the
        // only way this lock could come to wait on anything but the disk. The
        // cost: a delete of this key from another window can land between the
        // two and leave the public half without the secret, where either one
        // finishing first would leave both or neither. That holds no secret
        // and makes nothing a trust root.
        drop(held);
        self.insert_public_half(&merged)
    }

    /// The second write of [`Store::insert_secret`] and
    /// [`Store::insert_imported_secret`], made once the secret key is written.
    fn insert_public_half(&self, merged: &Cert) -> Result<()> {
        self.insert(merged)
            .map_err(|e| Error::PublicCertNotUpdated(Box::new(e)))
    }

    /// Merge `cert` into the secret key file and write it back, returning what
    /// was written. The read and the write both happen under `held`, so no
    /// other writer's merge can land between them and be lost.
    fn write_secret(&self, held: &StoreLock, cert: &Cert) -> Result<Cert> {
        if !cert.is_tsk() {
            return Err(Error::invalid("certificate carries no secret key material"));
        }
        let path = self.secret_path(&cert.fingerprint().to_hex());

        // Merged with what is already there, never written over it. This used
        // to serialise whatever it was handed straight onto the path: a file
        // holding a key's only copy of its secret material was replaced
        // wholesale by a certificate that might carry less of it, or none, and
        // there was no merge, no comparison and no backup. Importing a public
        // certificate the user already held a secret for destroyed the secret.
        //
        // The merge settles each key on its own, because a merge that only
        // ever adds material is not enough: a GnuPG stub is a secret-key
        // packet carrying no key, and taking it because it is "more" throws
        // away the real thing. See `merge_secret` for the rules it applies.
        //
        // A file that will not parse is moved aside rather than overwritten:
        // it cannot be merged, and destroying it is the failure this whole
        // function now exists to prevent.
        let cert = match Cert::from_file(&path) {
            Ok(existing) => merge_secret(existing, cert)?,
            Err(_) if path.exists() => {
                let mut aside = path.clone();
                aside.as_mut_os_string().push(".unreadable");
                for n in 1..1000 {
                    if !aside.exists() {
                        break;
                    }
                    aside = path.clone();
                    aside.as_mut_os_string().push(format!(".unreadable.{n}"));
                }
                fs::rename(&path, &aside).map_err(|e| {
                    Error::io(format!("moving unreadable {} aside", path.display()), e)
                })?;
                cert.clone()
            }
            Err(_) => cert.clone(),
        };

        // Staged beside the target and renamed into place, so a crash while
        // serialising leaves the previous file rather than a truncated one;
        // see `replace_private`.
        replace_private(held, &path, |file| Ok(cert.as_tsk().serialize(file)?))?;
        Ok(cert)
    }

    /// Every transferable secret key on disk.
    pub fn secret_certs(&self) -> Result<Vec<Cert>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.secrets_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(Error::io(
                    format!("reading {}", self.secrets_dir.display()),
                    e,
                ));
            }
        };
        for entry in entries {
            let path = entry
                .map_err(|e| Error::io(format!("reading {}", self.secrets_dir.display()), e))?
                .path();
            if !path.extension().is_some_and(|e| e == "pgp") {
                continue;
            }
            // Skip what will not parse rather than fail the listing. One
            // damaged or stray file used to disable every secret key at once:
            // decryption, signing and web-of-trust roots all read this list,
            // and each reported an error that pointed away from the cause.
            // `damaged_secret_files` names the offenders for the UI.
            if let Ok(cert) = Cert::from_file(&path) {
                out.push(cert);
            }
        }
        Ok(out)
    }

    /// Files in the secrets directory that look like keys but will not parse.
    ///
    /// The complement of [`Store::secret_certs`], for telling the user why a
    /// key they expect is missing instead of silently pretending it never
    /// existed.
    pub fn damaged_secret_files(&self) -> Vec<PathBuf> {
        existing_files(&self.secrets_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "pgp"))
            .filter(|p| Cert::from_file(p).is_err())
            .collect()
    }

    /// The secret key for `fingerprint`, if this store holds one.
    pub fn secret_cert(&self, fingerprint: &str) -> Result<Cert> {
        let path = self.secret_path(fingerprint);
        if !path.exists() {
            return Err(Error::NoSecretKey(fingerprint.to_string()));
        }
        Ok(Cert::from_file(&path)?)
    }

    /// Everything the store knows about `fingerprint`, both halves at once.
    ///
    /// [`Store::secret_cert`] and [`Store::lookup`] read different files, and
    /// the two drift apart: [`Store::insert`] writes cert-d and never the
    /// secret file, so a signature that arrives by import or by a keyserver
    /// refresh reaches the public half alone. For one's own revocation that
    /// matters, because the list and the details pane read cert-d and show
    /// `Revoked` while the secret file still looks live — and it is the secret
    /// file that signing, certifying and the lifecycle operations work from.
    /// Anything resolving a fingerprint in order to make *new* use of the key
    /// — a signature, a certification, a lifecycle self-signature — resolves
    /// it here, so that the certificate reaching [`crate::ops`],
    /// [`crate::certify`] and [`crate::lifecycle`] is the whole of what the
    /// store holds. Withdrawals are not refused: revoking a certificate, a
    /// user ID or a subkey, and retracting a certification, are what the owner
    /// of a revoked key may still need to do, and none of them asks
    /// [`crate::revoke::refuse_if_revoked`]. Soft revocations of one's own
    /// key, subkeys or user IDs still come here, for the date alone: what they
    /// sign over the secret half is written into cert-d as well, where a
    /// self-signature that reached cert-d alone would otherwise outrank a soft
    /// revocation; see [`crate::signature_time`]. Retracting a certification
    /// comes here to judge what of the certifier's still stands, which turns
    /// on revocations of its key that may have reached cert-d alone; see
    /// [`crate::certify::Standing`]. This is the only place both files are in
    /// reach.
    ///
    /// The secret half is the base, so its key material is what survives and
    /// the public half contributes signatures only. Where there is no secret
    /// half this is [`Store::lookup`].
    pub fn full_cert(&self, fingerprint: &str) -> Result<Cert> {
        let Ok(secret) = self.secret_cert(fingerprint) else {
            return self.lookup(fingerprint);
        };
        let Ok(public) = self.lookup(fingerprint) else {
            return Ok(secret);
        };
        // `lookup` searches subkeys as well, so it can answer with a
        // certificate other than the one asked for; `merge_public` reports that
        // as a primary key mismatch, and the secret half is then the whole of
        // what this store knows about the fingerprint.
        Ok(secret.clone().merge_public(public).unwrap_or(secret))
    }

    pub fn has_secret(&self, fingerprint: &str) -> bool {
        self.secret_path(fingerprint).exists()
    }

    /// GnuPG's default public keyring, if there is one.
    pub fn gnupg_keybox() -> Option<PathBuf> {
        let home = std::env::var_os("GNUPGHOME")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".gnupg")))?;
        let keybox = home.join("pubring.kbx");
        keybox.exists().then_some(keybox)
    }

    /// Import every certificate from a GnuPG Keybox.
    ///
    /// `pubring.kbx` is a container format of GnuPG's own, not an OpenPGP
    /// keyring, so `CertParser` cannot read it — which is why importing a
    /// GnuPG setup used to mean an export/import dance. A Keybox also holds
    /// X.509 certificates, and those are skipped.
    ///
    /// Only public certificates: GnuPG keeps secret keys separately, in
    /// gpg-agent's own format, and they are reached through the agent instead.
    pub fn import_keybox(&self, path: impl AsRef<Path>) -> Result<Vec<Cert>> {
        use sequoia_ipc::keybox::{Keybox, KeyboxRecord};

        let path = path.as_ref();
        let keybox = Keybox::from_file(path)
            .map_err(|e| Error::invalid(format!("{} is not a Keybox: {e}", path.display())))?;

        let mut imported = Vec::new();
        for record in keybox {
            let Ok(KeyboxRecord::OpenPGP(record)) = record else {
                continue;
            };
            // One unreadable record should not lose the rest of a keyring.
            let Ok(cert) = record.cert() else {
                continue;
            };
            // One that cannot be stored stops the import; see import_file.
            self.insert(&cert)
                .map_err(|e| stopped_after(&imported, e))?;
            imported.push(cert);
        }

        if imported.is_empty() {
            return Err(Error::invalid(format!(
                "{} holds no OpenPGP certificates",
                path.display()
            )));
        }
        Ok(imported)
    }

    /// Import every certificate in a keyring or armored file.
    ///
    /// Returns the certificates that were imported, secret keys included: a
    /// backup restore and a public keyring import land in the same code path,
    /// which is what a user dropping a file on the window expects.
    ///
    /// A certificate that will not parse is skipped, and one that cannot be
    /// stored stops the import there: a write that fails, on a full disk or an
    /// unwritable directory, would most likely fail again for every
    /// certificate after it. What was stored before it stays, and the error is
    /// [`Error::ImportStopped`], which counts it, so that the caller can tell
    /// an import that wrote nothing from one that wrote some of the file.
    pub fn import_file(&self, path: impl AsRef<Path>) -> Result<Vec<Cert>> {
        let path = path.as_ref();

        // A Keybox announces itself with "KBXf" eight bytes in. Sniffing beats
        // trusting the extension: people rename these files.
        let mut magic = [0u8; 12];
        if let Ok(mut file) = fs::File::open(path)
            && std::io::Read::read_exact(&mut file, &mut magic).is_ok()
            && &magic[8..12] == b"KBXf"
        {
            return self.import_keybox(path);
        }

        let parser = sequoia_openpgp::cert::CertParser::from_file(path)?;
        let mut imported = Vec::new();
        let mut skipped = 0usize;
        for cert in parser {
            // CertParser reports a certificate it cannot parse and carries on
            // to the next, so an error here is one bad entry, not a bad file.
            // Aborting used to leave the store half-updated and report total
            // failure after the certificates before the bad one had already
            // been written.
            let Ok(cert) = cert else {
                skipped += 1;
                continue;
            };
            let stored = if cert.is_tsk() {
                // insert_imported_secret, not insert_secret: a secret key that
                // arrived in a file is not thereby one the user trusts.
                self.insert_imported_secret(&cert)
            } else {
                self.insert(&cert)
            };
            stored.map_err(|e| stopped_after(&imported, e))?;
            imported.push(cert);
        }
        if imported.is_empty() {
            return Err(Error::invalid(if skipped == 0 {
                format!("{} contains no OpenPGP certificates", path.display())
            } else {
                format!(
                    "{} contains no readable OpenPGP certificates ({skipped} could not be parsed)",
                    path.display()
                )
            }));
        }
        Ok(imported)
    }

    /// Write certificates to an ASCII-armored file.
    ///
    /// Only public halves are written; exporting a secret key is a separate,
    /// deliberately louder operation.
    ///
    /// The export is armored in memory and written to `path` only once every
    /// certificate has been found. The file used to be opened, and truncated,
    /// first, so a fingerprint that failed to resolve left an existing file
    /// empty or holding an armor block with no end. The write is checked
    /// too: it used to happen in a `BufWriter`'s drop, which discards a
    /// failed write, and a certificate usually fits in its buffer whole, so
    /// an export to a full disk or over quota left an empty file and reported
    /// success.
    ///
    /// The file at `path` is written into, as it always has been, rather than
    /// replaced by a staged file renamed onto it as `ops` replaces its
    /// outputs. Those stage because the operation itself can fail part-way;
    /// here nothing is left to fail by then but the write, so a rename would
    /// buy little, and it would cost the file the user chose to export to: it
    /// puts a new file in place of a symlink at the path rather than writing
    /// where the link points, and the new file has the owner, permissions and
    /// ACL of any new file rather than the old one's. A failed write is
    /// reported, but it can leave the file cut short.
    pub fn export_file(&self, fingerprints: &[String], path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let mut writer = sequoia_openpgp::armor::Writer::new(
            Vec::new(),
            sequoia_openpgp::armor::Kind::PublicKey,
        )?;
        for fpr in fingerprints {
            let cert = self.lookup(fpr)?;
            // `export`, not `serialize`. They differ in exactly one thing:
            // export omits signatures marked non-exportable, which is what a
            // "local" certification made in this app is. serialize wrote them
            // out, so a private trust statement — signed, attributable — went
            // to whoever received the file, despite the certify dialog's
            // publishable/local distinction promising it would not.
            cert.strip_secret_key_material().export(&mut writer)?;
        }
        let armored = writer.finalize()?;
        fs::write(path, armored).map_err(|e| Error::io(format!("writing {}", path.display()), e))
    }

    fn secret_path(&self, fingerprint: &str) -> PathBuf {
        // Normalised, because these files are named from
        // `Fingerprint::to_hex`, which is uppercase, while callers pass
        // whatever they were given. A lowercase fingerprint used to miss the
        // file entirely — and since `has_secret` is this same lookup, it made
        // `delete` believe there was no secret key, skip the confirmation it
        // exists to enforce, remove the public half and orphan the secret on
        // disk. `cert_path` normalises for the same reason, the other way.
        self.secrets_dir
            .join(format!("{}.pgp", hex_only(fingerprint).to_uppercase()))
    }
}

/// Merge an incoming transferable secret key into the copy already stored,
/// deciding key by key which secret survives.
///
/// [`Cert::merge_public_and_secret`] alone prefers the incoming secret for
/// every key the incoming copy has one for, and a GnuPG stub counts as having
/// one — see [`crate::secret::is_usable`]. Importing the output of `gpg
/// --export-secret-subkeys`, or an export of a key that has since moved to a
/// smartcard, therefore replaced real key material with a placeholder that no
/// passphrase opens.
///
/// Reversing the merge order instead would only move the loss: a stub imported
/// first would then block the full backup that restores the key. So the
/// incoming stubs that would displace something are taken out before the
/// merge, which leaves three rules:
///
/// - an incoming secret that is usable wins, as it did before;
/// - an incoming stub is dropped wherever the stored copy already holds a
///   secret for that key, so what is held survives;
/// - anything at all is kept where the stored copy holds no secret for that
///   key, since a stub still records that the key exists elsewhere.
///
/// A usable incoming secret winning is what lets a full backup replace a stub.
/// The writers that hand back an updated copy of a stored key — revoke and the
/// lifecycle operations — are unaffected either way, because the secrets they
/// hand back are the ones they read from this same file.
///
/// Two copies that are both usable are not distinguished: the incoming one
/// wins, so re-importing a backup made under a different passphrase, or under
/// none, still replaces the stored encryption.
///
/// Taking the stubs out means rebuilding the incoming certificate through
/// [`Cert::from_packets`], so this can fail where the plain merge could not.
/// The packets come from a certificate sequoia has already accepted and
/// nothing but secrets is taken out of them, so there should be nothing left
/// to reject; and an error here stops the write and leaves the stored file
/// exactly as it was, which is the direction to fail in.
fn merge_secret(existing: Cert, incoming: &Cert) -> Result<Cert> {
    // Keyed by fingerprint rather than by role, so a key bound as both the
    // primary and a subkey is one entry. `keys()` walks the primary and every
    // subkey, including ones no policy accepts, which is what is wanted here:
    // an expired subkey's secret is still the user's only copy of it.
    let held: BTreeSet<_> = existing
        .keys()
        .secret()
        .map(|key| key.key().fingerprint())
        .collect();

    // `set_filter` rejects a secret by writing the key out as a public packet,
    // which is exactly the shape the merge below has nothing to prefer. Doing
    // it here rather than repairing the merged certificate afterwards keeps
    // the rule in one place and needs no second pass over the keys.
    let stripped = Cert::from_packets(
        incoming
            .clone()
            .into_tsk()
            .set_filter(move |key| {
                crate::secret::is_usable(key.secret()) || !held.contains(&key.fingerprint())
            })
            .into_packets(),
    )?;

    Ok(existing.merge_public_and_secret(stripped)?)
}

/// What an import returns when it cannot store a certificate, having stored
/// those in `imported` before it.
fn stopped_after(imported: &[Cert], source: Error) -> Error {
    Error::ImportStopped {
        stored: imported.len(),
        source: Box::new(source),
    }
}

/// Whether a cert-d lookup failed for want of anything to find, rather than
/// because the store could not be read.
fn is_not_found(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<StoreError>(),
        Some(StoreError::NotFound(_))
    )
}

/// Keep only the hex digits of `fingerprint`.
///
/// Every path in this module is built by interpolating a fingerprint, and each
/// one is public API or reachable from it. Sequoia-derived hex is all any
/// in-tree caller passes, so this changes nothing today — but a caller passing
/// `../../etc/thing` would otherwise have `delete` unlink whatever that named,
/// and a store is not the place to rely on every future caller being careful.
/// Stripping rather than erroring keeps the spaced form people paste from the
/// details pane working.
fn hex_only(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect()
}

/// The entry a fingerprint that a caller passes goes into the bookkeeping
/// lists as: its hex digits, uppercase, which is what `Fingerprint::to_hex`
/// gives.
///
/// It is the reduction [`Store::delete`] and every path here make through
/// `hex_only`, so the entry set_trust_root writes for some input is the one
/// delete takes out for the same input. set_trust_root used to store its
/// input only upper-cased: given the spaced form the details pane shows, a
/// delete removed the certificate and left its trust-root entry, a root again
/// the day the certificate came back, and a newline in the input wrote two
/// entries.
///
/// It is for what callers pass and never for the lines already in a list,
/// which [`read_list`] reads more strictly.
fn list_key(fingerprint: &str) -> String {
    hex_only(fingerprint).to_uppercase()
}

/// One of the bookkeeping lists, a fingerprint per line. A list that does
/// not exist is empty.
///
/// Each line is read the way the web of trust reads a trust-roots line, with
/// Sequoia's fingerprint parser, and listed as the `to_hex` of what it parses
/// to. The parser ignores case and whitespace and drops a leading 0x, so a
/// line in any of those forms is the entry the rest of the store and the
/// window compare, and they can show it and take it out. A spaced trust-roots
/// line, which set_trust_root used to write for spaced input, was a working
/// root that nothing comparing hex could see or remove.
///
/// A line the parser rejects is kept as written, and matches nothing. Not
/// every line in these files is meant as an entry: someone editing one by
/// hand may switch a fingerprint off with a `#` in front, and no reader of
/// these lists has ever counted such a line. Reduced to its hex digits, as
/// [`list_key`] reduces what callers pass, it would count again, in
/// trust-roots as a live root, and the next write would store it as a plain
/// fingerprint that older builds count as well. Kept as written, it goes back
/// out as it came in.
fn read_list(path: &Path) -> Result<BTreeSet<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .map(|line| match line.parse::<sequoia_openpgp::Fingerprint>() {
                Ok(fingerprint) => fingerprint.to_hex(),
                Err(_) => line.trim().to_owned(),
            })
            .filter(|entry| !entry.is_empty())
            .collect()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(Error::io(format!("reading {}", path.display()), e)),
    }
}

/// Put `fingerprint` on one of the bookkeeping lists, or take it off, under
/// the store's lock.
///
/// A list that would come out unchanged is not written again.
/// [`Store::delete`] takes the certificate it deletes off two lists before it
/// unlinks anything, whether it is on them or not, and a write it does not
/// need is one more way for it to fail. Input with no hex digits in it names
/// no entry and changes nothing, where it used to write a blank line into
/// the list on every call.
fn update_list(held: &StoreLock, path: &Path, fingerprint: &str, listed: bool) -> Result<()> {
    let key = list_key(fingerprint);
    if key.is_empty() {
        return Ok(());
    }
    let mut list = read_list(path)?;
    let changed = if listed {
        list.insert(key)
    } else {
        list.remove(&key)
    };
    if !changed {
        return Ok(());
    }

    let mut text = list.into_iter().collect::<Vec<_>>().join("\n");
    text.push('\n');
    write_private_atomic(held, path, text.as_bytes())
}

/// Unlink `path`, treating "it was not there" as success.
fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(format!("removing {}", path.display()), e)),
    }
}

/// Files directly inside `dir`, ignoring anything unreadable.
fn existing_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect()
}

/// Files directly inside `dir` whose names `is_staging` accepts.
fn staging_files(dir: &Path, is_staging: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    existing_files(dir)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(&is_staging)
        })
        .collect()
}

/// Whether `name` is a staging file for the file named `target`: the target's
/// name, then anything that starts with a dot and ends in `.tmp`.
///
/// That covers the names [`create_staging`] makes and the fixed
/// `<target>.tmp` earlier builds staged under.
fn is_staging_for(name: &str, target: &str) -> bool {
    name.strip_prefix(target)
        .is_some_and(|rest| rest.starts_with('.') && rest.ends_with(".tmp"))
}

/// The bookkeeping lists kept beside the secrets directory.
const BOOKKEEPING: [&str; 3] = ["trust-roots", "imported-secrets", "sha1-accepted"];

/// Remove the staging files a crashed write left in `dir`.
///
/// Only a crash leaves one, since a write that fails removes its own, and no
/// write opens a staging file that is already there, so nothing will ever reuse
/// one: without this they would pile up for good, and in the secrets directory
/// each can be a whole copy of a secret key. Only with the lock held, so none
/// of them can be a write still in progress, as long as the writer takes the
/// lock. An older build takes none and stages under the fixed names this also
/// removes, so one writing meanwhile can lose its staging file: its rename then
/// fails, and the file it meant to replace stays as it was. Best effort, like a
/// failed write's own clean-up: a leftover that cannot be removed is private
/// and in nobody's way, and no reason to refuse to open the store.
fn remove_leftover_staging(_held: &StoreLock, dir: &Path, is_staging: impl Fn(&str) -> bool) {
    for path in staging_files(dir, is_staging) {
        let _ = fs::remove_file(path);
    }
}

/// Create a new file only the current user can read, with the mode set at the
/// moment of creation.
///
/// Creating it and then relaxing to `chmod` would leave a window in which
/// another user could open the file and keep that descriptor across every
/// later write.
///
/// A file that already exists is refused rather than opened, so this never
/// writes into anything it did not make: not another writer's staging file,
/// not a leftover, and not a symlink or hard link planted at the name, which
/// `O_EXCL` does not follow. Every caller stages a new file and renames it
/// into place, so nothing needs to open an existing one.
#[cfg(not(windows))]
fn create_private(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| Error::io(format!("writing {}", path.display()), e))
}

/// Create a private staging file beside `path`, under a name no other write
/// is using.
///
/// Two writers used to share one: every write of a key or a list staged
/// under one fixed name, the second writer truncated the file the first was
/// still writing, and the first rename installed bytes from both. Now none
/// can. [`create_private`] makes a new file or fails, so no two writes ever
/// hold the same staging file, whatever it is called, and a writer that
/// takes the store's lock makes its staging files only while it holds it.
///
/// The name only makes a clash unlikely. It is the target's with
/// `.<process ID>-<counter>.tmp` after it: the counter tells writes in one
/// process apart, and the process ID tells processes apart only where they
/// share a PID namespace. A crash can leave a file under a process ID since
/// reused, and each `flatpak run` starts a sandbox with a PID namespace of
/// its own, so two rPGP windows in the Flatpak share a store and can share a
/// process ID too. A clash costs a retry under the next counter, up to
/// sixteen attempts, rather than a write into somebody else's file.
///
/// The target's name stays at the front and `.tmp` ends it, so nothing that
/// lists keys or certificates by extension ever sees a half-written one, and
/// the sweep in [`Store::open`] knows what it may remove.
fn create_staging(path: &Path) -> Result<(PathBuf, fs::File)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    create_staging_from(path, &NEXT)
}

/// [`create_staging`], numbering from `next`, which a test can start where it
/// likes.
fn create_staging_from(path: &Path, next: &AtomicU64) -> Result<(PathBuf, fs::File)> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        let mut staging = path.to_path_buf();
        staging.as_mut_os_string().push(format!(
            ".{}-{}.tmp",
            std::process::id(),
            next.fetch_add(1, Ordering::Relaxed)
        ));
        match create_private(&staging) {
            Err(Error::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists && attempts < 16 => {}
            created => return created.map(|file| (staging, file)),
        }
    }
}

/// Replace `path` with what `write` puts in a new private file beside it.
///
/// Staged, synced and renamed into place, so a crash or a full disk part-way
/// through leaves the previous file intact rather than a truncated or
/// zero-length one, and the rename keeps the private mode or ACL the staging
/// file was created with. When anything fails the staging file is removed
/// before the error goes back: it can hold a whole secret key, and it used to
/// be left where it was, still there after the key was deleted.
///
/// Takes the store's lock as proof that it is held, because the sweep in
/// [`Store::open`] removes staging files and may do so only because every
/// write that makes one holds the lock until it is gone.
fn replace_private(
    _held: &StoreLock,
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> Result<()>,
) -> Result<()> {
    let (staging, mut file) = create_staging(path)?;
    let written = write(&mut file).and_then(|()| {
        file.sync_all()
            .map_err(|e| Error::io(format!("writing {}", path.display()), e))
    });
    // Closed before it is renamed or removed, so no handle to it outlives
    // the write.
    drop(file);
    let replaced = written.and_then(|()| {
        fs::rename(&staging, path).map_err(|e| Error::io(format!("writing {}", path.display()), e))
    });
    if replaced.is_err() {
        // Best effort: the error going back is the one that matters, and a
        // file this cannot remove is swept by the next open.
        let _ = fs::remove_file(&staging);
    }
    replaced
}

/// Replace a file the store keeps for itself with `bytes`, atomically and
/// privately.
///
/// That matters more for the bookkeeping lists than their size suggests — a
/// truncated imported-secrets list does not fail closed. Every stranger
/// keypair it used to name silently becomes a trust root again, all at once,
/// which is the door the list exists to shut.
///
/// The staging file is created private, so the result is 0o600 from the moment
/// it exists rather than 0o666 & ~umask until the next `Store::open` repairs
/// it — a whole session, in an app the user leaves running.
fn write_private_atomic(held: &StoreLock, path: &Path, bytes: &[u8]) -> Result<()> {
    replace_private(held, path, |file| {
        file.write_all(bytes)
            .map_err(|e| Error::io(format!("writing {}", path.display()), e))
    })
}

/// How long a writer waits for another to finish before it gives up.
///
/// Every hold is one read-merge-write, milliseconds long, so a wait this long
/// means the holder is stuck — a process stopped part-way through a write —
/// and an error that says so is better than a window that hangs, since some
/// writes run on the GUI's event loop.
const LOCK_PATIENCE: Duration = Duration::from_secs(10);

/// The store's write lock, held for one read-merge-write and released when
/// dropped.
///
/// The secret keys and the bookkeeping lists are each read, merged and written
/// back, and nothing used to stop two writers doing that at once: two worker
/// threads, two rPGP windows, or rPGP and another program. The second writer's
/// merge started from what the first was about to replace, so one of the two
/// changes was lost, and a lost entry in imported-secrets makes a stranger's
/// key a trust root. Every write to the files this module keeps for itself
/// takes this lock first, and so does [`Store::open`] while it sweeps and
/// repairs them. Readers do not: a rename replaces a whole file at once, so a
/// reader sees the old one or the new one.
///
/// One lock for the whole store rather than one per file, because some writes
/// span files — an import marks a key in imported-secrets and writes it, and
/// a delete removes a key and its trust-root and SHA-1 entries — and one lock
/// has no order to take locks in and get wrong. Writes are rare and short, so
/// nothing is lost to a coarser lock.
///
/// It cannot deadlock. It is never held while waiting on anything else — the
/// public half goes to cert-d after it is released — and no function that
/// holds it calls one that takes it; the functions that take it pass it on to
/// those that need it instead. That rule matters, because a second hold in
/// one thread would wait on the first until it gave up: the lock belongs to
/// the open file, not to the process.
///
/// Advisory, through `File::try_lock`: `flock` on Unix, `LockFileEx` on
/// Windows. A writer that does not take it, such as an older build, is not
/// kept out, but neither can tear a file the other is making: an older build
/// stages under a fixed name this one never uses, and [`create_private`]
/// never opens a file that is already there. The lock file is never written
/// to; on Windows that is what makes locking it harmless, since a lock there
/// is mandatory for the bytes it covers.
///
/// On a filesystem that refuses to lock at all, every write fails with an
/// error naming the lock file, and so does [`Store::open`], whose repair takes
/// the lock too; the store used to open there. That fails closed rather than
/// write unguarded, which is what cert-d's own inserts do there as well.
struct StoreLock(fs::File);

impl StoreLock {
    fn acquire(path: &Path) -> Result<Self> {
        Self::acquire_within(path, LOCK_PATIENCE)
    }

    fn acquire_within(path: &Path, patience: Duration) -> Result<Self> {
        let mut options = fs::OpenOptions::new();
        // Opened for writing because creating the file needs write access, and
        // because std leaves it unspecified whether a file not open for
        // writing can be locked. Never truncated or written: the lock is all
        // it is for.
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| Error::io(format!("opening {}", path.display()), e))?;

        // Polled rather than blocked on, so that the wait can end.
        let deadline = Instant::now() + patience;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(StoreLock(file)),
                Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(Error::io(
                        format!("locking {}", path.display()),
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "another writer held it for too long",
                        ),
                    ));
                }
                Err(fs::TryLockError::Error(e)) => {
                    return Err(Error::io(format!("locking {}", path.display()), e));
                }
            }
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // Closing the file would release the lock as well, but Windows only
        // promises to do that eventually and asks for an explicit unlock.
        let _ = self.0.unlock();
    }
}

/// Restrict a path to the current user.
///
/// Windows has no mode, so `mode` is ignored there and the equivalent ACL is
/// derived from what the path leads to; see [`windows_acl`]. On a platform
/// that is neither, this is a no-op, because inventing a mapping would be
/// worse than being explicit about not having one.
///
/// A link at the end of the path is followed on Unix and Windows alike, so
/// what is restricted is what the link leads to: chmod follows a symlink, and
/// on Windows the ACL is set through a handle opened on that object.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io(format!("restricting {}", path.display()), e))
}

#[cfg(windows)]
fn restrict(path: &Path, _mode: u32) -> Result<()> {
    windows_acl::restrict(path)
}

/// See [`create_private`]; on Windows the ACL arrives with the file.
#[cfg(windows)]
fn create_private(path: &Path) -> Result<fs::File> {
    windows_acl::create_private(path)
}

#[cfg(all(not(unix), not(windows)))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// [`restrict`], treating "it was not there" as success.
///
/// For the files the repair on open lists first and restricts after: one that
/// is gone by then exposes nothing. Both platforms report that as `NotFound`,
/// whether Unix's chmod finds nothing or Windows finds nothing to open.
fn restrict_if_present(path: &Path, mode: u32) -> Result<()> {
    match restrict(path, mode) {
        Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        restricted => restricted,
    }
}

// ===========================================================================
// Windows ACLs.
//
// Replaces what used to be a no-op. The two properties to reproduce are the
// ones the Unix code gets from `open(O_CREAT, 0600)` and `chmod`:
//
//   1. ATOMIC CREATION. The file must never exist, even for an instant, with
//      an ACL another user can read. `CreateFileW` takes the security
//      descriptor as a creation argument, so the ACL is part of making the
//      file rather than a follow-up call.
//   2. REPAIR ON OPEN. A store written by an earlier build is already exposed
//      and the user has no way to know it, so every open rewrites the ACL.
//
// One honest difference from Unix, worth knowing before trusting the directory
// ACL: denying other users traverse rights on the secrets directory is close
// to decorative on Windows. "Bypass traverse checking"
// (SeChangeNotifyPrivilege) is granted to Users and Everyone by default and
// lets anyone who knows a file's full path open it without any rights on its
// parents. On Windows the per-file ACL is the control and the directory ACL is
// defence in depth; on Unix the 0700 directory really does gate access.
// ===========================================================================

#[cfg(windows)]
mod windows_acl {
    use std::fs;
    use std::io;
    use std::marker::PhantomData;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, HandleOrInvalid, OwnedHandle};
    use std::path::Path;
    use std::ptr::{self, NonNull};

    use windows_sys::Win32::Foundation::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_WRITE, GetLastError, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        READ_CONTROL, WRITE_DAC,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::error::{Error, Result};

    /// The access-control policy, written down exactly once so the creation
    /// path and the repair path cannot drift apart.
    ///
    /// `D:`   the DACL component of an SDDL security descriptor.
    /// `P`    SE_DACL_PROTECTED. Not decorative: without it Windows *merges*
    ///        the parent's inheritable ACEs into the DACL supplied here, so
    ///        whatever `%LOCALAPPDATA%` and its ancestors hand down comes back
    ///        and the secret key is readable again.
    /// `A`    ACCESS_ALLOWED. No deny ACEs are needed: a DACL with no matching
    ///        ACE already denies.
    /// `OICI` OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, on directories only,
    ///        so anything created inside by a code path that forgets
    ///        [`create_private`] still lands restricted. Deliberately not `IO`
    ///        (INHERIT_ONLY): the ACE must apply to the directory itself too.
    /// `FA`   FILE_ALL_ACCESS (0x001f01ff). The specific mask, not `GA`: the
    ///        access check does not map generic bits stored in an ACE, it
    ///        subtracts the mask literally.
    /// SID    the user this process runs as, written out in full. Emphatically
    ///        not `CO` (S-1-3-0): CREATOR OWNER is a placeholder substituted
    ///        only when an inheritable ACE is inherited by a new child, so on a
    ///        leaf file it stays literal, matches nobody, and the DACL grants
    ///        no one anything — the write through the creation handle appears
    ///        to work and the next open fails with ACCESS_DENIED. Not `OW`
    ///        (S-1-3-4) either: that resolves to whoever the owner happens to
    ///        be, and where the default owner for objects created by
    ///        administrators is the Administrators group, it would silently
    ///        widen the ACL to every local admin.
    fn sddl(container: bool) -> Result<String> {
        let sid = current_user_sid()?;
        let flags = if container { "OICI" } else { "" };
        Ok(format!("D:P(A;{flags};FA;;;{sid})"))
    }

    /// Restrict what `path` names to the current user, replacing whatever
    /// DACL it has.
    ///
    /// The repair half. Used for directories, which `fs::create_dir_all` has
    /// already made by the time we are called, and for files a previous build
    /// left behind.
    ///
    /// A link at the end of `path` is followed and the ACL goes on what it
    /// leads to, as chmod follows a symlink on Unix. This used to call
    /// SetNamedSecurityInfoW, which does not follow one: given the path of a
    /// junction, it set the ACL of the junction itself, as the windows-core CI
    /// job showed. A symlink goes through the same reparse-point handling,
    /// though that case was not observed. So a secrets directory moved to
    /// another drive with a junction left in its place kept whatever ACL its
    /// new location handed down, through every open. Each key file in it was
    /// still owner-only, as [`create_private`] made it, but the directory let
    /// in anyone its parents let in: to list the keys, and where those parents
    /// granted full control, to delete them or put others in their place. The
    /// object is opened here instead, by CreateFileW, which follows links as it
    /// opens, and the policy is both chosen from and set through that one
    /// handle.
    ///
    /// Following the link takes rights away from everyone but this user and
    /// grants this user nothing it could not grant itself: the policy names
    /// nobody else, and the open succeeds only where this user may already
    /// rewrite the ACL.
    pub(super) fn restrict(path: &Path) -> Result<()> {
        let wide = wide_path(path)?;

        // WRITE_DAC is what setting the DACL needs. READ_CONTROL too, because
        // SetSecurityInfo does not document all it needs and may read the
        // descriptor already there, and an object's owner is normally granted
        // both whatever its DACL says. FILE_READ_ATTRIBUTES is for the
        // metadata read below, which chooses the policy as fs::metadata on
        // the path used to. Named rights, not MAXIMUM_ALLOWED, with which
        // SetSecurityInfo documents that it propagates nothing to what is
        // inside a directory. Every share flag, for create_private's reason:
        // sharing is a concurrency setting, not an access-control boundary.
        //
        // No FILE_FLAG_OPEN_REPARSE_POINT, which would open a link at the end
        // of the path rather than what it leads to, as SetNamedSecurityInfoW
        // did. FILE_FLAG_BACKUP_SEMANTICS because CreateFileW opens no
        // directory without it. It overrides access checks only for a process
        // that has enabled the backup and restore privileges, which this one
        // never does.
        //
        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer alive for the call.
        // The security attributes and the template handle are optional and
        // null. The return value is validated below before being treated as
        // a handle.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        // Read before anything else can clobber it. Nothing at the path, or
        // a link that leads nowhere, is ERROR_FILE_NOT_FOUND or
        // ERROR_PATH_NOT_FOUND, which io::Error reports as NotFound, and
        // `restrict_if_present` depends on that.
        //
        // SAFETY: GetLastError takes no arguments and touches no memory.
        let code = unsafe { GetLastError() };
        // SAFETY: on success this is an owned, open handle for which
        // CloseHandle is the correct destructor, and it is not closed
        // anywhere else here. On failure it is the sentinel, which
        // `HandleOrInvalid` recognises and does not close.
        let handle = unsafe { HandleOrInvalid::from_raw_handle(raw) };
        // A File from here on, so every return below closes the handle.
        let object = fs::File::from(
            OwnedHandle::try_from(handle)
                .map_err(|_| win32(code, format!("restricting {}", path.display())))?,
        );

        // Which form of the policy applies is decided by what the object
        // *is*, not by the `mode` the caller passed: see the wrapper's doc
        // comment. Judged through the handle, so that it describes the object
        // the ACL is about to land on. A second look at the path could meet a
        // link retargeted in between and pair one object's policy with
        // another object.
        let container = object
            .metadata()
            .map_err(|e| Error::io(format!("inspecting {}", path.display()), e))?
            .is_dir();

        let descriptor = SecurityDescriptor::from_sddl(&sddl(container)?)?;
        let dacl = descriptor.dacl()?;

        // SAFETY: `object` owns an open handle with WRITE_DAC and is not
        // dropped until this function returns, after the call. The ACL
        // pointer is taken in the argument list itself, from a `dacl` that
        // borrows `descriptor`, and `descriptor` is not dropped until the call
        // has returned, so the allocation it points into outlives the call.
        // The borrow alone would not ensure that: the raw pointer carries no
        // lifetime, which is why it is never kept in a local of its own. Nor
        // is it ever null, which would grant everyone everything. The owner,
        // group and SACL parameters are null, which the API accepts for a
        // component it is not setting, and the matching bits are absent from
        // `securityinfo`. PROTECTED_DACL_SECURITY_INFORMATION is what strips
        // inherited ACEs already on the object; DACL alone would add ours and
        // keep theirs.
        let status = unsafe {
            SetSecurityInfo(
                object.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl.as_ptr(),
                ptr::null(),
            )
        };
        // Returns a WIN32_ERROR directly. GetLastError is meaningless here.
        if status != ERROR_SUCCESS {
            return Err(win32(status, format!("restricting {}", path.display())));
        }
        drop(descriptor);
        Ok(())
    }

    /// Create `path` accessible only to the current user, with the ACL applied
    /// by the same call that creates the file.
    ///
    /// A new file or nothing: CREATE_NEW fails with ERROR_FILE_EXISTS where
    /// something is already there, as `create_new` does on Unix. So the ACL
    /// passed in always applies. CreateFileW ignores it only when it opens a
    /// file that exists, which this used to do, and then had to put the
    /// policy on the handle itself or the old file's ACL survived.
    pub(super) fn create_private(path: &Path) -> Result<fs::File> {
        let descriptor = SecurityDescriptor::from_sddl(&sddl(false)?)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            // Never 1. rpgp spawns gpg-agent, and an inherited handle to an
            // open secret key file is a hole no ACL closes.
            bInheritHandle: 0,
        };
        let wide = wide_path(path)?;

        // GENERIC_WRITE is what the caller wants. The share mode matches what
        // `fs::OpenOptions` uses, because share mode is a concurrency setting
        // and not an access-control boundary — the ACL is the boundary, and an
        // exclusive open would only add spurious sharing violations when an
        // indexer or scanner holds a transient handle.
        //
        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer and `attributes`
        // (with the descriptor it points at) is alive across the call. The
        // return value is validated below before being treated as a handle.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        // Read the thread's last-error code before anything else can clobber
        // it. On failure it is the reason, ERROR_FILE_EXISTS among them, which
        // io::Error reports as AlreadyExists.
        //
        // SAFETY: GetLastError takes no arguments and touches no memory.
        let code = unsafe { GetLastError() };

        // CreateFileW reports failure as INVALID_HANDLE_VALUE, not null.
        // `HandleOrInvalid` exists for exactly this convention and its TryFrom
        // is the check; `File::from_raw_handle` would happily wrap -1.
        //
        // SAFETY: on success this is an owned, open handle for which
        // CloseHandle is the correct destructor, and it is not closed anywhere
        // else here. On failure it is the sentinel, which `HandleOrInvalid`
        // recognises and does not close.
        let handle = unsafe { HandleOrInvalid::from_raw_handle(raw) };
        let handle = OwnedHandle::try_from(handle)
            .map_err(|_| win32(code, format!("creating {}", path.display())))?;

        drop(descriptor);
        Ok(fs::File::from(handle))
    }

    /// A self-relative security descriptor from the SDDL parser, freed with
    /// `LocalFree` as that function documents.
    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl SecurityDescriptor {
        fn from_sddl(text: &str) -> Result<Self> {
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: `wide` is NUL-terminated and alive for the call;
            // `descriptor` is a valid out-pointer; the size out-parameter is
            // optional and documented to accept null. On success we take
            // ownership of the returned allocation.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(last_error(format!("parsing the ACL policy {text:?}")));
            }
            Ok(Self(descriptor))
        }

        /// The DACL inside this descriptor, borrowed from it.
        ///
        /// It points into the same allocation, so it must never be freed
        /// separately, and its lifetime keeps it from outliving `self`.
        fn dacl(&self) -> Result<BorrowedDacl<'_>> {
            let mut present = 0;
            let mut dacl: *mut ACL = ptr::null_mut();
            let mut defaulted = 0;
            // SAFETY: `self.0` is a valid descriptor produced by the SDDL
            // parser, and the three out-pointers are to live locals.
            let ok = unsafe {
                GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted)
            };
            if ok == 0 {
                return Err(last_error("reading back the ACL policy"));
            }
            // A descriptor with no DACL grants everyone everything. Our SDDL
            // always has a `D:` component, so this is unreachable — but the
            // failure mode is bad enough to check rather than assume.
            match NonNull::new(dacl) {
                Some(dacl) if present != 0 => Ok(BorrowedDacl(dacl, PhantomData)),
                _ => Err(Error::invalid("the ACL policy produced no DACL")),
            }
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: the only constructor stores a non-null pointer returned
            // by ConvertStringSecurityDescriptorToSecurityDescriptorW, whose
            // documented deallocator is LocalFree. Drop runs at most once, and
            // nothing else frees the allocation — the DACL `dacl()` lends out
            // points into it and has no destructor — so there is no double
            // free.
            unsafe { LocalFree(self.0.cast()) };
        }
    }

    /// The DACL inside a [`SecurityDescriptor`], for as long as the borrow of
    /// the descriptor lasts, as std's `BorrowedHandle` is a handle for as long
    /// as its borrow lasts.
    ///
    /// `dacl()` used to return a bare `*const ACL`, which carries no
    /// lifetime, so `SecurityDescriptor::from_sddl(..)?.dacl()?` would have
    /// compiled, freed the descriptor at the end of that statement, and left
    /// the pointer for the call that sets the ACL to read the freed ACL
    /// through. The borrow makes that a compile error. Not a `&ACL`, though:
    /// `ACL` is only the header of a variable-length structure whose ACEs
    /// follow it, and under Stacked Borrows, one model of Rust's aliasing
    /// rules, a pointer made from a reference to the header may read the
    /// header alone, where Windows reads the whole ACL through it.
    struct BorrowedDacl<'a>(NonNull<ACL>, PhantomData<&'a SecurityDescriptor>);

    impl BorrowedDacl<'_> {
        /// The pointer the Win32 calls take.
        ///
        /// It carries no lifetime of its own, so nothing checks that the
        /// descriptor is still alive where it is used. Take it in the argument
        /// list of the call it is for, where the borrow has just shown that,
        /// never into a local that could outlive the descriptor.
        fn as_ptr(&self) -> *const ACL {
            self.0.as_ptr()
        }
    }

    /// The SID of the user this process runs as, in `S-1-5-21-...` form.
    ///
    /// `pub(super)` so the tests can build the same expectation from the same
    /// place; there is no independent second source for it on a CI runner,
    /// whose account name is not documented.
    pub(super) fn current_user_sid() -> Result<String> {
        let mut raw_token = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that is always
        // valid and must never be closed; `raw_token` is a valid out-pointer.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) };
        if ok == 0 {
            return Err(last_error("opening the process token"));
        }
        // SAFETY: OpenProcessToken succeeded, so this is an owned, open handle
        // whose destructor is CloseHandle. Wrapping it here is what closes it,
        // and nothing else closes it.
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

        // Sizing call: documented to fail and write the required length.
        let mut len = 0u32;
        // SAFETY: a null buffer with length 0 is the documented way to ask for
        // the size; `len` is a valid out-pointer.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut len,
            )
        };
        // SAFETY: GetLastError takes no arguments and touches no memory.
        let code = unsafe { GetLastError() };
        if code != ERROR_INSUFFICIENT_BUFFER || len == 0 {
            return Err(win32(code, "sizing the process token"));
        }

        // TOKEN_USER contains a pointer, so the buffer has to be
        // pointer-aligned. A `Vec<u8>` is only byte-aligned; a `Vec<u64>` is
        // aligned enough on every architecture Windows runs on.
        let mut buffer = vec![0u64; (len as usize).div_ceil(mem::size_of::<u64>())];
        // SAFETY: the buffer is at least `len` bytes and writable, and `len` is
        // exactly the size the previous call asked for.
        let ok = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                len,
                &mut len,
            )
        };
        if ok == 0 {
            return Err(last_error("reading the process token"));
        }

        // SAFETY: on success the buffer holds a TOKEN_USER followed by the SID
        // it points at. The buffer is u64-aligned, satisfying TOKEN_USER's
        // alignment, and is at least as large as the API asked for. `buffer`
        // outlives every use of the SID below.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };

        let mut raw_string = ptr::null_mut();
        // SAFETY: `user.User.Sid` points into `buffer`, which is still alive,
        // and was written by the kernel as a valid SID. On success we take
        // ownership of the returned string.
        let ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut raw_string) };
        if ok == 0 {
            return Err(last_error("formatting the user SID"));
        }
        Ok(LocalString(raw_string).value())
    }

    /// A NUL-terminated wide string from `LocalAlloc`, freed on drop.
    struct LocalString(windows_sys::core::PWSTR);

    impl LocalString {
        fn value(&self) -> String {
            let mut len = 0;
            // SAFETY: the pointer is a non-null, NUL-terminated wide string
            // from the API that produced it, so every read up to and including
            // the terminator is in bounds.
            while unsafe { *self.0.add(len) } != 0 {
                len += 1;
            }
            // SAFETY: `len` units starting at the pointer are initialised, as
            // just established by walking to the terminator.
            let units = unsafe { std::slice::from_raw_parts(self.0, len) };
            String::from_utf16_lossy(units)
        }
    }

    impl Drop for LocalString {
        fn drop(&mut self) {
            // SAFETY: ConvertSidToStringSidW documents LocalFree as the
            // deallocator, and Drop runs at most once.
            unsafe { LocalFree(self.0.cast()) };
        }
    }

    /// A path as a NUL-terminated UTF-16 buffer.
    ///
    /// Through `encode_wide`, never `to_string_lossy`: a Windows path can be
    /// ill-formed UTF-16, and a lossy round-trip would silently name a
    /// different file. The path is passed as the caller built it, with no
    /// `canonicalize`: CreateFileW resolves any link in it as it opens, and
    /// resolving it beforehand as well would only open a gap in which the
    /// two resolutions could reach different objects.
    fn wide_path(path: &Path) -> Result<Vec<u16>> {
        let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
        // An interior NUL would truncate the name at the FFI boundary and open
        // something other than what the caller asked for.
        if units.contains(&0) {
            return Err(Error::invalid(format!(
                "{} contains a NUL and cannot be used as a Windows path",
                path.display()
            )));
        }
        units.push(0);
        Ok(units)
    }

    fn win32(code: u32, context: impl Into<String>) -> Error {
        Error::io(context, io::Error::from_raw_os_error(code as i32))
    }

    fn last_error(context: impl Into<String>) -> Error {
        // SAFETY: GetLastError takes no arguments and touches no memory.
        win32(unsafe { GetLastError() }, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sequoia_openpgp::crypto::{S2K, mpi};
    use sequoia_openpgp::packet::key;
    use sequoia_openpgp::{Fingerprint, Packet};

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    /// Importing a key with less secret material than we hold must not take
    /// what we already have.
    ///
    /// The shape here is a TSK whose primary carries secret material and whose
    /// subkeys do not — the mirror image of `gpg --export-secret-subkeys`,
    /// which keeps the subkey secrets and stubs the primary, except that these
    /// subkeys are left plainly public where gpg would write a stub. The stub
    /// shapes are what the tests below cover. insert_secret used to serialise
    /// whatever it was handed straight over the file, so importing one of these
    /// discarded every subkey secret the store held — silently, with no merge,
    /// no comparison and no backup.
    ///
    /// Replace the merge with the old unconditional write and this fails: the
    /// subkey comes back public.
    #[test]
    fn importing_a_partial_secret_key_does_not_discard_what_we_hold() {
        let (_dir, store) = scratch();
        let full = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        let secret_subkeys = |cert: &Cert| cert.keys().subkeys().secret().count();
        assert!(
            secret_subkeys(&full) > 0,
            "the generated key must have secret subkeys, or this proves nothing"
        );
        store.insert_secret(&full).unwrap();

        // The same key with its subkey secrets stripped: still a TSK, because
        // the primary keeps its own. `gpg --export-secret-subkeys` writes the
        // other way round, and as_tsk().set_filter() expresses either.
        let primary = full.primary_key().key().fingerprint();
        let mut bytes = Vec::new();
        full.as_tsk()
            .set_filter(move |k| k.fingerprint() == primary)
            .serialize(&mut bytes)
            .unwrap();
        let partial = Cert::from_bytes(&bytes).unwrap();
        assert!(partial.is_tsk(), "the primary still carries its secret");
        assert_eq!(secret_subkeys(&partial), 0, "subkey secrets are gone");

        store.insert_secret(&partial).unwrap();

        let on_disk = store
            .secret_certs()
            .unwrap()
            .into_iter()
            .find(|c| c.fingerprint() == full.fingerprint())
            .expect("the key is still in the store");
        assert_eq!(
            secret_subkeys(&on_disk),
            secret_subkeys(&full),
            "importing a partial key must not discard secret subkeys we already held"
        );
    }

    /// The two shapes GnuPG writes in place of a secret it is not holding.
    #[derive(Debug, Clone, Copy)]
    enum Stub {
        /// What `gpg --export-secret-subkeys` leaves for the primary.
        GnuDummy,
        /// What any export writes for a key that lives on a smartcard.
        DivertToCard,
    }

    /// A GnuPG stub, as secret key material.
    ///
    /// Both shapes are the private S2K type 101 followed by a hash-algorithm
    /// byte, `GNU`, and a mode: 1 for gnu-dummy, 2 for divert-to-card, the
    /// card form carrying the length and bytes of the card's serial number
    /// after it. Built here rather than exported, because exporting the card
    /// form needs a card to export from. `tests/gnupg_stubs.rs` holds a real
    /// gpg 2.4.9 export to pin the gnu-dummy half against; the card half is
    /// this description of GnuPG's format and no more.
    fn stub_secret(shape: Stub) -> key::SecretKeyMaterial {
        let mut parameters = vec![0, b'G', b'N', b'U'];
        match shape {
            Stub::GnuDummy => parameters.push(1),
            Stub::DivertToCard => {
                parameters.push(2);
                // An OpenPGP card application identifier with an invented
                // serial number. Nothing here reads it, but a real card stub
                // carries one, and it is what makes this stub longer than a
                // gnu-dummy — the two are not the same number of bytes.
                let serial = [
                    0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x05, 0x00, 0x00, 0x11,
                    0x22, 0x33, 0x44,
                ];
                parameters.push(serial.len() as u8);
                parameters.extend_from_slice(&serial);
            }
        }
        key::SecretKeyMaterial::Encrypted(key::Encrypted::new(
            S2K::Private {
                tag: 101,
                parameters: Some(parameters.into()),
            },
            // No cipher, no ciphertext: there is nothing here to decrypt. The
            // 16-bit checksum is what GnuPG 2.1 and later record.
            0.into(),
            Some(mpi::SecretKeyChecksum::Sum16),
            Vec::new().into(),
        ))
    }

    /// A key to hang stubs on.
    ///
    /// RFC 4880, not the default: a GnuPG stub is a v4 shape. RFC 9580 forbids
    /// the S2K usage byte a stub is written under, and gpg 2.4, which made the
    /// fixtures in `tests/gnupg_stubs.rs`, writes no v6 keys at all, so
    /// grafting a stub onto a v6 key would be testing a packet that cannot
    /// occur. The merge never looks at the key version, and the tests either
    /// side of these do use the default.
    fn stub_host(password: Option<&str>) -> Cert {
        let mut request = crate::keygen::KeyGenRequest::new("Stub <stub@example.org>");
        request.standard = crate::keygen::Standard::Rfc4880;
        request.password = password.map(|p| p.to_string().into());
        crate::keygen::generate(&request).unwrap().cert
    }

    /// `cert` with the secret of every key `which` names replaced by `stub`.
    fn with_stubs(
        cert: &Cert,
        stub: &key::SecretKeyMaterial,
        which: impl Fn(&Fingerprint) -> bool,
    ) -> Cert {
        let packets = cert
            .clone()
            .into_tsk()
            .into_packets()
            .map(|packet| match packet {
                Packet::PublicKey(key) if which(&key.fingerprint()) => {
                    Packet::SecretKey(key.add_secret(stub.clone()).0)
                }
                Packet::SecretKey(key) if which(&key.fingerprint()) => {
                    Packet::SecretKey(key.take_secret().0.add_secret(stub.clone()).0)
                }
                Packet::PublicSubkey(key) if which(&key.fingerprint()) => {
                    Packet::SecretSubkey(key.add_secret(stub.clone()).0)
                }
                Packet::SecretSubkey(key) if which(&key.fingerprint()) => {
                    Packet::SecretSubkey(key.take_secret().0.add_secret(stub.clone()).0)
                }
                other => other,
            })
            .collect::<Vec<_>>();
        Cert::from_packets(packets.into_iter()).unwrap()
    }

    /// Every key's secret material, paired with the key's fingerprint.
    ///
    /// Read back from serialised bytes, so that both sides of a comparison
    /// have been through the parser. A v4 packet carries no length for its
    /// S2K, so the parser of a stub cannot tell where the S2K's parameters
    /// end and puts all of it in the ciphertext instead: the same stub built
    /// in memory and parsed from a packet serialises identically and compares
    /// unequal.
    fn secrets(cert: &Cert) -> Vec<(Fingerprint, Option<key::SecretKeyMaterial>)> {
        let mut bytes = Vec::new();
        cert.as_tsk().serialize(&mut bytes).unwrap();
        Cert::from_bytes(&bytes)
            .unwrap()
            .keys()
            .map(|key| {
                (
                    key.key().fingerprint(),
                    key.key().optional_secret().cloned(),
                )
            })
            .collect()
    }

    /// A GnuPG stub must not displace secret material the store already holds.
    ///
    /// Both stub shapes parse as an encrypted secret, so `has_secret` — and
    /// therefore `Cert::is_tsk`, which is what routes a file to
    /// `insert_imported_secret` — is true of a certificate carrying nothing
    /// but stubs. A merge that prefers the incoming secret wherever there is
    /// one takes them, and the primary that could certify, revoke and set an
    /// expiry is gone.
    ///
    /// The passphrase-protected case is here because a stub and a protected
    /// key are both encrypted: anything that decides on `is_encrypted` alone
    /// gets one of the two wrong.
    #[test]
    fn a_stub_does_not_replace_a_usable_secret() {
        for password in [None, Some("correct horse")] {
            for shape in [Stub::GnuDummy, Stub::DivertToCard] {
                let (_dir, store) = scratch();
                let full = stub_host(password);
                let fingerprint = full.fingerprint().to_hex();
                store.insert_secret(&full).unwrap();
                let held = store.secret_cert(&fingerprint).unwrap();

                let stubbed = with_stubs(&full, &stub_secret(shape), |_| true);
                assert!(
                    stubbed.is_tsk(),
                    "a stub reads as secret material, which is the whole problem"
                );
                store.insert_secret(&stubbed).unwrap();

                assert_eq!(
                    secrets(&store.secret_cert(&fingerprint).unwrap()),
                    secrets(&held),
                    "{shape:?} replaced usable secret material (protected: {})",
                    password.is_some()
                );
            }
        }
    }

    /// Every key is settled on its own, not by which copy the merge saw last.
    ///
    /// The store holds a gnu-dummy primary over real subkeys — what a
    /// `gpg --export-secret-subkeys` file leaves behind when it is the first
    /// thing imported — and then the real primary arrives with its subkeys
    /// stubbed to a card. Neither copy is the better one as a whole, so
    /// neither merge order can be right: only deciding per key ends with
    /// every real secret.
    #[test]
    fn each_key_keeps_whichever_secret_is_usable() {
        for password in [None, Some("correct horse")] {
            let (_dir, store) = scratch();
            let full = stub_host(password);
            let fingerprint = full.fingerprint().to_hex();
            let primary = full.fingerprint();

            let stored = with_stubs(&full, &stub_secret(Stub::GnuDummy), |fp| *fp == primary);
            store.insert_secret(&stored).unwrap();

            let incoming = with_stubs(&full, &stub_secret(Stub::DivertToCard), |fp| *fp != primary);
            store.insert_secret(&incoming).unwrap();

            assert_eq!(
                secrets(&store.secret_cert(&fingerprint).unwrap()),
                secrets(&full),
                "every key should have ended with its real secret (protected: {})",
                password.is_some()
            );
        }
    }

    /// Where nothing usable is held, a stub is still worth keeping.
    ///
    /// It is the only record that the key exists somewhere else — on a card,
    /// or on the machine the export came from — and dropping it would leave a
    /// certificate that does not mention the subkey at all.
    #[test]
    fn a_stub_is_kept_where_no_secret_is_held() {
        let (_dir, store) = scratch();
        let full = stub_host(None);
        let fingerprint = full.fingerprint().to_hex();
        let primary = full.fingerprint();

        // The primary's secret and nothing else, so the store holds no subkey
        // secret for the stubs to be weighed against.
        let mut bytes = Vec::new();
        let only_primary = primary.clone();
        full.as_tsk()
            .set_filter(move |key| key.fingerprint() == only_primary)
            .serialize(&mut bytes)
            .unwrap();
        store
            .insert_secret(&Cert::from_bytes(&bytes).unwrap())
            .unwrap();

        let carded = with_stubs(&full, &stub_secret(Stub::DivertToCard), |fp| *fp != primary);
        store.insert_secret(&carded).unwrap();

        let after = store.secret_cert(&fingerprint).unwrap();
        assert!(
            after.keys().subkeys().count() > 0,
            "the generated key must have subkeys, or this proves nothing"
        );
        for subkey in after.keys().subkeys() {
            let secret = subkey
                .key()
                .optional_secret()
                .expect("a stub records that the subkey exists elsewhere");
            assert!(
                !crate::secret::is_usable(secret),
                "the stub should have been kept as it arrived"
            );
        }
    }

    /// A secret file that will not parse is moved aside, never written over.
    ///
    /// It is the one case where the merge cannot run, and the bytes it cannot
    /// read may still be the only copy of a key: truncated by a failed sync,
    /// or damaged on disk. Restoring from a backup is exactly when a user
    /// re-imports over such a file, so the second half goes through
    /// `import_file`, which is the path that reaches this from the GUI.
    #[test]
    fn an_unreadable_secret_file_is_moved_aside_rather_than_overwritten() {
        let (dir, store) = scratch();
        let key = stub_host(None);
        let fingerprint = key.fingerprint().to_hex();
        let path = store.secret_path(&fingerprint);

        let mut aside = path.clone();
        aside.as_mut_os_string().push(".unreadable");
        let mut second = path.clone();
        second.as_mut_os_string().push(".unreadable.1");

        fs::write(&path, b"not a key at all").unwrap();
        store.insert_secret(&key).unwrap();
        assert_eq!(fs::read(&aside).unwrap(), b"not a key at all");
        assert!(store.secret_cert(&fingerprint).unwrap().is_tsk());

        // Again, over a second damaged file, through the import path.
        let bundle = dir.path().join("backup.pgp");
        let mut bytes = Vec::new();
        key.as_tsk().serialize(&mut bytes).unwrap();
        fs::write(&bundle, &bytes).unwrap();
        fs::write(&path, b"nor is this").unwrap();
        store.import_file(&bundle).unwrap();

        assert_eq!(fs::read(&second).unwrap(), b"nor is this");
        assert_eq!(
            fs::read(&aside).unwrap(),
            b"not a key at all",
            "the first copy set aside must not be overwritten by the second"
        );
        assert!(store.secret_cert(&fingerprint).unwrap().is_tsk());
    }

    /// An imported secret key must not become a trust root.
    ///
    /// This is the attack the distinction exists to stop: a file containing a
    /// keypair the attacker generated, plus a certification it makes over some
    /// identity. Before, importing it satisfied "I hold the secret half", the
    /// key became an implicit root, and the identity it vouched for read as
    /// authenticated.
    #[test]
    fn an_imported_secret_key_is_not_a_trust_root() {
        use crate::keygen::{KeyGenRequest, generate};
        use sequoia_openpgp::serialize::Serialize;

        let (dir, store) = scratch();

        // Generated here: a root, as before.
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        let mine_fp = mine.fingerprint().to_hex().to_uppercase();
        assert!(store.effective_roots().unwrap().contains(&mine_fp));

        // Arrived in a file: held, usable, but not a root.
        let theirs = generate(&KeyGenRequest::new("Stranger <stranger@example.org>"))
            .unwrap()
            .cert;
        let bundle = dir.path().join("theirs.pgp");
        let mut bytes = Vec::new();
        theirs.as_tsk().serialize(&mut bytes).unwrap();
        std::fs::write(&bundle, &bytes).unwrap();

        store.import_file(&bundle).unwrap();
        let theirs_fp = theirs.fingerprint().to_hex().to_uppercase();

        assert!(
            store.has_secret(&theirs_fp),
            "the key should still be held and usable for decryption"
        );
        assert!(store.imported_secrets().unwrap().contains(&theirs_fp));
        assert!(
            !store.effective_roots().unwrap().contains(&theirs_fp),
            "an imported secret key became a trust root"
        );
        // And the key generated here is untouched by any of it.
        assert!(store.effective_roots().unwrap().contains(&mine_fp));

        // The user can still promote it deliberately.
        store.set_trust_root(&theirs_fp, true).unwrap();
        assert!(store.effective_roots().unwrap().contains(&theirs_fp));
    }

    /// `implicit_roots` holds a key generated here, listed or not, and no other
    /// key: not an imported one, and not one the explicit list alone makes a
    /// root.
    ///
    /// These are the keys the web of trust starts from whatever the list says,
    /// and the details pane locks the Trust root box for exactly them. A key
    /// counted here that should not be would be a root nothing in the window
    /// could take back; a key generated here and left out would be no root
    /// until ticked, as if it had been imported.
    #[test]
    fn implicit_roots_are_the_keys_generated_here_and_no_others() {
        use crate::keygen::{KeyGenRequest, generate};

        let (_dir, store) = scratch();
        let generate = |user_id: &str| generate(&KeyGenRequest::new(user_id)).unwrap().cert;
        let mine = generate("Me <me@example.org>");
        let imported = generate("Restored <restored@example.org>");
        let promoted = generate("Promoted <promoted@example.org>");
        let other = generate("Other <other@example.org>");
        store.insert_secret(&mine).unwrap();
        store.insert_imported_secret(&imported).unwrap();
        store.insert_imported_secret(&promoted).unwrap();
        store.insert(&other).unwrap();
        let fingerprint = |cert: &Cert| cert.fingerprint().to_hex().to_uppercase();
        // The key generated here is listed too, which must not take it out.
        for listed in [&mine, &promoted, &other] {
            store.set_trust_root(&fingerprint(listed), true).unwrap();
        }

        assert_eq!(
            store.implicit_roots().unwrap(),
            BTreeSet::from([fingerprint(&mine)]),
        );
        // And effective_roots is the explicit list plus exactly these.
        assert_eq!(
            store.effective_roots().unwrap(),
            BTreeSet::from([
                fingerprint(&mine),
                fingerprint(&promoted),
                fingerprint(&other)
            ]),
        );
    }

    /// Re-importing a backup of a key generated here must not demote it.
    #[test]
    fn re_importing_your_own_key_keeps_it_a_root() {
        use crate::keygen::{KeyGenRequest, generate};
        use sequoia_openpgp::serialize::Serialize;

        let (dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        let fp = mine.fingerprint().to_hex().to_uppercase();

        let backup = dir.path().join("backup.pgp");
        let mut bytes = Vec::new();
        mine.as_tsk().serialize(&mut bytes).unwrap();
        std::fs::write(&backup, &bytes).unwrap();
        store.import_file(&backup).unwrap();

        assert!(
            !store.imported_secrets().unwrap().contains(&fp),
            "a key we already held was marked as imported"
        );
        assert!(store.effective_roots().unwrap().contains(&fp));
    }

    /// `secret_fingerprints` must answer exactly what `has_secret` answers,
    /// including for a file that will not parse.
    ///
    /// That case is the whole reason the set is built from filenames rather
    /// than from `secret_certs`, which skips unparseable files: built the other
    /// way, a damaged key would report as absent here while `has_secret` still
    /// found it, and the certificate would silently lose its "secret key" badge.
    #[test]
    fn secret_fingerprints_agrees_with_has_secret_even_on_a_damaged_file() {
        use crate::keygen::{KeyGenRequest, generate};
        let (dir, store) = scratch();

        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert(&bob).unwrap();

        // A file that looks like a key and is not one.
        let damaged = dir
            .path()
            .join("secrets")
            .join("AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444555566667777888899990.pgp");
        std::fs::write(&damaged, b"not an OpenPGP key at all").unwrap();

        let set = store.secret_fingerprints().unwrap();

        // Agrees with has_secret on the real key, and on one we do not hold.
        let alice_fp = alice.fingerprint().to_hex().to_uppercase();
        assert!(set.contains(&alice_fp));
        assert!(store.has_secret(&alice_fp));
        let bob_fp = bob.fingerprint().to_hex().to_uppercase();
        assert!(!set.contains(&bob_fp));
        assert!(!store.has_secret(&bob_fp));

        // And on the damaged one: present to both, absent from secret_certs.
        let damaged_fp = damaged
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_uppercase();
        assert!(
            set.contains(&damaged_fp),
            "a damaged file must still count as holding a secret half"
        );
        assert!(store.has_secret(&damaged_fp));
        assert!(
            !store
                .secret_certs()
                .unwrap()
                .iter()
                .any(|c| c.fingerprint().to_hex().to_uppercase() == damaged_fp),
            "secret_certs is expected to skip it - that is the divergence"
        );
    }

    /// Against the developer's own GnuPG keyring when there is one. Read-only:
    /// it imports into a scratch store and never touches ~/.gnupg.
    #[test]
    #[ignore = "reads the local GnuPG keyring"]
    fn imports_the_local_gnupg_keybox() {
        let Some(keybox) = Store::gnupg_keybox() else {
            eprintln!("no pubring.kbx; skipping");
            return;
        };
        let (_dir, store) = scratch();

        // Through import_file, so the magic-byte sniffing is exercised too.
        let imported = store.import_file(&keybox).unwrap();
        eprintln!(
            "imported {} certificate(s) from {}",
            imported.len(),
            keybox.display()
        );
        for cert in imported.iter().take(3) {
            eprintln!("  {}", crate::CertSummary::from_cert(cert).primary_user_id);
        }

        assert!(!imported.is_empty());
        assert_eq!(store.certs().unwrap().len(), imported.len());
        // A Keybox holds only public certificates.
        assert!(imported.iter().all(|c| !c.is_tsk()));
    }

    /// Secret key material and revocation certificates must not be readable
    /// by other users on the machine. Asserted on the bytes on disk, because
    /// the default umask makes 0644 the thing that happens by accident.
    #[test]
    #[cfg(unix)]
    fn private_files_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        let (dir, store) = scratch();
        let secrets = dir.path().join("secrets");

        let request = crate::keygen::KeyGenRequest::new("Alice <alice@example.org>");
        let generated = crate::keygen::generate(&request).unwrap();
        store.insert_secret(&generated.cert).unwrap();
        let fingerprint = generated.cert.fingerprint().to_hex();
        store
            .save_revocation(
                &fingerprint,
                &crate::revoke::armor(&generated.revocation).unwrap(),
            )
            .unwrap();

        assert_eq!(mode(&secrets), 0o700, "secrets directory");
        assert_eq!(mode(&store.secret_path(&fingerprint)), 0o600, "secret key");
        assert_eq!(mode(&store.revocations_dir), 0o700, "revocations directory");
        assert_eq!(
            mode(&store.revocation_path(&fingerprint)),
            0o600,
            "revocation certificate",
        );

        // A store written by an earlier version is already exposed; reopening
        // it has to repair that rather than leave it.
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            store.secret_path(&fingerprint),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        // And the revocations, which the docs always said were covered.
        fs::set_permissions(&store.revocations_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            store.revocation_path(&fingerprint),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let reopened = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
        assert_eq!(mode(&secrets), 0o700, "secrets directory after reopen");
        assert_eq!(
            mode(&reopened.secret_path(&fingerprint)),
            0o600,
            "secret key after reopen",
        );
        assert_eq!(
            mode(&reopened.revocations_dir),
            0o700,
            "revocations directory after reopen",
        );
        assert_eq!(
            mode(&reopened.revocation_path(&fingerprint)),
            0o600,
            "revocation certificate after reopen",
        );
    }

    /// Every file the store keeps for itself is replaced whole, never written
    /// into, and comes out private whatever the file it replaced was.
    ///
    /// The lists are small enough to look harmless, but a truncated
    /// imported-secrets list does not fail closed: every stranger keypair it
    /// named silently becomes a trust root again, all at once, and
    /// certifications those keys issued start rendering as verified. A write
    /// in place truncates first and can then fail — a full disk is enough — so
    /// every one of these is staged and renamed. The revocation certificate
    /// was the one written in place until now.
    ///
    /// A second hard link to each file tells the two apart, whatever the
    /// umask: a rename replaces the name and leaves the old file, still at the
    /// link, as it was, while a write in place changes what the link reads. So
    /// does a file loosened to 0o644 first, which a write in place leaves at
    /// 0o644 and a rename replaces with a new 0o600 one.
    #[test]
    fn every_file_the_store_keeps_is_replaced_rather_than_written_into() {
        use crate::keygen::{KeyGenRequest, generate};

        let (dir, store) = scratch();
        let generate = |user_id: &str| generate(&KeyGenRequest::new(user_id)).unwrap().cert;
        let alice = generate("Alice <alice@example.org>");
        let (first, second) = (
            generate("First <first@example.org>"),
            generate("Second <second@example.org>"),
        );
        let alice_fp = alice.fingerprint().to_hex();

        let replaced = |path: &Path, write_first: &dyn Fn(), write_second: &dyn Fn()| {
            write_first();
            let before = fs::read(path).unwrap();
            let mut link = path.to_path_buf();
            link.as_mut_os_string().push(".old");
            fs::hard_link(path, &link).unwrap();
            // Windows carries the same property through an ACL rather than a
            // mode, which the windows_acls tests below check: for the lists in
            // the_directory_above_the_secrets_and_its_lists_are_owner_only,
            // and for the replacement the key and the revocation go through
            // in a_file_written_over_an_exposed_one_is_owner_only.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
            }

            write_second();
            assert_ne!(
                fs::read(path).unwrap(),
                before,
                "{}: the second write has to change the file, or this proves nothing",
                path.display()
            );
            assert_eq!(
                fs::read(&link).unwrap(),
                before,
                "{} was written into rather than replaced",
                path.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{} after it was replaced", path.display());
            }
        };

        replaced(
            &store.roots_path,
            &|| store.set_trust_root(&"AB".repeat(20), true).unwrap(),
            &|| store.set_trust_root(&"CD".repeat(20), true).unwrap(),
        );
        replaced(
            &store.sha1_path,
            &|| store.set_sha1_accepted(&"AB".repeat(20), true).unwrap(),
            &|| store.set_sha1_accepted(&"CD".repeat(20), true).unwrap(),
        );
        replaced(
            &store.imported_secrets_path,
            &|| store.insert_imported_secret(&first).unwrap(),
            &|| store.insert_imported_secret(&second).unwrap(),
        );
        replaced(
            &store.secret_path(&alice_fp),
            &|| store.insert_secret(&alice).unwrap(),
            &|| {
                store
                    .insert_secret(&with_user_id(&alice, "Alice <alice@example.net>"))
                    .unwrap()
            },
        );
        // Only replaced here, never read, so any bytes will do.
        replaced(
            &store.revocation_path(&alice_fp),
            &|| store.save_revocation(&alice_fp, b"the first").unwrap(),
            &|| store.save_revocation(&alice_fp, b"the second").unwrap(),
        );

        // Nothing is left behind for the next open to trip over.
        for directory in [
            dir.path(),
            store.secrets_dir.as_path(),
            store.revocations_dir.as_path(),
        ] {
            let staging = staging_files(directory, |name| name.ends_with(".tmp"));
            assert!(staging.is_empty(), "left behind: {staging:?}");
        }
        let reopened = store.reopen().unwrap();
        assert!(
            reopened.trust_roots().unwrap().contains(&"CD".repeat(20)),
            "the list must survive a reopen"
        );
    }

    /// `cert` with one more user ID, bound by its own primary key.
    fn with_user_id(cert: &Cert, user_id: &str) -> Cert {
        use sequoia_openpgp::packet::UserID;
        use sequoia_openpgp::packet::signature::SignatureBuilder;
        use sequoia_openpgp::types::SignatureType;

        let mut signer = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let user_id = UserID::from(user_id);
        let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
            .sign_userid_binding(&mut signer, cert.primary_key().key(), &user_id)
            .unwrap();
        cert.clone()
            .insert_packets(vec![Packet::from(user_id), Packet::from(binding)])
            .unwrap()
            .0
    }

    /// While the lock is held elsewhere, no write to the store's own files
    /// lands, and each goes through once it is released.
    ///
    /// Held the way another process would hold it: its own open of the lock
    /// file, locked with std's call rather than the store's. None of these
    /// writes took a lock before, so each landed at once, whatever else was
    /// writing.
    #[test]
    fn every_write_waits_while_the_lock_is_held_elsewhere() {
        use crate::keygen::{KeyGenRequest, generate};

        let (_dir, store) = scratch();
        let generated = generate(&KeyGenRequest::new("Alice <alice@example.org>")).unwrap();
        let alice = generated.cert.clone();
        let armored = crate::revoke::armor(&generated.revocation).unwrap();
        let imported = generate(&KeyGenRequest::new("Imported <imported@example.org>"))
            .unwrap()
            .cert;
        let public = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert(&public).unwrap();
        let fingerprint = |cert: &Cert| cert.fingerprint().to_hex();
        let listed = "AB".repeat(20);
        // What a crash leaves behind, which only an open removes.
        let leftover = store.roots_path.with_file_name("trust-roots.tmp");
        fs::write(&leftover, b"half a list").unwrap();

        let elsewhere = fs::OpenOptions::new()
            .write(true)
            .open(&store.lock_path)
            .unwrap();
        elsewhere.lock().unwrap();

        let landed = || {
            [
                store.trust_roots().unwrap().contains(&listed),
                store.sha1_accepted().unwrap().contains(&listed),
                store.has_secret(&fingerprint(&alice)),
                store.has_secret(&fingerprint(&imported)),
                store.has_revocation(&fingerprint(&alice)),
                !store.cert_path(&fingerprint(&public)).exists(),
                !leftover.exists(),
            ]
        };
        std::thread::scope(|scope| {
            let writes = [
                scope.spawn(|| store.set_trust_root(&listed, true)),
                scope.spawn(|| store.set_sha1_accepted(&listed, true)),
                scope.spawn(|| store.insert_secret(&alice)),
                scope.spawn(|| store.insert_imported_secret(&imported)),
                scope.spawn(|| store.save_revocation(&fingerprint(&alice), &armored)),
                scope.spawn(|| store.delete(&fingerprint(&public), false)),
                scope.spawn(|| store.reopen().map(drop)),
            ];

            std::thread::sleep(Duration::from_millis(500));
            assert_eq!(
                landed(),
                [false; 7],
                "a write landed while the lock was held elsewhere"
            );

            elsewhere.unlock().unwrap();
            for write in writes {
                write.join().unwrap().unwrap();
            }
        });
        assert_eq!(
            landed(),
            [true; 7],
            "every write lands once the lock is free"
        );
    }

    /// An import that had to wait for the lock looks for the key only once it
    /// holds it.
    ///
    /// Here another writer holds the lock and deletes a key generated here
    /// while an import of the same key waits. The key the import then writes
    /// came from outside, so it has to be marked imported, as it would be had
    /// the import come second. One that looked before it waited would find
    /// the key still held and write it back unmarked, and an imported key
    /// with no mark is a trust root.
    #[test]
    fn an_import_marks_a_key_that_was_deleted_while_it_waited() {
        let (_dir, store) = scratch();
        let key = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert_secret(&key).unwrap();
        let fingerprint = key.fingerprint().to_hex().to_uppercase();

        let elsewhere = fs::OpenOptions::new()
            .write(true)
            .open(&store.lock_path)
            .unwrap();
        elsewhere.lock().unwrap();
        std::thread::scope(|scope| {
            let import = scope.spawn(|| store.insert_imported_secret(&key));
            std::thread::sleep(Duration::from_millis(500));
            // The other writer's delete, made while it holds the lock.
            fs::remove_file(store.secret_path(&fingerprint)).unwrap();
            elsewhere.unlock().unwrap();
            import.join().unwrap().unwrap();
        });

        assert!(store.has_secret(&fingerprint));
        assert!(
            store.imported_secrets().unwrap().contains(&fingerprint),
            "a key imported after its delete was not marked imported"
        );
        assert!(!store.effective_roots().unwrap().contains(&fingerprint));
    }

    /// An import whose public half cert-d refuses still leaves its secret key
    /// marked imported.
    ///
    /// The secret key is on disk before the public half goes to cert-d, which
    /// happens once the lock is released. The mark used to come after cert-d,
    /// so an insert that failed there left an imported key held and unmarked,
    /// and an imported key with no mark is a trust root. Here cert-d fails
    /// because a file sits where it wants a directory for this fingerprint.
    #[test]
    fn an_import_that_cert_d_refuses_is_still_marked_imported() {
        let (_dir, store) = scratch();
        let key = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Stranger <stranger@example.org>",
        ))
        .unwrap()
        .cert;
        let fingerprint = key.fingerprint().to_hex().to_uppercase();
        let in_the_way = store
            .cert_path(&fingerprint)
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(!in_the_way.exists());
        fs::write(&in_the_way, b"").unwrap();

        assert!(
            store.insert_imported_secret(&key).is_err(),
            "cert-d took the public half after all, so this proves nothing"
        );
        assert!(store.has_secret(&fingerprint));
        assert!(
            store.imported_secrets().unwrap().contains(&fingerprint),
            "an import cert-d refused left its secret key unmarked"
        );
        assert!(!store.effective_roots().unwrap().contains(&fingerprint));
    }

    /// An import that cannot mark its key imported writes no secret key.
    ///
    /// The mark used to come after the secret key was written, so a mark that
    /// failed left an imported key held and unmarked, and an imported key with
    /// no mark is a trust root. A retry then found the key already held and
    /// never marked it at all. Here the mark fails because the list will not
    /// read, where a full disk would fail its write.
    #[test]
    fn an_import_that_cannot_be_marked_imported_writes_no_secret_key() {
        let (_dir, store) = scratch();
        let key = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Stranger <stranger@example.org>",
        ))
        .unwrap()
        .cert;
        let fingerprint = key.fingerprint().to_hex().to_uppercase();

        // Bytes that are not UTF-8, so the read fails rather than coming back
        // empty.
        fs::write(&store.imported_secrets_path, b"\xff\xfe not utf-8 \xff").unwrap();
        assert!(
            store.insert_imported_secret(&key).is_err(),
            "the damaged list did not fail the import, so this proves nothing"
        );

        // Once the list reads again, the key is no trust root, and a retry
        // marks it.
        fs::remove_file(&store.imported_secrets_path).unwrap();
        assert!(
            !store.effective_roots().unwrap().contains(&fingerprint),
            "an import that could not be marked left its key a trust root"
        );
        assert!(!store.has_secret(&fingerprint));
        store.insert_imported_secret(&key).unwrap();
        assert!(store.imported_secrets().unwrap().contains(&fingerprint));
        assert!(!store.effective_roots().unwrap().contains(&fingerprint));
    }

    /// An import handed a certificate with no secret key in it is refused
    /// before anything is written, the imported mark included.
    ///
    /// The mark comes before the secret key is written, so a refusal left to
    /// the write would come after the mark, and leave one behind for a key
    /// that never arrived. A mark like that only withholds root status, but an
    /// import that is refused should leave the store as it found it.
    #[test]
    fn an_import_with_no_secret_key_in_it_is_refused_before_it_is_marked() {
        let (_dir, store) = scratch();
        let public = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Stranger <stranger@example.org>",
        ))
        .unwrap()
        .cert
        .strip_secret_key_material();
        assert!(store.insert_imported_secret(&public).is_err());
        assert!(
            !store.imported_secrets_path.exists(),
            "a refused import marked its key imported"
        );
    }

    /// A delete that had to wait for the lock looks for a secret key only once
    /// it holds it.
    ///
    /// Here another writer holds the lock and saves a secret key for a
    /// certificate that had none, while a delete of that certificate, not
    /// confirmed for a secret key, waits. The delete has to refuse, as it
    /// would had it come second. One that looked before it waited would find
    /// no secret key and delete the certificate unconfirmed.
    #[test]
    fn a_delete_refuses_a_secret_key_that_arrived_while_it_waited() {
        use sequoia_openpgp::serialize::Serialize;

        let (_dir, store) = scratch();
        let key = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert(&key).unwrap();
        let fingerprint = key.fingerprint().to_hex();

        let elsewhere = fs::OpenOptions::new()
            .write(true)
            .open(&store.lock_path)
            .unwrap();
        elsewhere.lock().unwrap();
        let deleted = std::thread::scope(|scope| {
            let delete = scope.spawn(|| store.delete(&fingerprint, false));
            std::thread::sleep(Duration::from_millis(500));
            // The other writer's save, made while it holds the lock.
            let mut bytes = Vec::new();
            key.as_tsk().serialize(&mut bytes).unwrap();
            fs::write(store.secret_path(&fingerprint), bytes).unwrap();
            elsewhere.unlock().unwrap();
            delete.join().unwrap()
        });

        assert!(
            deleted.is_err(),
            "a certificate whose secret key arrived was deleted unconfirmed"
        );
        assert!(store.cert_path(&fingerprint).exists());
        assert!(store.has_secret(&fingerprint));
    }

    /// Writers on separate handles to one store, as two rPGP windows are, lose
    /// none of each other's changes.
    ///
    /// Each thread opens the store for itself, so only the files and the lock
    /// stand between them. Every write used to read a list, change it, and
    /// stage it under one fixed name: a writer whose read came before another's
    /// rename put back a list without the other's entry, and a writer whose
    /// staging file another had already renamed into place failed.
    #[test]
    fn writers_on_separate_handles_lose_none_of_each_others_changes() {
        const WRITERS: usize = 8;
        const EACH: usize = 5;

        let dir = tempfile::tempdir().unwrap();
        let open = || Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let fingerprint = |writer: usize, n: usize| format!("{:040X}", writer * 1000 + n);
        let stores: Vec<Store> = (0..WRITERS).map(|_| open()).collect();

        // One list at a time, every writer starting together, so that all of
        // them read at once: that is when a read the lock does not cover goes
        // stale. Errors are collected rather than unwrapped, because a writer
        // that panicked would leave the others waiting at the barrier.
        let start = std::sync::Barrier::new(WRITERS);
        let failures: Vec<String> = std::thread::scope(|scope| {
            let writers: Vec<_> = stores
                .iter()
                .enumerate()
                .map(|(writer, store)| {
                    let start = &start;
                    scope.spawn(move || {
                        let mut failures = Vec::new();
                        start.wait();
                        for n in 0..EACH {
                            if let Err(e) = store.set_trust_root(&fingerprint(writer, n), true) {
                                failures.push(e.to_string());
                            }
                        }
                        start.wait();
                        for n in 0..EACH {
                            if let Err(e) = store.set_sha1_accepted(&fingerprint(writer, n), true) {
                                failures.push(e.to_string());
                            }
                        }
                        failures
                    })
                })
                .collect();
            writers
                .into_iter()
                .flat_map(|writer| writer.join().unwrap())
                .collect()
        });
        assert!(failures.is_empty(), "{failures:#?}");

        let everything: BTreeSet<String> = (0..WRITERS)
            .flat_map(|writer| (0..EACH).map(move |n| fingerprint(writer, n)))
            .collect();
        let store = open();
        assert_eq!(store.trust_roots().unwrap(), everything);
        assert_eq!(store.sha1_accepted().unwrap(), everything);
    }

    /// Two saves of one secret key on separate handles both land, merged.
    ///
    /// Each adds a user ID, the way two windows each editing the key would.
    /// Both used to read the file before either wrote it and stage under the
    /// same fixed name, so one save failed, one user ID was lost, or the file
    /// was left holding bytes from both.
    #[test]
    fn two_saves_of_one_key_on_separate_handles_both_land() {
        let dir = tempfile::tempdir().unwrap();
        let open = || Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let (one, other) = (open(), open());
        let key = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        let fingerprint = key.fingerprint().to_hex();
        one.insert_secret(&key).unwrap();

        // Several rounds, because two writers with no lock between them lose
        // an update only when their reads and writes interleave.
        for round in 0..8 {
            let first = format!("First {round} <first@example.org>");
            let second = format!("Second {round} <second@example.org>");
            let (with_first, with_second) =
                (with_user_id(&key, &first), with_user_id(&key, &second));
            let start = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                let saves = [
                    scope.spawn(|| {
                        start.wait();
                        one.insert_secret(&with_first)
                    }),
                    scope.spawn(|| {
                        start.wait();
                        other.insert_secret(&with_second)
                    }),
                ];
                for save in saves {
                    save.join().unwrap().unwrap();
                }
            });

            let stored = one.secret_cert(&fingerprint).unwrap();
            assert!(stored.is_tsk());
            for user_id in [&first, &second] {
                assert!(
                    stored
                        .userids()
                        .any(|ua| ua.userid().value() == user_id.as_bytes()),
                    "round {round}: {user_id} was lost"
                );
            }
        }
    }

    /// A writer gives up on a lock that is never released, rather than hang.
    ///
    /// The lock here is released after two seconds, so a writer that waited
    /// without limit would still return — with the lock, which is the failure
    /// this looks for.
    #[test]
    fn a_lock_held_too_long_is_an_error_rather_than_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("write.lock");
        let elsewhere = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        elsewhere.lock().unwrap();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_secs(2));
                elsewhere.unlock().unwrap();
            });
            let started = Instant::now();
            let waited = StoreLock::acquire_within(&path, Duration::from_millis(200)).map(drop);
            assert!(
                matches!(&waited, Err(Error::Io { source, .. })
                    if source.kind() == io::ErrorKind::TimedOut),
                "{waited:?}"
            );
            assert!(started.elapsed() < Duration::from_secs(2));
        });
    }

    /// A write that fails leaves nothing beside its target, and the target as
    /// it was.
    ///
    /// The staging file can hold a whole secret key. It used to stay wherever
    /// a write failed, and nothing ever removed it, not even deleting the key.
    /// Two failures here: the writing itself, as a full disk fails it part-way,
    /// and the rename, onto a directory it cannot replace.
    #[test]
    fn a_failed_write_leaves_no_staging_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let held = StoreLock::acquire(&dir.path().join("write.lock")).unwrap();

        let path = dir.path().join("trust-roots");
        fs::write(&path, b"as it was").unwrap();
        let failed = replace_private(&held, &path, |file| {
            file.write_all(b"half of it").unwrap();
            Err(Error::invalid("the disk is full"))
        });
        assert!(failed.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"as it was");

        let in_the_way = dir.path().join("sha1-accepted");
        fs::create_dir(&in_the_way).unwrap();
        fs::write(in_the_way.join("inside"), b"").unwrap();
        assert!(write_private_atomic(&held, &in_the_way, b"never lands").is_err());

        let staging = staging_files(dir.path(), |name| name.ends_with(".tmp"));
        assert!(staging.is_empty(), "left behind: {staging:?}");
    }

    /// Deleting a secret key removes what a crashed write of it left behind,
    /// and nothing of any other key's.
    ///
    /// A staging file a crash leaves can be a whole copy of the key, and the
    /// delete used to leave it where it was while telling the user the key
    /// was gone.
    #[test]
    fn deleting_a_secret_key_removes_the_staging_files_a_crash_left_of_it() {
        let (_dir, store) = scratch();
        let key = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert_secret(&key).unwrap();
        let fingerprint = key.fingerprint().to_hex();

        let beside = |suffix: &str| {
            let mut path = store.secret_path(&fingerprint);
            path.as_mut_os_string().push(suffix);
            path
        };
        // The fixed name earlier builds staged under, and a unique one.
        let leftovers = [beside(".tmp"), beside(".4242-7.tmp")];
        let another = store
            .secret_path(&"AB".repeat(20))
            .with_extension("pgp.4242-8.tmp");
        for file in leftovers.iter().chain([&another]) {
            fs::write(file, b"a whole key, once").unwrap();
        }

        store.delete(&fingerprint, true).unwrap();
        for leftover in &leftovers {
            assert!(
                !leftover.exists(),
                "{} outlived the delete",
                leftover.display()
            );
        }
        assert!(
            another.exists(),
            "another key's staging file is not this delete's to remove"
        );
    }

    /// Opening the store removes the staging files a crash left behind, and
    /// nothing else.
    ///
    /// The unique names mean no later write reuses one, so without this they
    /// would pile up for good. The directory above the secrets is whatever the
    /// caller chose, so only names the store stages under go from there.
    #[test]
    fn opening_removes_the_staging_files_a_crash_left_behind() {
        let (dir, store) = scratch();
        fs::create_dir_all(&store.revocations_dir).unwrap();
        let fingerprint = "AB".repeat(20);
        let secrets = &store.secrets_dir;
        let leftovers = [
            secrets.join(format!("{fingerprint}.pgp.tmp")),
            secrets.join(format!("{fingerprint}.pgp.4242-7.tmp")),
            store
                .revocations_dir
                .join(format!("{fingerprint}.rev.4242-8.tmp")),
            dir.path().join("trust-roots.tmp"),
            dir.path().join("imported-secrets.4242-9.tmp"),
            dir.path().join("sha1-accepted.tmp"),
        ];
        let kept = [
            // Set aside by insert_secret, which is not a staging file.
            secrets.join(format!("{fingerprint}.pgp.unreadable")),
            dir.path().join("notes.tmp"),
            dir.path().join("trust-roots"),
        ];
        for file in leftovers.iter().chain(&kept) {
            fs::write(file, b"").unwrap();
        }

        store.reopen().unwrap();
        for leftover in &leftovers {
            assert!(
                !leftover.exists(),
                "{} outlived the open",
                leftover.display()
            );
        }
        for file in &kept {
            assert!(file.exists(), "{} is not a staging file", file.display());
        }
    }

    /// `create_private` makes a new file or nothing.
    ///
    /// It used to open whatever was at the name and truncate it: another
    /// writer's staging file, or, on Unix, a symlink planted there by anyone
    /// able to write the directory, which it then wrote through.
    #[test]
    fn create_private_never_opens_a_file_that_is_already_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-roots.tmp");
        fs::write(&path, b"somebody else's").unwrap();
        let refused = create_private(&path);
        assert!(
            matches!(&refused, Err(Error::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists),
            "{refused:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"somebody else's");

        #[cfg(unix)]
        {
            let target = dir.path().join("somewhere-else");
            let planted = dir.path().join("planted.tmp");
            std::os::unix::fs::symlink(&target, &planted).unwrap();
            assert!(create_private(&planted).is_err());
            assert!(!target.exists(), "a planted symlink was followed");
        }
    }

    /// A staging name that is already taken is passed over for the next one,
    /// for up to sixteen attempts.
    ///
    /// The process ID in the name tells processes apart only within one PID
    /// namespace. Two rPGP windows in the Flatpak can share a store and a
    /// process ID, and a crash can leave a file under a process ID since
    /// reused, so a name can be taken. That has to cost a retry, not the
    /// write, and not what is in the file there. A counter of the test's own
    /// says which names the attempts will take. Past sixteen the write gives
    /// up: a directory that answers every name that way will go on doing so,
    /// and the store's lock is held meanwhile.
    #[test]
    fn a_staging_name_already_taken_is_passed_over_for_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-roots");
        let name = |n: u64| {
            dir.path()
                .join(format!("trust-roots.{}-{n}.tmp", std::process::id()))
        };
        for n in 0..3 {
            fs::write(name(n), b"somebody else's").unwrap();
        }

        let (staging, file) = create_staging_from(&path, &AtomicU64::new(0))
            .unwrap_or_else(|e| panic!("a taken staging name failed the write: {e:?}"));
        drop(file);
        assert_eq!(staging, name(3));
        for n in 0..3 {
            assert_eq!(fs::read(name(n)).unwrap(), b"somebody else's");
        }

        for n in 100..116 {
            fs::write(name(n), b"").unwrap();
        }
        let next = AtomicU64::new(100);
        let refused = create_staging_from(&path, &next).map(|(staging, _)| staging);
        assert!(
            matches!(&refused, Err(Error::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists),
            "{refused:?}"
        );
        assert_eq!(next.load(Ordering::Relaxed), 116, "attempts made");
    }

    /// A symlink planted where trust-roots used to be staged is neither written
    /// through nor renamed into place.
    ///
    /// Every write of the list staged at `trust-roots.tmp`, opened it following
    /// symlinks and renamed it over the list, so anyone able to write the
    /// directory could point that name at a file of their own and, after the
    /// user's next change, own the list of trust roots.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_old_staging_name_is_not_written_through() {
        let (dir, store) = scratch();
        let theirs = dir.path().join("somebody-elses-roots");
        std::os::unix::fs::symlink(&theirs, dir.path().join("trust-roots.tmp")).unwrap();

        let fingerprint = "AB".repeat(20);
        store.set_trust_root(&fingerprint, true).unwrap();
        assert!(!theirs.exists(), "the list was written through the link");
        assert!(
            fs::symlink_metadata(&store.roots_path)
                .unwrap()
                .file_type()
                .is_file(),
            "trust-roots must be a file of its own"
        );
        assert!(store.trust_roots().unwrap().contains(&fingerprint));
    }

    /// The directory above the secrets and the lists in it are private as
    /// created, and repaired to that on every open.
    ///
    /// Only the files used to be. With the directory left group-writable, as a
    /// group-writable umask makes it, anyone in the group could rename a list
    /// of their own over trust-roots or unlink imported-secrets, whatever the
    /// files' own modes. Every list is repaired here, not only sha1-accepted,
    /// whose test in `tests/sha1_optin.rs` was the only one.
    #[cfg(unix)]
    #[test]
    fn the_directory_above_the_secrets_and_its_lists_are_kept_private() {
        use std::os::unix::fs::PermissionsExt;

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        // Made by the store, as open_default's rpgp directory is.
        let data = dir.path().join("rpgp");
        let secrets = data.join("secrets");
        let store = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
        assert_eq!(mode(&data), 0o700, "the directory above the secrets");

        let fingerprint = "AB".repeat(20);
        store.set_trust_root(&fingerprint, true).unwrap();
        store.set_sha1_accepted(&fingerprint, true).unwrap();
        store
            .insert_imported_secret(
                &crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
                    "Imported <imported@example.org>",
                ))
                .unwrap()
                .cert,
            )
            .unwrap();

        // Whatever an earlier build left behind. Named here rather than taken
        // from the store's own list, so that a name dropped from that list is
        // caught.
        let lists = ["trust-roots", "imported-secrets", "sha1-accepted"];
        fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
        for list in lists {
            fs::set_permissions(data.join(list), fs::Permissions::from_mode(0o644)).unwrap();
        }

        Store::open(dir.path().join("certs.d"), &secrets).unwrap();
        assert_eq!(
            mode(&data),
            0o700,
            "the directory above the secrets, reopened"
        );
        for list in lists {
            assert_eq!(mode(&data.join(list)), 0o600, "{list}, reopened");
        }
    }

    /// Opening the store is not failed by a file that vanishes while it opens.
    ///
    /// The repair finds each file first and restricts it after, and a file
    /// renamed or removed in between — by a build of rPGP that takes no lock,
    /// or by a file manager — used to fail the whole open: "rPGP could not
    /// start" at launch, or a stale list after a delete. The churn here is
    /// that other writer, as fast as it can go, in each place the repair
    /// looks: the secrets, the revocation certificates and the lists.
    ///
    /// Unix only: on Windows a file in the middle of being deleted answers
    /// "access denied" for a moment rather than "not found", which is not what
    /// this is about.
    #[cfg(unix)]
    #[test]
    fn opening_is_not_failed_by_a_file_that_vanishes_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        let revocations = dir.path().join("revocations");
        let open = || Store::open(dir.path().join("certs.d"), &secrets).map(drop);
        open().unwrap();
        fs::create_dir(&revocations).unwrap();

        let stop = std::sync::atomic::AtomicBool::new(false);
        let churn = |path: &dyn Fn(u64) -> PathBuf| {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let path = path(n);
                let _ = fs::write(&path, b"");
                let _ = fs::remove_file(&path);
                n += 1;
            }
        };
        let lists = ["trust-roots", "imported-secrets", "sha1-accepted"];
        let failed = std::thread::scope(|scope| {
            scope.spawn(|| churn(&|n| secrets.join(format!("{n:040X}.pgp"))));
            scope.spawn(|| churn(&|n| revocations.join(format!("{n:040X}.rev"))));
            scope.spawn(|| churn(&|n| dir.path().join(lists[n as usize % lists.len()])));
            let started = Instant::now();
            let failed = (0..200)
                .take_while(|_| started.elapsed() < Duration::from_secs(10))
                .map(|_| open())
                .find(Result::is_err);
            stop.store(true, Ordering::Relaxed);
            failed
        });
        assert!(failed.is_none(), "{failed:?}");
    }

    /// One file that will not parse used to take every secret key with it —
    /// and with them decryption, signing and the web-of-trust roots.
    #[test]
    fn a_damaged_secret_file_does_not_hide_the_others() {
        let (_dir, store) = scratch();
        let cert = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert_secret(&cert).unwrap();

        // What a crash mid-write, or a stray file, leaves behind.
        let junk = store.secrets_dir.join("junk.pgp");
        fs::write(&junk, b"this is not a key").unwrap();
        let empty = store.secrets_dir.join("truncated.pgp");
        fs::write(&empty, b"").unwrap();

        let certs = store.secret_certs().unwrap();
        assert_eq!(certs.len(), 1, "the good key must still be listed");
        assert_eq!(certs[0].fingerprint(), cert.fingerprint());

        let mut damaged = store.damaged_secret_files();
        damaged.sort();
        assert_eq!(damaged, vec![junk, empty]);
    }

    /// A "local" certification must never leave the store in an export.
    #[test]
    fn export_omits_local_certifications() {
        use sequoia_openpgp::parse::Parse;

        let (dir, store) = scratch();
        let generate = |uid: &str| {
            crate::keygen::generate(&crate::keygen::KeyGenRequest::new(uid))
                .unwrap()
                .cert
        };
        let alice = generate("Alice <alice@example.org>");
        let bob = generate("Bob <bob@example.org>");
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();

        let certify = |exportable: bool| {
            crate::certify::certify(
                &store,
                &crate::certify::CertifyRequest {
                    certifier: alice.fingerprint().to_hex(),
                    target: bob.fingerprint().to_hex(),
                    user_ids: vec!["Bob <bob@example.org>".into()],
                    exportable,
                    depth: 0,
                    amount: crate::certify::FULL,
                    expires: None,
                    password: None,
                },
            )
            .unwrap()
        };
        let count_certifications =
            |cert: &Cert| -> usize { cert.userids().map(|ua| ua.certifications().count()).sum() };

        // Local first. In the store it exists; in the export it must not.
        certify(false);
        assert_eq!(
            count_certifications(&store.lookup(&bob.fingerprint().to_hex()).unwrap()),
            1
        );
        let out = dir.path().join("bob-local.asc");
        store
            .export_file(&[bob.fingerprint().to_hex()], &out)
            .unwrap();
        let exported = Cert::from_file(&out).unwrap();
        assert_eq!(
            count_certifications(&exported),
            0,
            "a local certification leaked into the export"
        );

        // Control: a publishable one is written, so the export is not merely
        // stripping everything.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        certify(true);
        store
            .export_file(&[bob.fingerprint().to_hex()], &out)
            .unwrap();
        let exported = Cert::from_file(&out).unwrap();
        assert_eq!(
            count_certifications(&exported),
            1,
            "the publishable one should be there"
        );
    }

    /// An export that cannot be written is an error, not a success over an
    /// empty file.
    ///
    /// The armor used to reach the file only in a `BufWriter`'s drop, which
    /// discards a failed write, and a certificate usually fits in its buffer
    /// whole.
    ///
    /// `/dev/full` opens like a file on a full disk and fails every write the
    /// same way.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_export_that_cannot_be_written_is_an_error() {
        let (_dir, store) = scratch();
        let alice = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert(&alice).unwrap();
        let error = store
            .export_file(&[alice.fingerprint().to_hex()], "/dev/full")
            .expect_err("an export that was never written must not succeed");
        assert!(
            error.to_string().starts_with("writing /dev/full:"),
            "{error}"
        );
    }

    /// An export naming a certificate that is not held leaves the file at its
    /// path as it was.
    ///
    /// The file used to be opened and truncated before any certificate was
    /// looked up, so one that failed to resolve left an earlier file empty,
    /// or holding an armor block with no end.
    #[test]
    fn an_export_naming_a_certificate_not_held_leaves_the_file_there_as_it_was() {
        let (dir, store) = scratch();
        let alice = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert(&alice).unwrap();
        let out = dir.path().join("keys.asc");
        fs::write(&out, b"AN EARLIER EXPORT").unwrap();
        let absent = "0123456789ABCDEF0123456789ABCDEF01234567".to_string();

        for fingerprints in [
            vec![absent.clone()],
            vec![alice.fingerprint().to_hex(), absent],
        ] {
            assert!(store.export_file(&fingerprints, &out).is_err());
            assert_eq!(
                fs::read(&out).unwrap(),
                b"AN EARLIER EXPORT",
                "exporting {fingerprints:?}"
            );
        }
    }

    /// Fingerprints arrive in whatever case the caller had. The files are
    /// named in one case, so a mismatch used to make `has_secret` say no —
    /// which let `delete` skip the confirmation guarding a secret key, take
    /// the public half, and leave the secret behind.
    #[test]
    fn a_lowercase_fingerprint_finds_the_same_files() {
        let (_dir, store) = scratch();
        let generated = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap();
        store.insert_secret(&generated.cert).unwrap();
        let fingerprint = generated.cert.fingerprint().to_hex();
        let lower = fingerprint.to_lowercase();
        assert_ne!(
            lower, fingerprint,
            "a hex fingerprint has letters to differ in"
        );
        store
            .save_revocation(
                &lower,
                &crate::revoke::armor(&generated.revocation).unwrap(),
            )
            .unwrap();

        assert!(
            store.has_secret(&lower),
            "the secret key must be found either way"
        );
        assert!(store.secret_cert(&lower).is_ok());
        assert!(
            store.has_revocation(&fingerprint),
            "written lowercase, found uppercase"
        );

        // The guard must fire for a lowercase fingerprint too, and nothing
        // may have been removed when it does.
        assert!(store.delete(&lower, false).is_err());
        assert!(
            store.has_secret(&fingerprint),
            "the secret survived the refusal"
        );
        assert_eq!(store.reopen().unwrap().certs().unwrap().len(), 1);

        store.delete(&lower, true).unwrap();
        assert!(!store.has_secret(&fingerprint), "no orphaned secret key");
        assert!(store.reopen().unwrap().certs().unwrap().is_empty());
    }

    /// The fingerprints `store` lists, in the form the files are named.
    fn listed(store: &Store) -> BTreeSet<String> {
        store
            .certs()
            .unwrap()
            .iter()
            .map(|cert| cert.fingerprint().to_hex())
            .collect()
    }

    /// A deleted certificate is gone from the next listing of the store that
    /// deleted it, with no need to open the store again.
    ///
    /// cert-d's listing hands back the copy it parsed when it first met a
    /// file, and never looks at the file again, so the store listed a deleted
    /// certificate for as long as it stayed open. The GUI swapped in a
    /// reopened store after every delete to hide that, and where the reopen
    /// failed the deleted certificate came back on every reload. A secret key
    /// deleted with its certificate goes the same way.
    #[test]
    fn a_deleted_certificate_is_gone_from_the_next_listing_of_the_same_store() {
        let (_dir, store) = scratch();
        let generate = |user_id: &str| {
            crate::keygen::generate(&crate::keygen::KeyGenRequest::new(user_id))
                .unwrap()
                .cert
        };
        let (alice, bob, mine) = (
            generate("Alice <alice@example.org>"),
            generate("Bob <bob@example.org>"),
            generate("Me <me@example.org>"),
        );
        store.insert(&alice).unwrap();
        store.insert(&bob).unwrap();
        store.insert_secret(&mine).unwrap();
        let (alice, bob, mine) = (
            alice.fingerprint().to_hex(),
            bob.fingerprint().to_hex(),
            mine.fingerprint().to_hex(),
        );
        // Listed once before anything goes, as a reload would have listed
        // them, which is what fills cert-d's cache.
        assert_eq!(
            listed(&store),
            BTreeSet::from([alice.clone(), bob.clone(), mine.clone()])
        );

        store.delete(&alice, false).unwrap();
        assert_eq!(
            listed(&store),
            BTreeSet::from([bob.clone(), mine.clone()]),
            "the store that deleted the certificate still lists it"
        );
        assert!(store.lookup(&alice).is_err());

        store.delete(&mine, true).unwrap();
        assert_eq!(
            listed(&store),
            BTreeSet::from([bob]),
            "the store that deleted the key still lists its certificate"
        );
    }

    /// A listing shows what another handle on the same directories has
    /// written or deleted since this one last read it.
    ///
    /// cert-d is shared, with `sq` and with a second rPGP window, and once its
    /// listing had parsed a file it went on handing back that copy. A Refresh
    /// then showed a certificate another program had revoked as valid, and
    /// one it had deleted as still there, until the app was restarted or
    /// something looked that one certificate up on its own. One it added did
    /// appear, since the listing reads the directory for files it has not met,
    /// which makes it the control here.
    #[test]
    fn a_listing_shows_what_another_handle_changed_since_this_one_read_it() {
        let dir = tempfile::tempdir().unwrap();
        let open = || Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let (here, elsewhere) = (open(), open());
        let generate = |user_id: &str| {
            crate::keygen::generate(&crate::keygen::KeyGenRequest::new(user_id)).unwrap()
        };
        let alice = generate("Alice <alice@example.org>");
        let bob = generate("Bob <bob@example.org>").cert;
        let carol = generate("Carol <carol@example.org>").cert;
        here.insert(&alice.cert).unwrap();
        here.insert(&bob).unwrap();
        let (alice_fp, bob_fp, carol_fp) = (
            alice.cert.fingerprint().to_hex(),
            bob.fingerprint().to_hex(),
            carol.fingerprint().to_hex(),
        );

        let validity = |store: &Store, fingerprint: &str| {
            store
                .certs()
                .unwrap()
                .iter()
                .find(|cert| cert.fingerprint().to_hex() == fingerprint)
                .map(|cert| crate::CertSummary::from_cert(cert).validity)
        };
        assert_eq!(validity(&here, &alice_fp), Some(crate::Validity::Valid));
        assert_eq!(
            listed(&here),
            BTreeSet::from([alice_fp.clone(), bob_fp.clone()])
        );

        let revoked = alice
            .cert
            .clone()
            .insert_packets(alice.revocation.clone())
            .unwrap()
            .0;
        elsewhere.insert(&revoked).unwrap();
        elsewhere.delete(&bob_fp, false).unwrap();
        elsewhere.insert(&carol).unwrap();

        assert_eq!(
            validity(&here, &alice_fp),
            Some(crate::Validity::Revoked),
            "a revocation another handle stored did not reach this one's listing"
        );
        assert_eq!(
            listed(&here),
            BTreeSet::from([alice_fp, carol_fp]),
            "a certificate another handle deleted is still listed here"
        );
    }

    /// A write to cert-d that fails after the certificate has reached its
    /// file is reported as the success it was, and one that fails before
    /// anything is written is still an error.
    ///
    /// cert-d writes the file and then its SQLite index, and passes on a
    /// failure of the index, which a full disk between the two is enough for,
    /// with the certificate already in place. A certification that had been
    /// made was then reported as one that had not, and making it again put a
    /// second beside the first. The write is failed here after the real one,
    /// as the index would fail it.
    #[test]
    fn a_write_that_reached_cert_d_before_failing_is_reported_as_made() {
        let (_dir, store) = scratch();
        let bob =
            crate::keygen::generate(&crate::keygen::KeyGenRequest::new("Bob <bob@example.org>"))
                .unwrap()
                .cert;
        store.insert(&bob).unwrap();
        let fingerprint = bob.fingerprint().to_hex();
        let changed = with_user_id(&bob, "Bob <bob@work.example>");
        let has_work_address = || {
            crate::cert::user_ids(&store.lookup(&fingerprint).unwrap())
                .iter()
                .any(|uid| uid.text == "Bob <bob@work.example>")
        };

        let refused = store.insert_through(&changed, |_| {
            Err(anyhow::anyhow!("simulated: nothing reached the file"))
        });
        assert!(
            refused.is_err(),
            "a write that stored nothing was reported as made"
        );
        assert!(!has_work_address(), "the premise: nothing was written");

        store
            .insert_through(&changed, |public| {
                store.certs.update(public)?;
                Err(anyhow::anyhow!("simulated: database or disk is full"))
            })
            .expect("the certificate reached cert-d, so the write was made");
        assert!(has_work_address());
        assert!(listed(&store).contains(&fingerprint));
    }

    /// A secret key written before cert-d refused its public half says that
    /// it was kept, and the next write that cert-d takes brings the rest.
    ///
    /// The secret file is written first, so the key, or a change to it, is
    /// there even though the certificate the list, exports and Publish read
    /// did not take it. cert-d's own error came back instead, which read as a
    /// change that had not been made. Here cert-d fails because a file sits
    /// where it wants a directory for the fingerprint.
    #[test]
    fn a_secret_key_whose_certificate_cert_d_refused_says_it_was_kept() {
        let (_dir, store) = scratch();
        let generate = |user_id: &str| {
            crate::keygen::generate(&crate::keygen::KeyGenRequest::new(user_id))
                .unwrap()
                .cert
        };
        let block = |cert: &Cert| {
            let in_the_way = store
                .cert_path(&cert.fingerprint().to_hex())
                .parent()
                .unwrap()
                .to_path_buf();
            // Already there if an earlier key here shares the directory.
            if !in_the_way.exists() {
                fs::write(&in_the_way, b"").unwrap();
            }
            assert!(in_the_way.is_file());
            in_the_way
        };

        let mine = generate("Me <me@example.org>");
        let fingerprint = mine.fingerprint().to_hex();
        let in_the_way = block(&mine);
        match store.insert_secret(&mine) {
            Err(Error::PublicCertNotUpdated(_)) => {}
            other => panic!("cert-d's refusal was not reported as such: {other:?}"),
        }
        assert!(store.has_secret(&fingerprint), "the secret key was kept");
        assert!(store.lookup(&fingerprint).is_err());

        let imported = generate("Stranger <stranger@example.org>");
        block(&imported);
        match store.insert_imported_secret(&imported) {
            Err(Error::PublicCertNotUpdated(_)) => {}
            other => panic!("cert-d's refusal of an import was not reported as such: {other:?}"),
        }

        fs::remove_file(&in_the_way).unwrap();
        store.insert_secret(&mine).unwrap();
        assert!(listed(&store).contains(&fingerprint));
    }

    /// An import that stops at a certificate it cannot store says how many it
    /// had stored, and those stay.
    ///
    /// It used to return the error of the certificate that failed, which the
    /// GUI reported as an import that had failed, with the list left as it
    /// was, though the certificates before that one were in the store.
    #[test]
    fn an_import_that_stops_partway_says_how_many_it_stored() {
        let (dir, store) = scratch();
        let generate = || {
            crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
                "Someone <someone@example.org>",
            ))
            .unwrap()
            .cert
        };
        // Two whose files go in different directories of cert-d, so that one
        // can be blocked without the other.
        let first = generate();
        let second = std::iter::repeat_with(generate)
            .find(|cert| {
                store.cert_path(&cert.fingerprint().to_hex()).parent()
                    != store.cert_path(&first.fingerprint().to_hex()).parent()
            })
            .unwrap();
        let keyring = dir.path().join("keyring.pgp");
        let mut file = fs::File::create(&keyring).unwrap();
        first.serialize(&mut file).unwrap();
        second.serialize(&mut file).unwrap();
        drop(file);
        let in_the_way = store
            .cert_path(&second.fingerprint().to_hex())
            .parent()
            .unwrap()
            .to_path_buf();
        fs::write(&in_the_way, b"").unwrap();

        match store.import_file(&keyring) {
            Err(e @ Error::ImportStopped { stored: 1, .. }) => {
                let message = e.to_string();
                assert!(
                    message.starts_with("1 certificate(s) were stored, and then: "),
                    "{message}"
                );
            }
            other => panic!("the import did not say it stopped after one: {other:?}"),
        }
        assert_eq!(
            listed(&store),
            BTreeSet::from([first.fingerprint().to_hex()]),
            "what was stored before the import stopped should stay"
        );

        // Stopped at its first, it has no count to give.
        let (_dir, store) = scratch();
        let in_the_way = store
            .cert_path(&first.fingerprint().to_hex())
            .parent()
            .unwrap()
            .to_path_buf();
        fs::write(&in_the_way, b"").unwrap();
        match store.import_file(&keyring) {
            Err(e @ Error::ImportStopped { stored: 0, .. }) => {
                assert!(!e.to_string().contains("were stored"), "{e}");
            }
            other => panic!("the import did not say it stopped at once: {other:?}"),
        }
    }

    /// Deleting a secret key is not something to do by accident.
    #[test]
    fn refuses_to_delete_a_secret_key_unasked() {
        let (_dir, store) = scratch();
        let generated = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap();
        store.insert_secret(&generated.cert).unwrap();
        let fingerprint = generated.cert.fingerprint().to_hex();
        store
            .save_revocation(
                &fingerprint,
                &crate::revoke::armor(&generated.revocation).unwrap(),
            )
            .unwrap();
        store.set_trust_root(&fingerprint, true).unwrap();

        assert!(store.delete(&fingerprint, false).is_err());
        assert!(
            store.has_secret(&fingerprint),
            "the secret key must survive a refusal"
        );
        assert_eq!(store.reopen().unwrap().certs().unwrap().len(), 1);

        store.delete(&fingerprint, true).unwrap();
        assert!(!store.has_secret(&fingerprint));
        assert!(store.reopen().unwrap().certs().unwrap().is_empty());
        assert!(
            !store
                .trust_roots()
                .unwrap()
                .contains(&fingerprint.to_uppercase())
        );

        // Deliberately kept: once the secret key is gone this file is the only
        // way to retract a key that already reached a keyserver, and it cannot
        // be regenerated.
        assert!(
            store.has_revocation(&fingerprint),
            "the revocation certificate must outlive the key",
        );
    }

    /// A delete removes the certificate's trust-root and SHA-1 entries before
    /// anything else, and a certificate imported again gets neither back.
    ///
    /// The SHA-1 entry used to be left behind for good, and the trust-root
    /// entry was removed last, so a delete that could not rewrite that list
    /// had already unlinked the certificate: imported again, it was a trust
    /// root once more. Here the list will not read at first, which fails the
    /// delete at that step as a full disk would.
    #[test]
    fn a_delete_takes_the_list_entries_first_and_a_re_import_gets_none_back() {
        let (_dir, store) = scratch();
        let key =
            crate::keygen::generate(&crate::keygen::KeyGenRequest::new("Bob <bob@example.org>"))
                .unwrap()
                .cert;
        store.insert_imported_secret(&key).unwrap();
        let fingerprint = key.fingerprint().to_hex();
        store.set_trust_root(&fingerprint, true).unwrap();
        store.set_sha1_accepted(&fingerprint, true).unwrap();

        let listed = fs::read(&store.roots_path).unwrap();
        let mut damaged = listed.clone();
        damaged.extend_from_slice(b"\xff\xfe not utf-8 \xff\n");
        fs::write(&store.roots_path, &damaged).unwrap();
        assert!(
            store.delete(&fingerprint, true).is_err(),
            "the damaged list did not fail the delete, so this proves nothing"
        );
        assert!(
            store.has_secret(&fingerprint),
            "a delete that could not take the trust root out removed the secret key"
        );
        assert!(
            store.cert_path(&fingerprint).exists(),
            "a delete that could not take the trust root out removed the certificate"
        );

        fs::write(&store.roots_path, &listed).unwrap();
        store.delete(&fingerprint, true).unwrap();
        assert!(!store.trust_roots().unwrap().contains(&fingerprint));
        assert!(
            !store.sha1_accepted().unwrap().contains(&fingerprint),
            "the SHA-1 entry outlived the delete"
        );
        // Kept on purpose: it only withholds trust-root status.
        assert!(store.imported_secrets().unwrap().contains(&fingerprint));

        // Back as the lookup dialog brings a certificate in, and as a keypair.
        store.insert(&key).unwrap();
        assert!(!store.effective_roots().unwrap().contains(&fingerprint));
        assert!(store.sha1_policy().unwrap().is_strict());
        store.insert_imported_secret(&key).unwrap();
        assert!(!store.effective_roots().unwrap().contains(&fingerprint));
    }

    /// A delete leaves a list the certificate is not on as it was.
    ///
    /// The delete takes the certificate off both lists before it unlinks
    /// anything, and writing a list that does not change would make every
    /// delete depend on that write: an unwritable directory above the secrets
    /// would then refuse to delete anything, even a certificate on no list.
    /// A lowercase line tells a list written again from one left alone, since
    /// the store writes every line uppercase.
    #[test]
    fn a_delete_leaves_a_list_the_certificate_is_not_on_as_it_was() {
        let (_dir, store) = scratch();
        let cert = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        let other = format!("{}\n", "ab".repeat(20));
        for list in [&store.roots_path, &store.sha1_path] {
            fs::write(list, &other).unwrap();
        }

        store.delete(&fingerprint, false).unwrap();
        assert!(!store.cert_path(&fingerprint).exists());
        for list in [&store.roots_path, &store.sha1_path] {
            assert_eq!(
                fs::read_to_string(list).unwrap(),
                other,
                "{} was written again",
                list.display()
            );
        }
    }

    /// A fingerprint names the same entry in every list, whatever form it
    /// arrives in: spaced as the details pane shows it, lowercase, or after
    /// 0x. Input with no hex digits in it names no entry at all.
    ///
    /// set_trust_root used to store its input only upper-cased, while delete
    /// finds the files through `hex_only`. A delete given the spaced form
    /// removed the certificate and left its trust-root entry, a root again the
    /// day the certificate came back, and a newline in the input wrote two
    /// entries the same input could not take out. The lists were read only
    /// upper-cased as well, so a spaced or 0x entry already on disk matched no
    /// fingerprint, though in trust-roots the web of trust counted it a root.
    #[test]
    fn a_fingerprint_is_one_list_entry_whatever_form_it_arrives_in() {
        let (_dir, store) = scratch();
        let cert = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        let spaced = crate::cert::CertSummary::from_cert(&cert).fingerprint_pretty();
        assert_ne!(spaced, fingerprint);

        store.set_trust_root(&spaced, true).unwrap();
        assert_eq!(
            store.trust_roots().unwrap(),
            BTreeSet::from([fingerprint.clone()])
        );
        store.delete(&spaced, false).unwrap();
        assert!(
            store.trust_roots().unwrap().is_empty(),
            "a delete given the spaced form left the trust root behind"
        );
        store.insert(&cert).unwrap();
        assert!(!store.effective_roots().unwrap().contains(&fingerprint));

        // Two fingerprints on two lines are one malformed entry, not two
        // roots, and the same input takes it out again.
        let (first, second) = ("AB".repeat(20), "CD".repeat(20));
        let both = format!("{first}\n{second}");
        store.set_trust_root(&both, true).unwrap();
        let roots = store.trust_roots().unwrap();
        assert!(
            !roots.contains(&first) && !roots.contains(&second),
            "{roots:?}"
        );
        store.set_trust_root(&both, false).unwrap();
        assert!(store.trust_roots().unwrap().is_empty());

        // An entry already written in another form, by hand or by an earlier
        // build, reads as the fingerprint the web of trust parses it as, in
        // every list, and the fingerprint the window compares takes it out.
        let other_forms = format!(
            "{spaced}\n{}\n0x{}\n",
            spaced.to_lowercase(),
            fingerprint.to_lowercase()
        );
        for list in [
            &store.roots_path,
            &store.sha1_path,
            &store.imported_secrets_path,
        ] {
            fs::write(list, &other_forms).unwrap();
        }
        let just_it = BTreeSet::from([fingerprint.clone()]);
        assert_eq!(store.trust_roots().unwrap(), just_it);
        assert_eq!(store.sha1_accepted().unwrap(), just_it);
        assert_eq!(store.imported_secrets().unwrap(), just_it);
        store.set_trust_root(&fingerprint, false).unwrap();
        assert!(store.trust_roots().unwrap().is_empty());

        // Input with no hex digits in it names nothing, so nothing is written.
        fs::remove_file(&store.roots_path).unwrap();
        for nothing in ["", " : "] {
            store.set_trust_root(nothing, true).unwrap();
        }
        assert!(
            !store.roots_path.exists(),
            "input naming no fingerprint was written to the list"
        );
    }

    /// A trust-roots line that is not a fingerprint makes no root, and the
    /// next write to the list does not turn it into one.
    ///
    /// Someone editing the list by hand may switch a root off with a `#` in
    /// front of it, and the web of trust has never counted a line like that,
    /// or one written with colons. Read as their hex digits alone, the way
    /// what callers pass is reduced, each of these lines would be a live root,
    /// and the next write to the list would store it as a plain fingerprint,
    /// which every build counts. The roots are checked here the way the web of
    /// trust takes them, each parsed as a fingerprint, and the line has to go
    /// back out exactly as it came in, case included.
    #[test]
    fn a_trust_roots_line_that_is_not_a_fingerprint_never_becomes_a_root() {
        let (_dir, store) = scratch();
        let cert = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        let spaced = crate::cert::CertSummary::from_cert(&cert).fingerprint_pretty();
        let colons = fingerprint
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let makes_it_a_root = |roots: BTreeSet<String>| {
            roots
                .iter()
                .filter_map(|root| root.parse::<Fingerprint>().ok())
                .any(|root| root == cert.fingerprint())
        };
        let other = "AB".repeat(20);

        for line in [
            format!("#{fingerprint}"),
            format!("# {}", spaced.to_lowercase()),
            format!("-{fingerprint}"),
            colons,
        ] {
            assert!(line.parse::<Fingerprint>().is_err(), "{line:?} parses");
            fs::write(&store.roots_path, format!("{line}\n")).unwrap();
            assert!(
                !makes_it_a_root(store.effective_roots().unwrap()),
                "{line:?} was read as a trust root"
            );

            // Another certificate made a root and then not, which writes the
            // list twice. The line goes back out as it came in.
            store.set_trust_root(&other, true).unwrap();
            store.set_trust_root(&other, false).unwrap();
            assert_eq!(
                fs::read_to_string(&store.roots_path).unwrap(),
                format!("{line}\n"),
                "a write to the list changed {line:?}"
            );
            assert!(!makes_it_a_root(store.effective_roots().unwrap()));
        }
    }

    #[test]
    fn deleting_something_absent_is_not_an_error() {
        let (_dir, store) = scratch();
        store.delete(&"AB".repeat(20), true).unwrap();
    }

    /// Alice, and a Mallory whose primary fingerprint sorts below hers.
    ///
    /// `lookup_by_cert_or_subkey` sorts its candidates by certificate
    /// fingerprint, so which certificate comes first is not decided by who was
    /// inserted first — it is decided by the fingerprint, which an attacker
    /// picks by generating keys until one sorts where he wants it. Two tries
    /// on average, so the loop here is what he would do and not a contrivance;
    /// the bound only stops a test hanging if key generation ever stopped
    /// being random.
    fn alice_and_a_lower_sorting_mallory() -> (Cert, Cert) {
        let alice = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        for _ in 0..64 {
            let mallory = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
                "Mallory <mallory@example.org>",
            ))
            .unwrap()
            .cert;
            if mallory.fingerprint() < alice.fingerprint() {
                return (alice, mallory);
            }
        }
        panic!("64 generated keys all sorted above Alice's");
    }

    /// `carrier`, with `key` attached to it as an encryption subkey.
    ///
    /// Anyone can build this over anyone else's *public* key: a binding that
    /// claims encryption needs no primary-key back-signature, so nothing but
    /// the carrier's own secret goes into it. cert-d would index the key even
    /// with no binding at all, so this is the realistic shape rather than the
    /// cheapest one.
    fn carrying(
        carrier: &Cert,
        key: sequoia_openpgp::packet::Key<key::PublicParts, key::SubordinateRole>,
    ) -> Cert {
        use sequoia_openpgp::packet::signature::SignatureBuilder;
        use sequoia_openpgp::types::{KeyFlags, SignatureType};

        let mut signer = carrier
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let binding = key
            .bind(
                &mut signer,
                carrier,
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_key_flags(KeyFlags::empty().set_transport_encryption())
                    .unwrap(),
            )
            .unwrap();
        carrier
            .clone()
            .insert_packets(vec![Packet::from(key), binding.into()])
            .unwrap()
            .0
    }

    /// A store holding Alice, and a Mallory that sorts first and carries
    /// Alice's primary key as a subkey of his own.
    fn store_with_a_carrier() -> (tempfile::TempDir, Store, Cert, Cert) {
        let (dir, store) = scratch();
        let (alice, mallory) = alice_and_a_lower_sorting_mallory();
        let mallory = carrying(
            &mallory,
            alice.primary_key().key().clone().role_into_subordinate(),
        );
        store.insert(&alice).unwrap();
        store.insert(&mallory).unwrap();
        (dir, store, alice, mallory)
    }

    /// A handle names one certificate, and `lookup` must return that one even
    /// when another certificate in the store carries the same key.
    ///
    /// Nothing stops a stranger hanging somebody else's public key off a
    /// certificate of his own, and cert-d indexes every key packet it parses
    /// without looking at the binding, so both certificates answer to Alice's
    /// fingerprint. Drop the primary-match-first choice for the plain "first
    /// candidate" it replaced and this fails: `lookup` returns Mallory, and
    /// with him the wrong certificate to export, certify, revoke, or hand
    /// SHA-1 acceptance to.
    #[test]
    fn lookup_prefers_the_certificate_a_handle_names_over_one_carrying_its_key() {
        let (_dir, store, alice, mallory) = store_with_a_carrier();

        // The test proves nothing unless both certificates really are indexed
        // under Alice's fingerprint with Mallory's first, which is the whole
        // situation the choice exists for.
        let handle = sequoia_openpgp::KeyHandle::from(alice.fingerprint());
        let candidates = store.certs.lookup_by_cert_or_subkey(&handle).unwrap();
        let order: Vec<_> = candidates.iter().map(|c| c.fingerprint()).collect();
        assert_eq!(
            order,
            vec![mallory.fingerprint(), alice.fingerprint()],
            "cert-d should offer both certificates, Mallory's first"
        );

        assert_eq!(
            store
                .lookup(&alice.fingerprint().to_hex())
                .unwrap()
                .fingerprint(),
            alice.fingerprint(),
            "a fingerprint names a certificate, not a key some other certificate also carries"
        );
        assert_eq!(
            store.lookup(&alice.keyid().to_hex()).unwrap().fingerprint(),
            alice.fingerprint(),
            "the key ID is the second way to name the same certificate"
        );

        // The subkey-tolerant half of the search still has to work: certify
        // and revoke resolve the key that made a signature, which is usually a
        // subkey and belongs to no primary fingerprint at all.
        let own_subkey = mallory
            .keys()
            .subkeys()
            .map(|ka| ka.key().fingerprint())
            .find(|fp| *fp != alice.fingerprint())
            .expect("Mallory has subkeys of his own");
        assert_eq!(
            store.lookup(&own_subkey.to_hex()).unwrap().fingerprint(),
            mallory.fingerprint(),
            "a subkey still resolves to the certificate carrying it"
        );
    }

    /// Verification asks the other question, and gets every candidate.
    ///
    /// Return only the first and a verifier handed a certificate that merely
    /// carries the signer's subkey never gets to look at the signer's own; see
    /// `a_signature_verifies_though_another_certificate_carries_the_subkey`
    /// in [`crate::ops`] for what that costs.
    #[test]
    fn lookup_all_returns_every_certificate_carrying_the_key() {
        let (_dir, store, alice, mallory) = store_with_a_carrier();

        let found: Vec<_> = store
            .lookup_all(&alice.fingerprint().to_hex())
            .unwrap()
            .iter()
            .map(|c| c.fingerprint())
            .collect();
        assert_eq!(
            found,
            vec![mallory.fingerprint(), alice.fingerprint()],
            "both certificates carry the key, so a verifier has to be offered both"
        );

        // A key nothing carries is an empty answer rather than an error: the
        // caller turns it into a MissingKey report on that one signature
        // instead of abandoning the whole message.
        let absent = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Nobody <nobody@example.org>",
        ))
        .unwrap()
        .cert;
        assert!(
            store
                .lookup_all(&absent.fingerprint().to_hex())
                .unwrap()
                .is_empty(),
            "nothing carries this key, and that is an answer"
        );
    }

    /// The Windows counterparts of the tests above that check file modes:
    /// `private_files_are_not_world_readable`,
    /// `the_directory_above_the_secrets_and_its_lists_are_kept_private`, and the
    /// mode half of `every_file_the_store_keeps_is_replaced_rather_than_written_into`.
    ///
    /// Windows has no file mode, so the assertion is made against the DACL that is
    /// really on disk: the ACE count, the SID each ACE names, its access mask, its
    /// inheritance flags, and the SE_DACL_PROTECTED bit. "The file exists" and
    /// "the call returned Ok" both pass against the no-op these replace, which is
    /// the whole reason they are not what is checked.
    #[cfg(windows)]
    mod windows_acls {
        use super::*;

        use std::ffi::c_void;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;

        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
        };
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
            GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, OBJECT_INHERIT_ACE,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

        use crate::store::windows_acl::current_user_sid;

        /// S-1-1-0. The principal the tests plant and the code must remove.
        const EVERYONE: &str = "S-1-1-0";
        /// ACCESS_ALLOWED_ACE_TYPE. It lives in `Win32_System_SystemServices`, a
        /// module not otherwise needed and not worth enabling for one zero.
        const ALLOW: u8 = 0;
        /// OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, as they appear in the
        /// one-byte `AceFlags` of an ACE header.
        const INHERIT: u8 = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8;

        #[derive(Debug)]
        struct Ace {
            kind: u8,
            flags: u8,
            mask: u32,
            sid: String,
        }

        #[derive(Debug)]
        struct Dacl {
            protected: bool,
            aces: Vec<Ace>,
            sddl: String,
        }

        impl Dacl {
            fn grants_everyone(&self) -> bool {
                self.aces.iter().any(|ace| ace.sid == EVERYONE)
            }

            /// The whole policy in one assertion: nobody but `sid`, full control,
            /// the right inheritance, and inheritance from the parent switched off.
            #[track_caller]
            fn assert_only(&self, sid: &str, flags: u8, what: &str) {
                assert!(
                    self.protected,
                    "{what}: SE_DACL_PROTECTED is not set, so Windows will merge the parent's \
                     inheritable ACEs back in — {}",
                    self.sddl
                );
                assert_eq!(
                    self.aces.len(),
                    1,
                    "{what}: expected exactly one ACE, got {:#?} — {}",
                    self.aces,
                    self.sddl
                );
                let ace = &self.aces[0];
                assert_eq!(ace.kind, ALLOW, "{what}: ACE type — {}", self.sddl);
                assert_eq!(ace.sid, sid, "{what}: ACE principal — {}", self.sddl);
                assert_eq!(
                    ace.mask, FILE_ALL_ACCESS,
                    "{what}: access mask — {}",
                    self.sddl
                );
                assert_eq!(
                    ace.flags, flags,
                    "{what}: inheritance flags — {}",
                    self.sddl
                );
            }
        }

        fn wide(text: &str) -> Vec<u16> {
            text.encode_utf16().chain(std::iter::once(0)).collect()
        }

        fn wide_path(path: &Path) -> Vec<u16> {
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }

        fn from_wide(text: windows_sys::core::PWSTR) -> String {
            let mut len = 0;
            // SAFETY: the API that produced this pointer guarantees a non-null,
            // NUL-terminated wide string, so every read up to the terminator is in
            // bounds.
            while unsafe { *text.add(len) } != 0 {
                len += 1;
            }
            // SAFETY: `len` units from the start are initialised, as just walked.
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
        }

        /// Read the DACL that is actually on disk.
        fn read_dacl(path: &Path) -> Dacl {
            let name = wide_path(path);
            let mut dacl: *mut ACL = ptr::null_mut();
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: `name` is a live NUL-terminated wide string; `dacl` and
            // `descriptor` are valid out-pointers; the owner, group and SACL
            // out-pointers are null, which the API accepts for components not
            // named in `securityinfo`.
            let status = unsafe {
                GetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut dacl,
                    ptr::null_mut(),
                    &mut descriptor,
                )
            };
            assert_eq!(
                status,
                ERROR_SUCCESS,
                "reading the ACL of {}: {}",
                path.display(),
                io::Error::from_raw_os_error(status as i32)
            );
            // A NULL DACL is not an empty one: it grants everyone everything.
            assert!(
                !dacl.is_null(),
                "{} has a NULL DACL, which grants full access to everyone",
                path.display()
            );

            let mut control = 0u16;
            let mut revision = 0u32;
            // SAFETY: `descriptor` is the live descriptor just returned, and both
            // out-pointers are to locals.
            let ok =
                unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
            assert_ne!(ok, 0, "GetSecurityDescriptorControl on {}", path.display());
            let protected = control & SE_DACL_PROTECTED != 0;

            // SAFETY: `dacl` points into the live descriptor and is a valid ACL.
            let count = unsafe { (*dacl).AceCount };
            let mut aces = Vec::new();
            for index in 0..u32::from(count) {
                let mut raw: *mut c_void = ptr::null_mut();
                // SAFETY: `index` is below the ACL's own AceCount, so it is in
                // range, and `raw` is a valid out-pointer.
                let ok = unsafe { GetAce(dacl, index, &mut raw) };
                assert_ne!(ok, 0, "GetAce({index}) on {}", path.display());
                // SAFETY: every ACE begins with an ACE_HEADER, whatever its type.
                let header = unsafe { &*raw.cast::<ACE_HEADER>() };
                let (kind, flags) = (header.AceType, header.AceFlags);
                let (mask, sid) = if kind == ALLOW {
                    // SAFETY: the header says this is an ACCESS_ALLOWED_ACE, whose
                    // layout is header, mask, then the SID inline from SidStart.
                    let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
                    let sid = (&raw const ace.SidStart).cast_mut().cast::<c_void>();
                    (ace.Mask, sid_to_string(sid))
                } else {
                    (0, format!("<ACE type {kind}, not an allow ACE>"))
                };
                aces.push(Ace {
                    kind,
                    flags,
                    mask,
                    sid,
                });
            }

            let sddl = sddl_of(descriptor);
            // SAFETY: GetNamedSecurityInfoW documents LocalFree as the deallocator
            // for the descriptor, and `dacl` — which points inside it — is not used
            // again after this point.
            unsafe { LocalFree(descriptor.cast()) };
            Dacl {
                protected,
                aces,
                sddl,
            }
        }

        fn sid_to_string(sid: PSID) -> String {
            let mut text = ptr::null_mut();
            // SAFETY: `sid` points at a valid SID inside a live ACE, and `text` is
            // a valid out-pointer.
            let ok = unsafe { ConvertSidToStringSidW(sid, &mut text) };
            assert_ne!(ok, 0, "ConvertSidToStringSidW");
            let value = from_wide(text);
            // SAFETY: documented deallocator; `value` already owns a copy.
            unsafe { LocalFree(text.cast()) };
            value
        }

        /// Only ever used to build a panic message: one SDDL line in a CI log is
        /// far more useful than a decoded ACE dump, but it performs account lookups
        /// and can fail with ERROR_NONE_MAPPED, so it must not be the assertion.
        fn sddl_of(descriptor: PSECURITY_DESCRIPTOR) -> String {
            let mut text = ptr::null_mut();
            // SAFETY: `descriptor` is live; `text` is a valid out-pointer; the
            // length out-parameter is optional.
            let ok = unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor,
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return "<could not be rendered as SDDL>".to_string();
            }
            let value = from_wide(text);
            // SAFETY: documented deallocator; `value` already owns a copy.
            unsafe { LocalFree(text.cast()) };
            value
        }

        /// Put the ACL an older build would have left on `path`: Everyone, full
        /// control, and unprotected so the parent's ACEs keep flowing in.
        ///
        /// Written against the Win32 API directly rather than reusing the store's
        /// own helpers, so a bug in those cannot quietly turn the setup into a
        /// no-op and make the repair look successful. Every caller also asserts
        /// that the damage landed.
        fn loosen(path: &Path, inheritable: bool) {
            let flags = if inheritable { "OICI" } else { "" };
            // Us as well as Everyone, or the test could not clean up after itself.
            let text = wide(&format!(
                "D:(A;{flags};FA;;;{EVERYONE})(A;{flags};FA;;;{})",
                current_user_sid().unwrap()
            ));

            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: `text` is a live NUL-terminated wide string and `descriptor`
            // a valid out-pointer; the size out-parameter is optional.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "building the test's permissive descriptor");

            let mut dacl: *mut ACL = ptr::null_mut();
            let (mut present, mut defaulted) = (0, 0);
            // SAFETY: `descriptor` is live and the out-pointers are to locals.
            let ok = unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            };
            assert_ne!(ok, 0, "extracting the test's permissive DACL");

            let name = wide_path(path);
            // UNPROTECTED, not merely DACL: it has to clear SE_DACL_PROTECTED, or
            // the "repair an exposed store" case would start from an already
            // protected object and never exercise the interesting half.
            //
            // SAFETY: `name` is live and NUL-terminated; `dacl` points into
            // `descriptor`, which is alive until after the call.
            let status = unsafe {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    dacl,
                    ptr::null(),
                )
            };
            // SAFETY: documented deallocator; `dacl` is not used again.
            unsafe { LocalFree(descriptor.cast()) };
            assert_eq!(
                status,
                ERROR_SUCCESS,
                "loosening {}: {}",
                path.display(),
                io::Error::from_raw_os_error(status as i32)
            );
        }

        /// Property 1, atomic creation, with the parent stacked against it.
        ///
        /// The parent directory is given an inheritable Everyone ACE first. If
        /// `create_private` passes a descriptor without SE_DACL_PROTECTED, Windows
        /// merges that ACE into the new file at creation and the secret key is
        /// world-readable. Without this hostile parent the `P` would be untested:
        /// a plain tempdir may hand down nothing interesting and the test would
        /// pass with or without it.
        #[test]
        fn a_new_secret_key_is_owner_only_under_a_permissive_parent() {
            let dir = tempfile::tempdir().unwrap();
            let parent = dir.path().join("secrets");
            fs::create_dir(&parent).unwrap();

            loosen(&parent, true);
            assert!(
                read_dacl(&parent).grants_everyone(),
                "the test's own setup did not take: the parent has no Everyone ACE to inherit",
            );

            let path = parent.join("DEADBEEF.pgp");
            let mut file = create_private(&path).unwrap();
            file.write_all(b"pretend transferable secret key").unwrap();
            drop(file);

            let sid = current_user_sid().unwrap();
            read_dacl(&path).assert_only(&sid, 0, "a newly created secret key");

            // And the owner is not locked out of their own key. A DACL naming `CO`
            // would look perfectly tight to the assertion above and grant nobody
            // anything, including us; only reading the bytes back through a fresh
            // handle catches that.
            assert_eq!(fs::read(&path).unwrap(), b"pretend transferable secret key");
        }

        /// The case that is easy to miss: `CreateFileW` ignores
        /// `lpSecurityDescriptor` when the file already exists, so a key written
        /// into an exposed file kept that file's ACL. Nothing writes into an
        /// existing file any more — every write stages a new one, whose ACL
        /// arrives with it, and renames it over the old — so what has to hold
        /// is that the rename carries the staging file's ACL across rather than
        /// the destination keeping its own.
        #[test]
        fn a_file_written_over_an_exposed_one_is_owner_only() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("DEADBEEF.pgp");
            fs::write(&path, b"left behind by an older build").unwrap();
            loosen(&path, false);
            assert!(
                read_dacl(&path).grants_everyone(),
                "the test's own setup did not take: the file has no Everyone ACE",
            );

            let held = StoreLock::acquire(&dir.path().join("write.lock")).unwrap();
            write_private_atomic(&held, &path, b"rewritten").unwrap();

            read_dacl(&path).assert_only(
                &current_user_sid().unwrap(),
                0,
                "a secret key written over an exposed one",
            );
            assert_eq!(fs::read(&path).unwrap(), b"rewritten");
        }

        /// Property 2, repair on open, mirroring the chmod-and-reopen of
        /// `private_files_are_not_world_readable` over the same four paths: the
        /// secrets and the revocation certificates, each directory and the file
        /// in it. This loosened only the secrets until now, so nothing on
        /// Windows checked that the revocations are repaired as well. The
        /// directory above them is checked here only as the store first makes
        /// it; its repair, and the lists in it, are
        /// `the_directory_above_the_secrets_and_its_lists_are_owner_only`'s.
        ///
        /// Goes through `insert_secret` and `save_revocation` rather than calling
        /// `create_private` directly, so it also proves the real write paths use
        /// it. The per-file assertion after the reopen is what would fail if
        /// someone decided the directory ACL's inheritance was enough: propagation
        /// only adds inherited ACEs after a child's existing explicit ones, it
        /// never removes them.
        #[test]
        fn reopening_repairs_a_store_an_earlier_build_left_exposed() {
            let (dir, store) = scratch();
            let secrets = dir.path().join("secrets");

            let request = crate::keygen::KeyGenRequest::new("Alice <alice@example.org>");
            let generated = crate::keygen::generate(&request).unwrap();
            store.insert_secret(&generated.cert).unwrap();
            let fingerprint = generated.cert.fingerprint().to_hex();
            store
                .save_revocation(
                    &fingerprint,
                    &crate::revoke::armor(&generated.revocation).unwrap(),
                )
                .unwrap();

            let sid = current_user_sid().unwrap();
            let key = store.secret_path(&fingerprint);
            read_dacl(dir.path()).assert_only(&sid, INHERIT, "the directory above the secrets");
            read_dacl(&secrets).assert_only(&sid, INHERIT, "secrets directory");
            read_dacl(&key).assert_only(&sid, 0, "secret key");
            read_dacl(&store.revocations_dir).assert_only(&sid, INHERIT, "revocations directory");
            read_dacl(&store.revocation_path(&fingerprint)).assert_only(
                &sid,
                0,
                "revocation certificate",
            );

            // A store written by an earlier version is already exposed, and the
            // user has no way to know it.
            let revocation = store.revocation_path(&fingerprint);
            for (path, inheritable) in [
                (&secrets, true),
                (&key, false),
                (&store.revocations_dir, true),
                (&revocation, false),
            ] {
                loosen(path, inheritable);
                let before = read_dacl(path);
                assert!(
                    before.grants_everyone() && !before.protected,
                    "the test's own setup did not take on {} — {}",
                    path.display(),
                    before.sddl,
                );
            }

            let reopened = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
            read_dacl(&secrets).assert_only(&sid, INHERIT, "secrets directory after reopen");
            read_dacl(&reopened.secret_path(&fingerprint)).assert_only(
                &sid,
                0,
                "secret key after reopen",
            );
            read_dacl(&reopened.revocations_dir).assert_only(
                &sid,
                INHERIT,
                "revocations directory after reopen",
            );
            read_dacl(&reopened.revocation_path(&fingerprint)).assert_only(
                &sid,
                0,
                "revocation certificate after reopen",
            );
            assert!(
                !fs::read(&key).unwrap().is_empty(),
                "the repaired key must still be readable by the user who owns it",
            );
        }

        /// The directory above the secrets and the lists in it are owner-only
        /// as the store writes them, and repaired to that on every open.
        ///
        /// Each list is checked as its writer first makes it, as its writer
        /// leaves it after replacing an exposed copy, and after an open repairs
        /// one an earlier build left exposed. Nothing on Windows checked any
        /// of the three, although trust-roots decides whose certificate counts
        /// as fully trusted, and the comment in
        /// `every_file_the_store_keeps_is_replaced_rather_than_written_into`
        /// said these tests did.
        ///
        /// The replacement is made over an exposed copy rather than a private
        /// one. The rename that replaces a list is what decides its ACL, and a
        /// replacement that kept the old file's ACL, as ReplaceFileW does,
        /// would keep a private list private and pass regardless.
        #[test]
        fn the_directory_above_the_secrets_and_its_lists_are_owner_only() {
            use crate::keygen::{KeyGenRequest, generate};

            let dir = tempfile::tempdir().unwrap();
            // Made by the store, as open_default's rpgp directory is.
            let data = dir.path().join("rpgp");
            let secrets = data.join("secrets");
            let store = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
            let sid = current_user_sid().unwrap();
            read_dacl(&data).assert_only(&sid, INHERIT, "the directory above the secrets");

            // One entry on every list, through the store's own writers.
            let write_lists = |fingerprint: &str, user_id: &str| {
                store.set_trust_root(fingerprint, true).unwrap();
                store.set_sha1_accepted(fingerprint, true).unwrap();
                store
                    .insert_imported_secret(&generate(&KeyGenRequest::new(user_id)).unwrap().cert)
                    .unwrap();
            };
            // Named here rather than taken from the store's own list, so that a
            // name dropped from that list is caught.
            let lists = ["trust-roots", "imported-secrets", "sha1-accepted"];

            write_lists(&"AB".repeat(20), "First <first@example.org>");
            for list in lists {
                let path = data.join(list);
                read_dacl(&path).assert_only(&sid, 0, &format!("{list} as made"));
                loosen(&path, false);
                assert!(
                    read_dacl(&path).grants_everyone(),
                    "the test's own setup did not take on {list}",
                );
            }
            write_lists(&"CD".repeat(20), "Second <second@example.org>");
            for list in lists {
                read_dacl(&data.join(list)).assert_only(
                    &sid,
                    0,
                    &format!("{list} replaced over an exposed copy"),
                );
            }

            // Whatever an earlier build left behind.
            loosen(&data, true);
            for list in lists {
                loosen(&data.join(list), false);
            }
            for path in std::iter::once(data.clone()).chain(lists.map(|list| data.join(list))) {
                let before = read_dacl(&path);
                assert!(
                    before.grants_everyone() && !before.protected,
                    "the test's own setup did not take on {} — {}",
                    path.display(),
                    before.sddl,
                );
            }

            Store::open(dir.path().join("certs.d"), &secrets).unwrap();
            read_dacl(&data).assert_only(
                &sid,
                INHERIT,
                "the directory above the secrets, reopened",
            );
            for list in lists {
                read_dacl(&data.join(list)).assert_only(&sid, 0, &format!("{list}, reopened"));
            }
        }

        /// A secrets directory reached through a junction is restricted as the
        /// directory it is, with the inheritable ACE.
        ///
        /// Moving `rpgp\secrets` to another drive and leaving a junction in its
        /// place is a common way to spare a small system drive. The ACL used to
        /// be set with SetNamedSecurityInfoW, which, given the junction's path,
        /// sets the ACL of the junction itself and never reaches the directory
        /// behind it. That directory kept whatever its new location handed
        /// down, through every open. This test was written believing the
        /// opposite, that the call followed the junction, and on its first run
        /// in CI it found the directory with nothing but the ACEs it had
        /// inherited, not even the protection. It passes only if the ACL lands
        /// on the directory the junction leads to, and as a directory's, with
        /// the inheritable ACE.
        ///
        /// A junction rather than a directory symlink because making one needs
        /// no privilege, and through `mklink` because std cannot make one.
        #[test]
        fn a_secrets_directory_behind_a_junction_is_restricted_as_a_directory() {
            let dir = tempfile::tempdir().unwrap();
            let real = dir.path().join("elsewhere");
            fs::create_dir(&real).unwrap();
            let data = dir.path().join("rpgp");
            fs::create_dir(&data).unwrap();
            let secrets = data.join("secrets");
            let made = std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(&secrets)
                .arg(&real)
                .output()
                .unwrap();
            assert!(
                made.status.success(),
                "making the junction: {}{}",
                String::from_utf8_lossy(&made.stdout),
                String::from_utf8_lossy(&made.stderr),
            );
            assert!(
                fs::symlink_metadata(&secrets)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the test's own setup did not take: the secrets directory is not a junction",
            );

            Store::open(dir.path().join("certs.d"), &secrets).unwrap();
            read_dacl(&real).assert_only(
                &current_user_sid().unwrap(),
                INHERIT,
                "the directory behind the junction",
            );
        }
    }

    #[test]
    fn store_is_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Store>();
    }

    #[test]
    fn round_trips_a_generated_key() {
        let (_dir, store) = scratch();
        assert!(store.certs().unwrap().is_empty());

        let request = crate::keygen::KeyGenRequest::new("Alice <alice@example.org>");
        let cert = crate::keygen::generate(&request).unwrap().cert;
        store.insert_secret(&cert).unwrap();

        let certs = store.certs().unwrap();
        assert_eq!(certs.len(), 1);
        // The public store must not have picked up the secret half.
        assert!(!certs[0].is_tsk());
        assert!(store.has_secret(&cert.fingerprint().to_hex()));
        assert!(
            store
                .secret_cert(&cert.fingerprint().to_hex())
                .unwrap()
                .is_tsk()
        );
    }

    /// The two halves drift apart, and anything about to *act* with a key has
    /// to see both.
    ///
    /// `insert` writes cert-d and never the secret key file, so one's own
    /// revocation can arrive on the public half alone — the Import button
    /// taking back a published copy, or a keyserver refresh — and the list and
    /// the details pane then read `revoked` from cert-d while `secret_cert`
    /// still looks live. Signing, certifying and the lifecycle operations all
    /// work from the secret half, so the certificate they are given is put
    /// together here, where both files are in reach.
    #[test]
    fn the_full_certificate_carries_a_revocation_that_reached_only_cert_d() {
        let (_dir, store) = scratch();
        let generated = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap();
        let fingerprint = generated.cert.fingerprint().to_hex();
        store.insert_secret(&generated.cert).unwrap();

        // The revocation as it comes back from elsewhere: made on the owner's
        // other machine, met here as a public certificate. `insert` is the
        // entry point both Import and the keyserver use for one.
        let revoked = generated
            .cert
            .clone()
            .insert_packets(generated.revocation.clone())
            .unwrap()
            .0;
        store.insert(&revoked).unwrap();

        let validity = |cert: &Cert| crate::CertSummary::from_cert(cert).validity;
        assert_eq!(
            validity(&store.lookup(&fingerprint).unwrap()),
            crate::Validity::Revoked,
            "cert-d is where the revocation landed"
        );
        assert_eq!(
            validity(&store.secret_cert(&fingerprint).unwrap()),
            crate::Validity::Valid,
            "and the secret half is the copy that does not know — the premise here"
        );

        let full = store.full_cert(&fingerprint).unwrap();
        assert_eq!(validity(&full), crate::Validity::Revoked);
        assert!(
            full.is_tsk(),
            "the secret material must survive the merge, or nothing can sign with it"
        );

        // No secret half at all is the other shape, and the commonest one:
        // every certificate belonging to somebody else. `full_cert` is then
        // `lookup`, rather than the error `secret_cert` would return for it.
        let (_dir, store) = scratch();
        store.insert(&revoked).unwrap();
        let full = store.full_cert(&fingerprint).unwrap();
        assert_eq!(validity(&full), crate::Validity::Revoked);
        assert!(!full.is_tsk(), "there was no secret half to find");
    }
}
