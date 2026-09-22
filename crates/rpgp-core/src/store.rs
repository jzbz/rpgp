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
//! the only thing protecting it — the same trade GnuPG makes.
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

use sequoia_cert_store::store::StoreError;
use sequoia_cert_store::{CertStore, LazyCert, Store as _, StoreUpdate as _};
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;

use crate::error::{Error, Result};

pub struct Store {
    certs: CertStore<'static>,
    /// Kept so the store can be reopened after a deletion; see [`Store::reopen`].
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

    pub fn open(cert_dir: impl AsRef<Path>, secrets_dir: impl AsRef<Path>) -> Result<Self> {
        let cert_dir = cert_dir.as_ref();
        let secrets_dir = secrets_dir.as_ref();

        fs::create_dir_all(cert_dir)
            .map_err(|e| Error::io(format!("creating {}", cert_dir.display()), e))?;
        fs::create_dir_all(secrets_dir)
            .map_err(|e| Error::io(format!("creating {}", secrets_dir.display()), e))?;
        // Secret key material, and the revocation certificates that could
        // retire a key, must not be world-readable. Tighten on every open, not
        // only on create: a store made by an earlier version is already
        // exposed, and the user has no way to know it.
        restrict(secrets_dir, 0o700)?;
        for path in existing_files(secrets_dir) {
            restrict(&path, 0o600)?;
        }
        // The revocations directory too, when there is one. Anyone holding a
        // revocation certificate can retire the key it belongs to, and the
        // module doc has always claimed these are tightened on open — until
        // now it was only the secrets that were.
        let revocations_dir = secrets_dir.with_file_name("revocations");
        if revocations_dir.is_dir() {
            restrict(&revocations_dir, 0o700)?;
            for path in existing_files(&revocations_dir) {
                restrict(&path, 0o600)?;
            }
        }

        // The two bookkeeping files beside the secrets directory. Neither holds
        // key material, but trust-roots is the list of keys this user has
        // decided to trust — anyone able to write it can make a stranger's
        // certificate authenticate as fully trusted — and both were created
        // with the default mode in a parent directory this function does not
        // restrict, so they landed world-readable and group-writable on a
        // typical umask.
        for path in [
            secrets_dir.with_file_name("trust-roots"),
            secrets_dir.with_file_name("imported-secrets"),
            secrets_dir.with_file_name("sha1-accepted"),
        ] {
            if path.is_file() {
                restrict(&path, 0o600)?;
            }
        }

        Ok(Store {
            certs: CertStore::open(cert_dir)?,
            cert_dir: cert_dir.to_path_buf(),
            secrets_dir: secrets_dir.to_path_buf(),
            roots_path: secrets_dir.with_file_name("trust-roots"),
            imported_secrets_path: secrets_dir.with_file_name("imported-secrets"),
            sha1_path: secrets_dir.with_file_name("sha1-accepted"),
            revocations_dir: secrets_dir.with_file_name("revocations"),
        })
    }

    /// Remove a certificate from the store.
    ///
    /// Neither cert-d nor `sequoia-cert-store` offers a removal call, so this
    /// unlinks the file itself. The SQLite index beside it prunes entries whose
    /// file has gone, but only during a scan, and scans are rate-limited — so
    /// *this* store keeps reporting the certificate afterwards. Call
    /// [`Store::reopen`] for a view that reflects the deletion.
    ///
    /// The pre-made revocation certificate is deliberately left behind. If the
    /// key ever reached a keyserver, that file is the only way to retract it,
    /// and it cannot be regenerated once the secret key is gone — so the moment
    /// the key is deleted is exactly when it stops being redundant. Ask for it
    /// with [`Store::revocation_path`] before deleting if it should go too.
    pub fn delete(&self, fingerprint: &str, secret_too: bool) -> Result<()> {
        if self.has_secret(fingerprint) && !secret_too {
            return Err(Error::invalid(
                "this certificate has a secret key; deleting it needs to be confirmed",
            ));
        }

        // The secret first. If this fails halfway, a store still holding the
        // public certificate is the recoverable direction to fail in.
        if secret_too {
            remove_if_present(&self.secret_path(fingerprint))?;
        }
        remove_if_present(&self.cert_path(fingerprint))?;
        self.set_trust_root(fingerprint, false)?;
        Ok(())
    }

    /// A second handle on the same directories, with a fresh index.
    ///
    /// The only way to see a deletion, since a live store's index scan is
    /// rate-limited. Cheap enough for an operation a user performs by hand.
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
    pub fn save_revocation(&self, fingerprint: &str, armored: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.revocations_dir)
            .map_err(|e| Error::io(format!("creating {}", self.revocations_dir.display()), e))?;
        restrict(&self.revocations_dir, 0o700)?;

        // Anyone holding this file can retire the key it belongs to.
        let path = self.revocation_path(fingerprint);
        let mut file = create_private(&path)?;
        file.write_all(armored)
            .map_err(|e| Error::io(format!("writing {}", path.display()), e))
    }

    /// Fingerprints the user has explicitly marked as trust roots.
    pub fn trust_roots(&self) -> Result<BTreeSet<String>> {
        match fs::read_to_string(&self.roots_path) {
            Ok(text) => Ok(text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_uppercase)
                .collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(Error::io(
                format!("reading {}", self.roots_path.display()),
                e,
            )),
        }
    }

    pub fn set_trust_root(&self, fingerprint: &str, root: bool) -> Result<()> {
        let mut roots = self.trust_roots()?;
        if root {
            roots.insert(fingerprint.to_uppercase());
        } else {
            roots.remove(&fingerprint.to_uppercase());
        }

        let mut text = roots.into_iter().collect::<Vec<_>>().join("\n");
        text.push('\n');
        write_private_atomic(&self.roots_path, &text)
    }

    /// Fingerprints the user has allowed SHA-1 signatures from.
    ///
    /// Read [`crate::sha1`] before using this for anything: the list widens
    /// what *verifies*, and must never widen what is *trusted*. It is not a
    /// weaker cousin of [`Store::trust_roots`] and the two are never combined.
    pub fn sha1_accepted(&self) -> Result<BTreeSet<String>> {
        match fs::read_to_string(&self.sha1_path) {
            Ok(text) => Ok(text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_uppercase)
                .collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(Error::io(
                format!("reading {}", self.sha1_path.display()),
                e,
            )),
        }
    }

    pub fn set_sha1_accepted(&self, fingerprint: &str, accepted: bool) -> Result<()> {
        let mut list = self.sha1_accepted()?;
        let key = hex_only(fingerprint).to_uppercase();
        if accepted {
            list.insert(key);
        } else {
            list.remove(&key);
        }

        let mut text = list.into_iter().collect::<Vec<_>>().join("\n");
        text.push('\n');
        write_private_atomic(&self.sha1_path, &text)
    }

    /// The user's SHA-1 opt-in, resolved against the store.
    ///
    /// Not a policy sequoia is handed, despite the name: [`crate::Sha1Policy`]
    /// is the list of opted-in certificates, and hands out a policy per
    /// question asked of it. Empty until the user names a certificate, which
    /// is the default and stays the default until someone acts.
    ///
    /// An opted-in fingerprint that no longer resolves to a certificate is
    /// skipped rather than treated as an error: the user may have deleted the
    /// key and left the line behind, and a stale entry should cost them a
    /// silently strict verification, not a failed one.
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
        match fs::read_to_string(&self.imported_secrets_path) {
            Ok(text) => Ok(text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_uppercase)
                .collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(Error::io(
                format!("reading {}", self.imported_secrets_path.display()),
                e,
            )),
        }
    }

    /// Record a secret key as having arrived from outside.
    ///
    /// Only marks a key we do not already hold: re-importing a backup of a key
    /// you generated here must not demote it, and applying a revocation or an
    /// expiry edit rewrites the same file without changing where it came from.
    fn mark_imported_secret(&self, fingerprint: &str) -> Result<()> {
        let key = hex_only(fingerprint).to_uppercase();
        let mut imported = self.imported_secrets()?;
        if !imported.insert(key) {
            return Ok(());
        }
        let mut text = imported.into_iter().collect::<Vec<_>>().join("\n");
        text.push('\n');
        write_private_atomic(&self.imported_secrets_path, &text)
    }

    /// Store a secret key that arrived from outside, rather than one generated
    /// here. Identical to [`Store::insert_secret`] except that the key does not
    /// become an implicit trust root.
    pub fn insert_imported_secret(&self, cert: &Cert) -> Result<()> {
        let fingerprint = cert.fingerprint().to_hex();
        let already_held = self.has_secret(&fingerprint);
        self.insert_secret(cert)?;
        if !already_held {
            self.mark_imported_secret(&fingerprint)?;
        }
        Ok(())
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
    pub fn certs(&self) -> Result<Vec<CertRef>> {
        let mut out = Vec::new();
        for lazy in self.certs.certs() {
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
            Err(e)
                if matches!(
                    e.downcast_ref::<StoreError>(),
                    Some(StoreError::NotFound(_))
                ) =>
            {
                return Ok(Vec::new());
            }
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
    pub fn insert(&self, cert: &Cert) -> Result<()> {
        self.certs.update(Arc::new(LazyCert::from(
            cert.clone().strip_secret_key_material(),
        )))?;
        Ok(())
    }

    /// Store a transferable secret key, and its public half in cert-d.
    pub fn insert_secret(&self, cert: &Cert) -> Result<()> {
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

        // Written beside the target and renamed into place, so a crash while
        // serialising leaves a stray .tmp rather than a truncated .pgp. The
        // rename keeps the private mode/ACL the file was created with, and the
        // extension keeps secret_certs from ever seeing a half-written key.
        let staging = path.with_extension("pgp.tmp");
        {
            let mut file = create_private(&staging)?;
            cert.as_tsk().serialize(&mut file)?;
            file.sync_all()
                .map_err(|e| Error::io(format!("writing {}", staging.display()), e))?;
        }
        fs::rename(&staging, &path)
            .map_err(|e| Error::io(format!("writing {}", path.display()), e))?;
        self.insert(&cert)
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
    /// store holds. Withdrawals read the secret half alone and are meant to:
    /// revoking a certificate, a user ID or a subkey, and retracting a
    /// certification, are what the owner of a revoked key may still need to
    /// do, and none of them asks [`crate::revoke::refuse_if_revoked`], so
    /// there is nothing there for a merge to feed. This is the only place both
    /// files are in reach.
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
            self.insert(&cert)?;
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
            if cert.is_tsk() {
                // insert_imported_secret, not insert_secret: a secret key that
                // arrived in a file is not thereby one the user trusts.
                self.insert_imported_secret(&cert)?;
            } else {
                self.insert(&cert)?;
            }
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
    pub fn export_file(&self, fingerprints: &[String], path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let file = fs::File::create(path)
            .map_err(|e| Error::io(format!("writing {}", path.display()), e))?;
        let mut writer = sequoia_openpgp::armor::Writer::new(
            io::BufWriter::new(file),
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
        writer.finalize()?;
        Ok(())
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

/// Create a file only the current user can read, with the mode set at the
/// moment of creation.
///
/// Creating it and then relaxing to `chmod` would leave a window in which
/// another user could open the file and keep that descriptor across every
/// later write.
#[cfg(not(windows))]
fn create_private(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| Error::io(format!("writing {}", path.display()), e))
}

/// Replace a bookkeeping file atomically and privately.
///
/// The same stage-and-rename `insert_secret` uses, for the same reason: a
/// crash or a full disk between the truncate and the writeback leaves the
/// previous list intact rather than a zero-length one. That matters more here
/// than the size of the file suggests — a truncated imported-secrets list does
/// not fail closed. Every stranger keypair it used to name silently becomes a
/// trust root again, all at once, which is the door the list exists to shut.
///
/// The staging file is created private, so the result is 0o600 from the moment
/// it exists rather than 0o666 & ~umask until the next `Store::open` repairs
/// it — a whole session, in an app the user leaves running.
fn write_private_atomic(path: &Path, text: &str) -> Result<()> {
    let staging = path.with_extension("tmp");
    {
        let mut file = create_private(&staging)?;
        file.write_all(text.as_bytes())
            .map_err(|e| Error::io(format!("writing {}", staging.display()), e))?;
        file.sync_all()
            .map_err(|e| Error::io(format!("writing {}", staging.display()), e))?;
    }
    fs::rename(&staging, path).map_err(|e| Error::io(format!("writing {}", path.display()), e))
}

/// Restrict a path to the current user.
///
/// Windows has no mode, so `mode` is ignored there and the equivalent ACL is
/// derived from what the path is; see [`windows_acl`]. On a platform that is
/// neither, this is a no-op, because inventing a mapping would be worse than
/// being explicit about not having one.
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
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, HandleOrInvalid, OwnedHandle};
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_WRITE,
        GetLastError, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, WRITE_DAC,
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

    /// Restrict `path` to the current user, replacing whatever DACL it has.
    ///
    /// The repair half. Used for directories, which `fs::create_dir_all` has
    /// already made by the time we are called, and for files a previous build
    /// left behind.
    pub(super) fn restrict(path: &Path) -> Result<()> {
        // Which form of the policy applies is decided by what the path *is*,
        // not by the `mode` the caller passed: see the wrapper's doc comment.
        let container = fs::symlink_metadata(path)
            .map_err(|e| Error::io(format!("inspecting {}", path.display()), e))?
            .is_dir();

        let descriptor = SecurityDescriptor::from_sddl(&sddl(container)?)?;
        let dacl = descriptor.dacl()?;
        let wide = wide_path(path)?;

        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer alive for the call.
        // `dacl` borrows from `descriptor`, a live local, so the ACL it points
        // into outlives the call. The owner, group and SACL parameters are
        // null, which the API documents as "leave this component alone", and
        // the matching bits are absent from `securityinfo`.
        // PROTECTED_DACL_SECURITY_INFORMATION is what strips inherited ACEs
        // already on the object; DACL alone would add ours and keep theirs.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
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

        // WRITE_DAC is only for the pre-existing-file branch below;
        // GENERIC_WRITE is what the caller actually wants. The share mode
        // matches what `fs::OpenOptions` uses, because share mode is a
        // concurrency setting and not an access-control boundary — the ACL is
        // the boundary, and an exclusive open would only add spurious sharing
        // violations when an indexer or scanner holds a transient handle.
        //
        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer and `attributes`
        // (with the descriptor it points at) is alive across the call. The
        // return value is validated below before being treated as a handle.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        // Read the thread's last-error code before anything else can clobber
        // it. On success it is ERROR_ALREADY_EXISTS exactly when the file was
        // already there; on failure it is the reason.
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

        if code == ERROR_ALREADY_EXISTS {
            // CreateFileW applies lpSecurityDescriptor only when it creates the
            // file; over an existing one the member is documented to be
            // ignored, so the old ACL survived the truncation. That is the same
            // semantics as `open(O_CREAT|O_TRUNC, 0600)` on Unix, where the
            // mode likewise applies only at creation.
            //
            // This is repair, not create-then-tighten. The permissive window
            // predates this call and is not opened by it: on the path where the
            // file is new, the ACL arrives with the file and nothing runs in
            // between. Doing it on the handle rather than the path also leaves
            // no second name lookup to race.
            let dacl = descriptor.dacl()?;
            // SAFETY: `handle` is open and was requested with WRITE_DAC, which
            // this call requires. `dacl` points into `descriptor`, a live
            // local, so it outlives the call.
            let status = unsafe {
                SetSecurityInfo(
                    handle.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    dacl,
                    ptr::null(),
                )
            };
            if status != ERROR_SUCCESS {
                return Err(win32(status, format!("restricting {}", path.display())));
            }
        }

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

        /// The DACL inside this descriptor.
        ///
        /// Borrowed, not owned: it points into the same allocation, so it must
        /// not outlive `self` and must never be freed separately.
        fn dacl(&self) -> Result<*const ACL> {
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
            if present == 0 || dacl.is_null() {
                return Err(Error::invalid("the ACL policy produced no DACL"));
            }
            Ok(dacl)
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: the only constructor stores a non-null pointer returned
            // by ConvertStringSecurityDescriptorToSecurityDescriptorW, whose
            // documented deallocator is LocalFree. Drop runs at most once, so
            // there is no double free, and `dacl()` hands out borrows that
            // cannot outlive `self`.
            unsafe { LocalFree(self.0.cast()) };
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
    /// different file. The path is passed as the caller built it — no
    /// `canonicalize`, whose `\\?\` prefix the aclapi name-parsing layer is not
    /// reliably prepared for.
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

    /// The two bookkeeping lists are small enough to look harmless, but a
    /// truncated imported-secrets list does not fail closed: every stranger
    /// keypair it named silently becomes a trust root again, all at once, and
    /// certifications those keys issued start rendering as verified. A bare
    /// `fs::write` truncates first and can then fail — a full disk is enough —
    /// so the list is staged and renamed like the secret keys are.
    ///
    /// They also used to be created 0o666 & ~umask and only repaired by the
    /// next `Store::open`, which in an app the user leaves running is the rest
    /// of the session.
    #[test]
    fn the_bookkeeping_lists_are_written_privately_and_all_at_once() {
        let (dir, store) = scratch();
        let request = crate::keygen::KeyGenRequest::new("Alice <alice@example.org>");
        let generated = crate::keygen::generate(&request).unwrap();
        let fingerprint = generated.cert.fingerprint().to_hex();
        store.insert(&generated.cert).unwrap();
        store.set_trust_root(&fingerprint, true).unwrap();

        // Windows carries the same property through an ACL rather than a mode;
        // the acl tests below cover that side.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&store.roots_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "trust-roots as created");
        }

        // Nothing is left behind for the next open to trip over.
        assert!(
            !store.roots_path.with_extension("tmp").exists(),
            "the staging file must be renamed away, not left in the store"
        );

        // The rename is what makes it all-or-nothing: replacing the directory
        // entry cannot leave a half-written list, whatever happens mid-write.
        assert!(
            store
                .trust_roots()
                .unwrap()
                .contains(&fingerprint.to_uppercase())
        );
        let reopened = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        assert!(
            reopened
                .trust_roots()
                .unwrap()
                .contains(&fingerprint.to_uppercase()),
            "the list must survive a reopen"
        );
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

    /// Deletion, and the reopen it requires to be visible.
    #[test]
    fn deletes_a_public_certificate() {
        let (_dir, store) = scratch();
        let cert = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        assert_eq!(store.certs().unwrap().len(), 1);

        store.delete(&fingerprint, false).unwrap();

        // The live store still reports it: its index scan is rate-limited, and
        // that is exactly why `reopen` exists rather than being optional.
        let refreshed = store.reopen().unwrap();
        assert!(refreshed.certs().unwrap().is_empty());
        assert!(refreshed.lookup(&fingerprint).is_err());
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

    /// The Windows counterpart of `private_files_are_not_world_readable`.
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

        /// The branch that is easy to miss: `CreateFileW` ignores
        /// `lpSecurityDescriptor` when the file already exists, so overwriting an
        /// exposed key keeps its old ACL unless `create_private` notices
        /// ERROR_ALREADY_EXISTS and re-applies the DACL to the handle it holds.
        #[test]
        fn overwriting_an_exposed_key_replaces_its_acl() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("DEADBEEF.pgp");
            fs::write(&path, b"left behind by an older build").unwrap();
            loosen(&path, false);
            assert!(
                read_dacl(&path).grants_everyone(),
                "the test's own setup did not take: the file has no Everyone ACE",
            );

            let mut file = create_private(&path).unwrap();
            file.write_all(b"rewritten").unwrap();
            drop(file);

            read_dacl(&path).assert_only(
                &current_user_sid().unwrap(),
                0,
                "a secret key written over an exposed one",
            );
            assert_eq!(fs::read(&path).unwrap(), b"rewritten");
        }

        /// Property 2, repair on open, mirroring the Unix test's chmod-and-reopen.
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
            loosen(&secrets, true);
            loosen(&key, false);
            let (before_dir, before_key) = (read_dacl(&secrets), read_dacl(&key));
            assert!(
                before_dir.grants_everyone() && !before_dir.protected,
                "the test's own setup did not take on the directory — {}",
                before_dir.sddl,
            );
            assert!(
                before_key.grants_everyone() && !before_key.protected,
                "the test's own setup did not take on the key — {}",
                before_key.sddl,
            );

            let reopened = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
            read_dacl(&secrets).assert_only(&sid, INHERIT, "secrets directory after reopen");
            read_dacl(&reopened.secret_path(&fingerprint)).assert_only(
                &sid,
                0,
                "secret key after reopen",
            );
            assert!(
                !fs::read(&key).unwrap().is_empty(),
                "the repaired key must still be readable by the user who owns it",
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
