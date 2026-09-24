/// Errors surfaced to the GUI.
///
/// Sequoia reports failures as `anyhow::Error`, so most variants are a thin
/// wrapper that keeps the original chain intact for the details pane.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("OpenPGP operation failed: {0:#}")]
    OpenPgp(#[from] anyhow::Error),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// An I/O failure from inside a Sequoia writer stack, where there is no
    /// useful path to attach.
    #[error("I/O error: {0}")]
    RawIo(#[from] std::io::Error),

    #[error("no certificate store directory could be determined")]
    NoStoreDir,

    #[error("no certificate matches {0}")]
    NoSuchCert(String),

    #[error("no usable secret key for {0}")]
    NoSecretKey(String),

    #[error("no usable encryption key for {0}")]
    NoEncryptionKey(String),

    /// A certificate its owner has withdrawn, offered for something new.
    ///
    /// The message is a whole sentence because the GUI prints these verbatim
    /// after "Encryption failed: " and the like, and someone who ticked four
    /// recipients has to be told which one was refused and why, not merely that
    /// something was. `name` is the primary user ID for the same reason: it is
    /// what the picker showed, where a fingerprint would send the reader back to
    /// the list to work out whose key it was — and where there is no user ID to
    /// show, the fingerprint is the name, since the alternative names nothing.
    /// Where an operation has two
    /// certificates in play it carries a parenthesised role as well, as in
    /// "Carol <carol@example.org> (the certifier)".
    ///
    /// A variant of its own rather than an [`Error::Invalid`] holding the same
    /// text — which would print identically — so that the sentence is written
    /// once here instead of at each of the seven places that refuse, and so that
    /// `name` and `reason` stay apart for anything that wants to say it
    /// differently.
    ///
    /// `reason` is [`crate::revoke::Reason::clause`] rather than the dialog
    /// label, so that it reads as part of this sentence instead of dropping a
    /// capitalised label — and a second set of parentheses — into the middle of
    /// it.
    ///
    /// It says no more than that. The status bar is a single line of elided
    /// text, so every word after the name and the reason is one that pushes
    /// them closer to being cut; that a revoked key is not used for anything
    /// new is what the refusal itself conveys, and the README explains.
    #[error("{name} has been revoked — {reason}")]
    Revoked { name: String, reason: String },

    /// gpg-agent was asked to decrypt with a key it holds, and did not.
    ///
    /// `reason` is the agent's own answer as it gave it, such as "Operation
    /// cancelled <Pinentry>" when the user pressed Cancel, or what scdaemon
    /// said about a card that was not there, or else why the agent could not
    /// be reached. It is not sorted into kinds, because sequoia-gpg-agent
    /// passes on the words of the answer and not its code, and gpg-agent words
    /// it in the user's language. `name` is whose key the agent was asked
    /// about, as [`Error::Revoked`] names one.
    ///
    /// The reason comes first because the status bar elides the end of a
    /// line, and the reason is what the user acts on. It used to be dropped
    /// altogether, and the decryption reported that no secret key opened the
    /// message.
    #[error("gpg-agent: {reason} (the key of {name})")]
    AgentRefused { name: String, reason: String },

    /// A message is for a passphrase-protected key held here, and that key
    /// was not opened: `tried` is false when no passphrase was given, true
    /// when those given did not unlock it.
    ///
    /// `or_password` is true when the message was encrypted to a password as
    /// well, and what was given, if anything, was tried as that password too
    /// and did not open it. Decrypt / Verify has one field for both, so what
    /// was entered may have been meant as the message's password, and a
    /// failure about the key alone would send the user to the wrong one.
    ///
    /// Only for a key a packet in the message names. It used to read as "no
    /// secret key, and no password, opens this message", which sent the user
    /// looking for a key they had when what was missing was its passphrase.
    #[error("{}", key_locked(.name, *.tried, *.or_password))]
    KeyLocked {
        name: String,
        tried: bool,
        or_password: bool,
    },

    /// A secret key was written, and its public certificate then could not
    /// be.
    ///
    /// The store keeps each of the user's keys twice: whole in the secrets
    /// directory, and its public half in cert-d, which is what the list,
    /// exports and Publish read. The secret file is written first, so a cert-d
    /// write that fails after it leaves a change in the secret key and not in
    /// the certificate. The change is not lost, because every later write of
    /// that key merges the whole secret file into cert-d, and the next one that
    /// succeeds brings it across. Passed on as it came, the cert-d error read
    /// as a change that had not been made at all, which then surfaced with
    /// some unrelated later one, or went out with the next Publish.
    #[error("saved with the secret key, but its public certificate could not be updated: {0}")]
    PublicCertNotUpdated(#[source] Box<Error>),

    /// A revocation was stored in the public certificate, and the secret key
    /// file then could not be brought in step with it.
    ///
    /// The mirror of [`Error::PublicCertNotUpdated`], for the one write that
    /// goes the other way: a revocation reaches cert-d first, which is what
    /// the list, exports and Publish read, so by the time the secret key file
    /// fails to read or to write, the key is revoked for everything that
    /// leaves the machine. Passed on as it came, that failure read as a
    /// revocation that had not been made, and an emergency revocation applied
    /// because the secret key file had become unreadable was reported as
    /// failed however often it was tried. Every operation that makes something
    /// new reads both halves through [`crate::Store::full_cert`], so it still
    /// refuses the key; what goes without the revocation is the secret key
    /// file itself, and any copy made of it.
    #[error("revoked, but the secret key file could not be updated to match: {0}")]
    SecretKeyNotUpdated(#[source] Box<Error>),

    /// An import that stopped at a certificate it could not store.
    ///
    /// `stored` is how many it had stored before that one, and those stay
    /// stored. An import used to return the failing certificate's own error,
    /// which read as though nothing had been written: the GUI tried the file
    /// as a revocation certificate next, reported the import as failed and did
    /// not read the list again, so the certificates that had arrived did not
    /// appear until something else reloaded it.
    #[error("{}", import_stopped(.stored, .source))]
    ImportStopped {
        stored: usize,
        #[source]
        source: Box<Error>,
    },

    #[error("{0}")]
    Invalid(String),
}

/// How [`Error::ImportStopped`] reads: with the count only where there is one
/// to give, since saying that no certificates were stored adds nothing to the
/// reason none were.
fn import_stopped(stored: &usize, source: &Error) -> String {
    match stored {
        0 => source.to_string(),
        stored => format!("{stored} certificate(s) were stored, and then: {source}"),
    }
}

/// How [`Error::KeyLocked`] reads, depending on whether a passphrase was
/// given at all, and whether the message's password would open it too.
fn key_locked(name: &str, tried: bool, or_password: bool) -> String {
    match (tried, or_password) {
        (false, false) => {
            format!("this message is for a passphrase-protected key: enter its passphrase ({name})")
        }
        (true, false) => format!(
            "this message is for a passphrase-protected key, and the passphrase entered \
             does not unlock it ({name})"
        ),
        (false, true) => format!(
            "this message is for a passphrase-protected key and a password: enter the key's \
             passphrase or the message's password ({name})"
        ),
        (true, true) => format!(
            "this message is for a passphrase-protected key and a password, and what was \
             entered neither unlocks the key nor opens the message ({name})"
        ),
    }
}

impl Error {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Error::Invalid(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
