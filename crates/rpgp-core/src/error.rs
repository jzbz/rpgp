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
