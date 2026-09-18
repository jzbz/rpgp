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

    #[error("{0}")]
    Invalid(String),
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
