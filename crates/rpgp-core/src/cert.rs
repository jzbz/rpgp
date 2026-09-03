//! Flattened, GUI-friendly view of a certificate.

use std::time::SystemTime;

use sequoia_openpgp::Cert;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::types::RevocationStatus;

use crate::policy;

/// The name to show for a certificate: its policy-valid primary user ID, else
/// the first user ID present, else a placeholder.
///
/// Shared with [`crate::certify`], which needs the same answer per signature.
/// It used to carry its own copy of this rule, kept in step by hand, because
/// the alternative on offer was building a whole [`CertSummary`] to read one
/// field — which also walks every key for capabilities, computes revocation
/// status and allocates a String per user ID, all of it then dropped. Taking
/// the already-resolved `ValidCert` costs none of that, so the duplication had
/// nothing left to buy.
///
/// `valid` is the certificate under whichever policy the caller cares about,
/// or `None` when it satisfies none: a certificate too weak to validate still
/// has a name, and refusing to show one is how a user loses track of the key
/// they are trying to fix.
pub(crate) fn primary_user_id(
    cert: &Cert,
    valid: Option<&sequoia_openpgp::cert::ValidCert<'_>>,
) -> String {
    let text =
        |ua: &sequoia_openpgp::packet::UserID| String::from_utf8_lossy(ua.value()).into_owned();
    valid
        .and_then(|vc| vc.primary_userid().ok())
        .map(|ua| text(ua.userid()))
        .or_else(|| match valid {
            Some(vc) => vc.userids().next().map(|ua| text(ua.userid())),
            None => cert.userids().next().map(|ua| text(ua.userid())),
        })
        .unwrap_or_else(|| "(no user ID)".to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// Binding signatures check out under the standard policy and the
    /// certificate has not expired.
    Valid,
    Expired,
    Revoked,
    /// Nothing in the certificate is usable under the standard policy: the
    /// algorithms are too weak, or the self-signatures are missing or broken.
    Unusable,
}

impl Validity {
    pub fn as_str(self) -> &'static str {
        match self {
            Validity::Valid => "valid",
            Validity::Expired => "expired",
            Validity::Revoked => "revoked",
            Validity::Unusable => "unusable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertSummary {
    pub fingerprint: String,
    pub key_id: String,
    /// Primary user ID, or a placeholder when the certificate has none that is
    /// valid under the policy.
    pub primary_user_id: String,
    pub user_ids: Vec<String>,
    pub algorithm: String,
    pub created: SystemTime,
    pub expires: Option<SystemTime>,
    pub validity: Validity,
    pub can_certify: bool,
    pub can_sign: bool,
    pub can_encrypt: bool,
    /// Whether this certificate carries secret key material.
    pub has_secret: bool,
    /// Filled in by the caller from [`crate::wot`]; `from_cert` cannot know it,
    /// because authentication is a property of the whole store, not of one
    /// certificate.
    pub authentication: crate::Authentication,
    /// Whether the user has designated this certificate a trust root.
    pub is_trust_root: bool,
    /// The certificate is unusable, and SHA-1 self-signatures are the reason —
    /// so offering the opt-in in [`crate::sha1`] would actually help. False for
    /// a certificate that is broken some other way, where the opt-in would
    /// change nothing and offering it would only mislead.
    pub sha1_blocked: bool,
    /// The user has opted this certificate into SHA-1 verification. Filled in
    /// by the caller from [`crate::Store::sha1_accepted`], like
    /// [`CertSummary::is_trust_root`] beside it.
    pub sha1_accepted: bool,
    /// Why the certificate was revoked, when it has been.
    pub revocation: Option<String>,
    /// Serial of the smartcard whose key can sign for this certificate, when
    /// the user's gpg-agent reports one. Filled in by the caller.
    pub card_serial: Option<String>,
    /// The agent can sign for this certificate, card or not.
    pub agent_backed: bool,
}

impl CertSummary {
    /// Summarise under the standard policy.
    pub fn from_cert(cert: &Cert) -> Self {
        Self::from_cert_with(cert, &policy())
    }

    /// Summarise under a caller-supplied policy.
    ///
    /// Exists so the key list can show an opted-in SHA-1 certificate as what it
    /// is — a certificate with user IDs and subkeys — rather than as `unusable`
    /// while its signatures verify perfectly well two panes over. Pass
    /// [`crate::Store::sha1_policy`] to get that; pass nothing and you get the
    /// standard policy, which is what every trust-bearing caller does.
    pub fn from_cert_with(cert: &Cert, policy: &dyn Policy) -> Self {
        let now = SystemTime::now();

        let fingerprint = cert.fingerprint().to_hex();
        let key_id = cert.keyid().to_hex();
        let algorithm = format!("{}", cert.primary_key().key().pk_algo());
        let created = cert.primary_key().key().creation_time();
        let has_secret = cert.is_tsk();

        // Everything below needs the certificate interpreted under the policy.
        // A certificate that fails to validate still gets a row in the list —
        // Kleopatra shows unusable certificates rather than hiding them — so
        // fall back to the unpoliced parts instead of returning an error.
        let valid = cert.with_policy(policy, now).ok();

        let revoked = matches!(
            cert.revocation_status(policy, now),
            RevocationStatus::Revoked(_)
        );

        // Only asked when the certificate has already failed, which keeps it
        // off the hot path: a store full of ordinary certificates pays nothing
        // for this, and a certificate that is unusable anyway is worth one more
        // check to find out whether the user can do something about it.
        let sha1_blocked =
            valid.is_none() && cert.with_policy(&crate::sha1::permissive(), now).is_ok();

        let user_ids: Vec<String> = match valid.as_ref() {
            Some(vc) => vc
                .userids()
                .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                .collect(),
            None => cert
                .userids()
                .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                .collect(),
        };

        let primary_user_id = primary_user_id(cert, valid.as_ref());

        let expires = valid
            .as_ref()
            .and_then(|vc| vc.primary_key().key_expiration_time());

        // One traversal, three answers. Each `alive()` rebuilt the whole
        // policy-filtered iterator, so asking three questions walked every
        // subkey four times — once per question plus one for the storage-key
        // chain — and from_cert runs once per certificate on every reload.
        let (mut can_certify, mut can_sign, mut can_encrypt) = (false, false, false);
        if let Some(vc) = valid.as_ref() {
            for ka in vc.keys().alive().revoked(false) {
                let Some(flags) = ka.key_flags() else {
                    continue;
                };
                can_certify |= flags.for_certification();
                can_sign |= flags.for_signing();
                can_encrypt |= flags.for_transport_encryption() || flags.for_storage_encryption();
            }
        }

        let expired = expires.is_some_and(|t| t <= now);
        let validity = if revoked {
            Validity::Revoked
        } else if valid.is_none() {
            Validity::Unusable
        } else if expired {
            Validity::Expired
        } else {
            Validity::Valid
        };

        CertSummary {
            fingerprint,
            key_id,
            primary_user_id,
            user_ids,
            algorithm,
            created,
            expires,
            validity,
            can_certify,
            can_sign,
            can_encrypt,
            has_secret,
            authentication: crate::Authentication::Unknown,
            is_trust_root: false,
            sha1_blocked,
            sha1_accepted: false,
            revocation: revoked.then(|| describe_revocation(cert)).flatten(),
            card_serial: None,
            agent_backed: false,
        }
    }

    /// `SCE` in Kleopatra's shorthand: certify, sign, encrypt.
    pub fn capabilities(&self) -> String {
        let mut out = String::new();
        if self.can_certify {
            out.push('C');
        }
        if self.can_sign {
            out.push('S');
        }
        if self.can_encrypt {
            out.push('E');
        }
        if out.is_empty() {
            out.push('-');
        }
        out
    }

    /// Fingerprint in the spaced, four-hex-digit grouping used for reading
    /// aloud and comparing by eye.
    pub fn fingerprint_pretty(&self) -> String {
        // Written into one buffer of known size. Collecting the chunks into
        // owned Strings and joining them allocated a dozen times to produce a
        // 50-character string, once per row, on every reload and keystroke.
        let hex = self.fingerprint.as_bytes();
        let groups = hex.len().div_ceil(4);
        let mut out = String::with_capacity(hex.len() + groups.saturating_sub(1));
        for (i, chunk) in hex.chunks(4).enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&String::from_utf8_lossy(chunk));
        }
        out
    }

    /// True when `needle` (lowercased by the caller) appears in any field a
    /// user would plausibly search by.
    pub fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        self.fingerprint.to_lowercase().contains(needle)
            || self.key_id.to_lowercase().contains(needle)
            || self
                .user_ids
                .iter()
                .any(|u| u.to_lowercase().contains(needle))
    }
}

/// One subkey, flattened for the details dialog.
#[derive(Debug, Clone)]
pub struct SubkeySummary {
    pub fingerprint: String,
    pub algorithm: String,
    pub created: SystemTime,
    pub expires: Option<SystemTime>,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_certify: bool,
    pub revoked: bool,
    pub has_secret: bool,
}

impl SubkeySummary {
    pub fn capabilities(&self) -> String {
        let mut out = String::new();
        if self.can_certify {
            out.push('C');
        }
        if self.can_sign {
            out.push('S');
        }
        if self.can_encrypt {
            out.push('E');
        }
        if out.is_empty() {
            out.push('-');
        }
        out
    }
}

/// Every subkey of `cert`, primary key excluded — it is already the headline
/// of the details pane.
pub fn subkeys(cert: &Cert) -> Vec<SubkeySummary> {
    subkeys_with(cert, &policy())
}

pub fn subkeys_with(cert: &Cert, policy: &dyn Policy) -> Vec<SubkeySummary> {
    let now = SystemTime::now();
    let Ok(valid) = cert.with_policy(policy, now) else {
        return Vec::new();
    };

    // ValidKeyAmalgamation has no revocation_status; ask the iterator for the
    // revoked ones and match on fingerprint.
    let revoked: std::collections::HashSet<String> = valid
        .keys()
        .subkeys()
        .revoked(true)
        .map(|ka| ka.key().fingerprint().to_hex())
        .collect();

    valid
        .keys()
        .subkeys()
        .map(|ka| SubkeySummary {
            fingerprint: ka.key().fingerprint().to_hex(),
            algorithm: format!("{}", ka.key().pk_algo()),
            created: ka.key().creation_time(),
            expires: ka.key_expiration_time(),
            can_sign: ka.for_signing(),
            can_encrypt: ka.for_transport_encryption() || ka.for_storage_encryption(),
            can_certify: ka.for_certification(),
            revoked: revoked.contains(&ka.key().fingerprint().to_hex()),
            has_secret: ka.key().has_secret(),
        })
        .collect()
}

/// One user ID with the parts the summary pane cannot show.
#[derive(Debug, Clone)]
pub struct UserIdDetail {
    pub text: String,
    pub is_primary: bool,
    pub revoked: bool,
    /// When the holder last self-signed this identity.
    pub self_signed: Option<SystemTime>,
}

pub fn user_ids(cert: &Cert) -> Vec<UserIdDetail> {
    user_ids_with(cert, &policy())
}

pub fn user_ids_with(cert: &Cert, policy: &dyn Policy) -> Vec<UserIdDetail> {
    let now = SystemTime::now();
    let primary = cert
        .with_policy(policy, now)
        .ok()
        .and_then(|vc| vc.primary_userid().ok())
        .map(|ua| ua.userid().clone());

    cert.userids()
        .map(|ua| UserIdDetail {
            text: String::from_utf8_lossy(ua.userid().value()).into_owned(),
            is_primary: primary.as_ref() == Some(ua.userid()),
            revoked: matches!(
                ua.revocation_status(policy, now),
                RevocationStatus::Revoked(_)
            ),
            self_signed: ua
                .self_signatures()
                .filter_map(|sig| sig.signature_creation_time())
                .max(),
        })
        .collect()
}

fn describe_revocation(cert: &Cert) -> Option<String> {
    let (reason, message) = crate::revoke::revocation_reason(cert)?;
    Some(if message.is_empty() {
        reason.label().to_string()
    } else {
        format!("{} — {message}", reason.label())
    })
}

/// Render a timestamp as a local-time date, or `""` for "never".
pub fn format_time(time: Option<SystemTime>) -> String {
    match time {
        Some(t) => chrono::DateTime::<chrono::Local>::from(t)
            .format("%Y-%m-%d")
            .to_string(),
        None => String::new(),
    }
}

/// Whether any key on `cert` is named as an issuer of `signature`.
///
/// Issuer subpackets may carry a fingerprint or only a key ID, so the
/// comparison goes through `KeyHandle::aliases`, which treats a key ID as
/// matching the fingerprint it abbreviates.
pub fn issued_by(
    signature: &sequoia_openpgp::packet::Signature,
    cert: &sequoia_openpgp::Cert,
) -> bool {
    signature
        .get_issuers()
        .iter()
        .any(|issuer| cert.keys().any(|ka| issuer.aliases(ka.key().key_handle())))
}
