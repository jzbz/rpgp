//! Flattened, GUI-friendly view of a certificate.

use std::time::SystemTime;

use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::amalgamation::UserIDAmalgamation;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::types::RevocationStatus;

use crate::error::{Error, Result};
use crate::policy;

/// The name to show for a certificate: its policy-valid primary user ID, else
/// the first name it has signed for itself, else — for a certificate that
/// validates under no policy at all — the first name it merely carries, else a
/// placeholder.
///
/// Shared with [`crate::certify`], which needs the same answer per signature.
/// It used to carry its own copy of this rule, kept in step by hand, because
/// the alternative on offer was building a whole [`CertSummary`] to read one
/// field — which also walks every key for capabilities, computes revocation
/// status and allocates a String per user ID, all of it then dropped. Taking
/// the already-resolved `ValidCert` costs none of that, so the duplication had
/// nothing left to buy.
///
/// `valid` is the certificate under whichever policy the caller cares about, or
/// `None` when it satisfies none. A certificate too weak to validate still has
/// a name, and refusing to show one is how a user loses track of the key they
/// are trying to fix — but that reason applies just as well to a certificate
/// that *does* validate and whose user IDs do not, which is a shape sequoia
/// produces readily: the primary key falls back to its direct-key signature for
/// its own binding, so a certificate whose every user-ID binding the policy
/// rejects still validates, with no user ID in it. Such a row read "(no user
/// ID)" and could not be found by searching for the name printed on it.
///
/// The middle step is the reason this is three steps rather than two. Sequoia
/// keeps a user ID that carries no self-signature at all, so `cert.userids()`
/// includes any name a stranger appended to a certificate in flight; falling
/// straight back to it would put that name on the row, beside the `valid` pill,
/// as the certificate's own. [`self_signed_user_ids`] is the cryptographic
/// question instead of the claimed one, and only where even that finds nothing
/// — for a certificate that validates under no policy, whose row therefore
/// reads `unusable`, or `revoked` where it is both — is an unsigned name shown.
pub(crate) fn primary_user_id(
    cert: &Cert,
    valid: Option<&sequoia_openpgp::cert::ValidCert<'_>>,
) -> String {
    let text =
        |ua: &sequoia_openpgp::packet::UserID| String::from_utf8_lossy(ua.value()).into_owned();
    valid
        .and_then(|vc| vc.primary_userid().ok())
        .map(|ua| text(ua.userid()))
        .or_else(|| self_signed_user_ids(cert).next())
        .or_else(|| {
            valid
                .is_none()
                .then(|| cert.userids().next().map(|ua| text(ua.userid())))
                .flatten()
        })
        .unwrap_or_else(|| "(no user ID)".to_string())
}

/// The names a certificate has signed for itself, whatever the policy makes of
/// those signatures.
///
/// Sequoia hands out no self-signature it has not verified: `self_signatures`
/// is an `iter_verified`, which checks each one and drops those that fail. So
/// this is the cryptographic question — a user ID anyone at all can append has
/// nothing here. What it deliberately does not ask is whether the *policy*
/// accepts the signature, which is the whole case it exists for: a SHA-1
/// self-signature is a real signature the standard policy will not act on, and
/// the certificate is still that person's.
///
/// The verification is on demand rather than done once when the certificate is
/// canonicalised — sequoia moved it because doing it eagerly was expensive — so
/// it is real work here: one signature check per user ID, against a key already
/// parsed, for every row that gets this far. That is every `unusable` row on
/// every reload, where the old fallback took `cert.userids().next()` and
/// verified nothing. What it buys is the difference between a name the key
/// signed for itself and a name somebody else wrote on it.
fn self_signed_user_ids(cert: &Cert) -> impl Iterator<Item = String> + '_ {
    cert.userids()
        .filter(|ua| ua.self_signatures().next().is_some())
        .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
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
    /// Primary user ID: the policy-valid one, else a name the certificate has
    /// signed for itself, else — for a certificate that validates under no
    /// policy — one it merely carries, else a placeholder. The rule lives in
    /// `cert::primary_user_id`, which answers it for [`crate::certify`] too;
    /// plain text rather than a link because that function is crate-private.
    pub primary_user_id: String,
    /// The identities the row is searched by, from the same three steps.
    pub user_ids: Vec<String>,
    pub algorithm: String,
    pub created: SystemTime,
    pub expires: Option<SystemTime>,
    pub validity: Validity,
    /// What this app will use the certificate for, each answered under the
    /// policy the corresponding operation builds for itself and by the same key
    /// filters it selects with — so that what a picker offers and what the
    /// operation behind it accepts cannot come apart. A certificate its owner
    /// has revoked answers no to all three, as one that has expired or that
    /// does not validate already did.
    ///
    /// They are not a description of the certificate's contents. The details
    /// pane has that, per key, in [`subkeys_with`], where a revoked
    /// certificate's subkeys are still listed with the flags they carry. That
    /// pane answers under the standard policy, though, and so lists nothing for
    /// a certificate the user accepts SHA-1 from — for which the `-` on the row
    /// is now the only thing the app says about its key flags.
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
        Self::from_cert_with(cert, &crate::Sha1Policy::strict())
    }

    /// Summarise under the caller's SHA-1 opt-in.
    ///
    /// Exists so the key list can show an opted-in SHA-1 certificate as what it
    /// is — a certificate with user IDs and subkeys — rather than as `unusable`
    /// while its signatures verify perfectly well two panes over. Pass
    /// [`crate::Store::sha1_policy`] to get that; pass
    /// [`crate::Sha1Policy::strict`], as [`CertSummary::from_cert`] does, and
    /// every certificate is judged strictly, which is what every trust-bearing
    /// caller wants.
    ///
    /// The opt-in reaches what this function reports the certificate to *be*:
    /// its validity and its user IDs. It does not reach the three
    /// capability flags, which say what this app will do with the certificate
    /// and are therefore answered under the policy the operations themselves
    /// construct. Accepting SHA-1 buys the ability to check a signature and
    /// nothing else, so an opted-in certificate reports no capability at all:
    /// [`crate::ops::encrypt`] and [`crate::ops`]'s signing paths would refuse
    /// it, and a picker that offered it would be offering a refusal.
    ///
    /// Taking the concrete type rather than `&dyn Policy` is what lets the
    /// strict answer be reused rather than recomputed. A [`crate::Sha1Policy`]
    /// with nothing opted in *is* the standard policy — it delegates every
    /// question — so when it says so, the certificate under it is already the
    /// certificate under the standard policy, and the extra pass is skipped for
    /// every store where nobody has opted anything in.
    pub fn from_cert_with(cert: &Cert, policy: &crate::Sha1Policy) -> Self {
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

        // What the row is searched by, resolved exactly as the name above it
        // is: the policy-valid identities, else the ones the certificate has
        // signed for itself, else — for a certificate that validates under no
        // policy, whose row therefore reads `unusable`, or `revoked` where it
        // is both — whatever it carries. A row
        // that shows a name and cannot be found by typing it is the bug this
        // shares with `primary_user_id`.
        let user_ids: Vec<String> = match valid.as_ref() {
            Some(vc) => {
                let bound: Vec<String> = vc
                    .userids()
                    .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                    .collect();
                if bound.is_empty() {
                    self_signed_user_ids(cert).collect()
                } else {
                    bound
                }
            }
            None => cert
                .userids()
                .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                .collect(),
        };

        let primary_user_id = primary_user_id(cert, valid.as_ref());

        let expires = valid
            .as_ref()
            .and_then(|vc| vc.primary_key().key_expiration_time());

        // The certificate the capabilities below are read off: the one the
        // operations see, which is not always the one the caller does, since
        // they build `crate::policy()` themselves and never consult the opt-in
        // list.
        //
        // A revoked certificate is nothing to any of them, which the key
        // filters cannot work out for themselves: `revoked(false)` asks the
        // *certificate* only of the primary key, and asks a subkey about itself
        // alone. So a revoked certificate kept exactly the capabilities that
        // happened to sit on subkeys — "SE" for a key generated here, "E" for a
        // GnuPG-shaped one — and the pickers went on offering it for signing
        // and as a recipient with the `revoked` pill against its own row.
        // Expiry never needed this, because `alive()` does fold the
        // certificate's expiry into every subkey.
        //
        // The second pass costs nothing where it can decide nothing: not for a
        // revoked certificate, and not for a caller whose policy has nothing
        // opted in, because such a policy *is* the standard policy and `valid`
        // is already the answer.
        let strict_policy = (!revoked && !policy.is_strict()).then(crate::policy);
        let strictly_valid = strict_policy
            .as_ref()
            .and_then(|strict| cert.with_policy(strict, now).ok());
        let usable = match (revoked, policy.is_strict()) {
            (true, _) => None,
            (false, true) => valid.as_ref(),
            (false, false) => strictly_valid.as_ref(),
        };

        // One traversal for two of the three. Each `alive()` rebuilds the whole
        // policy-filtered iterator, so asking separately walked every subkey
        // once per question, and this runs once per certificate on every
        // reload. Encryption is asked of `ops` instead, at the price of a walk
        // of its own: "carries an encryption flag" and "is a key `encrypt` will
        // use" were two descriptions of one rule, and the second description is
        // precisely what drifted — the picker offered storage-only certificates
        // that encrypting then refused. `supported()` is here for the same
        // reason: `signing_keypair`, `certify` and the encryption filters all
        // select local key material with it, so a key whose algorithm this
        // build cannot use is not a capability, whatever its flags say. Their
        // agent fallbacks do not filter on it, because the agent does the
        // arithmetic rather than this build; for an agent-backed key of an
        // algorithm this build lacks, the flag is therefore the narrower of the
        // two, which is the direction a picker can afford to be wrong in.
        let (mut can_certify, mut can_sign, mut can_encrypt) = (false, false, false);
        if let Some(vc) = usable {
            for ka in vc.keys().alive().revoked(false).supported() {
                let Some(flags) = ka.key_flags() else {
                    continue;
                };
                can_certify |= flags.for_certification();
                can_sign |= flags.for_signing();
            }
            can_encrypt = crate::ops::has_encryption_key(vc);
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

/// The one user ID on `cert` that [`user_ids_with`] renders as `wanted`.
///
/// A user ID is bytes; the text every dialog shows is those bytes rendered
/// lossily, and that is not injective — every invalid byte becomes U+FFFD. Two
/// user IDs differing only there display identically, so picking the first
/// match signs over whichever came first while the list named the other, and
/// nothing in the dialog could have told the user which one they picked. Refuse
/// instead, and say why.
///
/// Sequoia sorts a certificate's user IDs by their raw bytes, so "whichever came
/// first" was not even arbitrary: it was always the lower-sorting one, silently,
/// whichever row was clicked. [`crate::certify`] has refused ambiguity since it
/// learned this; the two paths that retract something — withdrawing a
/// certification, retiring one of your own identities — kept the first match,
/// so Withdraw could sign a revocation over a user ID that carries no
/// certification of ours, and Revoke on one row could retire the row above it,
/// both reporting success. One copy of the rule, so the three cannot drift
/// apart again.
///
/// Every user ID the certificate carries is considered, including those with no
/// binding signature, because those are exactly what an ambiguous match is made
/// of: sequoia keeps a user ID anyone appended in flight, and resolving to it
/// silently is the failure this prevents.
pub(crate) fn resolve_user_id<'a>(cert: &'a Cert, wanted: &str) -> Result<UserIDAmalgamation<'a>> {
    let mut candidates = cert
        .userids()
        .filter(|ua| String::from_utf8_lossy(ua.userid().value()) == wanted);
    let found = candidates
        .next()
        .ok_or_else(|| Error::invalid(format!("{wanted} is not a user ID on this key")))?;
    if candidates.next().is_some() {
        return Err(Error::invalid(format!(
            "{wanted} matches more than one user ID on this key; they differ in \
             bytes that do not display, so there is no way to say which you meant"
        )));
    }
    Ok(found)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyGenRequest, generate};
    use crate::store::Store;
    use sequoia_openpgp::Packet;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::packet::UserID;
    use sequoia_openpgp::packet::signature::SignatureBuilder;
    use sequoia_openpgp::types::{KeyFlags, SignatureType};
    use std::time::Duration;

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    /// Revoking a key withdraws it, and which capabilities survived that used
    /// to depend on where they happened to sit.
    ///
    /// `revoked(false)` asks the *certificate* only of the primary key; of a
    /// subkey it asks that subkey alone. A key generated here certifies with
    /// its primary and signs and encrypts with subkeys, so revoking it left
    /// "SE" on the row beside the `revoked` pill, and the Sign / Encrypt dialog
    /// went on offering it as a signer and as a recipient. A GnuPG-shaped key,
    /// which signs with its primary, kept "E" instead — the same certificate
    /// state reading two different ways because of key layout.
    #[test]
    fn a_revoked_certificate_offers_no_capability() {
        let (_dir, store) = scratch();
        let cert = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let fingerprint = cert.fingerprint().to_hex();
        store.insert_secret(&cert).unwrap();
        assert_eq!(
            CertSummary::from_cert(&cert).capabilities(),
            "CSE",
            "the premise: live, it can do all three"
        );

        // The app's own default reason, Retired, which is soft — the case where
        // the key looks healthiest to anyone who has not read the revocation.
        crate::revoke::revoke_cert(&store, &crate::revoke::RevokeRequest::new(&fingerprint))
            .unwrap();
        let summary = CertSummary::from_cert(&store.lookup(&fingerprint).unwrap());
        assert_eq!(summary.validity, Validity::Revoked);
        assert_eq!(
            summary.capabilities(),
            "-",
            "a withdrawn key is not offered for anything new"
        );
        assert!(!summary.can_sign && !summary.can_encrypt && !summary.can_certify);

        // The other layout, so that the answer is the certificate's state and
        // not the arrangement of its keys. Revoked with the signature
        // `CertBuilder` hands back, which is Unspecified and therefore hard.
        let (gnupg_shaped, revocation) = CertBuilder::new()
            .add_userid("Bob <bob@example.org>")
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();
        assert_eq!(
            CertSummary::from_cert(&gnupg_shaped).capabilities(),
            "CSE",
            "the premise again, for the second layout"
        );
        let revoked = gnupg_shaped
            .insert_packets(vec![Packet::from(revocation)])
            .unwrap()
            .0;
        let summary = CertSummary::from_cert(&revoked);
        assert_eq!(summary.validity, Validity::Revoked);
        assert_eq!(summary.capabilities(), "-");
    }

    /// A certificate can validate while none of its user IDs does, and then the
    /// row showed "(no user ID)" over a certificate whose name is right there.
    ///
    /// Sequoia's primary key falls back to the direct-key signature for its own
    /// binding when no user ID binds, so the certificate as a whole is valid.
    /// The name and the searchable identities were both taken from the
    /// policy-valid user IDs alone, so the row could not be found by typing the
    /// name printed on the key — and the details pane, which reads the
    /// unpoliced user IDs, disagreed with the list about the same certificate.
    ///
    /// The binding here is expired rather than SHA-1 — the shape this build can
    /// make, since its backend refuses to *create* a SHA-1 signature — but the
    /// certificate is the same shape either way: a self-signature that verifies
    /// and that the policy will not act on.
    #[test]
    fn a_valid_certificate_whose_user_ids_do_not_bind_is_still_named_and_searchable() {
        let hour = Duration::from_secs(60 * 60);
        // Dated in the past so the expired binding below is still made after
        // the key it binds to.
        let (cert, _) = CertBuilder::new()
            .set_creation_time(SystemTime::now() - 30 * hour)
            .add_signing_subkey()
            .generate()
            .unwrap();
        let mut signer = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();

        // One name the key has signed for itself, bound by a signature that has
        // since run out; and one anybody could have appended on the way here,
        // which carries no signature at all.
        let mine = UserID::from("Old Maintainer <maint@example.org>");
        let expired = SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_signature_creation_time(SystemTime::now() - 2 * hour)
            .unwrap()
            .set_signature_validity_period(hour)
            .unwrap()
            .sign_userid_binding(&mut signer, None, &mine)
            .unwrap();
        let theirs = UserID::from("Mallory <mallory@example.invalid>");
        let cert = cert
            .insert_packets(vec![
                Packet::from(mine),
                Packet::from(expired),
                Packet::from(theirs),
            ])
            .unwrap()
            .0;

        let summary = CertSummary::from_cert(&cert);
        assert_eq!(
            summary.validity,
            Validity::Valid,
            "the premise: the certificate itself validates"
        );
        assert!(
            cert.with_policy(&policy(), None)
                .unwrap()
                .userids()
                .next()
                .is_none(),
            "and the premise's other half: no user ID binds under the policy"
        );

        assert_eq!(
            summary.primary_user_id,
            "Old Maintainer <maint@example.org>"
        );
        assert!(
            summary.matches("maint") && summary.matches("example.org"),
            "the row has to be findable by the name it shows: {:?}",
            summary.user_ids
        );
        assert!(
            !summary.matches("mallory"),
            "and a name the key never signed is not the key's: {:?}",
            summary.user_ids
        );

        // Strip every signature and the certificate validates under nothing.
        // Then even an unsigned name earns its place: the row says `unusable`
        // beside it, and a key nobody can identify is a key nobody can fix.
        let stripped = Cert::from_packets(
            cert.into_packets()
                .filter(|p| !matches!(p, Packet::Signature(_))),
        )
        .unwrap();
        let summary = CertSummary::from_cert(&stripped);
        assert_eq!(summary.validity, Validity::Unusable);
        assert_eq!(summary.user_ids.len(), 2);
        assert_ne!(summary.primary_user_id, "(no user ID)");
    }
}
