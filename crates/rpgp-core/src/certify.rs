//! Certifying other people's certificates, and reading the certifications a
//! certificate already carries.
//!
//! A certification is a signature by one certificate over a *user ID* of
//! another — the OpenPGP way of saying "I checked, and this name and address
//! really do belong to this key". It is the raw material the web of trust in
//! [`crate::wot`] reasons over.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use sequoia_openpgp::Cert;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::types::{RevocationStatus, SignatureType};

use crate::error::{Error, Result};
use crate::policy;
use crate::store::Store;
use zeroize::Zeroizing;

/// Full confidence, in OpenPGP's 0..=255 trust scale.
pub const FULL: u8 = 120;
/// Partial confidence: enough only in combination with other certifications.
pub const PARTIAL: u8 = 60;

#[derive(Debug, Clone)]
pub struct CertifyRequest {
    /// Fingerprint of our own certificate doing the certifying.
    pub certifier: String,
    /// Fingerprint of the certificate being certified.
    pub target: String,
    /// Which of the target's user IDs to sign. Certifying a certificate as a
    /// whole is not a thing OpenPGP can express; every certification names one
    /// user ID.
    pub user_ids: Vec<String>,
    /// Exportable certifications are meant to be published and shared; a local
    /// one stays in this store and is never written out by `export_file`.
    pub exportable: bool,
    /// 0 for an ordinary certification. 1 or more makes it a *trust signature*:
    /// the target becomes a trusted introducer whose own certifications this
    /// store will honour, up to `depth` hops away.
    pub depth: u8,
    /// How much this certification vouches for the binding: [`FULL`] or
    /// [`PARTIAL`].
    pub amount: u8,
    pub expires: Option<Duration>,
    pub password: Option<Zeroizing<String>>,
}

impl CertifyRequest {
    pub fn new(certifier: impl Into<String>, target: impl Into<String>) -> Self {
        CertifyRequest {
            certifier: certifier.into(),
            target: target.into(),
            user_ids: Vec::new(),
            exportable: true,
            depth: 0,
            amount: FULL,
            expires: None,
            password: None,
        }
    }
}

/// One certification already present on a certificate.
#[derive(Debug, Clone)]
pub struct Certification {
    pub user_id: String,
    /// The certifier's primary user ID when their certificate is in the store,
    /// otherwise their key handle.
    pub certifier: String,
    pub certifier_fingerprint: Option<String>,
    pub created: Option<SystemTime>,
    pub exportable: bool,
    pub depth: u8,
    pub amount: u8,
    /// Whether the signature checks out against the certifier's key. `None`
    /// when the certifier is not in the store and it could not be checked.
    pub verified: Option<bool>,
    /// Made by a certificate whose secret key this store holds.
    pub by_me: bool,
    /// This entry withdraws an earlier certification rather than making one.
    pub is_revocation: bool,
}

impl Certification {
    /// Whether this certification should count towards trust: it verified, and
    /// it was made by someone we can name.
    pub fn is_good(&self) -> bool {
        self.verified == Some(true) && !self.is_revocation
    }
}

/// Sign one or more of `target`'s user IDs with `certifier`'s key.
///
/// The updated certificate is written back to the store and returned.
pub fn certify(store: &Store, request: &CertifyRequest) -> Result<Cert> {
    if request.user_ids.is_empty() {
        return Err(Error::invalid("select at least one user ID to certify"));
    }
    if request.certifier == request.target {
        return Err(Error::invalid(
            "a certificate already vouches for itself; certify someone else's",
        ));
    }

    let policy = policy();
    // The certifier may be a card key, which has no local secret half; the
    // public certificate is enough for the agent to find it by keygrip.
    let certifier = store
        .secret_cert(&request.certifier)
        .or_else(|_| store.lookup(&request.certifier))?;
    let target = store.lookup(&request.target)?;

    let valid = certifier
        .with_policy(&policy, None)
        .map_err(|_| Error::NoSecretKey(request.certifier.clone()))?;
    let local = valid
        .keys()
        .secret()
        .alive()
        .revoked(false)
        .supported()
        .for_certification()
        .next();

    let mut signer: Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync> = match local {
        Some(ka) => crate::secret::signer(
            ka.key().clone(),
            request.password.as_deref().map(String::as_str),
        )?,
        None => Box::new(crate::agent::certifier_for(&certifier)?),
    };

    let mut signatures: Vec<Signature> = Vec::new();
    for wanted in &request.user_ids {
        // A user ID is bytes; this string is those bytes rendered lossily, and
        // that is not injective — every invalid byte becomes U+FFFD. Two user
        // IDs differing only there display identically, so `find` would sign
        // whichever came first and report the other's text. Refuse instead:
        // nothing in the dialog could have told the user which one they picked.
        let mut candidates = target
            .userids()
            .filter(|ua| String::from_utf8_lossy(ua.userid().value()) == wanted.as_str());
        let amalgamation = candidates
            .next()
            .ok_or_else(|| Error::invalid(format!("{wanted} is not a user ID on this key")))?;
        if candidates.next().is_some() {
            return Err(Error::invalid(format!(
                "{wanted} matches more than one user ID on this key; they differ in \
                 bytes that do not display, so there is no way to say which you meant"
            )));
        }
        let userid = amalgamation.userid().clone();

        // A user ID its owner has retracted is not ours to vouch for. Signing
        // one publishes an attestation binding a name the holder has disowned
        // — usually an address that has since been reassigned to someone else,
        // which is precisely the claim a certification must not make.
        if matches!(
            amalgamation.revocation_status(&policy, None),
            RevocationStatus::Revoked(_)
        ) {
            return Err(Error::invalid(format!(
                "{wanted} has been revoked by its owner"
            )));
        }

        // The mirror of revoke_certification's rule. A revocation supersedes
        // a certification made strictly earlier, so a certification has to be
        // dated strictly *later* than any revocation of ours on this user ID
        // or it is born dead. Withdraw-then-recertify within a second is one
        // person clicking twice; only our own revocations count, for the same
        // reason only our own certifications count over there.
        //
        // "Ours" means one that verifies against our key, not one that merely
        // names it. other_revocations() hands back packets exactly as they were
        // parsed, and an issuer subpacket is an unauthenticated hint anyone can
        // write — so filtering on the name alone let a planted packet dated in
        // the far future set `when` to that instant, producing a certification
        // that is not yet valid and never takes effect. Refetching the target
        // re-planted it, so every retry was neutralised the same way. This is
        // the same verification certifications() already performs below.
        let certifier_key = certifier.primary_key().key();
        let mut when = SystemTime::now();
        for revocation in amalgamation
            .other_revocations()
            .filter(|sig| crate::cert::issued_by(sig, &certifier))
            .filter(|sig| {
                (*sig)
                    .clone()
                    .verify_userid_revocation(certifier_key, target.primary_key().key(), &userid)
                    .is_ok()
            })
        {
            if let Some(created) = revocation.signature_creation_time() {
                let after = created + Duration::from_secs(1);
                if after > when {
                    when = after;
                }
            }
        }

        let mut builder = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(when)?
            .set_exportable_certification(request.exportable)?;

        // An ordinary certification already means "full confidence in this
        // binding". Anything else — a lower amount, or delegation to a trusted
        // introducer — has to be spelled out as a trust signature.
        if request.depth > 0 || request.amount != FULL {
            builder = builder.set_trust_signature(request.depth, request.amount)?;
        }
        if let Some(expires) = request.expires {
            builder = builder.set_signature_validity_period(expires)?;
        }

        signatures.push(builder.sign_userid_binding(
            &mut *signer,
            target.primary_key().key(),
            &userid,
        )?);
    }

    let certified = target.insert_packets(signatures)?.0;
    store.insert(&certified)?;
    Ok(certified)
}

/// The primary user ID, chosen exactly as [`crate::cert::CertSummary::from_cert`]
/// chooses it: the policy-valid primary user ID, else the first user ID present,
/// else a placeholder. Duplicated from that function deliberately and kept in step
/// with it by hand — building a whole summary per signature to read one field
/// also walks every key for capabilities, computes revocation status and
/// allocates a String per user ID, all of which is then dropped.
fn primary_user_id(cert: &Cert) -> String {
    let policy = policy();
    let now = SystemTime::now();
    let valid = cert.with_policy(&policy, now).ok();
    valid
        .as_ref()
        .and_then(|vc| vc.primary_userid().ok())
        .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
        .or_else(|| match valid.as_ref() {
            Some(vc) => vc
                .userids()
                .next()
                .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned()),
            None => cert
                .userids()
                .next()
                .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned()),
        })
        .unwrap_or_else(|| "(no user ID)".to_string())
}

/// Every third-party certification on `cert`, verified where possible.
/// One resolved certifier, kept for the length of a `certifications()` call.
///
/// Derived values only, never the `Cert`: a certificate endorsed by hundreds
/// of people in the store would otherwise pin hundreds of parsed certificates
/// for the duration.
struct Certifier {
    /// Every key that could have made the certification. Kept whole rather
    /// than reduced to the primary, because `certify` signs with the first
    /// `for_certification()` key — often a subkey — so a primary-only check
    /// marks this program's own certifications unverified.
    keys: Vec<Key<PublicParts, UnspecifiedRole>>,
    name: String,
    fingerprint: String,
    by_me: bool,
}

pub fn certifications(store: &Store, cert: &Cert) -> Result<Vec<Certification>> {
    let mut out = Vec::new();
    let primary = cert.primary_key().key();

    // Both hoisted out of the per-signature loop below. The secrets directory
    // was stat'd once per signature to answer by_me, and the certifier was
    // re-read from the store, re-parsed and re-validated against the policy
    // once per signature — so a certificate carrying twenty endorsements from
    // one person did all of that twenty times over. `unwrap_or_default`, not
    // `?`: an unreadable secrets directory reads as "no secrets" here exactly
    // as `has_secret` treated it, rather than failing the whole listing.
    let secrets = store.secret_fingerprints().unwrap_or_default();
    let mut certifiers: HashMap<String, Option<Certifier>> = HashMap::new();

    for ua in cert.userids() {
        let user_id = String::from_utf8_lossy(ua.userid().value()).into_owned();

        // `certifications()` holds third-party endorsements;
        // `other_revocations()` holds the signatures that withdraw them. Both
        // belong in the list — a withdrawal the user cannot see is a withdrawal
        // they will make twice.
        let entries = ua
            .certifications()
            .map(|signature| (signature, false))
            .chain(ua.other_revocations().map(|signature| (signature, true)));

        for (signature, is_revocation) in entries {
            let (depth, amount) = signature.trust_signature().unwrap_or((0, FULL));
            let mut entry = Certification {
                is_revocation,
                user_id: user_id.clone(),
                certifier: String::new(),
                certifier_fingerprint: None,
                created: signature.signature_creation_time(),
                exportable: signature.exportable_certification().unwrap_or(true),
                depth,
                amount,
                verified: None,
                by_me: false,
            };

            // Check the signature against whichever issuer we can resolve. An
            // unresolvable issuer is normal — it just means we have not met
            // that person — so it is reported rather than dropped.
            for handle in signature.get_issuers() {
                let handle = handle.to_string();

                // Verify before attributing, not after. get_issuers() reports
                // the issuer subpackets from both the hashed and the unhashed
                // area, and the unhashed half is not covered by the signature
                // — the comment above certify() says exactly that. Naming the
                // certifier, and worse setting by_me, from that hint meant a
                // packet anyone could write earned a real identity in the list
                // and a "(you)" badge with a withdraw affordance beside it.
                //
                // Every certification-capable key is kept, not just the
                // primary: certify() signs with the first `for_certification()`
                // key, which may well be a subkey, so a primary-only check
                // would reject certifications this very program made.
                let resolved = certifiers.entry(handle.clone()).or_insert_with(|| {
                    let certifier = store.lookup(&handle).ok()?;
                    let policy = policy();
                    let keys = certifier
                        .with_policy(&policy, None)
                        .ok()
                        .into_iter()
                        .flat_map(|valid| {
                            valid
                                .keys()
                                .alive()
                                .revoked(false)
                                .supported()
                                .for_certification()
                                .map(|ka| ka.key().clone())
                                .collect::<Vec<_>>()
                        })
                        .chain(std::iter::once(
                            certifier
                                .primary_key()
                                .key()
                                .clone()
                                .role_into_unspecified(),
                        ))
                        .collect();
                    let fingerprint = certifier.fingerprint().to_hex();
                    Some(Certifier {
                        keys,
                        name: primary_user_id(&certifier),
                        by_me: secrets.contains(&fingerprint),
                        fingerprint,
                    })
                });

                // An unresolvable issuer is normal — it just means we have not
                // met that person — so it is reported rather than dropped.
                let Some(resolved) = resolved else {
                    entry.certifier = handle;
                    continue;
                };

                let verified = resolved.keys.iter().any(|key| {
                    if is_revocation {
                        signature
                            .clone()
                            .verify_userid_revocation(key, primary, ua.userid())
                            .is_ok()
                    } else {
                        signature
                            .clone()
                            .verify_userid_binding(key, primary, ua.userid())
                            .is_ok()
                    }
                });
                entry.verified = Some(verified);
                if verified {
                    entry.certifier = resolved.name.clone();
                    entry.by_me = resolved.by_me;
                    entry.certifier_fingerprint = Some(resolved.fingerprint.clone());
                } else {
                    // Names this certifier but does not verify against it.
                    // Report the handle rather than the identity: by_me stays
                    // false, so no withdraw affordance appears beside a
                    // signature we cannot show the user made.
                    entry.certifier = handle;
                }
                break;
            }

            if entry.certifier.is_empty() {
                entry.certifier = "unknown certifier".to_string();
            }
            out.push(entry);
        }
    }

    out.sort_by(|a, b| {
        b.by_me
            .cmp(&a.by_me)
            .then_with(|| a.user_id.cmp(&b.user_id))
            .then_with(|| a.certifier.cmp(&b.certifier))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyGenRequest, generate};

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    #[test]
    fn certifies_a_user_id_and_reads_it_back() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();

        assert!(certifications(&store, &bob).unwrap().is_empty());

        let mut request =
            CertifyRequest::new(alice.fingerprint().to_hex(), bob.fingerprint().to_hex());
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        certify(&store, &request).unwrap();

        let bob = store.lookup(&bob.fingerprint().to_hex()).unwrap();
        let found = certifications(&store, &bob).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].user_id, "Bob <bob@example.org>");
        assert_eq!(found[0].certifier, "Alice <alice@example.org>");
        assert_eq!(found[0].verified, Some(true));
        assert!(found[0].by_me);
        assert!(found[0].exportable);
        assert_eq!(found[0].amount, FULL);
        assert_eq!(found[0].depth, 0);
    }

    /// Certifying is a public claim that a name belongs to someone. Once the
    /// holder revokes a user ID they are saying it no longer does — an old
    /// address, typically, which the provider may since have handed to a
    /// stranger. Vouching for it then puts our signature behind a claim its
    /// own subject has withdrawn.
    #[test]
    fn refuses_to_vouch_for_a_user_id_its_owner_has_revoked() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert_secret(&bob).unwrap();
        let bob_fp = bob.fingerprint().to_hex();
        crate::lifecycle::add_user_id(&store, &bob_fp, "Bob <bob@oldjob.example>", None).unwrap();

        // Bob leaves the job and disowns the address.
        crate::lifecycle::revoke_user_id(
            &store,
            &bob_fp,
            "Bob <bob@oldjob.example>",
            "left that job",
            None,
        )
        .unwrap();

        let mut request = CertifyRequest::new(alice.fingerprint().to_hex(), &bob_fp);
        request.user_ids = vec!["Bob <bob@oldjob.example>".to_string()];
        let refused = certify(&store, &request);
        assert!(
            refused.is_err(),
            "certified an address its owner had revoked"
        );

        // And the live one is still certifiable, or the guard is just a wall.
        let mut request = CertifyRequest::new(alice.fingerprint().to_hex(), &bob_fp);
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        certify(&store, &request).unwrap();
        let bob = store.lookup(&bob_fp).unwrap();
        let found = certifications(&store, &bob).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].user_id, "Bob <bob@example.org>");
    }

    /// A user ID is bytes, and everything above the storage layer handles it
    /// as `from_utf8_lossy` text — which maps every invalid byte to the same
    /// replacement character. Two user IDs differing only in those bytes are
    /// one string by the time they reach the dialog, so the user picks a row
    /// that names both and `find` would sign whichever came first while the
    /// list reported the other. There is no answer to give here, only a
    /// choice between guessing and saying so.
    #[test]
    fn two_user_ids_that_display_alike_are_refused_rather_than_guessed() {
        use sequoia_openpgp::packet::UserID;

        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert_secret(&bob).unwrap();
        let bob_fp = bob.fingerprint().to_hex();

        // Two user IDs, different bytes, identical rendering: 0xFE and 0xFF
        // are both invalid UTF-8 and both display as U+FFFD.
        let mut signer = bob
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let mut packets: Vec<sequoia_openpgp::Packet> = Vec::new();
        for byte in [0xFEu8, 0xFF] {
            let raw = [b"Bob <bob@", &[byte][..], b".example>"].concat();
            let userid = UserID::from(raw);
            let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
                .sign_userid_binding(&mut signer, bob.primary_key().key(), &userid)
                .unwrap();
            packets.push(sequoia_openpgp::Packet::from(userid));
            packets.push(sequoia_openpgp::Packet::from(binding));
        }
        let bob = bob.insert_packets(packets).unwrap().0;
        store.insert_secret(&bob).unwrap();

        let displayed = String::from_utf8_lossy(
            &[b"Bob <bob@".to_vec(), vec![0xFE], b".example>".to_vec()].concat(),
        )
        .into_owned();

        let mut request = CertifyRequest::new(alice.fingerprint().to_hex(), &bob_fp);
        request.user_ids = vec![displayed.clone()];
        let refused = certify(&store, &request);
        let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            message.contains("more than one user ID"),
            "an ambiguous identity must be refused, not guessed at; got {message:?}"
        );

        // An unambiguous one still signs, or this is just a wall.
        let mut request = CertifyRequest::new(alice.fingerprint().to_hex(), &bob_fp);
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        certify(&store, &request).unwrap();
    }

    #[test]
    fn records_a_partial_trust_signature() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();

        let mut request =
            CertifyRequest::new(alice.fingerprint().to_hex(), bob.fingerprint().to_hex());
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        request.amount = PARTIAL;
        request.depth = 1;
        request.exportable = false;
        certify(&store, &request).unwrap();

        let bob = store.lookup(&bob.fingerprint().to_hex()).unwrap();
        let found = certifications(&store, &bob).unwrap();

        assert_eq!(found[0].amount, PARTIAL);
        assert_eq!(found[0].depth, 1);
        assert!(!found[0].exportable);
        assert!(found[0].is_good());
    }

    #[test]
    fn refuses_to_certify_yourself_or_nothing() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let fingerprint = alice.fingerprint().to_hex();

        let mut same = CertifyRequest::new(&fingerprint, &fingerprint);
        same.user_ids = vec!["Alice <alice@example.org>".to_string()];
        assert!(certify(&store, &same).is_err());

        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert(&bob).unwrap();
        let empty = CertifyRequest::new(&fingerprint, bob.fingerprint().to_hex());
        assert!(certify(&store, &empty).is_err());
    }
}
