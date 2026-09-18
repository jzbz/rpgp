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
    // Both halves of the certifier: the secret one may be missing altogether,
    // since a card key has no local secret half and the public certificate is
    // enough for the agent to find it by keygrip — and where it is present it
    // can still be behind cert-d by a revocation the user imported or fetched,
    // which the guard below has to see.
    let certifier = store.full_cert(&request.certifier)?;
    let target = store.lookup(&request.target)?;

    // Neither end may be a certificate its owner has withdrawn, and both are
    // checked here so that a card is never asked for its PIN on behalf of a
    // certification that cannot count. sequoia-wot judges the target as it was
    // when the certification was made and discards the certification outright
    // if the target was revoked then (TargetHardRevoked, TargetSoftRevoked), and
    // it drops every certification of a revoked target at the reference time
    // besides — so what the status bar used to report as "Certified 1 user
    // ID(s)", with a green tick beside it, was a signature that could never move
    // the trust column. The reason the per-user-ID guard below gives, that a
    // claim its own subject has withdrawn is not ours to make, applies with more
    // force to a whole certificate revoked as compromised.
    //
    // Both are named by role, because this is the one operation where the
    // status bar shows two people's keys and "Certification failed: Carol has
    // been revoked" would leave the reader guessing which of them Carol was.
    crate::revoke::refuse_if_revoked_as(&certifier, Some("the certifier"))?;
    crate::revoke::refuse_if_revoked_as(&target, Some("the key being certified"))?;

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
        // Exactly one user ID, or none. The displayed text is a lossy rendering
        // of bytes and two user IDs can share one, which is not a guess to make
        // on somebody's behalf; the rule and its history live in
        // `cert::resolve_user_id`, which the withdrawal paths ask as well.
        let amalgamation = crate::cert::resolve_user_id(&target, wanted)?;
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

/// The primary user ID under the standard policy, for naming a certifier.
///
/// The rule itself lives in [`crate::cert::primary_user_id`], called with the
/// `ValidCert` resolved here: this file used to carry a copy of it, kept in
/// step by hand, and the reason it gave for the copy — that reading one field
/// off a whole `CertSummary` costs a walk of every key — is answered by
/// sharing the rule rather than the summary.
fn primary_user_id(cert: &Cert) -> String {
    let policy = policy();
    let valid = cert.with_policy(&policy, SystemTime::now()).ok();
    crate::cert::primary_user_id(cert, valid.as_ref())
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

    /// The same reasoning one level up. A certification of a revoked
    /// certificate is born dead: sequoia-wot resolves the target as it stood
    /// when the signature was made and discards the certification if it was
    /// revoked then, and drops every certification of a revoked target at the
    /// reference time besides. So the status bar reported "Certified 1 user
    /// ID(s)" and the list drew a tick while the trust column never moved —
    /// and for a hard revocation an exportable attestation over a key its owner
    /// had declared stolen went into the store, and into exports.
    ///
    /// Looking outwards the answer is the same: a certificate its owner has
    /// withdrawn has no standing left to vouch for anyone.
    #[test]
    fn refuses_to_certify_when_either_end_has_been_revoked() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        let dave = generate(&KeyGenRequest::new("Dave <dave@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert_secret(&bob).unwrap();
        store.insert(&dave).unwrap();
        let (alice_fp, bob_fp, dave_fp) = (
            alice.fingerprint().to_hex(),
            bob.fingerprint().to_hex(),
            dave.fingerprint().to_hex(),
        );

        // Bob's laptop is stolen and he publishes the revocation.
        let mut request = crate::revoke::RevokeRequest::new(&bob_fp);
        request.reason = crate::revoke::Reason::Compromised;
        crate::revoke::revoke_cert(&store, &request).unwrap();

        let mut request = CertifyRequest::new(&alice_fp, &bob_fp);
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        // Mapped to `()` before `expect_err` so that a broken guard reports the
        // assertion rather than `Debug`-printing the whole certificate over it.
        let refused = certify(&store, &request)
            .map(|_| ())
            .expect_err("certified a key its owner had revoked");
        let message = refused.to_string();
        assert!(
            message.contains("Bob <bob@example.org> (the key being certified)")
                && message.contains("revoked"),
            "the refusal must say which key, in which role, and why: {message}"
        );
        assert!(
            certifications(&store, &store.lookup(&bob_fp).unwrap())
                .unwrap()
                .is_empty(),
            "a refused certification must not be written to the store"
        );

        // A live target is still certifiable, or the guard is just a wall.
        let mut request = CertifyRequest::new(&alice_fp, &dave_fp);
        request.user_ids = vec!["Dave <dave@example.org>".to_string()];
        certify(&store, &request).unwrap();

        // Now the certifier's end. The primary key of a revoked certificate is
        // already filtered out — for the primary key alone `revoked(false)` does
        // consult the certificate — so the reachable shape is a certificate
        // whose *subkey* certifies, which plenty of imported keys have.
        let (carol, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Carol <carol@example.org>")
            .add_subkey(
                sequoia_openpgp::types::KeyFlags::empty().set_certification(),
                None,
                None,
            )
            .generate()
            .unwrap();
        let carol_fp = carol.fingerprint().to_hex();
        store.insert_secret(&carol).unwrap();
        crate::revoke::revoke_cert(&store, &crate::revoke::RevokeRequest::new(&carol_fp)).unwrap();

        let mut request = CertifyRequest::new(&carol_fp, &dave_fp);
        request.user_ids = vec!["Dave <dave@example.org>".to_string()];
        let refused = certify(&store, &request)
            .map(|_| ())
            .expect_err("vouched for someone with a revoked key");
        let message = refused.to_string();
        assert!(
            message.contains("Carol <carol@example.org> (the certifier)"),
            "the refusal must name the certifier as the certifier: {message}"
        );
        assert!(
            !message.contains("Dave <dave@example.org>"),
            "and must not point at the target, which is fine: {message}"
        );
        assert_eq!(
            certifications(&store, &store.lookup(&dave_fp).unwrap())
                .unwrap()
                .len(),
            1,
            "only Alice's certification should be on Dave"
        );
    }

    /// The certifier is resolved from both of the store's halves, so a
    /// revocation that reached cert-d alone still refuses.
    ///
    /// `Store::insert` writes cert-d and never the secret key file, so this is
    /// the shape a revocation takes when it arrives by import or by a keyserver
    /// refresh: the secret half, which is where the certification key lives,
    /// looks live. Retired rather than the default, because a soft revocation
    /// is the one that still reads as usable to anyone who has not seen it.
    #[test]
    fn refuses_to_certify_when_the_certifiers_revocation_reached_only_cert_d() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let dave = generate(&KeyGenRequest::new("Dave <dave@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&dave).unwrap();
        let (alice_fp, dave_fp) = (alice.fingerprint().to_hex(), dave.fingerprint().to_hex());

        // Retired where the key also lives — the owner's other machine — and
        // met here as the public certificate, which is all `insert` ever
        // writes.
        let elsewhere_dir = tempfile::tempdir().unwrap();
        let elsewhere = Store::open(
            elsewhere_dir.path().join("certs.d"),
            elsewhere_dir.path().join("secrets"),
        )
        .unwrap();
        elsewhere.insert_secret(&alice).unwrap();
        let mut request = crate::revoke::RevokeRequest::new(&alice_fp);
        request.reason = crate::revoke::Reason::Retired;
        crate::revoke::revoke_cert(&elsewhere, &request).unwrap();
        store.insert(&elsewhere.lookup(&alice_fp).unwrap()).unwrap();

        assert!(
            !matches!(
                store
                    .secret_cert(&alice_fp)
                    .unwrap()
                    .revocation_status(&policy(), None),
                RevocationStatus::Revoked(_)
            ),
            "the secret half not knowing is the premise of this test"
        );

        let mut request = CertifyRequest::new(&alice_fp, &dave_fp);
        request.user_ids = vec!["Dave <dave@example.org>".to_string()];
        let refused = certify(&store, &request)
            .map(|_| ())
            .expect_err("vouched for someone with a key whose revocation was in cert-d");
        let message = refused.to_string();
        assert!(
            message.contains("Alice <alice@example.org> (the certifier)"),
            "the refusal must name the certifier as the certifier: {message}"
        );
        assert!(
            certifications(&store, &store.lookup(&dave_fp).unwrap())
                .unwrap()
                .is_empty(),
            "a refused certification must not be written to the store"
        );
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
