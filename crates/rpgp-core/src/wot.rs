//! Web-of-trust authentication.
//!
//! Certificate *validity* — what [`crate::cert::Validity`] reports — only says
//! the certificate is internally sound: the self-signatures check out and it
//! has not expired or been revoked. It says nothing about whether the name on
//! it is real. That second question is what this module answers, by looking for
//! a chain of certifications from one of the store's trust roots to the binding
//! between a certificate and one of its user IDs.
//!
//! The two are independent, and both matter: a perfectly valid certificate from
//! a stranger is unauthenticated, and an expired certificate can still be one
//! you long ago confirmed belongs to a friend.

use std::collections::HashMap;

use sequoia_openpgp::{Cert, Fingerprint};
use sequoia_wot::Network;

/// How well a certificate's identity is backed by the web of trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Authentication {
    /// No chain of certifications reaches this binding from a trust root.
    #[default]
    Unknown,
    /// Some evidence, but below the threshold to accept the name outright.
    Marginal,
    /// Authenticated: a chain of sufficient weight reaches it.
    Full,
}

impl Authentication {
    pub fn as_str(self) -> &'static str {
        match self {
            Authentication::Unknown => "unverified",
            Authentication::Marginal => "partly verified",
            Authentication::Full => "verified",
        }
    }

    fn from_amount(amount: usize) -> Self {
        if amount >= sequoia_wot::FULLY_TRUSTED {
            Authentication::Full
        } else if amount >= sequoia_wot::PARTIALLY_TRUSTED {
            Authentication::Marginal
        } else {
            Authentication::Unknown
        }
    }
}

/// Authenticate every certificate in `certs` against `roots`.
///
/// Returns the best result across each certificate's user IDs, keyed by
/// uppercase fingerprint. The network is built once for the whole set because
/// that is the expensive part; asking it about one more binding is cheap.
///
/// A failure to build the network is reported as "nothing is authenticated"
/// rather than as an error: an unusable trust graph should grey out the
/// trust column, not stop the list from being shown.
pub fn authenticate_all<C>(
    certs: &[C],
    roots: &[String],
) -> HashMap<(String, String), Authentication>
where
    C: std::ops::Deref<Target = Cert>,
{
    // Empty rather than an all-Unknown map: `for_user_id` answers Unknown for
    // anything absent, so the two are indistinguishable to every caller, and
    // building one entry per binding up front only to overwrite it allocated
    // the key twice per certificate on every reload.
    let roots: Vec<Fingerprint> = roots.iter().filter_map(|r| r.parse().ok()).collect();
    if roots.is_empty() {
        return HashMap::new();
    }

    let policy = crate::policy();
    let Ok(network) =
        Network::from_cert_refs(certs.iter().map(|c| &**c), &policy, None, roots.as_slice())
    else {
        return HashMap::new();
    };

    // Keyed by binding — (certificate, user ID) — not by certificate.
    //
    // sequoia-wot authenticates a binding: the question it answers is whether
    // *this name* on *this key* is vouched for, and answering it for each user
    // ID and keeping the maximum threw away which name earned the verdict. A
    // certificate carrying a certified work address and an uncertified
    // pseudonym then reported one verdict for both, and every display site
    // re-attached it to whichever name it happened to be printing — so the
    // pseudonym wore the work address's badge.
    let mut result: HashMap<(String, String), Authentication> = HashMap::new();
    for cert in certs {
        let fingerprint = cert.fingerprint();
        let key = fingerprint.to_hex().to_uppercase();
        for ua in cert.userids() {
            let paths = network.authenticate(
                ua.userid().clone(),
                fingerprint.clone(),
                sequoia_wot::FULLY_TRUSTED,
            );
            result.insert(
                (
                    key.clone(),
                    String::from_utf8_lossy(ua.userid().value()).into_owned(),
                ),
                Authentication::from_amount(paths.amount()),
            );
        }
    }

    result
}

/// The verdict for one identity, which is the only question this answers.
///
/// Absent means Unknown: a certificate with no path to a root, a user ID that
/// was not on the certificate when the graph was built, or an empty map from
/// the early returns above.
pub fn for_user_id(
    authenticated: &HashMap<(String, String), Authentication>,
    fingerprint: &str,
    user_id: &str,
) -> Authentication {
    authenticated
        .get(&(fingerprint.to_uppercase(), user_id.to_string()))
        .copied()
        .unwrap_or_default()
}

// Ordering so `if found > best` above means "more authenticated".
impl PartialOrd for Authentication {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Authentication {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(a: Authentication) -> u8 {
            match a {
                Authentication::Unknown => 0,
                Authentication::Marginal => 1,
                Authentication::Full => 2,
            }
        }
        rank(*self).cmp(&rank(*other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certify::{CertifyRequest, FULL, PARTIAL, certify};
    use crate::keygen::{KeyGenRequest, generate};
    use crate::store::Store;

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    fn authentication_of(store: &Store, fingerprint: &str, user_id: &str) -> Authentication {
        let certs = store.certs().unwrap();
        let roots: Vec<String> = store.effective_roots().unwrap().into_iter().collect();
        for_user_id(&authenticate_all(&certs, &roots), fingerprint, user_id)
    }

    /// A verdict belongs to one identity, not to the whole certificate.
    ///
    /// sequoia-wot authenticates a binding — this name on this key. Folding
    /// every user ID into a maximum and storing it under the fingerprint alone
    /// meant one certified identity lent its badge to every other name on the
    /// same key, including one nobody has vouched for. Someone certifies a
    /// colleague's work address, and the pseudonym beside it inherits the tick.
    ///
    /// Restore the fold — take the maximum over `cert.userids()` and key the map
    /// by fingerprint — and this fails: the uncertified identity reads Full.
    #[test]
    fn a_verdict_belongs_to_one_identity_not_to_the_certificate() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Work <work@example.org>"))
            .unwrap()
            .cert;

        // The second identity is added in a store of its own: add_user_id needs
        // the secret to sign the binding, and a secret key in the store under
        // review would make Them a trust root and authenticate it trivially.
        let (_their_dir, their_store) = scratch();
        their_store.insert_secret(&them).unwrap();
        let them = crate::lifecycle::add_user_id(
            &their_store,
            &them.fingerprint().to_hex(),
            "Pseudonym <alias@example.org>",
            None,
        )
        .unwrap();

        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();

        // Only the work address is vouched for.
        let mut request =
            CertifyRequest::new(me.fingerprint().to_hex(), them.fingerprint().to_hex());
        request.user_ids = vec!["Work <work@example.org>".to_string()];
        certify(&store, &request).unwrap();

        let fpr = them.fingerprint().to_hex();
        assert_eq!(
            authentication_of(&store, &fpr, "Work <work@example.org>"),
            Authentication::Full,
            "the certified identity is authenticated"
        );
        assert_eq!(
            authentication_of(&store, &fpr, "Pseudonym <alias@example.org>"),
            Authentication::Unknown,
            "an identity nobody certified must not inherit the other's verdict"
        );
    }

    #[test]
    fn a_stranger_is_unauthenticated_until_certified() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let stranger = generate(&KeyGenRequest::new("Stranger <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&stranger).unwrap();

        let stranger_fpr = stranger.fingerprint().to_hex();
        assert_eq!(
            authentication_of(&store, &stranger_fpr, "Stranger <them@example.org>"),
            Authentication::Unknown
        );

        // My own key is a root, so it authenticates itself.
        assert_eq!(
            authentication_of(&store, &me.fingerprint().to_hex(), "Me <me@example.org>"),
            Authentication::Full
        );

        let mut request = CertifyRequest::new(me.fingerprint().to_hex(), &stranger_fpr);
        request.user_ids = vec!["Stranger <them@example.org>".to_string()];
        certify(&store, &request).unwrap();

        assert_eq!(
            authentication_of(&store, &stranger_fpr, "Stranger <them@example.org>"),
            Authentication::Full
        );
    }

    #[test]
    fn a_partial_certification_only_gets_partway() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let acquaintance = generate(&KeyGenRequest::new("Pat <pat@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&acquaintance).unwrap();

        let mut request = CertifyRequest::new(
            me.fingerprint().to_hex(),
            acquaintance.fingerprint().to_hex(),
        );
        request.user_ids = vec!["Pat <pat@example.org>".to_string()];
        request.amount = PARTIAL;
        certify(&store, &request).unwrap();

        assert_eq!(
            authentication_of(
                &store,
                &acquaintance.fingerprint().to_hex(),
                "Pat <pat@example.org>"
            ),
            Authentication::Marginal
        );
    }

    /// Me, a trust root; an introducer whose secret key is here but was
    /// imported, so that it can certify without being a root itself; and a
    /// distant certificate only the introducer has certified. Me certifies the
    /// introducer as `delegate` sets out.
    ///
    /// The introducer is imported rather than generated for the reason the
    /// verdicts below depend on. A secret key generated here is a trust root,
    /// and these tests used to store the introducer that way, so its own
    /// certification made the distant certificate Full with or without the
    /// delegation, and they would have passed with trust signatures ignored
    /// altogether.
    fn introduced(delegate: impl FnOnce(&mut CertifyRequest)) -> Authentication {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let introducer = generate(&KeyGenRequest::new("Introducer <intro@example.org>"))
            .unwrap()
            .cert;
        let friend_of_friend = generate(&KeyGenRequest::new("Distant <far@example.org>"))
            .unwrap()
            .cert;
        let distant = |store: &Store| {
            authentication_of(
                store,
                &friend_of_friend.fingerprint().to_hex(),
                "Distant <far@example.org>",
            )
        };

        store.insert_secret(&me).unwrap();
        store.insert_imported_secret(&introducer).unwrap();
        store.insert(&friend_of_friend).unwrap();
        assert!(
            !store
                .effective_roots()
                .unwrap()
                .contains(&introducer.fingerprint().to_hex()),
            "the introducer must not be a trust root, or nothing here is tested"
        );

        let mut onward = CertifyRequest::new(
            introducer.fingerprint().to_hex(),
            friend_of_friend.fingerprint().to_hex(),
        );
        onward.user_ids = vec!["Distant <far@example.org>".to_string()];
        certify(&store, &onward).unwrap();
        assert_eq!(
            distant(&store),
            Authentication::Unknown,
            "certified only by someone nobody vouches for, the distant certificate is a stranger"
        );

        let mut request =
            CertifyRequest::new(me.fingerprint().to_hex(), introducer.fingerprint().to_hex());
        request.user_ids = vec!["Introducer <intro@example.org>".to_string()];
        delegate(&mut request);
        certify(&store, &request).unwrap();
        assert_eq!(
            authentication_of(
                &store,
                &introducer.fingerprint().to_hex(),
                "Introducer <intro@example.org>"
            ),
            Authentication::Full,
            "the introducer is certified either way"
        );
        distant(&store)
    }

    #[test]
    fn a_trusted_introducer_extends_authentication_one_hop() {
        let distant = introduced(|request| {
            request.depth = 1;
            request.amount = FULL;
        });
        assert_eq!(distant, Authentication::Full);
    }

    /// The dangerous direction: an ordinary certification vouches for the one
    /// identity it names, and must not make its subject an introducer whose
    /// own certifications count as well.
    #[test]
    fn a_plain_certification_does_not_make_an_introducer() {
        let distant = introduced(|request| request.depth = 0);
        assert_eq!(distant, Authentication::Unknown);
    }

    #[test]
    fn explicit_trust_roots_are_honoured() {
        let (_dir, store) = scratch();
        let outside = generate(&KeyGenRequest::new("Outside <out@example.org>"))
            .unwrap()
            .cert;
        let vouched = generate(&KeyGenRequest::new("Vouched <v@example.org>"))
            .unwrap()
            .cert;
        let vouched_for = |store: &Store| {
            authentication_of(
                store,
                &vouched.fingerprint().to_hex(),
                "Vouched <v@example.org>",
            )
        };
        // Imported, so not a root until the user says so: a secret key
        // generated here would be one already, which is what this test used
        // to use while saying that nothing was a root to begin with.
        store.insert_imported_secret(&outside).unwrap();
        store.insert(&vouched).unwrap();
        assert!(
            store.effective_roots().unwrap().is_empty(),
            "nothing may be a root to begin with, or nothing here is tested"
        );

        let mut request = CertifyRequest::new(
            outside.fingerprint().to_hex(),
            vouched.fingerprint().to_hex(),
        );
        request.user_ids = vec!["Vouched <v@example.org>".to_string()];
        certify(&store, &request).unwrap();
        assert_eq!(vouched_for(&store), Authentication::Unknown);

        store
            .set_trust_root(&outside.fingerprint().to_hex(), true)
            .unwrap();
        assert_eq!(store.trust_roots().unwrap().len(), 1);
        assert_eq!(vouched_for(&store), Authentication::Full);

        store
            .set_trust_root(&outside.fingerprint().to_hex(), false)
            .unwrap();
        assert!(store.trust_roots().unwrap().is_empty());
        assert_eq!(
            vouched_for(&store),
            Authentication::Unknown,
            "a root taken away must stop authenticating what it vouched for"
        );
    }
}
