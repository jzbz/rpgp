//! Fill a store with throwaway keys and a small web of trust, so the GUI can be
//! looked at with content in it. Never point this at a real store.
//!
//!     XDG_DATA_HOME=/tmp/demo cargo run -p rpgp-core --example seed-demo-store
//!
//! The resulting graph covers every state the trust column can show:
//!
//!     Ada, Grace         own keys, so trust roots      -> verified
//!     Alan               certified in full by Ada      -> verified
//!     Barbara            trusted introducer, from Ada  -> verified
//!     Katherine          certified by Barbara          -> verified, one hop out
//!     Radia              partially certified by Ada    -> partly verified
//!     Linus              nobody has vouched for them   -> unverified

use rpgp_core::Store;
use rpgp_core::certify::{CertifyRequest, PARTIAL, certify};
use rpgp_core::keygen::{KeyGenRequest, KeyType, generate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(std::env::args_os().nth(1).ok_or(
        "usage: seed-demo-store <directory>   (e.g. /tmp/rpgp-demo; \
         this never writes to the default store)",
    )?);
    // The same layout Store::open_default builds.
    let secrets_dir = root.join("rpgp").join("secrets");
    let store = Store::open(root.join("pgp.cert.d"), &secrets_dir)?;

    let ada = make(
        &store,
        "Ada Lovelace <ada@analytical.engine>",
        KeyType::Curve25519,
        true,
    )?;
    let _grace = make(
        &store,
        "Grace Hopper <grace@navy.mil>",
        KeyType::Rsa3072,
        true,
    )?;
    let alan = make(
        &store,
        "Alan Turing <alan@bletchley.uk>",
        KeyType::Curve25519,
        false,
    )?;
    let katherine = make(
        &store,
        "Katherine Johnson <katherine@nasa.gov>",
        KeyType::Curve25519,
        false,
    )?;
    let radia = make(
        &store,
        "Radia Perlman <radia@spanning.tree>",
        KeyType::Rsa3072,
        false,
    )?;
    let _linus = make(
        &store,
        "Linus Torvalds <linus@kernel.org>",
        KeyType::Curve25519,
        false,
    )?;

    // Barbara needs her secret key briefly so she can certify Katherine, then
    // gives it up: she should appear as somebody else's key, not one of ours.
    let barbara = make(
        &store,
        "Barbara Liskov <barbara@substitution.org>",
        KeyType::Curve25519,
        true,
    )?;

    certification(
        &store,
        &ada,
        &alan,
        "Alan Turing <alan@bletchley.uk>",
        |_| {},
    )?;
    certification(
        &store,
        &ada,
        &radia,
        "Radia Perlman <radia@spanning.tree>",
        |r| {
            r.amount = PARTIAL;
        },
    )?;
    certification(
        &store,
        &ada,
        &barbara,
        "Barbara Liskov <barbara@substitution.org>",
        |r| {
            r.depth = 1;
        },
    )?;
    certification(
        &store,
        &barbara,
        &katherine,
        "Katherine Johnson <katherine@nasa.gov>",
        |_| {},
    )?;

    // From the directory this actually wrote to. Rebuilding it from
    // dirs::data_dir() named a different place on two of the three platforms:
    // the store uses data_local_dir(), which on Windows is Local rather than
    // Roaming, so this deleted nothing and Barbara kept her secret key.
    std::fs::remove_file(secrets_dir.join(format!("{barbara}.pgp")))?;
    println!("dropped Barbara's secret key so she reads as a third party");

    Ok(())
}

/// Generate a key, store it, and return its fingerprint.
fn make(
    store: &Store,
    user_id: &str,
    key_type: KeyType,
    keep_secret: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut request = KeyGenRequest::new(user_id);
    request.key_type = key_type;
    let key = generate(&request)?;

    if keep_secret {
        store.insert_secret(&key.cert)?;
        // Same as the GUI's key generation: keep the revocation certificate.
        store.save_revocation(
            &key.cert.fingerprint().to_hex(),
            &rpgp_core::revoke::armor(&key.revocation)?,
        )?;
    } else {
        store.insert(&key.cert)?;
    }

    let fingerprint = key.cert.fingerprint().to_hex();
    println!("{fingerprint} {user_id}");
    Ok(fingerprint)
}

fn certification(
    store: &Store,
    certifier: &str,
    target: &str,
    user_id: &str,
    adjust: impl FnOnce(&mut CertifyRequest),
) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = CertifyRequest::new(certifier, target);
    request.user_ids = vec![user_id.to_string()];
    adjust(&mut request);
    certify(store, &request)?;
    Ok(())
}
