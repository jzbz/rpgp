//! Fill a store with throwaway keys and a small web of trust, so the GUI can be
//! looked at with content in it. Never point this at a real store.
//!
//!     cargo run -p rpgp-core --example seed-demo-store -- /tmp/rpgp-demo
//!
//! It writes only inside the directory it is given, laid out as
//! `Store::open_default` lays out the data directory, so on Linux the GUI
//! opens it with
//!
//!     XDG_DATA_HOME=/tmp/rpgp-demo cargo run -p rpgp-gui
//!
//! That half is for Linux alone. The `dirs` crate reads `XDG_DATA_HOME` there
//! but not on macOS or Windows, where the GUI opens the default store whatever
//! the variable says.
//!
//! Everyone in it is the cryptographers' usual cast, at the reserved
//! example.org, example.com and example.net domains, because the store ends up
//! in screenshots: a real person's name beside a "verified" badge reads as a
//! claim about them. Trent, the cast's trusted third party, is the trusted
//! introducer, and Mallory, its attacker, is the key nobody vouches for:
//!
//!     Alice, Releases    own keys, so trust roots       -> verified
//!     Bob                certified in full by Alice     -> verified
//!     Trent              trusted introducer, from Alice -> verified
//!     Carol              certified by Trent             -> verified, one hop out
//!     Dave               partially certified by Alice   -> partly verified
//!     Mallory            nobody has vouched for them    -> unverified
//!
//! It also writes `message-from-bob.asc` beside the store: a message Bob
//! signed and encrypted to Alice, for the Decrypt / Verify dialog and the
//! notepad to open. Bob's secret key never reaches the store; the message is
//! signed with the copy this process generated.

use rpgp_core::Store;
use rpgp_core::certify::{CertifyRequest, PARTIAL, certify};
use rpgp_core::keygen::{KeyGenRequest, KeyType, generate};
use sequoia_openpgp::Cert;

const MESSAGE: &str = "The signed release is on the mirror, with the checksums beside it.\n\
                       Shout if anything looks off before Thursday.\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(std::env::args_os().nth(1).ok_or(
        "usage: seed-demo-store <directory>   (e.g. /tmp/rpgp-demo; \
         this never writes to the default store)",
    )?);
    // The same layout Store::open_default builds.
    let secrets_dir = root.join("rpgp").join("secrets");
    let store = Store::open(root.join("pgp.cert.d"), &secrets_dir)?;

    let alice = make(
        &store,
        "Alice <alice@example.org>",
        KeyType::Curve25519,
        true,
    )?;
    let _releases = make(
        &store,
        "Example Project Releases <releases@example.net>",
        KeyType::Rsa3072,
        true,
    )?;
    let bob = make(&store, "Bob <bob@example.com>", KeyType::Curve25519, false)?;
    let carol = make(
        &store,
        "Carol <carol@example.net>",
        KeyType::Curve25519,
        false,
    )?;
    let dave = make(&store, "Dave <dave@example.com>", KeyType::Rsa3072, false)?;
    let _mallory = make(
        &store,
        "Mallory <mallory@example.org>",
        KeyType::Curve25519,
        false,
    )?;

    // Trent needs his secret key briefly so he can certify Carol, then gives
    // it up: he should appear as somebody else's key, not one of ours.
    let trent = make(
        &store,
        "Trent <trent@example.org>",
        KeyType::Curve25519,
        true,
    )?;

    certification(&store, &alice, &bob, "Bob <bob@example.com>", |_| {})?;
    certification(&store, &alice, &dave, "Dave <dave@example.com>", |r| {
        r.amount = PARTIAL;
    })?;
    certification(&store, &alice, &trent, "Trent <trent@example.org>", |r| {
        r.depth = 1;
    })?;
    certification(&store, &trent, &carol, "Carol <carol@example.net>", |_| {})?;

    let message = root.join("message-from-bob.asc");
    rpgp_core::ops::encrypt(
        std::slice::from_ref(&alice),
        &[],
        Some((&bob, None)),
        MESSAGE.as_bytes(),
        std::fs::File::create(&message)?,
    )?;
    println!("wrote {}", message.display());

    // From the directory this actually wrote to. Rebuilding it from
    // dirs::data_dir() named a different place on two of the three platforms:
    // the store uses data_local_dir(), which on Windows is Local rather than
    // Roaming, so this deleted nothing and the third party kept a secret key.
    std::fs::remove_file(secrets_dir.join(format!("{}.pgp", trent.fingerprint().to_hex())))?;
    println!("dropped Trent's secret key so he reads as a third party");

    Ok(())
}

/// Generate a key, store it, and return it with its secret, which this
/// process holds whether or not the store keeps one.
fn make(
    store: &Store,
    user_id: &str,
    key_type: KeyType,
    keep_secret: bool,
) -> Result<Cert, Box<dyn std::error::Error>> {
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

    println!("{} {user_id}", key.cert.fingerprint().to_hex());
    Ok(key.cert)
}

fn certification(
    store: &Store,
    certifier: &Cert,
    target: &Cert,
    user_id: &str,
    adjust: impl FnOnce(&mut CertifyRequest),
) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = CertifyRequest::new(
        certifier.fingerprint().to_hex(),
        target.fingerprint().to_hex(),
    );
    request.user_ids = vec![user_id.to_string()];
    adjust(&mut request);
    certify(store, &request)?;
    Ok(())
}
