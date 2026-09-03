//! What a store reload costs, and how it scales.
//!
//! Reload is the dominant workload: it runs at startup and after every
//! mutation — import, certify, revoke, keygen, delete — so its cost is latency
//! the user feels rather than throughput that can be amortised.
//!
//! It used to run on the Slint event loop, and these numbers are why it no
//! longer does: 18ms at a thousand certificates and 118ms at five thousand,
//! against a 16ms frame. Off the loop the cost is a list that fills a moment
//! later rather than a window that stops repainting, but it is the same cost —
//! this still measures the thing worth making smaller.
//!
//! Deliberately not criterion. The questions here are "does this scale" and
//! "did that change help", both answered by wall-clock at two-times
//! resolution; criterion would answer them more precisely at the cost of about
//! fifty crates in `Cargo.lock`, and the Flatpak build vendors the whole
//! lockfile offline. `harness = false` in Cargo.toml makes this a plain
//! binary, so `cargo bench` runs it and no test harness is involved.
//!
//! Only the rpgp-core half of a reload is measured: parsing the store,
//! summarising each certificate, and rebuilding the trust graph — the part
//! that scales with the keyring. The GUI's row building and sorting are
//! measured separately by rpgp-gui's keystroke bench, which reaches them
//! through the `rpgp_gui` library target added for exactly that purpose. This
//! used to say a bench could not reach them at all, which stopped being true
//! when that target was added.
//!
//!     cargo bench -p rpgp-core
//!     RPGP_BENCH_SIZES=50,200,1000 cargo bench -p rpgp-core

use std::time::{Duration, Instant};

use rpgp_core::certify::{CertifyRequest, certify};
use rpgp_core::keygen::{KeyGenRequest, generate};
use rpgp_core::store::Store;
use rpgp_core::{CertSummary, wot};

/// One measurement: the fastest run of several, plus the median.
///
/// The minimum is the least noisy estimate of the work itself — it is the run
/// that happened to be least interrupted — while the median says whether the
/// spread is worth distrusting. Reporting both makes a suspicious sample
/// obvious instead of hiding it behind an average.
struct Timing {
    min: Duration,
    median: Duration,
}

fn time<T>(samples: usize, mut f: impl FnMut() -> T) -> Timing {
    // One untimed pass so page faults and lazily-built caches inside the store
    // are not charged to the first sample.
    let _ = f();

    let mut runs: Vec<Duration> = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let value = f();
        runs.push(start.elapsed());
        // Kept alive across the timer so the work cannot be optimised away.
        std::hint::black_box(value);
    }
    runs.sort();
    Timing {
        min: runs[0],
        median: runs[runs.len() / 2],
    }
}

fn report(label: &str, n: usize, t: Timing) {
    let per = t.min.as_secs_f64() * 1e6 / n as f64;
    println!(
        "  {label:<26} min {:>9.2?}   median {:>9.2?}   {per:>8.1} us/cert",
        t.min, t.median
    );
}

/// A store of `n` certificates: two with secret keys, and a certification from
/// the first onto every tenth certificate so the trust graph has real edges to
/// walk rather than being trivially empty.
fn fixture(dir: &std::path::Path, n: usize) -> Store {
    let store = Store::open(dir.join("pgp.cert.d"), dir.join("secrets")).unwrap();

    let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
        .unwrap()
        .cert;
    store.insert_secret(&mine).unwrap();
    let second = generate(&KeyGenRequest::new("Also me <also@example.org>"))
        .unwrap()
        .cert;
    store.insert_secret(&second).unwrap();

    for i in 0..n.saturating_sub(2) {
        let user_id = format!("Person {i} <person{i}@example.org>");
        let cert = generate(&KeyGenRequest::new(&user_id)).unwrap().cert;
        store.insert(&cert).unwrap();
        if i % 10 == 0 {
            let mut request =
                CertifyRequest::new(mine.fingerprint().to_hex(), cert.fingerprint().to_hex());
            request.user_ids = vec![user_id];
            let _ = certify(&store, &request);
        }
    }
    store
}

fn main() {
    let sizes: Vec<usize> = std::env::var("RPGP_BENCH_SIZES")
        .ok()
        .map(|s| s.split(',').filter_map(|n| n.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![50, 200, 1000]);
    let samples: usize = std::env::var("RPGP_BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);

    println!("rpgp reload benchmark — {samples} samples per measurement\n");

    for &n in &sizes {
        let dir = tempfile::tempdir().unwrap();
        let build = Instant::now();
        let store = fixture(dir.path(), n);
        let certs = store.certs().unwrap();
        println!(
            "n = {n} certificates  (fixture built in {:.1?}, store holds {})",
            build.elapsed(),
            certs.len()
        );

        // The cold pass: a fresh handle with an empty cache, which is what
        // startup and every delete-then-reopen actually pay. Separate from
        // store.certs() below, which measures the warm cache the rest of the
        // session sees.
        //
        // Added to settle a review claim that Store::open should call cert-d's
        // prefetch_all to parallelise this. Measured at n=1000 and n=3000 over
        // 25 samples, it is consistently a shade slower, not faster: cert-d
        // already reads the files in parallel, and the canonicalisation left
        // over is ~1.5 us per certificate. Do not add it back without a
        // measurement that says otherwise on this line.
        report(
            "cold open + certs()",
            n,
            time(samples, || {
                let fresh =
                    Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
                fresh.certs().unwrap()
            }),
        );
        report("store.certs()", n, time(samples, || store.certs().unwrap()));
        report(
            "CertSummary::from_cert xN",
            n,
            time(samples, || {
                certs
                    .iter()
                    .map(|c| CertSummary::from_cert(c))
                    .collect::<Vec<_>>()
            }),
        );
        report(
            "secret_fingerprints()",
            n,
            time(samples, || store.secret_fingerprints().unwrap()),
        );
        report(
            "effective_roots()",
            n,
            time(samples, || store.effective_roots().unwrap()),
        );

        let roots: Vec<String> = store.effective_roots().unwrap().into_iter().collect();
        report(
            "wot::authenticate_all()",
            n,
            time(samples, || wot::authenticate_all(&certs, &roots)),
        );

        // The sequence reload actually performs, so the parts can be weighed
        // against the whole rather than only against each other.
        report(
            "= reload core (all above)",
            n,
            time(samples, || {
                let certs = store.certs().unwrap();
                let summaries: Vec<_> = certs.iter().map(|c| CertSummary::from_cert(c)).collect();
                let roots: Vec<String> = store.effective_roots().unwrap().into_iter().collect();
                let authenticated = wot::authenticate_all(&certs, &roots);
                let secrets = store.secret_fingerprints().unwrap();
                (summaries, authenticated, secrets)
            }),
        );
        println!();
    }
}
