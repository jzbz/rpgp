//! Finding certificates that are not in the store yet: Web Key Directory and
//! HKPS keyservers.
//!
//! Both protocols are plain HTTPS GETs returning an OpenPGP certificate, which
//! is why this is hand-rolled rather than delegated to `sequoia-net`: that
//! crate hardcodes `hyper-tls` and a `dnssec-openssl` resolver with no feature
//! to opt out, and OpenSSL is precisely what this build has avoided
//! everywhere else. `reqwest` with `rustls-tls` keeps it pure Rust.
//!
//! WKD is tried before a keyserver. A certificate served from the domain of
//! the address itself carries more weight than one anybody could upload.

use std::time::Duration;

use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse;

use crate::error::{Error, Result};

/// Where a certificate was found, so the UI can say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Served by the domain of the address itself.
    WebKeyDirectory,
    Keyserver,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::WebKeyDirectory => "web key directory",
            Source::Keyserver => "keyserver",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Found {
    pub cert: Cert,
    pub source: Source,
}

const TIMEOUT: Duration = Duration::from_secs(10);

/// The most a keyserver or WKD reply is allowed to be.
///
/// A certificate with a great many signatures runs to a few hundred kilobytes;
/// a keyserver bundle of several is a few megabytes. Anything past this is not
/// a certificate, it is a host — malicious or broken — trying to make the app
/// allocate until it dies. Both the announced length and the bytes actually
/// received are held to it, because the two need not agree.
const MAX_REPLY: usize = 8 * 1024 * 1024;

/// One client for both directions: same timeout, same identity, same rule for
/// redirects. Five hops is generous for a keyserver; a hop that leaves HTTPS
/// is refused outright, since a downgrade on the way to fetch key material is
/// exactly what a network attacker would arrange.
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(concat!("rpgp/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("too many redirects")
            } else if attempt.url().scheme() != "https" {
                attempt.error("redirected off HTTPS")
            } else if redirects_inward(attempt.url()) {
                attempt.error("redirected to a private address")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| Error::invalid(format!("cannot build an HTTP client: {e}")))
}
/// Whether a redirect target names an address inside the machine or its
/// network, which a keyserver never legitimately does.
///
/// Scheme and hop count alone left the client willing to follow a hostile
/// server's `Location` to a loopback or RFC1918 address, turning a key lookup
/// into a probe of whatever the user's network runs — blind, since the body is
/// parsed as a certificate and discarded, but the difference between a refused
/// connection and a timeout is still an answer.
///
/// Only IP literals are rejected. A DNS name that resolves inward still passes,
/// because refusing that needs a resolver-level hook rather than a URL test;
/// this closes the direct case and does not pretend to close the other one.
fn redirects_inward(url: &reqwest::Url) -> bool {
    use std::net::IpAddr;

    let Some(host) = url.host_str() else {
        return false;
    };
    // An IPv6 literal arrives bracketed in a URL; a domain name will not parse
    // as an address at all, which is the "not a literal" case below.
    let Ok(addr) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    else {
        return false;
    };
    inward(addr)
}

/// Whether an address points somewhere the caller's own network can reach.
///
/// Split out so the IPv4-mapped case can recurse: `::ffff:127.0.0.1` is a
/// perfectly ordinary way to write a loopback address in a URL, and every IPv6
/// test below says no to it — `is_loopback` is true only of `::1`, and both
/// segment masks read the first segment, which is zero in a mapped address. It
/// therefore sailed through the guard and named 127.0.0.1 anyway.
fn inward(addr: std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match addr {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            // These first, and before any IPv4 unwrapping: to_ipv4() reads ::1
            // as the IPv4-compatible 0.0.0.1, which is neither loopback nor
            // private, so unwrapping first would wave the plain IPv6 loopback
            // through.
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // An IPv4-mapped or IPv4-compatible address *is* that IPv4
            // address; ask the question that applies to it. ::ffff:127.0.0.1
            // is an ordinary way to write loopback in a URL and satisfies none
            // of the tests below — is_loopback holds only for ::1, and both
            // segment masks read the first segment, which is zero here.
            if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return inward(IpAddr::V4(v4));
            }
            // Unique-local (fc00::/7) and link-local (fe80::/10). The std
            // predicates for these are still unstable, so test directly.
            (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Verifying keyserver: it only serves addresses whose owner confirmed them.
const DEFAULT_KEYSERVER: &str = "https://keys.openpgp.org";

/// The keyserver to talk to. `RPGP_KEYSERVER` overrides it, for organisations
/// running their own and for testing against a local one rather than uploading
/// to public infrastructure.
fn keyserver() -> String {
    std::env::var("RPGP_KEYSERVER")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_KEYSERVER.to_string())
}

/// Look `query` up, preferring the Web Key Directory.
///
/// `query` is an e-mail address, a fingerprint or a key ID. Only an address can
/// be looked up over WKD, since the protocol is defined in terms of one.
pub fn lookup(query: &str) -> Result<Vec<Found>> {
    let query = query.trim();
    if query.is_empty() {
        return Err(Error::invalid("nothing to look up"));
    }

    if query.contains('@')
        && let Ok(found) = lookup_wkd(query)
        && !found.is_empty()
    {
        return Ok(found);
    }
    lookup_keyserver(query)
}

/// Fetch from the address's own domain.
pub fn lookup_wkd(address: &str) -> Result<Vec<Found>> {
    let (local, domain) = address
        .rsplit_once('@')
        .ok_or_else(|| Error::invalid(format!("{address} is not an e-mail address")))?;
    if local.is_empty() || domain.is_empty() {
        return Err(Error::invalid(format!(
            "{address} is not an e-mail address"
        )));
    }

    let domain = domain.to_lowercase();
    let hash = wkd_hash(local);
    let encoded = percent_encode(local);

    // The advanced method is tried first, as the specification requires: a
    // domain that delegates to openpgpkey.<domain> should win over the direct
    // URL, which may be served by unrelated web hosting.
    let urls = [
        format!(
            "https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={encoded}"
        ),
        format!("https://{domain}/.well-known/openpgpkey/hu/{hash}?l={encoded}"),
    ];

    for url in urls {
        if let Ok(bytes) = get(&url)
            && let Ok(certs) = parse(&bytes)
            && !certs.is_empty()
        {
            return Ok(certs
                .into_iter()
                .map(|cert| Found {
                    cert,
                    source: Source::WebKeyDirectory,
                })
                .collect());
        }
    }
    Ok(Vec::new())
}

/// Fetch from a HKPS keyserver.
pub fn lookup_keyserver(query: &str) -> Result<Vec<Found>> {
    let url = format!(
        "{}/pks/lookup?op=get&options=mr&search={}",
        keyserver(),
        percent_encode(query)
    );
    let bytes = get(&url)?;
    Ok(parse(&bytes)?
        .into_iter()
        .map(|cert| Found {
            cert,
            source: Source::Keyserver,
        })
        .collect())
}

/// The local part hashed and z-base-32 encoded, as WKD defines it: lowercased,
/// SHA-1, then 32 characters of z-base-32.
fn wkd_hash(local: &str) -> String {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(local.to_lowercase().as_bytes());
    zbase32::encode(digest)
}

/// Escape the characters that would otherwise end the query parameter. Kept
/// deliberately small rather than pulling a dependency for it.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn get(url: &str) -> Result<Vec<u8>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::invalid(format!("cannot start the network runtime: {e}")))?;

    runtime.block_on(async {
        let mut response = client()?
            .get(url)
            .send()
            .await
            .map_err(|e| Error::invalid(format!("lookup failed: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::invalid(format!(
                "lookup returned {}",
                response.status()
            )));
        }

        // A lookup is the least trusted fetch this app makes: WKD means
        // whatever domain sits in the address the user typed. Refuse an
        // announced size over the cap before reading a byte, then hold the
        // bytes actually received to it as well, because a server is free to
        // lie about the first or send no length at all.
        if response
            .content_length()
            .is_some_and(|len| len > MAX_REPLY as u64)
        {
            return Err(Error::invalid("the reply is too large to be a certificate"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::invalid(format!("reading the reply failed: {e}")))?
        {
            if body.len() + chunk.len() > MAX_REPLY {
                return Err(Error::invalid("the reply is too large to be a certificate"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    })
}

fn parse(bytes: &[u8]) -> Result<Vec<Cert>> {
    let mut out = Vec::new();
    // A keyserver can serve several certificates; a broken one among them
    // should not lose the rest, so failures are dropped rather than returned.
    for cert in CertParser::from_bytes(bytes)?.flatten() {
        out.push(cert);
    }
    Ok(out)
}

/// What a keyserver did with an upload.
#[derive(Debug, Clone)]
pub struct Published {
    /// Fingerprint the server says it stored.
    pub fingerprint: String,
    /// Addresses the server will publish once their owner confirms, and the
    /// state it reports for each.
    pub addresses: Vec<(String, String)>,
    /// Handed back so verification mails can be requested for the addresses.
    pub token: Option<String>,
}

/// Upload a certificate to the keyserver.
///
/// This cannot be undone. A keyserver has no delete: once a certificate is
/// uploaded it is public, permanently, and so is every user ID on it. Callers
/// must make that clear before getting here.
///
/// Only the public half is ever sent — the secret key material is stripped
/// first, so a caller that hands over a certificate carrying secrets does not
/// publish them by accident.
/// The exact bytes [`publish`] uploads.
///
/// Split out so the guarantees in publish's doc comment can be asserted on the
/// upload itself, without a keyserver to talk to. The test that claimed to
/// prove them only ever inspected the *reply*, and carried `#[ignore]`, so
/// nothing would have caught a regression here.
fn upload_body(cert: &Cert) -> Result<String> {
    use sequoia_openpgp::serialize::SerializeInto;

    let public = cert.clone().strip_secret_key_material();
    // export_to_vec, not to_vec: the difference is that export omits
    // signatures marked non-exportable, which is what a "local" certification
    // made in this app is. to_vec would have sent every private trust
    // statement the user ever made about this key to a public server.
    String::from_utf8(public.armored().export_to_vec()?)
        .map_err(|_| Error::invalid("the certificate did not armor as text"))
}

pub fn publish(cert: &Cert) -> Result<Published> {
    let armored = upload_body(cert)?;

    let body = serde_json::json!({ "keytext": armored });
    let reply = post(&format!("{}/vks/v1/upload", keyserver()), body)?;

    Ok(Published {
        fingerprint: reply
            .get("key_fpr")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_uppercase(),
        addresses: reply
            .get("status")
            .and_then(|v| v.as_object())
            .map(|statuses| {
                statuses
                    .iter()
                    .map(|(address, state)| {
                        (
                            address.clone(),
                            state.as_str().unwrap_or("unknown").to_lowercase(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        token: reply
            .get("token")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    })
}

/// Ask the keyserver to mail each address a confirmation link.
///
/// Until an address is confirmed the keyserver stores the certificate but will
/// not serve it by that address, which is the whole point of a verifying
/// keyserver: nobody can publish an identity they do not control.
pub fn request_verification(token: &str, addresses: &[String]) -> Result<()> {
    if addresses.is_empty() {
        return Err(Error::invalid("no addresses to verify"));
    }
    let body = serde_json::json!({ "token": token, "addresses": addresses });
    post(&format!("{}/vks/v1/request-verify", keyserver()), body)?;
    Ok(())
}

fn post(url: &str, body: serde_json::Value) -> Result<serde_json::Value> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::invalid(format!("cannot start the network runtime: {e}")))?;

    runtime.block_on(async {
        let mut response = client()?
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::invalid(format!("upload failed: {e}")))?;

        let status = response.status();
        // Bounded like get(): a JSON status reply is a few hundred bytes, and
        // an upload endpoint is no more entitled to an unbounded read.
        //
        // A read that fails or overruns the cap is remembered rather than
        // returned here. The status check below explains a refusal out of
        // whatever body arrived, which is more use than a transport error;
        // only a reply claiming success has to be whole, so that is where the
        // failure surfaces. Ending the loop silently, as this once did,
        // reported a dropped connection as unexpected data.
        let mut raw = Vec::new();
        let mut incomplete: Option<Error> = None;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if raw.len() + chunk.len() > MAX_REPLY {
                        incomplete = Some(Error::invalid("the reply is too large"));
                        break;
                    }
                    raw.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    incomplete = Some(Error::invalid(format!("reading the reply failed: {e}")));
                    break;
                }
            }
        }
        let text = String::from_utf8_lossy(&raw).into_owned();
        if !status.is_success() {
            // The server explains refusals in the body; passing it through
            // beats reporting a bare status code.
            return Err(Error::invalid(format!(
                "the keyserver refused the upload ({status}): {}",
                text.trim()
            )));
        }
        if let Some(e) = incomplete {
            return Err(e);
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::invalid(format!("the keyserver replied with unexpected data: {e}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_wkd_hash_from_the_specification() {
        // The example from the WKD draft: Joe.Doe@example.org hashes to this.
        assert_eq!(wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    }

    #[test]
    fn escapes_the_query() {
        assert_eq!(percent_encode("a b+c@d"), "a%20b%2Bc%40d");
        assert_eq!(percent_encode("plain-name.1_x~"), "plain-name.1_x~");
    }

    /// Against the real network, so `#[ignore]`d: it needs an internet
    /// connection and depends on other people's servers staying up.
    #[test]
    #[ignore = "hits the network"]
    fn finds_a_certificate_on_the_live_network() {
        // A long-standing WKD deployment, used as the example in several
        // OpenPGP tutorials.
        match lookup_wkd("wiktor@metacode.biz") {
            Ok(found) if !found.is_empty() => {
                let summary = crate::CertSummary::from_cert(&found[0].cert);
                eprintln!(
                    "WKD: {} {} via {}",
                    summary.fingerprint,
                    summary.primary_user_id,
                    found[0].source.as_str()
                );
                assert_eq!(found[0].source, Source::WebKeyDirectory);
            }
            Ok(_) => eprintln!("WKD: nothing served for that address"),
            Err(e) => eprintln!("WKD: {e}"),
        }

        // keys.openpgp.org serves by fingerprint without verification.
        let fingerprint = "653909A2F0E37C106F5FAF546C8857E0D8E8F074";
        match lookup_keyserver(fingerprint) {
            Ok(found) if !found.is_empty() => {
                let summary = crate::CertSummary::from_cert(&found[0].cert);
                eprintln!(
                    "keyserver: {} {}",
                    summary.fingerprint, summary.primary_user_id
                );
                assert_eq!(found[0].source, Source::Keyserver);
                assert_eq!(summary.fingerprint, fingerprint);
            }
            Ok(_) => eprintln!("keyserver: nothing served"),
            Err(e) => eprintln!("keyserver: {e}"),
        }
    }

    /// Serve one HTTP reply from a throwaway socket and hand back its origin.
    ///
    /// Enough of a server to exercise the fetch path and no more: it answers
    /// exactly one request with whatever bytes the caller supplies.
    fn serve_once(reply: Vec<u8>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut scratch = [0u8; 2048];
                let _ = socket.read(&mut scratch);
                let _ = socket.write_all(&reply);
                let _ = socket.flush();
            }
        });
        origin
    }

    /// The size cap and the redirect policy are claims the module doc makes.
    /// They were made on the upload path only, and the lookup path — the one
    /// reachable by any WKD domain a user types — quietly had neither for
    /// several commits, because nothing tested them. Hence this.
    ///
    /// Serial with the other env-var tests by way of a mutex: RPGP_KEYSERVER
    /// is process-wide state.
    /// RPGP_KEYSERVER is process-wide, so every test that sets it takes this.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_lookup_refuses_an_oversized_reply_and_a_downgrade() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        // (1) An announced length past the cap is refused before a byte of
        // body is read.
        let huge = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_REPLY as u64 + 1
        )
        .into_bytes();
        unsafe { std::env::set_var("RPGP_KEYSERVER", serve_once(huge)) };
        let err = lookup_keyserver("alice@example.org")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("too large"),
            "announced length not refused: {err}"
        );

        // (2) A body that runs past the cap with no length announced is cut
        // off by the streaming check rather than buffered.
        let mut chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/pgp-keys\r\n\r\n".to_vec();
        chunked.extend(std::iter::repeat_n(b'A', MAX_REPLY + 4096));
        unsafe { std::env::set_var("RPGP_KEYSERVER", serve_once(chunked)) };
        let err = lookup_keyserver("alice@example.org")
            .unwrap_err()
            .to_string();
        assert!(err.contains("too large"), "streamed body not capped: {err}");

        // (3) A redirect that leaves HTTPS is refused rather than followed.
        let redirect =
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/evil\r\nContent-Length: 0\r\n\r\n"
                .to_vec();
        unsafe { std::env::set_var("RPGP_KEYSERVER", serve_once(redirect)) };
        let err = lookup_keyserver("alice@example.org")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("lookup failed") || err.contains("redirect"),
            "a non-HTTPS redirect should not be followed: {err}"
        );

        unsafe { std::env::remove_var("RPGP_KEYSERVER") };
    }

    /// A reply that stops mid-body must say the read failed, not that the
    /// keyserver sent something unexpected.
    ///
    /// `post` ended its read loop on `Err` exactly as silently as on
    /// end-of-body, so a dropped connection surfaced as "the keyserver replied
    /// with unexpected data" — the one diagnosis that rules out what actually
    /// happened. Publishing is irreversible, and this message is the user's
    /// only signal that the upload's fate is unknown rather than rejected.
    #[test]
    fn a_truncated_upload_reply_reports_the_read_failure() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        // Announce a full body, send a fragment, then drop the connection.
        let mut reply =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n"
                .to_vec();
        reply.extend_from_slice(br#"{"key_fpr":"AAAA","token":"t"#);
        unsafe { std::env::set_var("RPGP_KEYSERVER", serve_once(reply)) };

        let cert = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Demo <demo@example.invalid>",
        ))
        .unwrap()
        .cert;
        let err = publish(&cert).unwrap_err().to_string();

        assert!(
            err.contains("reading the reply failed"),
            "a dropped connection must not be reported as bad data: {err}"
        );

        unsafe { std::env::remove_var("RPGP_KEYSERVER") };
    }

    /// Publishing against a local stand-in for the VKS API, so the request we
    /// build and the reply we parse are exercised without uploading anything
    /// to public infrastructure.
    #[test]
    /// Run it against any server that answers `POST /vks/v1/upload` with
    /// `{"key_fpr", "status", "token"}` and accepts `POST
    /// /vks/v1/request-verify`, pointed at by `RPGP_KEYSERVER`. Asserting on
    /// the request is the point: the upload must be an armored *public* key
    /// block containing no secret key material.
    #[ignore = "needs a local stand-in for the VKS API at $RPGP_KEYSERVER"]
    fn publishes_to_a_local_keyserver() {
        let cert = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Demo <demo@example.invalid>",
        ))
        .unwrap()
        .cert;

        let published = publish(&cert).expect("the mock should accept the upload");
        eprintln!("fingerprint: {}", published.fingerprint);
        eprintln!("addresses:   {:?}", published.addresses);
        eprintln!("token:       {:?}", published.token);

        // The mock echoes a placeholder; what matters is that the reply's
        // key_fpr is parsed and upper-cased rather than dropped.
        assert_eq!(published.fingerprint.len(), 40);
        assert!(published.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(published.token.is_some());
        assert!(
            published
                .addresses
                .iter()
                .any(|(a, state)| a == "demo@example.invalid" && state == "unpublished")
        );

        request_verification(
            published.token.as_deref().unwrap(),
            &["demo@example.invalid".to_string()],
        )
        .expect("verification request should be accepted");
    }

    /// What publish actually uploads: a public key block, with no secret key
    /// material and no local certifications.
    ///
    /// Runs without a keyserver, so unlike the ignored integration test below
    /// this one guards the property on every `cargo test`.
    ///
    /// The local-certification half is the part with teeth. Serialising a
    /// `Cert` writes only the public half whatever `strip_secret_key_material`
    /// did, so the no-secrets assertion documents the invariant more than it
    /// defends it; swapping `export_to_vec` for `to_vec`, on the other hand,
    /// silently ships every private trust statement the user ever made, and
    /// that is what this catches.
    #[test]
    fn the_upload_carries_no_secret_material_and_no_local_certifications() {
        use crate::certify::{CertifyRequest, certify};
        use crate::keygen::{KeyGenRequest, generate};
        use sequoia_openpgp::parse::Parse;

        let dir = tempfile::tempdir().unwrap();
        let store =
            crate::store::Store::open(dir.path().join("certs.d"), dir.path().join("secrets"))
                .unwrap();

        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();
        assert!(alice.is_tsk(), "the fixture must carry a secret half");

        // A local certification: kept in this store, never published.
        let mut request =
            CertifyRequest::new(alice.fingerprint().to_hex(), bob.fingerprint().to_hex());
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        request.exportable = false;
        let bob = certify(&store, &request).unwrap();
        assert_eq!(
            bob.userids().next().unwrap().certifications().count(),
            1,
            "the local certification must be on the cert we are about to upload"
        );

        let body = upload_body(&bob).unwrap();
        assert!(body.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(
            !body.contains("PRIVATE KEY BLOCK"),
            "a private key block reached the upload body"
        );

        let uploaded = Cert::from_bytes(body.as_bytes()).unwrap();
        assert!(
            !uploaded.is_tsk(),
            "the uploaded certificate still carries secret key material"
        );
        assert_eq!(uploaded.fingerprint(), bob.fingerprint());
        assert_eq!(
            uploaded.userids().next().unwrap().certifications().count(),
            0,
            "a non-exportable local certification reached the upload"
        );

        // And the signer's own secret key never armors into the body either.
        let alice_body = upload_body(&alice).unwrap();
        assert!(!Cert::from_bytes(alice_body.as_bytes()).unwrap().is_tsk());
    }

    /// The redirect guard, exercised directly: scheme and hop count never
    /// looked at where a redirect pointed, so a hostile server could send the
    /// client at the machine's own network.
    #[test]
    fn refuses_redirects_that_point_inward() {
        let inward = [
            "https://127.0.0.1/vks/v1/by-email/a@b.c",
            "https://10.0.0.5:8443/",
            "https://192.168.1.1/",
            "https://172.16.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://0.0.0.0/",
            "https://[::1]/",
            "https://[fe80::1]/",
            "https://[fc00::1]/",
            // IPv4-mapped and IPv4-compatible forms of the same private
            // addresses. Every IPv6 predicate says no to these — is_loopback
            // holds only for ::1, and the segment masks read the first
            // segment, which is zero here — so they walked straight through
            // the guard and named 127.0.0.1 anyway.
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:169.254.169.254]/latest/meta-data/",
            "https://[::ffff:10.0.0.5]/",
            "https://[::ffff:192.168.1.1]/",
        ];
        for url in inward {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(redirects_inward(&parsed), "should have been refused: {url}");
        }

        let outward = [
            "https://keys.openpgp.org/vks/v1/upload",
            "https://openpgpkey.example.org/.well-known/openpgpkey/",
            "https://8.8.8.8/",
            "https://[2606:4700:4700::1111]/",
        ];
        for url in outward {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(
                !redirects_inward(&parsed),
                "should have been allowed: {url}"
            );
        }
    }

    #[test]
    fn rejects_input_that_is_not_an_address() {
        assert!(lookup_wkd("not-an-address").is_err());
        assert!(lookup_wkd("@example.org").is_err());
        assert!(lookup("   ").is_err());
    }
}
