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
//! the address itself carries more weight than one anybody could upload —
//! which is a claim about the address and not about the host, so what a WKD
//! host serves is kept only where it carries the address that was asked for.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::cert::amalgamation::UserIDAmalgamation;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::{Cert, KeyHandle};

use crate::error::{Error, Result};

/// Where a certificate was found, so the UI can say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Served by the domain of the address itself, and carrying it: see
    /// [`only_the_requested_address`], which is what makes this label mean
    /// what the lookup dialog shows it to mean.
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

/// Who a fetch is aimed at, which is what decides whether the configured
/// keyserver's own name is exempt from the guard.
///
/// The exemption used to belong to every client rather than to the fetch that
/// earned it. Matching by name alone, it therefore also covered a WKD address
/// whose domain happened to be the keyserver's host, and any redirect naming
/// that host from anywhere at all — the opposite of what this module and the
/// README both say. The keyserver is the one host the *user* configured;
/// everything else is somebody else's choice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Peer {
    /// A URL this module built out of `RPGP_KEYSERVER`.
    Keyserver,
    /// A host somebody else named: the domain half of an address typed into
    /// the lookup field, or wherever a server's `Location` points.
    Elsewhere,
}

/// One client per fetch: same timeout, same identity, same rule for redirects.
fn client(peer: Peer) -> Result<reqwest::Client> {
    // Read once, here, so that neither the resolver nor the redirect policy
    // can straddle a change to the variable part way through a fetch.
    let configured = match peer {
        Peer::Keyserver => reqwest::Url::parse(&keyserver()).ok(),
        Peer::Elsewhere => None,
    };
    let exempt = configured
        .as_ref()
        .and_then(|url| url.host_str().map(str::to_lowercase));

    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(concat!("rpgp/", env!("CARGO_PKG_VERSION")))
        // A proxy from the environment would undo the guard completely. For an
        // HTTPS URL reqwest opens a CONNECT tunnel, so only the proxy's own
        // host reaches the resolver below: the target name travels to the
        // proxy as text and is resolved there, on the far side, wherever it
        // points. The same variables break the ordinary case too, since a
        // proxy named `proxy.corp` resolves to a private address and the guard
        // then refuses the proxy itself, failing every lookup. Neither is a
        // trade worth making for a fetch whose whole risk is that somebody
        // else chose the host.
        .no_proxy()
        .dns_resolver(Arc::new(Guarded { exempt }))
        .redirect(reqwest::redirect::Policy::custom(
            move |attempt| match redirect_refusal(
                attempt.url(),
                attempt.previous().len(),
                configured.as_ref(),
            ) {
                Some(reason) => attempt.error(reason),
                None => attempt.follow(),
            },
        ))
        .build()
        .map_err(|e| Error::invalid(format!("cannot build an HTTP client: {e}")))
}

/// Why a redirect must not be followed, or `None` to follow it.
///
/// A function of its own rather than the body of the policy closure, because
/// through a socket these clauses hide each other: the one redirect target
/// that is easy to stand up, a plain-HTTP server on loopback, trips the scheme
/// test and the literal test at once, so deleting either left the test that
/// named it green. Each clause can be put to the question separately here.
fn redirect_refusal(
    url: &reqwest::Url,
    hops: usize,
    keyserver: Option<&reqwest::Url>,
) -> Option<&'static str> {
    // Five hops is generous for a keyserver.
    if hops >= 5 {
        Some("too many redirects")
    } else if url.scheme() != "https" {
        // A downgrade on the way to fetch key material is exactly what a
        // network attacker would arrange, and reqwest refuses none on its own:
        // `https_only` is off by default, and all it does about an https to
        // http hop is drop the Referer header.
        Some("redirected off HTTPS")
    } else if inward_literal(url) {
        Some("redirected to a private address")
    } else if keyserver.is_some_and(|base| {
        base.host_str() == url.host_str()
            && (base.scheme() != url.scheme()
                || base.port_or_known_default() != url.port_or_known_default())
    }) {
        // [`Guarded`] exempts the keyserver by name, because a name is all
        // reqwest hands a resolver; the port is visible only here. Without
        // this, a redirect naming the keyserver's host on some other port
        // reached every port on an internal keyserver with the guard switched
        // off. A hop to any other host is left alone: that one still faces the
        // guard, which is the whole point of not exempting it.
        Some("redirected to another port on the keyserver's host")
    } else {
        None
    }
}

/// A resolver that refuses a name resolving inside the machine or its network.
///
/// [`inward_literal`] can only see an address written as an address, and the
/// hosts this client is pointed at are not chosen here: a WKD URL is built from
/// the domain half of whatever address someone handed the user, and a redirect
/// names whatever the server likes. `evil.example` with an A record of
/// 127.0.0.1 satisfied every test and probed the local network anyway — the
/// case the note on `inward_literal` said it did not close, closed here.
///
/// Resolving rather than testing a URL also closes the gap between the check
/// and the connection: reqwest connects to exactly the addresses handed back,
/// so a second DNS answer cannot arrive in between.
///
/// The configured keyserver is exempt, and only it, and only while this client
/// is the one fetching from it. `RPGP_KEYSERVER` exists for an organisation's
/// internal server, which is precisely a name that resolves to a private
/// address; refusing that would break the documented reason the variable
/// exists. A WKD domain and a redirect target are somebody else's choice, so
/// neither is exempt — hence [`Peer`], which is what keeps a lookup of
/// `alice@keys.corp.internal:8443`, or a hostile server's `Location` naming
/// that host, from inheriting an exemption meant for the keyserver alone.
struct Guarded {
    /// The configured keyserver's host, lowercased, filled in by [`client`]
    /// when it builds this resolver so a resolution cannot straddle a change
    /// to the variable, and only for [`Peer::Keyserver`].
    exempt: Option<String>,
}

impl reqwest::dns::Resolve for Guarded {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_lowercase();
        let exempt = self.exempt.as_deref() == Some(host.as_str());
        Box::pin(async move {
            let lookup = host.clone();
            // The system resolver, off the runtime thread, which is what the
            // default resolver does too. Port 0 because reqwest substitutes the
            // one the URL asked for.
            let addrs: Vec<SocketAddr> =
                tokio::task::spawn_blocking(move || (lookup.as_str(), 0u16).to_socket_addrs())
                    .await??
                    .collect();

            // One inward answer refuses the name outright rather than being
            // filtered out of the list: a server free to answer with a public
            // address and a private one would otherwise still have the private
            // one tried.
            if !exempt && let Some(bad) = addrs.iter().find(|addr| inward(addr.ip())) {
                return Err(format!(
                    "{host} resolves to {}, which is inside this network",
                    bad.ip()
                )
                .into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Whether a URL names an address inside the machine or its network, which a
/// keyserver or a WKD host never legitimately does.
///
/// Scheme and hop count alone left the client willing to follow a hostile
/// server's `Location` to a loopback or RFC1918 address, turning a key lookup
/// into a probe of whatever the user's network runs — blind, since the body is
/// parsed as a certificate and discarded, but the difference between a refused
/// connection and a timeout is still an answer.
///
/// Only IP literals, and deliberately so: a literal never reaches a resolver at
/// all, because hyper connects to one straight away. The name half of the same
/// question belongs to [`Guarded`], which is where it is now answered.
fn inward_literal(url: &reqwest::Url) -> bool {
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
fn inward(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // 100.64.0.0/10, shared address space. A carrier's NAT puts
                // the subscriber's own network in here, and Tailscale gives
                // every node on a tailnet an address in it and routes it over
                // tailscale0 — so a name answering with one of these reaches
                // this machine's network as surely as RFC1918 does, and the
                // NAS on the other end is exactly what the guard is for. The
                // tailnet's IPv6 half was already refused as unique-local; it
                // was only the IPv4 half that walked through. `is_shared` is
                // still unstable, hence the arithmetic.
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
                // 0.0.0.0/8, "this network": `is_unspecified` covers only
                // 0.0.0.0 itself, and nothing in the rest of the block is a
                // destination anybody legitimately serves from.
                || octets[0] == 0
                // 192.0.0.0/24, IETF protocol assignments, which is where a
                // DS-Lite home router answers on 192.0.0.1.
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
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
            let seg = v6.segments();
            // Local-use NAT64, 64:ff9b:1::/48 (RFC 8215). A site's translator
            // maps this onto whatever IPv4 space that site chose, so the
            // address names something inside the site and the embedded bits
            // say nothing about what: refuse the prefix outright.
            if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
                return true;
            }
            // The well-known NAT64 prefix, 64:ff9b::/96 (RFC 6052), where the
            // last 32 bits *are* the IPv4 address the translator will send to.
            // Ask the IPv4 question of them rather than refusing the prefix:
            // on an IPv6-only network DNS64 answers every public name from
            // here, and refusing it would break lookups outright.
            if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
                return inward(IpAddr::V4(Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    seg[6] as u8,
                    (seg[7] >> 8) as u8,
                    seg[7] as u8,
                )));
            }
            // 6to4, 2002::/16 (RFC 3056): the IPv4 address is the two segments
            // after the prefix. A host with a 6to4 tunnel of its own
            // encapsulates straight to that address instead of handing the
            // packet to a relay, so a private one names this machine's own
            // network again.
            if seg[0] == 0x2002 {
                return inward(IpAddr::V4(Ipv4Addr::new(
                    (seg[1] >> 8) as u8,
                    seg[1] as u8,
                    (seg[2] >> 8) as u8,
                    seg[2] as u8,
                )));
            }
            // Teredo, 2001:0::/32 (RFC 4380): the client's IPv4 address is the
            // last 32 bits with every bit flipped. A Teredo client sends
            // straight to a peer at that address once it has one, so the same
            // reasoning as 6to4 applies to it.
            if seg[0] == 0x2001 && seg[1] == 0x0000 {
                let client = !(((seg[6] as u32) << 16) | seg[7] as u32);
                return inward(IpAddr::V4(Ipv4Addr::from(client)));
            }
            // Unique-local (fc00::/7), link-local (fe80::/10) and site-local
            // (fec0::/10). The last is deprecated, but a host that still
            // honours it routes those addresses into the site.
            v6.is_unique_local() || v6.is_unicast_link_local() || (seg[0] & 0xffc0) == 0xfec0
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
///
/// Nothing is believed on the strength of where it came from: the reply is cut
/// down to the address that was asked for before any of it is handed back, and
/// a reply with nothing of the kind in it is nothing found rather than an
/// error, so [`lookup`] goes on to the keyserver.
pub fn lookup_wkd(address: &str) -> Result<Vec<Found>> {
    lookup_wkd_resolving(address, resolves)
}

/// [`lookup_wkd`], told by its caller which names have an address.
///
/// The seam is here because the choice [`wkd_url`] makes decides which host the
/// fetch names, and so which host the guards are asked about — while whether
/// `openpgpkey.localhost` resolves is a property of the machine the tests run
/// on rather than of this code. systemd-resolved synthesises every `*.localhost`
/// name; a resolver without that answers only `localhost` itself. A test about
/// the hosts a lookup may reach has to fix that choice rather than inherit it,
/// or it silently asserts about whichever URL the machine happened to pick.
fn lookup_wkd_resolving(address: &str, resolves: impl FnOnce(&str) -> bool) -> Result<Vec<Found>> {
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

    let advanced = format!(
        "https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={encoded}"
    );
    let direct = format!("https://{domain}/.well-known/openpgpkey/hu/{hash}?l={encoded}");

    // The domain half of an address is not required to be a name: `alice@[::1]`
    // and `alice@127.0.0.1:8080` are both accepted by the split above, and a
    // literal never reaches [`Guarded`] because hyper connects to one without
    // asking a resolver. So the URL test has to be applied here, where an
    // address someone else supplied first becomes a URL. Only the direct form
    // can be a literal — the advanced one carries an `openpgpkey.` prefix,
    // which makes it a name whatever the domain was.
    if reqwest::Url::parse(&direct).is_ok_and(|url| inward_literal(&url)) {
        return Err(Error::invalid(format!(
            "{address} names an address inside this network, not a domain to look up"
        )));
    }

    let url = wkd_url(advanced, direct, resolves);

    // A host that cannot be reached, refuses, or answers with something that is
    // not a certificate has no key for this address, which is not a failure to
    // report: `lookup` falls through to the keyserver either way.
    let Ok(bytes) = get(&url, Peer::Elsewhere) else {
        return Ok(Vec::new());
    };
    let Ok(certs) = parse(&bytes) else {
        return Ok(Vec::new());
    };

    Ok(only_the_requested_address(certs, address)
        .into_iter()
        .map(|cert| Found {
            cert,
            source: Source::WebKeyDirectory,
        })
        .collect())
}

/// Which of the two WKD URLs to fetch: the advanced one whenever
/// `openpgpkey.<domain>` has an address at all, the direct one only when it has
/// none.
///
/// The choice is a question about DNS rather than about what a host answers.
/// The specification is explicit: implementations must try the advanced method
/// first, and "Only if an address for the required sub-domain does not exist,
/// they SHOULD fall back to the direct method. A non-responding server does not
/// mean that the fall back should be carried out." Trying the advanced URL and
/// moving on whenever it did not yield a certificate — a 404, a TLS failure, a
/// timeout, a body that did not parse — handed every address a delegating
/// domain has not published to whoever runs the apex web site, which is the
/// party the delegation exists to keep out. The comment that stood over that
/// loop named exactly this risk and claimed the order alone answered it.
///
/// The host is taken from the parsed URL rather than pasted together again,
/// because the domain half of an address may carry a port: `openpgpkey.` plus
/// `example.org:8443` is a name and a port, not a name.
///
/// The cost is a domain that wildcards its DNS and publishes by the direct
/// method: `openpgpkey.<domain>` then resolves to a host serving no key, and
/// there is no second attempt. The specification puts that on the site — it
/// requires such a site to keep the `openpgpkey` sub-domain out of the wildcard
/// — and a lookup that finds nothing here still goes on to the keyserver.
///
/// `resolves` is a parameter so the rule can be put to the question without a
/// resolver, the way [`redirect_refusal`] is tested without a socket.
fn wkd_url(advanced: String, direct: String, resolves: impl FnOnce(&str) -> bool) -> String {
    let subdomain = reqwest::Url::parse(&advanced)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned));
    match subdomain {
        Some(host) if resolves(&host) => advanced,
        _ => direct,
    }
}

/// Whether a name has an address at all.
///
/// A resolver error reads as "no such name", because the system resolver will
/// not say which error it was: on Unix every `getaddrinfo` failure but
/// `EAI_SYSTEM` reaches std as an uncategorised `io::Error`, so NXDOMAIN and
/// SERVFAIL arrive alike. That makes the rule above a mitigation rather than a
/// guarantee — an on-path attacker who can forge a DNS answer can still force
/// the direct method, since nothing here validates DNSSEC — but it closes the
/// case that needs nobody on the wire: a delegated host answering 404 while the
/// apex host answers with a certificate.
///
/// Silence is not an error and is not read as absence. A resolver that has said
/// nothing within [`TIMEOUT`] has not said the name is missing, and falling
/// back on that would hand the address to the apex host for no better reason
/// than a slow network. The lookup then asks for the advanced URL, whose fetch
/// will resolve the same name under its own timeout and most likely find
/// nothing, and the keyserver still gets its turn afterwards.
///
/// The bound is why this runs on a thread of its own. `getaddrinfo` cannot be
/// cancelled, and with glibc's defaults against three unanswering nameservers
/// it takes about thirty seconds; on the caller's thread that is thirty
/// seconds the lookup cannot be brought back from, with the main window
/// disabled meanwhile. Abandoned here, it is bounded at ten like every fetch —
/// the same trade the `shutdown_background` in [`get`] makes, and the reason a
/// lookup's worst case is what it was before this pre-resolution existed: two
/// stalls on the WKD path where there used to be two WKD fetches.
///
/// It is [`Guarded`], on the connection that follows, that decides whether the
/// addresses may be reached; nothing is connected to here. The addresses found
/// here are dropped, and the fetch resolves the name again through the guard,
/// so the advanced host is looked up twice on a WKD fetch. That is the price
/// of leaving the judgement at the connection, where what is judged is the
/// address actually dialled rather than one found a moment earlier.
fn resolves(host: &str) -> bool {
    let host = host.to_owned();
    let (answer, waiting) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Port 0 because the port is not part of the question: std passes a
        // null service to `getaddrinfo` whatever number is written here.
        let _ = answer.send(
            (host.as_str(), 0u16)
                .to_socket_addrs()
                .is_ok_and(|mut addrs| addrs.next().is_some()),
        );
    });
    // A thread that was abandoned, or that died without answering, has said
    // nothing, which is not absence either.
    waiting.recv_timeout(TIMEOUT).unwrap_or(true)
}

/// Keep only what a WKD reply was entitled to return: certificates carrying
/// `address`, each stripped of every other identity on it.
///
/// The specification makes both halves a MUST — "A client MUST check that the
/// received key has the requested User-Id and MUST drop all other User-Ids
/// found in the received key" — and neither was done. A host serving
/// `alice@evil.example` could answer with `Bob <bob@bank.example>`, and the
/// lookup dialog listed it as coming from the web key directory, which is the
/// strongest provenance this application displays and the one the module doc
/// above claims. Importing it stored every user ID on it, and the certify
/// dialog offers those pre-ticked, so a certification meant for one identity
/// could be made over a name from a domain the server does not control.
///
/// A user ID counts only where the certificate signed for it. `cert.userids()`
/// includes a name anybody appended in flight, so matching on those alone would
/// let an unsigned `alice@example.org` stapled to a stranger's certificate pass
/// the check and be the one thing left after the strip. As in
/// [`crate::cert::primary_user_id`], the question asked is the cryptographic
/// one and not the policy one: a SHA-1 self-signature is still the holder's
/// own, and a certificate carrying one is exactly what someone looks up in
/// order to replace it.
///
/// A matching identity that has been revoked is kept. The specification allows
/// a revoked key to be served, and a revocation is the one thing about a key
/// its owner most wants seen.
fn only_the_requested_address(certs: Vec<Cert>, address: &str) -> Vec<Cert> {
    // An address this library cannot parse cannot be compared with a user ID,
    // and a check worded as a MUST fails closed rather than open.
    let Some(wanted) = normalized_address(address) else {
        return Vec::new();
    };
    certs
        .into_iter()
        .map(|cert| {
            cert.retain_userids(|ua| names_address(&ua, &wanted))
                // A photo is an identity claim as much as a name is, and this
                // reply is entitled to carry exactly one identity.
                .retain_user_attributes(|_| false)
        })
        .filter(|cert| cert.userids().next().is_some())
        .collect()
}

/// Keep only the certificates that answer `query`.
///
/// A keyserver is not held to the WKD rule: `keys.openpgp.org` serves only
/// addresses whose owner confirmed them, and dropping every other user ID is
/// something the WKD specification asks of a WKD client. But a reply still has
/// to be an answer to the question that was asked. `RPGP_KEYSERVER` may name
/// any HKP server, verifying or not, and a fingerprint query answered with an
/// entirely different certificate was listed as found.
///
/// Only a query this module can interpret is filtered on. A fingerprint or key
/// ID is matched against the certificate's primary key and against every
/// subkey the certificate has signed for, because HKP servers answer subkey
/// handles too and dropping those would lose genuine results. The binding is
/// required for the reason a self-signature is in [`names_address`]: a key
/// packet costs nothing to append, so an unbound one let anybody's key be
/// stapled to a stranger's certificate and that certificate be listed as the
/// answer to the stapled key's fingerprint — a genuine, often already-stored
/// certificate offered as the holder of a key it has never carried. An address
/// is matched as a WKD reply is, minus the strip. Anything else is a free-text
/// search, where the server decides what matches and a filter here could only
/// empty the list.
///
/// What this cannot decide is whose key a properly bound subkey is: two
/// certificates may bind the same key, and a handle is all an HKP query says,
/// so a certificate that has signed for a key it was given still answers for
/// it. Only the holder's own certification could tell those apart, and a
/// keyserver reply carries no authentication this module could weigh.
///
/// Something that looks like an address but does not parse as one — a quoted
/// local part, a host carrying a port — counts as free text too, and passes
/// unfiltered. That is the opposite of [`only_the_requested_address`], which
/// keeps nothing when it cannot read the address, and the difference is
/// deliberate: there the check is the whole of what makes the label honest, so
/// it fails closed, while here the server was asked a question this module
/// cannot restate and dropping its answer would only lose results.
fn answers_the_query(certs: Vec<Cert>, query: &str) -> Vec<Cert> {
    if let Ok(handle) = query.parse::<KeyHandle>()
        && !handle.is_invalid()
    {
        return certs
            .into_iter()
            .filter(|cert| {
                handle.aliases(cert.key_handle())
                    || cert.keys().subkeys().any(|ka| {
                        ka.self_signatures().next().is_some()
                            && handle.aliases(ka.key().key_handle())
                    })
            })
            .collect();
    }
    if query.contains('@')
        && let Some(wanted) = normalized_address(query)
    {
        return certs
            .into_iter()
            .filter(|cert| cert.userids().any(|ua| names_address(&ua, &wanted)))
            .collect();
    }
    certs
}

/// The address written the way [`UserID::email_normalized`] writes one, which
/// is how two addresses are compared here: punycoded domain, lowercased without
/// locale tailoring.
///
/// Both sides of every comparison go through sequoia's own rule rather than a
/// hand-written one, so that this module agrees with the rest of the OpenPGP
/// stack about when two addresses are the same address. `None` for anything
/// that is not an address at all.
fn normalized_address(address: &str) -> Option<String> {
    UserID::from_address(None, None, address)
        .ok()?
        .email_normalized()
        .ok()
        .flatten()
}

/// Whether `ua` is an identity the certificate signed for itself, naming
/// `wanted` — which must already be normalised by [`normalized_address`].
fn names_address(ua: &UserIDAmalgamation<'_>, wanted: &str) -> bool {
    // Sequoia hands out no self-signature it has not verified, so this is the
    // certificate speaking rather than whoever last handled it.
    ua.self_signatures().next().is_some()
        && ua.userid().email_normalized().ok().flatten().as_deref() == Some(wanted)
}

/// Fetch from a HKPS keyserver.
pub fn lookup_keyserver(query: &str) -> Result<Vec<Found>> {
    let url = format!(
        "{}/pks/lookup?op=get&options=mr&search={}",
        keyserver(),
        percent_encode(query)
    );
    let bytes = get(&url, Peer::Keyserver)?;
    Ok(answers_the_query(parse(&bytes)?, query)
        .into_iter()
        .map(|cert| Found {
            cert,
            source: Source::Keyserver,
        })
        .collect())
}

/// The local part hashed and z-base-32 encoded, as WKD defines it:
/// ASCII-lowercased, SHA-1, then 32 characters of z-base-32.
///
/// ASCII and nothing else. The specification maps "all upper-case ASCII
/// characters" to lower case and leaves non-ASCII characters alone, while
/// `str::to_lowercase` applies the whole Unicode mapping. The two disagree
/// about any local part carrying a non-ASCII capital — `Ärger` was hashed as
/// `ärger`, a different `hu` path from the one a conforming publisher wrote, so
/// a key that was published was quietly not found — and Unicode folds U+212A
/// KELVIN SIGN to `k`, so a look-alike `Kevin` fetched the real `kevin`'s key
/// instead.
fn wkd_hash(local: &str) -> String {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(local.to_ascii_lowercase().as_bytes());
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

fn get(url: &str, peer: Peer) -> Result<Vec<u8>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::invalid(format!("cannot start the network runtime: {e}")))?;

    let outcome = runtime.block_on(async {
        let mut response = client(peer)?
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
    });
    // Hand the runtime off rather than dropping it here. Dropping one blocks
    // until every blocking task has finished, and the resolver's
    // `getaddrinfo` is one of those, so a fetch whose timeout had already
    // fired still sat here for as long as the *system* resolver took — with
    // glibc's defaults against three unanswering nameservers, about thirty
    // seconds rather than TIMEOUT's ten, twice over for a lookup that tries a
    // WKD URL and then the keyserver, with the whole main window disabled
    // meanwhile. Handed off, the stuck thread finishes and exits on its own.
    // [`resolves`] abandons its own resolution for the same reason.
    runtime.shutdown_background();
    outcome
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

/// Upload a certificate to the keyserver.
///
/// This cannot be undone. A keyserver has no delete: once a certificate is
/// uploaded it is public, permanently, and so is every user ID on it. Callers
/// must make that clear before getting here.
///
/// Only the public half is ever sent — the secret key material is stripped
/// first, so a caller that hands over a certificate carrying secrets does not
/// publish them by accident.
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

    // Both callers build this URL out of `keyserver()`, so the exemption is
    // this fetch's to use.
    let outcome = runtime.block_on(async {
        let mut response = client(Peer::Keyserver)?
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
    });
    // Handed off rather than dropped, for the reason given in `get`.
    runtime.shutdown_background();
    outcome
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn derives_the_wkd_hash_from_the_specification() {
        // The example from the WKD draft: Joe.Doe@example.org hashes to this.
        assert_eq!(wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    }

    /// Only ASCII is mapped to lower case, which is what the specification says
    /// and what a publisher's tooling does.
    ///
    /// The vectors are `gpg-wks-client --print-wkd-hash` (GnuPG 2.4.9) for
    /// `ÄRGER@example.de` and for a `Kevin` whose K is U+212A KELVIN SIGN. The
    /// draft's own `Joe.Doe` vector cannot catch this, since both mappings
    /// agree on it: `str::to_lowercase` lowercases the `Ä`, which asks the
    /// publisher's host for a path it never wrote, and folds the Kelvin sign
    /// into ASCII `k`, which asks it for somebody else's key.
    #[test]
    fn maps_only_ascii_to_lower_case_in_the_wkd_hash() {
        assert_eq!(wkd_hash("ÄRGER"), "ewd7piirpeasam9iz8or84x4be3xhxqw");
        assert_eq!(wkd_hash("Ärger"), wkd_hash("ÄRGER"));
        assert_ne!(
            wkd_hash("ärger"),
            wkd_hash("ÄRGER"),
            "a non-ASCII capital is a different local part, not the same one"
        );

        assert_eq!(wkd_hash("\u{212a}evin"), "zsoj3njigu43ez6rcptj7rdb4z9kbtih");
        assert_ne!(
            wkd_hash("\u{212a}evin"),
            wkd_hash("kevin"),
            "a Kelvin sign was folded into ASCII k and fetched another mailbox"
        );
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

    /// [`serve_once`] with a tally of the connections it accepted, and its
    /// port rather than its origin.
    ///
    /// Several guards below are proved by what does *not* happen: the fetch
    /// fails either way, so what has to be asserted is that the client never
    /// reached the host it was steered at. A count of accepted connections
    /// says that where an error string cannot — and the port is what is handed
    /// back because these tests point a *name* at this listener, which is the
    /// only way a resolver is asked anything at all.
    fn serve_counting(reply: Vec<u8>) -> (u16, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let tally = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut socket) = stream else { break };
                tally.fetch_add(1, Ordering::SeqCst);
                let mut scratch = [0u8; 2048];
                let _ = socket.read(&mut scratch);
                let _ = socket.write_all(&reply);
                let _ = socket.flush();
            }
        });
        (port, hits)
    }

    /// An armored certificate, as a reply a fetch would accept. Used to bait
    /// the guards: a redirect that is followed has to *succeed*, or the test
    /// cannot tell a guard from a dead socket.
    fn bait_reply() -> Vec<u8> {
        let cert = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        armored_reply(&cert)
    }

    /// `cert` armored, wrapped in the 200 reply a keyserver or WKD host would
    /// send. What the *body* says is the point of the filtering tests below,
    /// which is why the certificate is the caller's to choose.
    ///
    /// Serialised rather than exported, because a hostile server sends what it
    /// likes: sequoia's export rules drop any component carrying no exportable
    /// self-signature, which is precisely the packet a splicing test staples
    /// on. For a certificate that was generated rather than assembled the two
    /// produce the same bytes.
    fn armored_reply(cert: &Cert) -> Vec<u8> {
        use sequoia_openpgp::serialize::SerializeInto;
        let body = cert.armored().to_vec().unwrap();
        let mut reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/pgp-keys\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        reply.extend_from_slice(&body);
        reply
    }

    /// Serialises every test here that touches process-wide state.
    ///
    /// `RPGP_KEYSERVER` and the proxy variables are process-wide, so every
    /// test that sets one takes this. So does every test that merely *resolves
    /// a name*, which is less obvious: `set_var` is unsafe precisely because
    /// the C environment can be read without any lock of std's, and
    /// `getaddrinfo` is one of those readers — glibc's resolver reads
    /// `LOCALDOMAIN` and `RES_OPTIONS`, and an NSS module its own variables,
    /// on the blocking thread [`Guarded`] resolves on. A resolving test that
    /// skipped this mutex was the one reader nothing covered.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The size cap is a claim the module doc makes. It was made on the upload
    /// path only, and the lookup path — the one reachable by any WKD domain a
    /// user types — quietly had neither cap nor redirect policy for several
    /// commits, because nothing tested them. Hence this and the guard tests
    /// that follow it.
    #[test]
    fn a_lookup_refuses_an_oversized_reply() {
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

        unsafe { std::env::remove_var("RPGP_KEYSERVER") };
    }

    /// The scheme clause of the redirect policy, on a redirect that nothing
    /// else in the policy would refuse.
    ///
    /// The target has to be a server that would actually answer, and answer
    /// with something the caller would accept. Pointing at a dead port made
    /// this vacuous: every transport error is formatted through the same
    /// "lookup failed: {e}" line at get(), so deleting the redirect policy left
    /// reqwest to follow the redirect, fail to connect, and produce the very
    /// string the assertion accepted.
    ///
    /// Answering was not enough either. The obvious target, `serve_once` on
    /// loopback, is an IP literal, so the private-address clause refused it
    /// too and the test stayed green with the scheme clause deleted. Here the
    /// target is a *name*, which is therefore no literal; it is the configured
    /// keyserver's host, so the resolver lets it through; and it is that
    /// keyserver's own origin, so the port clause does not fire either. The
    /// scheme is all that is left.
    #[test]
    fn a_redirect_off_https_is_refused_where_nothing_else_would_refuse_it() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        let (port, hits) = serve_counting(bait_reply());
        unsafe { std::env::set_var("RPGP_KEYSERVER", format!("http://localhost:{port}")) };

        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://localhost:{port}/evil\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes();
        let source = serve_once(redirect);
        let outcome = get(&format!("{source}/pks/lookup"), Peer::Keyserver);

        unsafe { std::env::remove_var("RPGP_KEYSERVER") };

        assert!(
            outcome.is_err(),
            "a redirect off HTTPS was followed and returned {:?}",
            outcome.map(|body| body.len())
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the http target was contacted despite the policy"
        );
    }

    /// Each clause of the redirect policy, on a URL that trips that clause and
    /// no other.
    ///
    /// Through a socket the clauses mask each other, which is how the test
    /// above spent several commits unable to detect the loss of the guard it
    /// was named for. Here they are separable, and each reason is pinned to
    /// the input that should produce it.
    #[test]
    fn the_redirect_policy_names_one_reason_for_each_refusal() {
        let url = |text: &str| reqwest::Url::parse(text).unwrap();
        let keyserver = url("https://keys.corp.internal/");

        assert_eq!(
            redirect_refusal(&url("https://keys.openpgp.org/x"), 5, None),
            Some("too many redirects")
        );
        assert_eq!(
            redirect_refusal(&url("http://cdn.example.net/key"), 0, None),
            Some("redirected off HTTPS")
        );
        assert_eq!(
            redirect_refusal(&url("https://10.0.0.5/key"), 0, None),
            Some("redirected to a private address")
        );
        assert_eq!(
            redirect_refusal(
                &url("https://keys.corp.internal:8443/admin/export"),
                0,
                Some(&keyserver)
            ),
            Some("redirected to another port on the keyserver's host")
        );

        // And what must still be followed. A hop away from the keyserver to
        // some other host is one of them: it is not exempt, so it faces the
        // resolver's guard like any other name, which is what the README
        // promises rather than a refusal here.
        assert_eq!(
            redirect_refusal(&url("https://keys.openpgp.org/x"), 4, None),
            None
        );
        assert_eq!(
            redirect_refusal(
                &url("https://keys.corp.internal/other"),
                0,
                Some(&keyserver)
            ),
            None
        );
        assert_eq!(
            redirect_refusal(&url("https://mirror.example.org/x"), 0, Some(&keyserver)),
            None
        );
        // Nothing is exempt on a fetch that is not the keyserver's, so there
        // the same off-port URL is an ordinary hop, refused or allowed by the
        // resolver on its merits.
        assert_eq!(
            redirect_refusal(
                &url("https://keys.corp.internal:8443/admin/export"),
                0,
                None
            ),
            None
        );
    }

    /// The exemption belongs to the keyserver fetch, not to every fetch.
    ///
    /// It is decided from a hostname, because a hostname is all reqwest hands
    /// a resolver. So while every client carried it, anyone who could steer a
    /// lookup could borrow it: a WKD address whose domain is the keyserver's
    /// host reached any port on that host, and so did a redirect from a
    /// hostile server naming it. Both are somebody else's choice, which is
    /// exactly what the exemption is not for.
    #[test]
    fn the_keyserver_exemption_covers_only_the_keyserver() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        // (1) A WKD address whose domain is the configured keyserver's host.
        // The resolver is pinned so the fetch is the direct URL, the one whose
        // host is `localhost` and so the one the exemption would cover: left
        // to the machine's own resolver this asserts about whichever URL that
        // machine picks, and systemd-resolved answers for
        // `openpgpkey.localhost`, whose host the exemption never named.
        let (port, hits) = serve_counting(bait_reply());
        unsafe { std::env::set_var("RPGP_KEYSERVER", format!("https://localhost:{port}")) };
        let found = lookup_wkd_resolving(&format!("alice@localhost:{port}"), |_| false)
            .expect("a WKD fetch that is refused is not an error, it is nothing found");
        // A shape check and not a guard check: an address whose domain half
        // carries a port does not parse, so the filter keeps nothing whatever
        // the fetch did. The hit count below is what has teeth here.
        assert!(
            found.is_empty(),
            "an address that does not parse must match no user ID"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a WKD lookup borrowed the keyserver's exemption"
        );

        // (2) A redirect naming that host, from a server that is not it.
        let (port, hits) = serve_counting(bait_reply());
        unsafe { std::env::set_var("RPGP_KEYSERVER", format!("https://localhost:{port}")) };
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: https://localhost:{port}/evil\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes();
        let source = serve_once(redirect);
        let err = get(
            &format!("{source}/.well-known/openpgpkey/hu/x"),
            Peer::Elsewhere,
        )
        .expect_err("a redirect to a name resolving inward was followed")
        .to_string();

        unsafe { std::env::remove_var("RPGP_KEYSERVER") };

        assert!(
            err.contains("lookup failed"),
            "refused for the wrong reason: {err}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a redirect borrowed the keyserver's exemption"
        );
    }

    /// A proxy in the environment must not carry a fetch around the guard.
    ///
    /// reqwest reads `HTTPS_PROXY` and friends by default, and for an HTTPS URL
    /// it opens a CONNECT tunnel: the target name goes to the proxy as text and
    /// is resolved there, so the resolver below never sees it and the guard
    /// decides nothing. `localhost` is the one name every machine resolves
    /// inward, so it stands in for the hostile domain.
    ///
    /// What the fetch returns cannot tell the two apart — it fails either way,
    /// and `get` formats a transport error without its source chain, so the
    /// guard's own words never reach the caller. What the *proxy* received can:
    /// a listener that counts connections is silent when the guard decided the
    /// fetch and has a CONNECT in hand when a proxy did.
    #[test]
    fn an_environment_proxy_cannot_carry_a_fetch_around_the_guard() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        let (port, hits) = serve_counting(b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec());
        unsafe {
            std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{port}"));
            // Whatever the developer's own environment exempts, this test's
            // host must not be exempt from the proxy, or it would pass by
            // never being intercepted at all.
            std::env::remove_var("NO_PROXY");
            std::env::remove_var("no_proxy");
        }

        let outcome = get("https://localhost/pks/lookup", Peer::Elsewhere);

        unsafe { std::env::remove_var("HTTPS_PROXY") };

        assert!(
            outcome.is_err(),
            "a name resolving to loopback was fetched and returned {:?}",
            outcome.map(|body| body.len())
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the fetch was handed to a proxy, which resolves the name itself"
        );
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
            // Shared address space, 100.64.0.0/10: a carrier's NAT, and every
            // node on a Tailscale tailnet, including the fixed MagicDNS
            // address. The tailnet's IPv6 half was already refused as
            // unique-local; its IPv4 half was not refused at all.
            "https://100.64.0.1/",
            "https://100.100.100.100/",
            "https://100.127.255.255:5000/",
            "https://[::ffff:100.64.0.1]/",
            // 0.0.0.0/8 beyond the unspecified address itself, and the block
            // a DS-Lite router answers from.
            "https://0.1.2.3/",
            "https://192.0.0.1/",
            // Local-use NAT64 (RFC 8215), and the three transition forms that
            // carry an IPv4 address inside them: the well-known NAT64 prefix,
            // 6to4 and Teredo, each here wrapping 10.0.0.5.
            "https://[64:ff9b:1::a00:5]/",
            "https://[64:ff9b::a00:5]/",
            "https://[2002:a00:5::1]/",
            "https://[2001:0:4136:e378:8000:63bf:f5ff:fffa]/",
            // Site-local, deprecated but still routed into the site by a host
            // that honours it.
            "https://[fec0::1]/",
        ];
        for url in inward {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(inward_literal(&parsed), "should have been refused: {url}");
        }

        let outward = [
            "https://keys.openpgp.org/vks/v1/upload",
            "https://openpgpkey.example.org/.well-known/openpgpkey/",
            "https://8.8.8.8/",
            "https://[2606:4700:4700::1111]/",
            // The edges of the shared block, so the mask cannot quietly widen
            // to 100.0.0.0/8 or narrow to 100.64.0.0/16.
            "https://100.63.255.255/",
            "https://100.128.0.0/",
            "https://192.0.1.1/",
            // The same three transition forms wrapping 8.8.8.8, which must
            // still be reachable. Refusing the well-known NAT64 prefix
            // outright would break every lookup on an IPv6-only network,
            // where DNS64 answers public names from it.
            "https://[64:ff9b::808:808]/",
            "https://[2002:808:808::1]/",
            "https://[2001:0:4136:e378:8000:63bf:f7f7:f7f7]/",
            // Teredo is 2001:0::/32, not 2001::/16.
            "https://[2001:4860:4860::8888]/",
        ];
        for url in outward {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(!inward_literal(&parsed), "should have been allowed: {url}");
        }
    }

    /// The name half of the same guard, which the URL test above cannot reach:
    /// a domain that *resolves* inward rather than being written as an address.
    ///
    /// `localhost` is the one name every machine resolves to loopback, so it
    /// stands in for the attacker's `evil.example` with an A record of
    /// 127.0.0.1 without needing a resolver of our own. The exempt case is the
    /// other half of the rule: `RPGP_KEYSERVER` exists for an internal server,
    /// which is exactly a name resolving to a private address.
    #[test]
    fn refuses_a_name_that_resolves_inward_unless_it_is_the_keyserver() {
        // Not for the variable, which this test never reads: for the
        // resolution, which reads the environment through libc while a
        // sibling test may be writing it. See the note on SERIAL.
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        use reqwest::dns::Resolve;
        use std::str::FromStr;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let guarded = Guarded { exempt: None };
        let outcome = runtime.block_on(async {
            guarded
                .resolve(reqwest::dns::Name::from_str("localhost").unwrap())
                .await
                .map(|addrs| addrs.collect::<Vec<_>>())
        });
        let err = outcome
            .expect_err("a name resolving to loopback was allowed")
            .to_string();
        assert!(
            err.contains("inside this network"),
            "refused for the wrong reason: {err}"
        );

        let exempt = Guarded {
            exempt: Some("localhost".to_string()),
        };
        let addrs = runtime
            .block_on(async {
                exempt
                    .resolve(reqwest::dns::Name::from_str("localhost").unwrap())
                    .await
                    .map(|addrs| addrs.collect::<Vec<_>>())
            })
            .expect("the configured keyserver's own host must still resolve");
        assert!(
            addrs.iter().any(|addr| addr.ip().is_loopback()),
            "the exempt host resolved to nothing inward: {addrs:?}"
        );
    }

    /// The resolver is wired into the client, not merely correct in isolation.
    ///
    /// Every other test here points at an IP literal, which hyper connects to
    /// without asking a resolver at all — so deleting the `dns_resolver` line
    /// would leave all of them green. This one fetches a name: the server is
    /// real and answers, so success is what happens if the guard is not
    /// installed, and only the guard can turn it into an error.
    #[test]
    fn the_client_actually_asks_the_guarded_resolver() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // Not the keyserver, so `localhost` is not the exempt host.
        unsafe { std::env::remove_var("RPGP_KEYSERVER") };

        let body = b"nothing that parses as a certificate";
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        )
        .into_bytes();
        let origin = serve_once(reply);
        let port = origin.rsplit_once(':').expect("origin carries a port").1;

        let err = get(&format!("http://localhost:{port}/"), Peer::Keyserver)
            .expect_err("a name resolving to loopback was fetched")
            .to_string();
        assert!(
            err.contains("lookup failed"),
            "refused for the wrong reason: {err}"
        );
    }

    /// The domain half of an address is not required to be a name, and a
    /// literal never reaches the resolver — hyper connects to one directly —
    /// so `lookup_wkd` has to refuse it before building a URL. The port comes
    /// along for free, which is what turns this from "reach loopback:443" into
    /// a port scan.
    #[test]
    fn refuses_a_wkd_domain_written_as_an_address() {
        for address in [
            "alice@127.0.0.1",
            "alice@127.0.0.1:8080",
            "alice@[::1]",
            "alice@10.0.0.5",
            "alice@169.254.169.254",
            "alice@[::ffff:127.0.0.1]",
            "alice@100.100.100.100:5000",
        ] {
            let err = lookup_wkd(address)
                .err()
                .unwrap_or_else(|| panic!("{address} was looked up rather than refused"))
                .to_string();
            assert!(
                err.contains("inside this network"),
                "{address} refused for the wrong reason: {err}"
            );
        }
    }

    #[test]
    fn rejects_input_that_is_not_an_address() {
        assert!(lookup_wkd("not-an-address").is_err());
        assert!(lookup_wkd("@example.org").is_err());
        assert!(lookup("   ").is_err());
    }

    /// A WKD host answers for the address it was asked about and for nothing
    /// else, which is a MUST the code did not honour: whatever it served was
    /// listed under the "web key directory" label with every user ID on it.
    ///
    /// The filter is exercised here rather than through a socket because every
    /// WKD URL is https, so a local stand-in would need a certificate
    /// authority of its own to be reached at all; what a fetch that does
    /// happen hands to this function is covered by the keyserver test below,
    /// which runs over plain HTTP.
    #[test]
    fn a_wkd_reply_keeps_only_the_address_it_was_asked_for() {
        use sequoia_openpgp::Packet;
        use sequoia_openpgp::cert::{CertBuilder, UserIDRevocationBuilder};
        use sequoia_openpgp::types::{ReasonForRevocation, RevocationStatus};

        let (alice, _) = CertBuilder::new()
            .add_userid("Alice <alice@example.org>")
            .add_userid("Bob <bob@bank.example>")
            .generate()
            .unwrap();
        let (mallory, _) = CertBuilder::new()
            .add_userid("Mallory <mallory@evil.example>")
            .generate()
            .unwrap();

        // Asked in another case, and with the domain in another case again:
        // both sides are normalised, so this is the same address.
        let kept =
            only_the_requested_address(vec![alice.clone(), mallory.clone()], "ALICE@Example.ORG");

        assert_eq!(
            kept.len(),
            1,
            "a certificate for an address nobody asked about was kept"
        );
        assert_eq!(kept[0].fingerprint(), alice.fingerprint());
        let names: Vec<String> = kept[0]
            .userids()
            .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
            .collect();
        assert_eq!(
            names,
            ["Alice <alice@example.org>"],
            "an identity from another domain survived the strip"
        );

        // A user ID with no self-signature is a name anybody can staple to a
        // certificate in flight, and is not the certificate claiming it.
        let stapled = mallory
            .insert_packets(vec![Packet::from(UserID::from(
                "Alice <alice@example.org>",
            ))])
            .unwrap()
            .0;
        assert!(
            stapled
                .userids()
                .any(|ua| ua.userid().email().ok().flatten() == Some("alice@example.org")),
            "the fixture must carry the appended name, or this proves nothing"
        );
        assert!(
            only_the_requested_address(vec![stapled], "alice@example.org").is_empty(),
            "a name nobody signed passed as the certificate's own"
        );

        // A revoked identity is still the identity that was asked for. The
        // specification allows a revoked key to be served, and a revocation is
        // the one thing about a key its owner most wants seen, so the filter
        // must not be what hides it.
        let mut signer = alice
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let revocation = UserIDRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"no longer used")
            .unwrap()
            .build(
                &mut signer,
                &alice,
                &UserID::from("Alice <alice@example.org>"),
                None,
            )
            .unwrap();
        let revoked = alice.insert_packets(revocation).unwrap().0;
        assert!(
            matches!(
                revoked
                    .userids()
                    .find(|ua| ua.userid().email().ok().flatten() == Some("alice@example.org"))
                    .unwrap()
                    .revocation_status(&crate::policy(), None),
                RevocationStatus::Revoked(_)
            ),
            "the fixture must carry the revocation, or this proves nothing"
        );
        assert_eq!(
            only_the_requested_address(vec![revoked], "alice@example.org").len(),
            1,
            "a revoked identity was dropped, hiding the revocation"
        );
    }

    /// The direct URL is for a domain that has no `openpgpkey` sub-domain, not
    /// for one whose delegated host merely said no.
    ///
    /// A pure function for the reason [`redirect_refusal`] is one: the answer
    /// turns on a resolver, and a test that drove a socket could only assert
    /// that a fetch failed, which it does either way.
    #[test]
    fn falls_back_to_the_direct_url_only_where_the_subdomain_has_no_address() {
        let advanced = "https://openpgpkey.company.example:8443/.well-known/openpgpkey/\
                        company.example/hu/kei1q4tipxxu1yj79k9kfukdhfy631xe?l=bob"
            .to_string();
        let direct = "https://company.example:8443/.well-known/openpgpkey/hu/\
                      kei1q4tipxxu1yj79k9kfukdhfy631xe?l=bob"
            .to_string();

        let mut asked = String::new();
        let chosen = wkd_url(advanced.clone(), direct.clone(), |host| {
            asked = host.to_string();
            true
        });
        assert_eq!(
            asked, "openpgpkey.company.example",
            "the name asked about must be the sub-domain, without the port"
        );
        assert_eq!(
            chosen, advanced,
            "a domain that delegates must be answered by the host it delegates to"
        );

        assert_eq!(
            wkd_url(advanced, direct.clone(), |_| false),
            direct,
            "a domain with no openpgpkey sub-domain publishes at the direct URL"
        );
    }

    /// A keyserver answer has to be an answer to the question that was asked.
    ///
    /// `RPGP_KEYSERVER` may name any HKP server, verifying or not, and nothing
    /// compared a reply with the query: a fingerprint query answered with an
    /// unrelated certificate was listed as found, and so was an address query
    /// answered with a certificate that does not carry the address. A key
    /// stapled on as an unbound packet is the same borrowing on the key side,
    /// and what a certificate has signed for is again where the line falls.
    #[test]
    fn a_keyserver_answer_that_is_not_what_was_asked_for_is_not_a_result() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        use sequoia_openpgp::Packet;
        use sequoia_openpgp::cert::CertBuilder;
        use sequoia_openpgp::serialize::SerializeInto;

        let (mallory, _) = CertBuilder::new()
            .add_userid("Mallory <mallory@evil.example>")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();
        let reply = armored_reply(&mallory);

        // A key packet is as cheap to append as a name is: Alice's key, given
        // the subordinate role, on Mallory's certificate, with no binding
        // signature because appending one needs Alice's secret.
        let (alice, _) = CertBuilder::new()
            .add_userid("Alice <alice@example.org>")
            .generate()
            .unwrap();
        let spliced = mallory
            .clone()
            .insert_packets(vec![Packet::from(
                alice.primary_key().key().clone().role_into_subordinate(),
            )])
            .unwrap()
            .0;
        let spliced_reply = armored_reply(&spliced);
        // Asserted on the armoring the stand-in serves rather than on the
        // certificate in hand, because a splice that did not survive the trip
        // would leave the fetch below passing for the wrong reason.
        let served = parse(&spliced.armored().to_vec().unwrap()).unwrap();
        assert!(
            served.iter().any(|cert| {
                cert.keys().any(|ka| {
                    ka.key().fingerprint() == alice.fingerprint()
                        && ka.self_signatures().next().is_none()
                })
            }),
            "the fixture must carry the stapled key unsigned, or this proves nothing"
        );

        // Each stand-in serves one reply and is then done with, so every query
        // gets one of its own. They are all asked before anything is asserted,
        // and the variable is put back first, so that a failure here does not
        // leave the rest of the process pointed at a dead port.
        let ask = |reply: &[u8], query: &str| {
            unsafe { std::env::set_var("RPGP_KEYSERVER", serve_once(reply.to_vec())) };
            lookup_keyserver(query)
        };
        // (1) An address query, and a fingerprint query, each answered with a
        // certificate that is not the one asked about, and a fingerprint query
        // answered with a certificate carrying that very key as a packet it
        // never signed for.
        let other_address = ask(&reply, "alice@example.org");
        let other_fingerprint = ask(&reply, "653909A2F0E37C106F5FAF546C8857E0D8E8F074");
        let stapled_key = ask(&spliced_reply, &alice.fingerprint().to_hex());
        // (2) And what must still come back: the queries this certificate does
        // answer, and a free-text search, where the server decides what
        // matches and filtering here could only empty the list.
        let own_fingerprint = ask(&reply, &mallory.fingerprint().to_hex());
        let own_address = ask(&reply, "mallory@evil.example");
        let name_search = ask(&reply, "Mallory");
        // A subkey the certificate did sign for is still an answer: HKP
        // servers are asked by handle and answer for subkeys too.
        let bound_subkey = ask(
            &reply,
            &mallory
                .keys()
                .subkeys()
                .next()
                .expect("the generated certificate must have a subkey")
                .key()
                .fingerprint()
                .to_hex(),
        );

        unsafe { std::env::remove_var("RPGP_KEYSERVER") };

        assert!(
            other_address.unwrap().is_empty(),
            "a certificate for another address was reported as found"
        );
        assert!(
            other_fingerprint.unwrap().is_empty(),
            "a certificate with another fingerprint was reported as found"
        );
        assert!(
            stapled_key.unwrap().is_empty(),
            "a key nobody bound passed as the certificate's own"
        );

        let found = own_fingerprint.unwrap();
        assert_eq!(found.len(), 1, "the certificate asked for was dropped");
        assert_eq!(found[0].cert.fingerprint(), mallory.fingerprint());
        assert_eq!(found[0].source, Source::Keyserver);

        assert_eq!(
            own_address.unwrap().len(),
            1,
            "the address the certificate carries was filtered out"
        );
        assert_eq!(
            name_search.unwrap().len(),
            1,
            "a name search was answered by the server and dropped here"
        );
        assert_eq!(
            bound_subkey.unwrap().len(),
            1,
            "a subkey handle the certificate signed for was filtered out"
        );
    }
}
