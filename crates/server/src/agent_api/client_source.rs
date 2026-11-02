//! Who a request is from, for the per-source limits and the capped log.
//!
//! It is the peer of the TCP connection. Behind a reverse proxy that would make everyone one
//! source, so a peer listed in `[server] trusted_proxies` may say who it is forwarding for: the
//! client is the rightmost `X-Forwarded-For` entry not itself in the list. Rightmost, because
//! each proxy appends what it saw, so everything left of the last trusted hop is whatever the
//! client chose to send. From any other peer the header means nothing at all.
//!
//! An entry that isn't an address, or a chain that is all trusted, says nothing useful, so the
//! source stays the peer: the proxy's one shared allowance, which is safe, and what a mistake
//! here costs. `serve`'s cap on connections goes by the peer in any case, as that is what holds
//! them.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{Extensions, HeaderMap, HeaderName};
use axum::middleware::Next;
use axum::response::Response;

use super::ApiState;

const FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Who a request is from, in its extensions, as [`note_client_source`] worked it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientSource(pub(crate) IpAddr);

/// The client behind `peer`, by the rules at the top of this file.
fn client_source(peer: IpAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> IpAddr {
    let peer = peer.to_canonical();
    if !trusted.contains(&peer) {
        return peer;
    }
    // Several headers are one list, in order, so the last is the nearest.
    let values: Vec<_> = headers.get_all(FORWARDED_FOR).iter().collect();
    for value in values.into_iter().rev() {
        let Ok(text) = value.to_str() else {
            return peer;
        };
        for entry in text.rsplit(',') {
            let Ok(address) = entry.trim().parse::<IpAddr>() else {
                return peer;
            };
            let address = address.to_canonical();
            if !trusted.contains(&address) {
                return address;
            }
        }
    }
    peer
}

/// Works out who a request is from. A request with no peer can only come from a test; such
/// requests share one allowance.
pub(crate) async fn note_client_source(
    State(state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Response {
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |peer| {
            client_source(
                peer.0.ip(),
                request.headers(),
                state.config().trusted_proxies(),
            )
        });
    request.extensions_mut().insert(ClientSource(source));
    next.run(request).await
}

/// Who a request is from, by its extensions.
pub(crate) fn source_of(extensions: &Extensions) -> IpAddr {
    extensions
        .get::<ClientSource>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |source| source.0)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use axum::http::{HeaderMap, HeaderValue};

    use super::{FORWARDED_FOR, client_source};

    const PROXY: &str = "192.0.2.100";
    const OTHER_PROXY: &str = "2001:db8::100";
    const CLIENT: &str = "198.51.100.7";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn source(peer: &str, values: &[&str]) -> IpAddr {
        client_source(ip(peer), &headers(values), &[ip(PROXY), ip(OTHER_PROXY)])
    }

    #[test]
    fn a_direct_peer_cannot_spoof_it() {
        assert_eq!(source(CLIENT, &["203.0.113.9"]), ip(CLIENT));
        assert_eq!(
            client_source(ip(PROXY), &headers(&[CLIENT]), &[]),
            ip(PROXY),
            "with nobody listed, the header is ignored from everyone"
        );
    }

    #[test]
    fn a_trusted_peer_gives_the_rightmost_entry_it_doesnt_trust() {
        assert_eq!(source(PROXY, &[CLIENT]), ip(CLIENT));
        // What the client sent itself is further left, and doesn't count.
        assert_eq!(source(PROXY, &["203.0.113.9, 198.51.100.7"]), ip(CLIENT));
        // Through two proxies.
        assert_eq!(
            source(PROXY, &[" 203.0.113.9 ,198.51.100.7 , 2001:db8::100 "]),
            ip(CLIENT)
        );
    }

    #[test]
    fn several_headers_are_one_list_in_order() {
        assert_eq!(source(PROXY, &["203.0.113.9", CLIENT]), ip(CLIENT));
        assert_eq!(
            source(PROXY, &["203.0.113.9", "198.51.100.7, 192.0.2.100"]),
            ip(CLIENT)
        );
        assert_eq!(source(PROXY, &[CLIENT, PROXY]), ip(CLIENT));
    }

    #[test]
    fn garbage_before_any_client_leaves_the_proxy_as_the_source() {
        for bad in [
            "unknown",
            "",
            "198.51.100.7:443",
            "[2001:db8::1]:443",
            "198.51.100.7, not-an-address",
            "198.51.100.7,",
            "<img src=x>",
        ] {
            assert_eq!(source(PROXY, &[bad]), ip(PROXY), "{bad}");
        }
        // Left of the client it does no harm: anyone can send that.
        assert_eq!(source(PROXY, &["unknown, 198.51.100.7"]), ip(CLIENT));
        let mut binary = HeaderMap::new();
        binary.append(FORWARDED_FOR, HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(client_source(ip(PROXY), &binary, &[ip(PROXY)]), ip(PROXY));
    }

    #[test]
    fn with_everything_trusted_or_nothing_sent_it_is_the_peer() {
        assert_eq!(source(PROXY, &[]), ip(PROXY));
        assert_eq!(source(PROXY, &["192.0.2.100, 2001:db8::100"]), ip(PROXY));
    }

    #[test]
    fn ipv6_works_and_a_mapped_address_is_the_ipv4_one() {
        assert_eq!(source(OTHER_PROXY, &["2001:db8:1::7"]), ip("2001:db8:1::7"));
        // A trusted peer on an IPv6 socket, and a client written that way.
        assert_eq!(source("::ffff:192.0.2.100", &[CLIENT]), ip(CLIENT));
        assert_eq!(source(PROXY, &["::ffff:198.51.100.7"]), ip(CLIENT));
        // A trusted hop written that way is still trusted.
        assert_eq!(
            source(PROXY, &["198.51.100.7, ::ffff:192.0.2.100"]),
            ip(CLIENT)
        );
        // And the peer comes back canonical, for the limiter.
        assert_eq!(source("::ffff:198.51.100.7", &[]), ip(CLIENT));
    }
}
