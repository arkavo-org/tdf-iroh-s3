//! Publishing the node's address to the BitTorrent Mainline DHT (`[iroh]
//! publish_dht`).
//!
//! The endpoint's address information is a pkarr record signed by the
//! endpoint's secret key, stored on the DHT under the endpoint ID. A viewer
//! that knows only the endpoint ID can then find the node without a relay or
//! a configured address, with a `DhtAddressLookup` of its own.
//!
//! What the record holds is decided by [`addr_filter`]: the home relay URL and
//! the direct IP addresses that are reachable from the public internet.

use iroh::address_lookup::AddrFilter;
use iroh_base::TransportAddr;
use iroh_mainline_address_lookup::{Builder, DhtAddressLookup};
use n0_mainline::DhtBuilder;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// How the node publishes. The default is what production uses.
#[derive(Debug, Clone, Copy, Default)]
pub struct DhtOptions {
    /// Publish every direct address, private and loopback ones included.
    /// Only for tests and closed networks: on the internet those addresses
    /// are useless to a viewer and show the node's internal addressing.
    pub include_non_global_addrs: bool,
}

/// The lookup that publishes the endpoint's address, signed with the
/// endpoint's own key (the endpoint hands the key over when it is built).
///
/// `bootstrap` replaces the default Mainline bootstrap nodes; empty keeps
/// them.
pub fn publisher(bootstrap: &[String], options: DhtOptions) -> Builder {
    let mut dht = DhtBuilder::default();
    if !bootstrap.is_empty() {
        dht.bootstrap(bootstrap);
    }
    DhtAddressLookup::builder()
        .dht_builder(dht)
        .addr_filter(addr_filter(options.include_non_global_addrs))
}

/// Keeps the relay URL and, unless `include_non_global`, only the direct IP
/// addresses that are globally routable. The crate's own default is relay
/// only, which would leave the record without any direct address.
pub fn addr_filter(include_non_global: bool) -> AddrFilter {
    AddrFilter::new(move |addrs| {
        Cow::Owned(
            addrs
                .iter()
                .filter(|addr| match addr {
                    TransportAddr::Relay(_) => true,
                    TransportAddr::Ip(sock) => include_non_global || is_global(sock.ip()),
                    _ => false,
                })
                .cloned()
                .collect(),
        )
    })
}

/// Whether `ip` can be reached from the public internet: not private,
/// loopback, link-local, carrier-grade NAT, multicast, documentation or
/// otherwise reserved.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_v4(ip),
        IpAddr::V6(ip) => is_global_v6(ip),
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (b & 0xc0) == 64) // 100.64.0.0/10, carrier-grade NAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24, IETF protocol assignments
        || (a == 198 && (b & 0xfe) == 18) // 198.18.0.0/15, benchmarking
        || a >= 240) // 240.0.0.0/4, reserved
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_v4(v4);
    }
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)) // 2001:db8::/32, documentation
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_base::RelayUrl;
    use std::net::SocketAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_are_global() {
        for s in ["3.91.18.97", "8.8.8.8", "2600:1f18::1", "2a00:1450::1"] {
            assert!(is_global(ip(s)), "{s}");
        }
    }

    #[test]
    fn private_and_reserved_addresses_are_not_global() {
        for s in [
            "0.0.0.0",
            "10.0.0.5",
            "172.31.4.9",
            "172.16.0.1",
            "192.168.1.2",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.2.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_global(ip(s)), "{s}");
        }
        // The edges of the ranges above are global.
        for s in [
            "100.63.255.255",
            "100.128.0.0",
            "198.17.255.255",
            "172.32.0.1",
        ] {
            assert!(is_global(ip(s)), "{s}");
        }
        assert!(is_global(ip("::ffff:3.91.18.97")));
    }

    fn sample() -> Vec<TransportAddr> {
        let relay: RelayUrl = "https://relay.example./".parse().unwrap();
        let sock = |s: &str| TransportAddr::Ip(s.parse::<SocketAddr>().unwrap());
        vec![
            TransportAddr::Relay(relay),
            sock("3.91.18.97:11204"),
            sock("172.31.4.9:11204"),
            sock("127.0.0.1:11204"),
        ]
    }

    #[test]
    fn filter_keeps_the_relay_and_global_addresses_only() {
        let kept = addr_filter(false).apply(&sample()).into_owned();
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept[0].is_relay());
        assert_eq!(kept[1], sample()[1]);
    }

    #[test]
    fn filter_can_keep_everything() {
        assert_eq!(addr_filter(true).apply(&sample()).into_owned(), sample());
    }
}
