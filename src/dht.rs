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

/// Most direct addresses one record carries. A pkarr packet holds at most 1000
/// bytes of DNS data, and the crate refuses a whole update that exceeds it
/// (no truncation, no relay-only fallback), which would leave the node with
/// no record or a stale one. iroh-dns writes one TXT record per address
/// (`addr=<socket address>`, up to 47 characters for a full IPv6 address and
/// port, plus DNS framing). Measured with full-length IPv6 addresses, 13 fit
/// beside a 20-character relay host, 12 beside 100 and 10 beside 200; eight
/// leave room in every case (`a_full_record_fits_a_pkarr_packet`).
pub const MAX_DIRECT_ADDRS: usize = 8;

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

/// Keeps the home relay URL and, unless `include_non_global`, only the direct
/// IP addresses that are globally routable, at most [`MAX_DIRECT_ADDRS`] of
/// them: IPv4 first, then IPv6, each in the order given. The crate's own
/// default is relay only, which would leave the record without any direct
/// address.
pub fn addr_filter(include_non_global: bool) -> AddrFilter {
    AddrFilter::new(move |addrs| {
        let mut kept: Vec<TransportAddr> = addrs
            .iter()
            .find(|a| a.is_relay())
            .cloned()
            .into_iter()
            .collect();
        let direct = |v4: bool| {
            addrs.iter().filter(move |addr| match addr {
                TransportAddr::Ip(sock) => {
                    sock.is_ipv4() == v4 && (include_non_global || is_global(sock.ip()))
                }
                _ => false,
            })
        };
        kept.extend(
            direct(true)
                .chain(direct(false))
                .take(MAX_DIRECT_ADDRS)
                .cloned(),
        );
        Cow::Owned(kept)
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

/// Global unicast `2000::/3` only, minus the blocks inside it that are not
/// routable on the public internet. Everything outside `2000::/3` (unspecified,
/// loopback, IPv4-mapped, NAT64, ULA, link-local, site-local, multicast, ...)
/// is excluded by the allowlist itself.
fn is_global_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    (s[0] & 0xe000) == 0x2000 // 2000::/3
        && !(s[0] == 0x2001 && s[1] < 0x0200) // 2001::/23, IETF protocol assignments (Teredo, ORCHID, ...)
        && !(s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32, documentation
        && s[0] != 0x2002 // 2002::/16, 6to4
        && !(s[0] == 0x3fff && s[1] < 0x1000) // 3fff::/20, documentation
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
        for s in [
            "3.91.18.97",
            "8.8.8.8",
            "2606:4700::1111",
            "2600:1f18::1",
            "2a00:1450::1",
            "2001:4860:4860::8888",
            "2001:200::1", // just past 2001::/23
            "3ffe::1",     // outside 3fff::/20
            "3fff:1000::1",
        ] {
            assert!(is_global(ip(s)), "{s}");
        }
    }

    #[test]
    fn private_and_reserved_ipv4_addresses_are_not_global() {
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
    }

    #[test]
    fn non_global_ipv6_blocks_are_not_global() {
        for (what, s) in [
            ("unspecified ::/128", "::"),
            ("loopback ::1", "::1"),
            ("IPv4-mapped ::ffff:0:0/96", "::ffff:3.91.18.97"),
            ("IPv4-mapped, private", "::ffff:10.0.0.1"),
            ("NAT64 64:ff9b::/96", "64:ff9b::808:808"),
            ("local-use NAT64 64:ff9b:1::/48", "64:ff9b:1::1"),
            ("discard 100::/64", "100::1"),
            ("IETF protocol assignments 2001::/23 (Teredo)", "2001::1"),
            ("IETF protocol assignments 2001::/23 (ORCHID)", "2001:10::1"),
            (
                "IETF protocol assignments 2001::/23, last",
                "2001:1ff:ffff::1",
            ),
            ("documentation 2001:db8::/32", "2001:db8::1"),
            ("documentation 3fff::/20", "3fff::1"),
            ("documentation 3fff::/20, last", "3fff:fff:ffff::1"),
            ("6to4 2002::/16", "2002:5bcc:18fd::1"),
            ("ULA fc00::/7", "fc00::1"),
            ("ULA fd00::/8", "fd12:3456::1"),
            ("link-local fe80::/10", "fe80::1"),
            ("site-local fec0::/10", "fec0::1"),
            ("multicast ff00::/8", "ff02::1"),
        ] {
            assert!(!is_global(ip(s)), "{what}: {s}");
        }
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

    /// 30 global IPv6 addresses, the longest form (eight groups and a port),
    /// plus a few global IPv4 ones and the relay.
    fn crowded() -> Vec<TransportAddr> {
        let mut addrs = vec![TransportAddr::Relay(
            "https://use1-1.relay.n0.iroh.link./"
                .parse::<RelayUrl>()
                .unwrap(),
        )];
        for i in 0..30u16 {
            let a = format!("[2601:147:c182:6fa0:ca6:3b5b:a281:{:x}]:56799", 0xcda0 + i);
            addrs.push(TransportAddr::Ip(a.parse().unwrap()));
        }
        for i in 1..=3u8 {
            addrs.push(TransportAddr::Ip(
                format!("98.204.36.{i}:54571").parse().unwrap(),
            ));
        }
        addrs
    }

    #[test]
    fn filter_bounds_the_direct_addresses_and_puts_ipv4_first() {
        let kept = addr_filter(false).apply(&crowded()).into_owned();
        assert!(kept[0].is_relay());
        assert_eq!(kept.len(), 1 + MAX_DIRECT_ADDRS);
        let direct: Vec<_> = kept[1..]
            .iter()
            .map(|a| match a {
                TransportAddr::Ip(s) => *s,
                other => panic!("{other:?}"),
            })
            .collect();
        assert!(direct[..3].iter().all(|a| a.is_ipv4()), "{direct:?}");
        assert!(direct[3..].iter().all(|a| a.is_ipv6()), "{direct:?}");
    }

    /// The filtered record is encoded by the same path the publisher uses
    /// (`EndpointInfo::to_pkarr_signed_packet`), which refuses a DNS packet
    /// over 1000 bytes. Unbounded, 30 addresses do not fit.
    #[test]
    fn a_full_record_fits_a_pkarr_packet() {
        use iroh::address_lookup::EndpointData;
        use iroh::endpoint_info::EndpointInfo;

        let key = iroh::SecretKey::generate();
        let encode = |addrs: Vec<TransportAddr>| {
            let info = EndpointInfo::from_parts(key.public(), EndpointData::from_iter(addrs));
            info.to_pkarr_signed_packet(&key, 30)
        };
        assert!(
            encode(crowded()).is_err(),
            "the unfiltered record is too big"
        );

        let kept = addr_filter(false).apply(&crowded()).into_owned();
        encode(kept).expect("the filtered record fits");

        // Also with a much longer relay URL than n0's.
        let mut long = crowded();
        long[0] = TransportAddr::Relay(
            format!("https://{}.example.com./", "r".repeat(100))
                .parse::<RelayUrl>()
                .unwrap(),
        );
        let kept = addr_filter(false).apply(&long).into_owned();
        encode(kept).expect("the filtered record fits a long relay URL");
    }
}
