//! The address list in the shapes other VPN software wants, so that people can use it in an app that
//! does the splitting itself (a phone, a router, a client without this feature).

use crate::cidr::{self, Cidr, Family};
use serde_json::json;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// One network per line: the Russian blocks themselves
    Cidr,
    /// An `AllowedIPs` line that covers everything EXCEPT the Russian blocks (for a WireGuard [Peer])
    Wireguard,
    /// OpenVPN `route ... net_gateway` lines (IPv4), which keep the Russian blocks out of the tunnel
    Openvpn,
    /// AmneziaVPN site list (IPv4) for "addresses from the list should not be accessed via VPN"
    Amnezia,
}

fn mask(len: u8) -> String {
    let bits = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
    cidr::u128_to_ip(Family::V4, bits as u128).to_string()
}

/// Everything in the family's address space that `blocks` does not cover.
pub fn complement(fam: Family, blocks: &[Cidr]) -> Vec<Cidr> {
    let all = (0u128, if fam == Family::V4 { u32::MAX as u128 } else { u128::MAX });
    cidr::aggregate(fam, cidr::subtract(vec![all], blocks.iter().map(Cidr::range).collect()))
}

pub fn render(format: Format, v4: &[Cidr], v6: &[Cidr], with_v6: bool) -> String {
    let join = |list: &[Cidr]| list.iter().map(Cidr::to_string).collect::<Vec<_>>().join(", ");
    match format {
        Format::Cidr => v4.iter().chain(v6.iter().filter(|_| with_v6)).map(|c| format!("{c}\n")).collect(),
        Format::Wireguard => {
            let mut all = complement(Family::V4, v4);
            if with_v6 {
                all.extend(complement(Family::V6, v6));
            }
            format!(
                "# runet-direct export: AllowedIPs covering everything except the Russian blocks.\n\
                 # Paste the line into the [Peer] section of the WireGuard configuration.\n\
                 # It lists {} networks; very long lists can be slow to import on phones.\n\
                 AllowedIPs = {}\n",
                all.len(),
                join(&all)
            )
        }
        Format::Openvpn => {
            let mut out = String::from("# runet-direct export: routes that bypass the tunnel (IPv4)\n");
            for c in v4 {
                out.push_str(&format!("route {} {} net_gateway\n", cidr::u128_to_ip(Family::V4, c.addr), mask(c.len)));
            }
            out
        }
        Format::Amnezia => {
            let items: Vec<_> = v4.iter().map(|c| json!({"hostname": c.to_string(), "ip": ""})).collect();
            serde_json::to_string_pretty(&items).expect("serializable") + "\n"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }
    fn size(list: &[Cidr]) -> u128 {
        list.iter().map(|b| b.last() - b.first() + 1).sum()
    }

    #[test]
    fn the_complement_is_exactly_the_rest_of_the_address_space() {
        let blocks = [c("10.0.0.0/8"), c("213.59.0.0/16"), c("0.0.0.0/32")];
        let rest = complement(Family::V4, &blocks);
        assert_eq!(size(&rest) + size(&blocks), 1u128 << 32);
        for r in &rest {
            for b in &blocks {
                assert!(r.last() < b.first() || r.first() > b.last(), "{r} overlaps {b}");
            }
        }
        let v6 = complement(Family::V6, &[c("2a02:6b8::/32")]);
        assert_eq!(size(&v6), u128::MAX - (1u128 << 96) + 1, "2^128 minus the 2^96 addresses of the /32");
        assert_eq!(complement(Family::V4, &[]), [c("0.0.0.0/0")]);
        assert!(complement(Family::V4, &[c("0.0.0.0/0")]).is_empty());
    }

    #[test]
    fn every_format_has_the_shape_the_other_software_expects() {
        let v4 = [c("5.228.0.0/16"), c("37.9.96.0/19")];
        let v6 = [c("2a02:6b8::/32")];
        assert_eq!(render(Format::Cidr, &v4, &v6, true), "5.228.0.0/16\n37.9.96.0/19\n2a02:6b8::/32\n");
        assert_eq!(render(Format::Cidr, &v4, &v6, false), "5.228.0.0/16\n37.9.96.0/19\n");
        let wg = render(Format::Wireguard, &v4, &v6, false);
        assert!(wg.lines().last().unwrap().starts_with("AllowedIPs = 0.0.0.0/"), "{wg}");
        assert!(!wg.contains("5.228.0.0/16"));
        let ovpn = render(Format::Openvpn, &v4, &v6, true);
        assert!(ovpn.contains("route 5.228.0.0 255.255.0.0 net_gateway\n") && ovpn.contains("route 37.9.96.0 255.255.224.0 net_gateway\n"));
        let am: serde_json::Value = serde_json::from_str(&render(Format::Amnezia, &v4, &v6, true)).unwrap();
        assert_eq!(am[0], serde_json::json!({"hostname": "5.228.0.0/16", "ip": ""}));
        assert_eq!(am.as_array().unwrap().len(), 2, "IPv4 only");
    }
}
