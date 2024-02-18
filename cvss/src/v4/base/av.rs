//! CVSS v4.0 Base Metric Group - Attack Vector (AV)

use crate::{Error, Metric, MetricType};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// Attack Vector (AV) - CVSS v4.0 Base Metric Group
///
/// Described in CVSS v4.0 Specification: Section 2.1.1:
/// <https://www.first.org/cvss/v4.0/specification-document>
///
/// > This metric reflects the context by which vulnerability exploitation is possible.
/// > This metric value (and consequently the resulting severity) will be larger the more
/// > remote (logically, and physically) an attacker can be in order to exploit the vulnerable
/// > system. The assumption is that the number of potential attackers for a vulnerability
/// > that could be exploited from across a network is larger than the number of potential
/// > attackers that could exploit a vulnerability requiring physical access to a device,
/// > and therefore warrants a greater severity.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AttackVector {
    /// Physical (P)
    ///
    /// > The attack requires the attacker to physically touch or manipulate
    /// > the vulnerable system. Physical interaction may be brief (e.g., evil maid attack[^note])
    /// > or persistent. An example of such an attack is a cold boot attack in which
    /// > an attacker gains access to disk encryption keys after physically accessing the target
    /// > system. Other examples include peripheral attacks via FireWire/USB Direct
    /// > Memory Access (DMA).
    /// >
    /// > [^note]: See <https://www.schneier.com/blog/archives/2009/10/evil_maid_attac.html>
    /// >     for a description of the evil maid attack.
    Physical,

    /// Local (L)
    ///
    /// > The vulnerable system is not bound to the network stack and the
    /// > attacker’s path is via read/write/execute capabilities. Either:
    /// >
    /// > - the attacker exploits the vulnerability by accessing the target
    /// >   system locally (e.g., keyboard, console), or through terminal emulation (e.g., SSH); _or_
    /// > - the attacker relies on User Interaction by another person to perform actions required
    /// >   to exploit the vulnerability (e.g., using social engineering techniques to trick a
    /// >   legitimate user into opening a malicious document).
    Local,

    /// Adjacent (A)
    ///
    /// > The vulnerable system is bound to a protocol stack, but the attack is limited _at the
    /// > protocol level_ to a logically adjacent topology. This can mean an attack must be
    /// > launched from the same shared proximity (e.g., Bluetooth, NFC, or IEEE 802.11) or logical
    /// > network (e.g., local IP subnet), or from within a secure or otherwise limited
    /// > administrative domain (e.g., MPLS, secure VPN within an administrative network zone).
    /// > One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6)
    /// > flood leading to a denial of service on the local LAN segment (e.g., CVE-2013-6014).
    Adjacent,

    /// Network (N)
    ///
    /// > The vulnerable system is bound to the network stack and the set of possible attackers
    /// > extends beyond the other options listed below, up to and including the entire Internet.
    /// > Such a vulnerability is often termed “remotely exploitable” and can be thought of as an
    /// > attack being exploitable _at the protocol level_ one or more network hops away
    /// > (e.g., across one or more routers). An example of a network attack is an attacker
    /// > causing a denial of service (DoS) by sending a specially crafted TCP packet across a
    /// > wide area network (e.g., CVE-2004-0230).
    Network,
}

impl Metric for AttackVector {
    const TYPE: MetricType = MetricType::AV;

    // FIXME: replace
    fn score(self) -> f64 {
        match self {
            AttackVector::Physical => 0.20,
            AttackVector::Local => 0.55,
            AttackVector::Adjacent => 0.62,
            AttackVector::Network => 0.85,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            AttackVector::Physical => "P",
            AttackVector::Local => "L",
            AttackVector::Adjacent => "A",
            AttackVector::Network => "N",
        }
    }
}

impl fmt::Display for AttackVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for AttackVector {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "P" => Ok(AttackVector::Physical),
            "L" => Ok(AttackVector::Local),
            "A" => Ok(AttackVector::Adjacent),
            "N" => Ok(AttackVector::Network),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
