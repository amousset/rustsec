//! Exploit Code Maturity (E)

use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// Exploit Code Maturity (E) - CVSS v3.1 Temporal Metric Group
///
/// Described in CVSS v3.1 Specification: Section 3.1:
/// <https://www.first.org/cvss/v3.1/specification-document#t6>
///
/// > This metric measures the likelihood of the vulnerability being attacked, and is typically
/// > based on the current state of exploit techniques, exploit code availability, or active,
/// > “in-the-wild” exploitation. Public availability of easy-to-use exploit code increases the
/// > number of potential attackers by including those who are unskilled, thereby increasing the
/// > severity of the vulnerability. Initially, real-world exploitation may only be theoretical.
/// > Publication of proof-of-concept code, functional exploit code, or sufficient technical
/// > details necessary to exploit the vulnerability may follow. Furthermore, the exploit code
/// > available may progress from a proof-of-concept demonstration to exploit code that is
/// > successful in exploiting the vulnerability consistently. In severe cases, it may be delivered
/// > as the payload of a network-based worm or virus or other automated attack tools.
/// >
/// > The more easily a vulnerability can be exploited, the higher the vulnerability score.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ExploitCodeMaturity {
    /// Not Defined (X)
    ///
    /// > Assigning this value indicates there is insufficient information to choose one of the
    /// > other values, and has no impact on the overall Temporal Score, i.e., it has the same
    /// > effect on scoring as assigning High.
    NotDefined,

    /// High (H)
    ///
    /// > Functional autonomous code exists, or no exploit is required (manual trigger) and details
    /// > are widely available. Exploit code works in every situation, or is actively being
    /// > delivered via an autonomous agent (such as a worm or virus). Network-connected systems
    /// > are likely to encounter scanning or exploitation attempts. Exploit development has
    /// > reached the level of reliable, widely available, easy-to-use automated tools.
    High,

    /// Functional (F)
    ///
    /// > Functional exploit code is available. The code works in most situations where the
    /// > vulnerability exists.
    Functional,

    /// Proof-of-concept (P)
    ///
    /// > Proof-of-concept exploit code is available, or an attack demonstration is not practical
    /// > for most systems. The code or technique is not functional in all situations and may
    /// > require substantial modification by a skilled attacker.
    ProofOfConcept,

    /// Unproven (U)
    ///
    /// > No exploit code is available, or an exploit is theoretical.
    Unproven,
}

impl Default for ExploitCodeMaturity {
    fn default() -> ExploitCodeMaturity {
        ExploitCodeMaturity::NotDefined
    }
}

impl Metric for ExploitCodeMaturity {
    const TYPE: MetricType = MetricType::E;

    fn score(self) -> f64 {
        match self {
            ExploitCodeMaturity::NotDefined => 1.0,
            ExploitCodeMaturity::High => 1.0,
            ExploitCodeMaturity::Functional => 0.97,
            ExploitCodeMaturity::ProofOfConcept => 0.94,
            ExploitCodeMaturity::Unproven => 0.91,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ExploitCodeMaturity::NotDefined => "X",
            ExploitCodeMaturity::High => "H",
            ExploitCodeMaturity::Functional => "F",
            ExploitCodeMaturity::ProofOfConcept => "P",
            ExploitCodeMaturity::Unproven => "U",
        }
    }
}

impl fmt::Display for ExploitCodeMaturity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ExploitCodeMaturity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ExploitCodeMaturity::NotDefined),
            "H" => Ok(ExploitCodeMaturity::High),
            "F" => Ok(ExploitCodeMaturity::Functional),
            "P" => Ok(ExploitCodeMaturity::ProofOfConcept),
            "U" => Ok(ExploitCodeMaturity::Unproven),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
