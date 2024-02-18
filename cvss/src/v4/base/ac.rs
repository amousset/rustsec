//! Attack Complexity (AC)

use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// Attack Complexity (AC) - CVSS v4.0 Base Metric Group
///
/// Described in CVSS v4.0 Specification: Section 2.1.2:
/// <https://www.first.org/cvss/v4.0/specification-document>
///
/// > This metric captures measurable actions that must be taken by the attacker to actively
/// > evade or circumvent **existing built-in security-enhancing conditions** in order to obtain a
/// > working exploit. These are conditions whose primary purpose is to increase security and/or
/// > increase exploit engineering complexity. A vulnerability exploitable without a
/// > target-specific variable has a lower complexity than a vulnerability that would require
/// > non-trivial customization. This metric is meant to capture security mechanisms utilized by
/// > the vulnerable system, and does not relate to the amount of time or attempts it would take
/// > for an attacker to succeed, e.g. a race condition. If the attacker does not take action to
/// > overcome these conditions, the attack will always fail.
/// >
/// > The evasion or satisfaction of authentication mechanisms or requisites is included in the
/// > Privileges Required assessment and is **not** considered here as a factor of relevance for
/// > Attack Complexity.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AttackComplexity {
    /// High (H)
    ///
    /// > The successful attack depends on the evasion or circumvention of security-enhancing
    /// > techniques in place that would otherwise hinder the attack. These include:
    /// >
    /// > - _Evasion of exploit mitigation techniques_. The attacker must have additional methods available
    /// >   to bypass security measures in place. For example, circumvention of **address space
    /// >   randomization (ASLR) or data execution prevention (DEP)** must be performed for the
    /// >   attack to be successful.
    /// > - _Obtaining target-specific secrets_. The attacker must gather
    /// >   some **target-specific secret** before the attack can be successful. A secret is any piece
    /// >   of information that cannot be obtained through any amount of reconnaissance. To obtain
    /// >   the secret the attacker must perform additional attacks or break otherwise secure
    /// >   measures (e.g. knowledge of a secret key may be needed to break a crypto channel).
    /// >   This operation must be performed for each attacked target.
    High,

    /// Low (L)
    ///
    /// > The attacker must take no measurable action to exploit the vulnerability.
    /// > The attack requires no target-specific circumvention to exploit the
    /// > vulnerability. An attacker can expect repeatable success against the
    /// > vulnerable system.
    Low,
}

impl Default for AttackComplexity {
    fn default() -> AttackComplexity {
        AttackComplexity::High
    }
}

impl Metric for AttackComplexity {
    const TYPE: MetricType = MetricType::AC;

    // FIXME
    fn score(self) -> f64 {
        match self {
            AttackComplexity::High => 0.44,
            AttackComplexity::Low => 0.77,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            AttackComplexity::High => "H",
            AttackComplexity::Low => "L",
        }
    }
}

impl fmt::Display for AttackComplexity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for AttackComplexity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "H" => Ok(AttackComplexity::High),
            "L" => Ok(AttackComplexity::Low),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
