//! Availability Requirement (AR)

use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// Availability Requirement (AR) - CVSS v3.1 Environmental Metric Group
///
/// Described in CVSS v3.1 Specification: Section 4.1:
/// <https://www.first.org/cvss/v3.1/specification-document#t6>
///

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AvailabilityRequirement {
    /// Not Defined (X)
    ///
    /// > Assigning this value indicates there is insufficient information to choose
    /// > one of the other values, and has no impact on the overall Environmental
    /// > Score, i.e., it has the same effect on scoring as assigning Medium.
    NotDefined,

    /// High (H)
    ///
    /// > Loss of Availability is likely to have a catastrophic adverse effect on the organization
    /// > or individuals associated with the organization (e.g., employees, customers).
    High,

    /// Medium (M)
    ///
    /// > Loss of Availability is likely to have a serious adverse effect on the organization or
    /// > individuals associated with the organization (e.g., employees, customers).
    Medium,

    /// Low (L)
    ///
    /// > Loss of Availability is likely to have only a limited adverse effect on the organization
    /// > or individuals associated with the organization (e.g., employees, customers).
    Low,
}

impl Default for AvailabilityRequirement {
    fn default() -> AvailabilityRequirement {
        AvailabilityRequirement::NotDefined
    }
}

impl Metric for AvailabilityRequirement {
    const TYPE: MetricType = MetricType::AR;

    fn score(self) -> f64 {
        match self {
            AvailabilityRequirement::NotDefined => 1.0,
            AvailabilityRequirement::High => 1.5,
            AvailabilityRequirement::Medium => 1.0,
            AvailabilityRequirement::Low => 0.5,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            AvailabilityRequirement::NotDefined => "X",
            AvailabilityRequirement::High => "H",
            AvailabilityRequirement::Medium => "M",
            AvailabilityRequirement::Low => "L",
        }
    }
}

impl fmt::Display for AvailabilityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for AvailabilityRequirement {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(AvailabilityRequirement::NotDefined),
            "H" => Ok(AvailabilityRequirement::High),
            "M" => Ok(AvailabilityRequirement::Medium),
            "L" => Ok(AvailabilityRequirement::Low),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
