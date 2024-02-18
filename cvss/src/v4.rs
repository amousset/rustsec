//! Common Vulnerability Scoring System (v4.0)
//!
//! <https://www.first.org/cvss/specification-document>

// TODO(tarcieri): Environmental and Temporal Metrics

pub mod base;

mod score;

pub use self::{base::Base, score::Score};
