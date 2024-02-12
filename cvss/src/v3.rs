//! Common Vulnerability Scoring System (v3.1)
//!
//! <https://www.first.org/cvss/specification-document>

pub mod base;
pub mod temporal;

mod score;

pub use self::{base::Base, score::Score};
