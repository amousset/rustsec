//! `rustsec-admin update-advisories` subcommand
//!
//! Updates advisories content from external sources

use abscissa_core::{Command, Runnable};
use gumdrop::Options;
use std::path::{Path, PathBuf};

/// `rustsec-admin update-advisories` subcommand
#[derive(Command, Debug, Default, Options)]
pub struct UpdateAdvisoriesCmd {
    #[options(long = "github-actions-output")]
    github_action_output: bool,
    /// Path to the advisory database
    #[options(free, help = "filesystem path to the RustSec advisory DB git repo")]
    path: Vec<PathBuf>,
}

impl Runnable for UpdateAdvisoriesCmd {
    fn run(&self) {
        let repo_path = match self.path.len() {
            0 => Path::new("."),
            1 => self.path[0].as_path(),
            _ => Self::print_usage_and_exit(&[]),
        };
        let output_mode = if self.github_action_output {
            crate::updater::OutputMode::GithubAction
        } else {
            crate::updater::OutputMode::HumanReadable
        };

        crate::updater::update_advisories(repo_path, output_mode);
    }
}
