//! RustSec Advisory DB tool to update advisory data

use crate::prelude::*;
use rustsec::collection::Collection;
use std::{path::Path, process::exit, thread::sleep, time::Duration};

// Goals:
// * update existing data
// * warn about inconsistent data
// * detect potential missing advisories

// External sources:
// * NVD CVE API
// * GitHub Security Advisory API

// Workflow:
//
// Read current advisories
// Check for updated data from NVD (cvss, cwe, aliases)
// Check for inconsistencies from NVD
// TODO GHSA

// Open PR for changes, issues for problems and potential advisories

const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cve/1.0";
// minimal sleep between call to the API to comply wit rate-limiting
// value found by trial and error
const NVD_API_SLEEP_MS: u64 = 150;

/// What sort of output should be generated on stdout.
#[derive(PartialEq, Clone, Copy)]
pub enum OutputMode {
    /// Normal human readable logging
    HumanReadable,
    /// Output designed for use in the github action that runs this in prod
    GithubAction,
}

/// assign ids to advisories in a particular repo_path
pub fn update_advisories(repo_path: &Path, output_mode: OutputMode) {
    let db = rustsec::Database::open(repo_path).unwrap_or_else(|e| {
        status_err!(
            "couldn't open advisory DB repo from {}: {}",
            repo_path.display(),
            e
        );
        exit(1);
    });

    let advisories = db.iter();

    // Ensure we're parsing some advisories
    if advisories.len() == 0 {
        status_err!("no advisories found!");
        exit(1);
    }

    if output_mode == OutputMode::HumanReadable {
        status_ok!(
            "Loaded",
            "{} security advisories (from {})",
            advisories.len(),
            repo_path.display()
        );
    }

    for advisory in advisories {
        let advisory_clone = advisory.clone();
        let metadata = advisory_clone.metadata;
        let id = metadata.id;
        println!("{}", id);

        // Look for an existing CVE id
        let cve_ids = metadata
            .aliases
            .iter()
            .chain(std::iter::once(&id))
            .filter(|alias| alias.kind() == rustsec::advisory::id::Kind::CVE);

        // FIXME store new and different cvss scores
        // build an array and AFTER

        let mut nvd_scores: Vec<cvss::v3::Base> = vec![];
        let mut _references: Vec<String> = vec![];
        let mut broken_cve_aliases: Vec<rustsec::advisory::id::Id> = vec![];

        for id in cve_ids {
            match fetch_cve(id) {
                Ok(Some(CveInfo {
                    cvss: Some(nvd_cvss),
                    references: _,
                })) => nvd_scores.push(nvd_cvss),
                Ok(_) => (),
                Err(_) => broken_cve_aliases.push(id.clone()),
            }
        }

        nvd_scores.sort();
        nvd_scores.dedup();

        for broken_alias in broken_cve_aliases {
            println!("Broken alias for {}: {}", id, broken_alias);
        }

        if let Some(ref _current_cvss) = advisory.metadata.cvss {}
    }

    let mut collection_strs = vec![];
    let crates_str = Collection::Crates.to_string();
    let rust_str = Collection::Rust.to_string();
    collection_strs.push(crates_str);
    collection_strs.push(rust_str);
}

// Interesting parts of NVD data
#[derive(Debug)]
struct CveInfo {
    cvss: Option<cvss::v3::Base>,
    references: Vec<String>,
}

fn fetch_cve(id: &rustsec::advisory::id::Id) -> Result<Option<CveInfo>, ()> {
    let response = ureq::get(&format!("{}/{}", NVD_API_URL, id))
        .call()
        .map_err(|_| ())?;
    if response.status() == 404 {
        return Ok(None);
    }

    let body = response.into_string().map_err(|_| ())?;

    // FIXME special handling of 404 as it meaningful

    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    let cvss = data["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
        .as_str()
        .and_then(|s| s.parse().ok());

    let references = vec![];

    sleep(Duration::from_millis(NVD_API_SLEEP_MS));
    Ok(Some(CveInfo { cvss, references }))
}

/*
///Assign ids to files with placeholder IDs within the directory defined by dir_path
fn assign_ids_across_directory(
    collection_str: String,
    repo_path: &Path,
    highest_ids: &mut Map<u32, u32>,
    output_mode: OutputMode,
    assignments: &mut Vec<String>,
) {
    let dir_path = repo_path.join(collection_str);

    if let Ok(collection_entry) = fs::read_dir(dir_path) {
        for dir_entry in collection_entry {
            let unwrapped_dir_entry = dir_entry.unwrap();
            let dir_name = unwrapped_dir_entry.file_name().into_string().unwrap();
            let dir_path = unwrapped_dir_entry.path();
            let dir_path_clone = dir_path.clone();
            for advisory_entry in fs::read_dir(dir_path).unwrap() {
                let unwrapped_advisory = advisory_entry.unwrap();
                let advisory_path = unwrapped_advisory.path();
                let advisory_path_clone = advisory_path.clone();
                let advisory_path_for_reading = advisory_path.clone();
                let advisory_path_for_deleting = advisory_path.clone();
                let displayed_advisory_path = advisory_path.display();
                let advisory_filename = unwrapped_advisory.file_name();
                let advisory_filename_str = advisory_filename.into_string().unwrap();
                if advisory_filename_str.contains("RUSTSEC-0000-0000") {
                    let advisory_data = fs::read_to_string(advisory_path_clone)
                        .map_err(|e| {
                            format_err!(
                                ErrorKind::Io,
                                "Couldn't open {}: {}",
                                displayed_advisory_path,
                                e
                            );
                        })
                        .unwrap();

                    let advisory_parts = parser::Parts::parse(&advisory_data).unwrap();
                    let advisory: Advisory = toml::from_str(&advisory_parts.front_matter).unwrap();
                    let date = advisory.metadata.date;
                    let year = date.year();
                    let new_id = highest_ids.get(&year).cloned().unwrap_or_default() + 1;
                    let year_str = year.to_string();
                    let string_id = format!("RUSTSEC-{}-{:04}", year_str, new_id);
                    let new_filename = format!("{}.md", string_id);
                    let new_path = dir_path_clone.join(new_filename);
                    let original_file = File::open(advisory_path_for_reading).unwrap();
                    let reader = BufReader::new(original_file);
                    let new_file = File::create(new_path).unwrap();
                    let mut writer = LineWriter::new(new_file);
                    for line in reader.lines() {
                        let current_line = line.unwrap();
                        if current_line.contains("id = ") {
                            writer
                                .write_all(format!("id = \"{}\"\n", string_id).as_ref())
                                .unwrap();
                        } else {
                            let current_line_with_newline = format!("{}\n", current_line);
                            writer
                                .write_all(current_line_with_newline.as_ref())
                                .unwrap();
                        }
                    }
                    highest_ids.insert(year, new_id);
                    fs::remove_file(advisory_path_for_deleting).unwrap();
                    if output_mode == OutputMode::HumanReadable {
                        status_ok!("Assignment", "Assigned {} to {}", string_id, dir_name);
                    } else {
                        assignments.push(format!("{} to {}", string_id, dir_name))
                    }
                }
            }
        }
    }
}
*/
