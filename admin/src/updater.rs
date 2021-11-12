//! RustSec Advisory DB tool to update advisory data

use crate::prelude::*;
use std::collections::HashSet;
use std::{path::Path, process::exit, thread::sleep, time::Duration};
use url::Url;

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
const NVD_API_SLEEP_MS: u64 = 200;

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
        let advisory_id = metadata.id;
        //println!("{}", advisory_id);

        // Look for an existing CVE id
        let cve_ids = metadata
            .aliases
            .iter()
            .chain(std::iter::once(&advisory_id))
            .filter(|alias| alias.kind() == rustsec::advisory::id::Kind::CVE);

        let mut nvd_scores: HashSet<cvss::v3::Base> = HashSet::new();
        let mut references: Vec<Url> = vec![];
        let mut broken_cve_aliases: Vec<rustsec::advisory::id::Id> = vec![];
        for id in cve_ids {
            let info = fetch_cve(id);

            match info {
                Ok(Some(CveInfo {
                    cvss: Some(ref nvd_cvss),
                    references: _,
                })) => {
                    let _ = nvd_scores.insert(nvd_cvss.clone());
                }
                Ok(_) => (),
                Err(_) => broken_cve_aliases.push(id.clone()),
            }

            match info {
                Ok(Some(CveInfo {
                    cvss: _,
                    references: nvd_references,
                })) => {
                    references.append(&mut nvd_references.clone());
                }
                _ => (),
            }
        }

        for broken_alias in broken_cve_aliases {
            println!("Broken alias for {}: {}", advisory_id, broken_alias);
        }

        // Try to extract ghsa ids from references
        // to add it is missing
        let mut ghsa_ids: Vec<rustsec::advisory::id::Id> = vec![];
        for reference in references {
            let s_ref = reference.as_str();

            if s_ref.contains("rustsec")
                || s_ref.contains("https://crates.io")
                || s_ref.contains("RustSec")
                || s_ref.contains("RUSTSEC-")
            {
                continue;
            }

            if s_ref.contains("GHSA-") {
                let begin = s_ref.find("GHSA-").unwrap();
                let ghsa = &s_ref[begin..begin + 19];
                ghsa_ids.push(ghsa.parse().unwrap());
                continue;
            }

            let mut complete_references = advisory.metadata.references.clone();
            if let Some(u) = advisory.metadata.url.as_ref() {
                complete_references.push(u.clone());
            }
            if complete_references
                .iter()
                .find(|u| **u == reference)
                .is_none()
            {
                println!("Missing reference for {}: {}", advisory_id, reference);
            }
        }

        for ghsa_id in ghsa_ids {
            if !advisory.metadata.aliases.contains(&ghsa_id) {
                // FIXME check if they are really Rust advisories
                println!("New {} alias for {}", ghsa_id, advisory_id);
            }
        }

        if nvd_scores.len() == 1 {
            let nvd_score = nvd_scores.iter().next().unwrap();
            if let Some(ref current_cvss) = advisory.metadata.cvss {
                if current_cvss != nvd_score {
                    println!("Potential cvss update for {}: {}", advisory_id, nvd_score)
                }
            } else {
                println!("Add cvss for {}: {}", advisory_id, nvd_score);
            }
        } else if nvd_scores.len() > 1 {
            println!(
                "Inconsistency: {} cvss values for {}",
                nvd_scores.len(),
                advisory_id
            );
        }
    }
}

// Interesting parts of NVD data
#[derive(Debug)]
struct CveInfo {
    cvss: Option<cvss::v3::Base>,
    references: Vec<Url>,
}

fn fetch_cve(id: &rustsec::advisory::id::Id) -> Result<Option<CveInfo>, ()> {
    let response = ureq::get(&format!("{}/{}", NVD_API_URL, id))
        .call()
        .map_err(|_| ())?;
    if response.status() == 404 {
        return Ok(None);
    }
    let body = response.into_string().map_err(|_| ())?;

    let data: serde_json::Value = serde_json::from_str(&body).unwrap();
    let cvss = data["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
        .as_str()
        .and_then(|s| s.parse().ok());

    let mut references = vec![];
    let r_references = data["result"]["CVE_Items"][0]["cve"]["references"]["reference_data"]
        .as_array()
        .unwrap();
    for r_ref in r_references {
        let url = Url::parse(r_ref["url"].as_str().unwrap()).unwrap();
        references.push(url);
    }

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
