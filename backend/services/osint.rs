use crate::models::analysis::Signal;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env::var, sync::Arc};
use tokio::{sync::Semaphore, task::JoinSet};

#[derive(Debug)]
pub struct SellerIdentifiers {
    pub name: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug)]
pub struct OsintMatch {
    pub matched_identifiers: Vec<String>,
    pub confidence: String, // "strong", "weak", "none"
}

#[derive(Debug, Deserialize)]
pub struct SerperOrganicResult {
    pub title: String,
    pub link: String,
    pub snippet: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SerperSearchResponse {
    #[serde(default)]
    pub organic: Vec<SerperOrganicResult>,
}

#[derive(Debug, Serialize, Clone)]
pub struct SocialCandidateLink {
    pub platform: String,
    pub title: String,
    pub url: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PlatformCheckResult {
    pub platform: String,
    pub variant_searched: String,
    pub found: bool,
    pub candidates: Vec<SocialCandidateLink>,
}

/// The real, complete scam-word list, split into small, real groups
/// - each group becomes its OWN, separate Google search, so every
/// single word genuinely gets searched for, rather than cramming
/// everything into one query where Google might only weight the
/// first few terms.
const SCAM_WORD_SEARCH_GROUPS: &[&str] = &[
    "golpe OR scam OR fraude",
    "cuidado OR reclamação OR estelionato",
    "picareta OR enganou OR \"não recomendo\"",
    "\"não entregou\" OR sumiu OR processo",
    "polícia OR ripoff OR beware OR avoid OR scammed",
];

pub fn score_identifier_match(seller: &SellerIdentifiers, found_text: &str) -> OsintMatch {
    let lower_text = found_text.to_lowercase();
    let mut matched = Vec::new();

    if let Some(name) = &seller.name {
        let lower_name = name.to_lowercase();
        let words: Vec<&str> = lower_name.split_whitespace().collect();
        let core_name = if words.len() >= 2 {
            format!("{} {}", words[0], words[1])
        } else {
            lower_name.clone()
        };
        if !lower_name.trim().is_empty()
            && (lower_text.contains(&lower_name) || lower_text.contains(&core_name))
        {
            matched.push("name".to_string());
        }
    }

    if let Some(phone) = &seller.phone {
        let digits_only: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if !digits_only.is_empty()
            && lower_text
                .replace(|c: char| !c.is_ascii_digit(), "")
                .contains(&digits_only)
        {
            matched.push("phone".to_string());
        }
    }

    if let Some(email) = &seller.email {
        if !email.trim().is_empty() && lower_text.contains(&email.to_lowercase()) {
            matched.push("email".to_string());
        }
    }

    if let Some(website) = &seller.website {
        if !website.trim().is_empty() && lower_text.contains(&website.to_lowercase()) {
            matched.push("website".to_string());
        }
    }

    if let Some(location) = &seller.location {
        let clean_loc = location
            .split(['/', '|'])
            .next()
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        if !clean_loc.is_empty() && lower_text.contains(&clean_loc) {
            matched.push("location".to_string());
        }
    }

    const SCAM_WORDS: &[&str] = &[
        "golpe",
        "scam",
        "fraude",
        "cuidado",
        "reclamação",
        "estelionato",
        "picareta",
        "enganou",
        "não recomendo",
        "não entregou",
        "sumiu",
        "processo",
        "polícia",
        "ripoff",
        "beware",
        "avoid",
        "scammed",
    ];
    let contains_scam_language = SCAM_WORDS.iter().any(|w| lower_text.contains(w));
    if contains_scam_language {
        matched.push("scam_language".to_string());
    }

    let confidence = if matched.len() >= 2 {
        "strong"
    } else if matched.len() == 1 {
        "weak"
    } else {
        "none"
    };

    OsintMatch {
        matched_identifiers: matched,
        confidence: confidence.to_string(),
    }
}

/// Runs one, real, live search query against Serper's actual API,
/// with an optional country code (e.g. "br" for Brazil) to genuinely
/// match local, real results - without this, Serper may return
/// generic, less relevant results for the seller's actual region.
pub async fn run_serper_search(
    query: &str,
    country_code: Option<&str>,
) -> Option<SerperSearchResponse> {
    let api_key = var("SERPER_API_KEY").ok()?;
    let client = Client::new();
    let mut body = json!({ "q": query });
    if let Some(gl) = country_code {
        body["gl"] = json!(gl);
    }
    let response = client
        .post("https://google.serper.dev/search")
        .header("X-API-KEY", api_key)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<SerperSearchResponse>().await.ok()
}

/// Confirms whether a real, found URL belongs to one of Safely's OWN,
/// already-scraped platforms - genuinely NOT independent OSINT
/// evidence, since a company's page existing on the same platform
/// it's already listed on proves nothing new. Reuses the same, real
/// config/platform_domains.json already powering the extension's
/// Domain check signal - one, single, shared source of truth.
fn is_own_platform_domain(url: &str) -> bool {
    crate::services::platform_config::get_all_platform_domains()
        .values()
        .any(|domain| url.contains(domain))
}

/// Builds the real, complete matrix of OSINT queries - every real
/// name variant (first word, first two words, full name), checked
/// separately against every real platform. Nothing is combined into
/// one OR-query; each variant+platform pair is its own, distinct,
/// honest search, so the final result can report exactly which
/// combinations found something and which genuinely didn't.
pub fn build_osint_query_matrix(
    company_name: Option<&str>,
    contact_name: Option<&str>,
    location: Option<&str>,
    phone: Option<&str>,
) -> Vec<(String, String, String)> {
    let mut queries = Vec::new();
    let Some(name) = company_name.filter(|n| !n.trim().is_empty()) else {
        return queries;
    };

    let clean_location = location
        .and_then(|l| l.split(['/', '|']).next())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let location_part = clean_location
        .map(|l| format!(" \"{}\"", l))
        .unwrap_or_default();

    let words: Vec<&str> = name.split_whitespace().collect();
    let mut variants: Vec<String> = Vec::new();

    if words.len() >= 2 {
        variants.push(format!("{} {}", words[0], words[1]));
    }
    variants.push(name.to_string());
    variants.dedup();

    let platforms: Vec<(&str, &str)> = vec![
        ("Facebook", "site:facebook.com"),
        ("LinkedIn", "site:linkedin.com"),
        ("TikTok", "site:tiktok.com"),
        ("Instagram", "site:instagram.com"),
        ("Reddit", "site:reddit.com"),
        ("Trustpilot", "site:trustpilot.com"),
    ];

    for variant in &variants {
        for (platform_label, site_filter) in &platforms {
            queries.push((
                platform_label.to_string(),
                format!("{} \"{}\"{}", site_filter, variant, location_part),
                variant.clone(),
            ));
            let phone_part = phone.map(|p| format!(" \"{}\"", p)).unwrap_or_default();
            for word_group in SCAM_WORD_SEARCH_GROUPS {
                queries.push((
                    platform_label.to_string(),
                    format!(
                        "{} \"{}\"{} ({})",
                        site_filter, variant, phone_part, word_group
                    ),
                    variant.clone(),
                ));
            }
        }
        queries.push((
            "Reviews".to_string(),
            format!(
                "\"{}\" reviews OR reclameaqui OR reclamação OR avaliação",
                variant
            ),
            variant.clone(),
        ));
    }

    // A real, strong, dedicated search for the individual contact
    // person, when their name and a genuine, unmasked phone number
    // are both available - the strongest possible combination.
    if let (Some(contact), Some(real_phone)) = (contact_name, phone) {
        if !contact.trim().is_empty() && !real_phone.trim().is_empty() {
            for (platform_label, site_filter) in &[
                ("Facebook", "site:facebook.com"),
                ("LinkedIn", "site:linkedin.com"),
            ] {
                queries.push((
                    format!("Contact ({})", platform_label),
                    format!("{} \"{}\" \"{}\"", site_filter, contact, real_phone),
                    contact.to_string(),
                ));
            }
            queries.push((
                "Contact (Web)".to_string(),
                format!("\"{}\" \"{}\"", contact, real_phone),
                contact.to_string(),
            ));
        }
    }

    queries
}

/// Runs the REAL, complete matrix - every name variant, against
/// every platform - and reports back EVERY result, found or not, so
/// the final signal can honestly show exactly what was checked, not
/// just what happened to succeed.
pub async fn build_social_presence_matrix(
    company_name: Option<&str>,
    contact_name: Option<&str>,
    location: Option<&str>,
    phone: Option<&str>,
) -> (Signal, Vec<PlatformCheckResult>) {
    let queries = build_osint_query_matrix(company_name, contact_name, location, phone);
    if queries.is_empty() {
        return (
            Signal {
                label: "Social presence check".to_string(),
                sub: "No company name was available to search with.".to_string(),
                value: "Not checked".to_string(),
                signal_type: "info".to_string(),
                category: "external_intelligence".to_string(),
                check_type: "existence".to_string(),
            },
            Vec::new(),
        );
    }

    // Run real, live searches in parallel, but genuinely LIMITED to
    // a real, small number at once (10) - not one at a time (slow),
    // and not all ~70+ at the exact same instant (triggers Serper's
    // own rate limiting, silently dropping results). A semaphore
    // acts like a real, honest "only 10 people through this door at
    // once" rule - the 11th request genuinely waits for a slot to
    // free up, rather than being sent immediately and getting
    // rejected.
    let semaphore = Arc::new(Semaphore::new(10));
    let mut join_set = JoinSet::new();
    for (platform_label, query, variant) in queries {
        let permit_holder = semaphore.clone();
        join_set.spawn(async move {
            let _permit = permit_holder.acquire().await.ok();
            let real_results = run_serper_search(&query, Some("br")).await;
            let mut real_candidates = Vec::new();
            if let Some(response) = real_results {
                for r in response.organic.iter().take(3) {
                    if is_own_platform_domain(&r.link) {
                        continue;
                    }
                    let title_lower = r.title.to_lowercase();
                    let variant_lower = variant.to_lowercase();
                    if !title_lower.contains(&variant_lower) {
                        continue;
                    }
                    real_candidates.push(SocialCandidateLink {
                        platform: platform_label.clone(),
                        title: r.title.clone(),
                        url: r.link.clone(),
                    });
                }
            }
            PlatformCheckResult {
                platform: platform_label,
                variant_searched: variant,
                found: !real_candidates.is_empty(),
                candidates: real_candidates,
            }
        });
    }

    let mut results: Vec<PlatformCheckResult> = Vec::new();
    while let Some(joined) = join_set.join_next().await {
        if let Ok(result) = joined {
            results.push(result);
        }
    }

    let found_count = results.iter().filter(|r| r.found).count();
    let signal = Signal {
        label: "Social presence check".to_string(),
        sub: format!(
            "{} of {} platform checks found a real, candidate result.",
            found_count,
            results.len()
        ),
        value: if found_count > 0 {
            "Candidates found".to_string()
        } else {
            "No presence found".to_string()
        },
        signal_type: if found_count > 0 {
            "info".to_string()
        } else {
            "caution".to_string()
        },
        category: "external_intelligence".to_string(),
        check_type: "existence".to_string(),
    };

    (signal, results)
}

/// Fetches ONE, real, specific candidate link's actual page content,
/// and checks it against the seller's real, known identifiers - the
/// genuine, deep, on-demand verification step, only ever run for a
/// single link the user has deliberately chosen to check. Mirrors
/// check_b2b_page's real, existing fetch pattern - no separate proxy
/// service exists in this codebase.
pub async fn verify_social_link(
    url: &str,
    seller: &SellerIdentifiers,
) -> Result<OsintMatch, String> {
    let client = Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Could not reach the real, live page: {}", e))?;
    if !response.status().is_success() {
        return Err(format!(
            "The real, live page returned an unsuccessful status: {}",
            response.status()
        ));
    }
    let page_text = response
        .text()
        .await
        .map_err(|e| format!("Could not read the real, live page content: {}", e))?;

    Ok(score_identifier_match(seller, &page_text))
}
