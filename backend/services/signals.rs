use crate::{
    models::{analysis::Signal, helpers::format_account_age, sellers::Sellers},
    services::{
        b2b_scrapers::{B2bListingProfile, B2bSupplierProfile},
        b2c_scrapers::B2cProfileResult,
        claude::{B2bClaudeAnalysis, ClaudeAnalysis, Finding},
        whois::WhoisResult,
    },
};
use chrono::{Datelike, NaiveDate, Utc};

/// It takes Claude's raw analysis and turns it into a real, ordered list of
/// 7 separate signal cards each one representing one specific thing that was checked.
///
/// It starts with an empty list, adds the price signal, built directly, by hand,
/// adds several signals using a shared helper, finding_to_signal, adds the
/// account age signal, built by hand again, pushes the image authenticity signal,
/// built by hand once more and returns the complete list.
pub fn build_signals(analysis: &ClaudeAnalysis, seller: &Sellers) -> Vec<Signal> {
    let mut signals = Vec::new();
    signals.push(Signal {
        label: "Price analysis".to_string(),
        sub: analysis.price_assessment.reasoning.clone(),
        value: analysis.price_assessment.verdict.clone(),
        signal_type: if analysis.price_assessment.verdict == "normal" {
            "good".to_string()
        } else {
            "caution".to_string()
        },
        category: "listing".to_string(),
        check_type: "anomaly".to_string(),
    });

    signals.push(finding_to_signal(
        "Urgency language",
        &analysis.urgency_language.evidence,
        &analysis.urgency_language,
        "communication",
        "pattern",
    ));

    signals.push(finding_to_signal(
        "Advance payment request",
        &analysis.advance_payment_request.evidence,
        &analysis.advance_payment_request,
        "communication",
        "pattern",
    ));

    signals.push(Signal {
        label: "Entity age".to_string(),
        sub: "Cross-referenced with Safely records".to_string(),
        value: seller
            .join_date
            .map(|d| format_account_age(d))
            .unwrap_or_else(|| "Unknown".to_string()),
        signal_type: "info".to_string(),
        category: "marketplace".to_string(),
        check_type: "anomaly".to_string(),
    });

    signals.push(finding_to_signal(
        "Duplicate listing",
        &analysis.duplicate_listing.evidence,
        &analysis.duplicate_listing,
        "listing",
        "pattern",
    ));

    signals.push(Signal {
        label: "Image authenticity".to_string(),
        sub: analysis.image_authenticity.reasoning.clone(),
        value: analysis.image_authenticity.verdict.clone(),
        signal_type: if analysis.image_authenticity.verdict == "original" {
            "good".to_string()
        } else {
            "caution".to_string()
        },
        category: "listing".to_string(),
        check_type: "existence".to_string(),
    });

    signals.push(finding_to_signal(
        "Overall legitimacy check",
        &analysis.fraud_pattern_match.evidence,
        &analysis.fraud_pattern_match,
        "behavioral",
        "pattern",
    ));

    signals.push(Signal {
        label: "Contact info".to_string(),
        sub: analysis.contact_info_in_listing.evidence.clone(),
        value: if analysis.contact_info_in_listing.found {
            "Confirmed".to_string()
        } else {
            "Not confirmed".to_string()
        },
        signal_type: if analysis.contact_info_in_listing.found {
            "caution".to_string()
        } else {
            "good".to_string()
        },
        category: "communication".to_string(),
        check_type: "existence".to_string(),
    });

    signals
}

/// It converts one of Claude's yes/no findings (like "was urgency language detected?")
/// into a properly-formatted Signal card, ready to display.
///
/// It takes three pieces of information, builds the value field, based on whether it was found,
/// builds the signal_type field, deciding how it should visually display.
pub fn finding_to_signal(
    label: &str,
    sub: &str,
    finding: &Finding,
    category: &str,
    check_type: &str,
) -> Signal {
    Signal {
        label: label.to_string(),
        sub: sub.to_string(),
        value: if finding.found {
            "Detected".to_string()
        } else {
            "None found".to_string()
        },
        signal_type: if finding.found {
            "caution".to_string()
        } else {
            "good".to_string()
        },
        category: category.to_string(),
        check_type: check_type.to_string(),
    }
}

/// It checks whether the extension flagged this website as a fake,
/// lookalike domain, and if so, builds a real signal card explaining
/// exactly what's wrong — otherwise, it returns nothing at all.
///
/// It matches on the domain check's status. If the domain is genuinely legitimate,
/// if the domain is suspicious — the more involved case. If anything else,
/// genuinely nothing to report.
pub fn build_domain_signal(
    status: Option<&str>,
    real_name: Option<&str>,
    real_domain: Option<&str>,
    current_domain: Option<&str>,
    current_domain_html: Option<&str>,
    real_domain_html: Option<&str>,
) -> Option<Signal> {
    match status {
        Some("legitimate") => Some(Signal {
            label: "Domain check".to_string(),
            sub: format!(
                "This matches {}'s real, verified domain.",
                real_name.unwrap_or("the marketplace")
            ),
            value: "Verified".to_string(),
            signal_type: "good".to_string(),
            category: "website".to_string(),
            check_type: "existence".to_string(),
        }),
        Some("suspicious") => {
            let current_display = current_domain_html
                .or(current_domain)
                .unwrap_or("an unrecognized domain");
            let real_display = real_domain_html.or(real_domain).unwrap_or("unknown");
            Some(Signal {
                label: "Domain check".to_string(),
                sub: format!(
                    "This does not match {}'s real domain ({}). You're currently on {} instead.",
                    real_name.unwrap_or("the marketplace"),
                    real_display,
                    current_display,
                ),
                value: "Suspicious".to_string(),
                signal_type: "bad".to_string(),
                category: "website".to_string(),
                check_type: "existence".to_string(),
            })
        }
        _ => None,
    }
}

/// Builds a real signal from a WHOIS lookup, if one was performed.
/// Genuinely new information - Layer 3's first real "Active
/// collection" signal - correctly labeled as an Existence check under
/// the Website category, matching the same taxonomy every other
/// signal already uses.
pub fn build_whois_signal(whois: Option<&WhoisResult>) -> Option<Signal> {
    let whois = whois?;

    if !whois.registered {
        return Some(Signal {
            label: "Seller website check".to_string(),
            sub:
                "The seller's mentioned website domain does not appear to be genuinely registered."
                    .to_string(),
            value: "Unregistered".to_string(),
            signal_type: "bad".to_string(),
            category: "website".to_string(),
            check_type: "existence".to_string(),
        });
    }

    let registrar_note = whois.registrar.as_deref().unwrap_or("an unknown registrar");
    let created_note = whois.created.as_deref().unwrap_or("an unknown date");

    Some(Signal {
        label: "Seller website check".to_string(),
        sub: format!(
            "This domain is registered through {}, since {}.",
            registrar_note, created_note
        ),
        value: "Registered".to_string(),
        signal_type: "good".to_string(),
        category: "website".to_string(),
        check_type: "existence".to_string(),
    })
}

/// Builds signals from OLX's verified-seller "store" data - genuinely
/// new, real trust information (member duration, product count,
/// rating) that's already sitting on the listing page itself for
/// verified sellers, at zero extra cost.
pub fn build_seller_verification_signals(
    verified: bool,
    rating: Option<f64>,
    total_products: Option<i32>,
) -> Vec<Signal> {
    let mut signals = Vec::new();

    signals.push(Signal {
        label: "Platform verification".to_string(),
        sub: if verified {
            "This seller is verified on the platform.".to_string()
        } else {
            "This seller is not verified on the platform.".to_string()
        },
        value: if verified {
            "Verified".to_string()
        } else {
            "Not verified".to_string()
        },
        signal_type: if verified {
            "good".to_string()
        } else {
            "caution".to_string()
        },
        category: "identity".to_string(),
        check_type: "existence".to_string(),
    });

    if let (Some(r), Some(p)) = (rating, total_products) {
        signals.push(Signal {
            label: "Seller track record".to_string(),
            sub: format!(
                "This seller has listed {} products with a {:.1} average rating.",
                p, r
            ),
            value: format!("{:.1} rating, {} listings", r, p),
            signal_type: if r < 3.0 {
                "caution".to_string()
            } else {
                "good".to_string()
            },
            category: "reputation".to_string(),
            check_type: "anomaly".to_string(),
        });
    }

    signals
}

/// Builds a real signal from a seller's own store page, once visited
/// - Tier 2's real, direct proof (or disproof) of identity
/// consistency, genuinely stronger than anything Tier 1 alone could
/// confirm.
pub fn build_store_page_signal(
    result: &B2cProfileResult,
    claimed_website: Option<&str>,
) -> Option<Signal> {
    let website_cross_confirmed = match (claimed_website, &result.website) {
        (Some(claimed), Some(found_on_store)) => {
            claimed.to_lowercase() == found_on_store.to_lowercase()
        }
        _ => false,
    };

    let (value, signal_type, sub) = match (result.seller_name_confirmed, website_cross_confirmed) {
        (true, true) => (
            "Fully confirmed",
            "good",
            "The seller's name AND their claimed website both genuinely appear on their own store page - a strong, independent match.".to_string(),
        ),
        (true, false) => (
            "Name confirmed only",
            "caution",
            "The seller's name appears on their store page, but their claimed website could not be independently confirmed there.".to_string(),
        ),
        (false, _) => (
            "Unconfirmed",
            "caution",
            "The seller's name could not be confirmed on their own store page.".to_string(),
        ),
    };

    Some(Signal {
        label: "Store page check".to_string(),
        sub,
        value: value.to_string(),
        signal_type: signal_type.to_string(),
        category: "identity".to_string(),
        check_type: "consistency".to_string(),
    })
}

/// Builds a signal from B2Brazil's own "Verified company" badge - a
/// real, direct trust indicator, since the platform's own disclaimer
/// text says an unverified company's info isn't guaranteed accurate.
pub fn build_b2b_verification_signal(supplier: &B2bSupplierProfile) -> Signal {
    if supplier.platform_verified_badge {
        Signal {
            label: "Platform verification".to_string(),
            sub: format!(
                "{} has a verified badge on {}.",
                supplier.company_name.as_deref().unwrap_or("This company"),
                supplier.source_platform
            ),
            value: "Verified".to_string(),
            signal_type: "good".to_string(),
            category: "identity".to_string(),
            check_type: "existence".to_string(),
        }
    } else {
        Signal {
            label: "Platform verification".to_string(),
            sub: format!(
                "{} does not have a verified badge - the platform itself states unverified company info is not guaranteed accurate.",
                supplier.company_name.as_deref().unwrap_or("This company")
            ),
            value: "Unverified".to_string(),
            signal_type: "caution".to_string(),
            category: "identity".to_string(),
            check_type: "existence".to_string(),
        }
    }
}

/// Checks how long ago this company claims to have been established -
/// a genuinely new company is not inherently fraudulent, but it's a
/// real, honest anomaly worth noting, the same logic already applied
/// to OLX account age.
pub fn build_b2b_company_age_signal(supplier: &B2bSupplierProfile) -> Signal {
    let Some(year_str) = supplier.year_established.as_deref() else {
        return Signal {
            label: "Entity age".to_string(),
            sub: "No founding year was provided by this company.".to_string(),
            value: "Not provided".to_string(),
            signal_type: "info".to_string(),
            category: "company".to_string(),
            check_type: "anomaly".to_string(),
        };
    };
    let Ok(established_year) = year_str.trim().parse::<i32>() else {
        return Signal {
            label: "Entity age".to_string(),
            sub: format!(
                "The stated founding year ('{}') could not be understood.",
                year_str
            ),
            value: "Invalid date".to_string(),
            signal_type: "caution".to_string(),
            category: "company".to_string(),
            check_type: "anomaly".to_string(),
        };
    };

    let current_year = Utc::now().year();
    if established_year > current_year {
        return Signal {
            label: "Entity age".to_string(),
            sub: format!(
                "The stated founding year ('{}') is in the future.",
                established_year
            ),
            value: "Invalid date".to_string(),
            signal_type: "caution".to_string(),
            category: "company".to_string(),
            check_type: "anomaly".to_string(),
        };
    }

    let established_date = NaiveDate::from_ymd_opt(established_year, 1, 1)
        .unwrap_or_else(|| NaiveDate::from_ymd_opt(current_year, 1, 1).unwrap());
    let value = format_account_age(established_date);
    let age_years = current_year - established_year;
    let signal_type = if age_years <= 1 { "caution" } else { "good" };
    Signal {
        label: "Entity age".to_string(),
        sub: format!(
            "This company states it was established in {}.",
            established_year
        ),
        value,
        signal_type: signal_type.to_string(),
        category: "company".to_string(),
        check_type: "anomaly".to_string(),
    }
}

/// Checks whether the company has genuinely filled in transparency
/// fields (employee count, sales revenue, export percentage). Missing
/// these isn't inherently suspicious - many legitimate businesses
/// leave them blank for privacy - so this stays a mild, informational
/// signal, not a harsh one.
pub fn build_b2b_transparency_signal(supplier: &B2bSupplierProfile) -> Signal {
    let filled_count = [
        supplier.employee_count.is_some(),
        supplier.sales_revenue.is_some(),
        supplier.export_percentage.is_some(),
    ]
    .iter()
    .filter(|&&present| present)
    .count();

    let signal_type = if filled_count >= 2 { "good" } else { "info" };

    Signal {
        label: "Company profile completeness".to_string(),
        sub: format!(
            "{} of 3 transparency fields (employees, sales volume, export percentage) are filled in.",
            filled_count
        ),
        value: format!("{}/3 fields provided", filled_count),
        signal_type: signal_type.to_string(),
        category: "company".to_string(),
        check_type: "existence".to_string(),
    }
}

/// Checks how many of the real, listing-specific fields (price, MOQ,
/// Incoterms, etc.) were genuinely filled in versus left as "Not
/// informed." Incomplete listings are common in B2B and not
/// inherently suspicious, so this stays a mild pattern check, not a
/// harsh red flag.
pub fn build_b2b_listing_completeness_signal(listing: &B2bListingProfile) -> Signal {
    let fields = [
        &listing.unit_price,
        &listing.fob_price,
        &listing.minimum_order_quantity,
        &listing.payment_type,
        &listing.preferred_port,
        &listing.production_capacity,
        &listing.delivery_timeframe,
        &listing.incoterms,
        &listing.packaging_details,
    ];
    let filled_count = fields.iter().filter(|f| f.is_some()).count();
    let total = fields.len();
    let signal_type = if filled_count == 0 { "caution" } else { "info" };

    Signal {
        label: "Listing completeness".to_string(),
        sub: format!(
            "{} of {} listing details (price, MOQ, Incoterms, etc.) were provided by the supplier.",
            filled_count, total
        ),
        value: format!("{}/{} fields provided", filled_count, total),
        signal_type: signal_type.to_string(),
        category: "listing".to_string(),
        check_type: "pattern".to_string(),
    }
}

fn b2b_finding_to_signal(
    label: &str,
    category: &str,
    check_type: &str,
    finding: &Finding,
) -> Signal {
    Signal {
        label: label.to_string(),
        sub: finding.evidence.clone(),
        value: if finding.found {
            "Confirmed".to_string()
        } else {
            "Not confirmed".to_string()
        },
        signal_type: if finding.found {
            "good".to_string()
        } else {
            "caution".to_string()
        },
        category: category.to_string(),
        check_type: check_type.to_string(),
    }
}

pub fn build_b2b_claude_signals(analysis: &B2bClaudeAnalysis) -> Vec<Signal> {
    vec![
        b2b_finding_to_signal(
            "Overall legitimacy check",
            "company",
            "existence",
            &analysis.business_legitimacy,
        ),
        b2b_finding_to_signal(
            "Registration consistency",
            "company",
            "consistency",
            &analysis.registration_consistency,
        ),
        b2b_finding_to_signal(
            "Duplicate listing",
            "listing",
            "pattern",
            &analysis.listing_specificity,
        ),
        Signal {
            label: "Price analysis".to_string(),
            sub: analysis.pricing_transparency.reasoning.clone(),
            value: analysis.pricing_transparency.verdict.clone(),
            signal_type: if analysis.pricing_transparency.verdict == "normal" {
                "good".to_string()
            } else {
                "caution".to_string()
            },
            category: "listing".to_string(),
            check_type: "anomaly".to_string(),
        },
        b2b_finding_to_signal(
            "Contact info",
            "identity",
            "existence",
            &analysis.contact_verifiability,
        ),
        finding_to_signal(
            "Urgency language",
            &analysis.urgency_language.evidence,
            &analysis.urgency_language,
            "communication",
            "pattern",
        ),
        finding_to_signal(
            "Advance payment request",
            &analysis.advance_payment_request.evidence,
            &analysis.advance_payment_request,
            "communication",
            "pattern",
        ),
        Signal {
            label: "Image authenticity".to_string(),
            sub: analysis.image_authenticity.reasoning.clone(),
            value: analysis.image_authenticity.verdict.clone(),
            signal_type: if analysis.image_authenticity.verdict == "original" {
                "good".to_string()
            } else {
                "caution".to_string()
            },
            category: "listing".to_string(),
            check_type: "existence".to_string(),
        },
    ]
}

/// The real, fixed display order: Table 1 (unified signals) always
/// first, then Table 2 (the contact info/verifiability pair, which
/// looks similar but means opposite things per platform), then Table
/// 3 (genuinely platform-specific signals).
fn table_rank(label: &str) -> u8 {
    match label {
        "Domain check" => 0,
        "Price analysis" => 1,
        "Urgency language" => 2,
        "Advance payment request" => 3,
        "Entity age" => 4,
        "Duplicate listing" => 5,
        "Image authenticity" => 6,
        "Overall legitimacy check" => 7,
        "Safely history" => 8,
        "Seller website check" => 9,
        "Platform verification" => 10,
        "Contact info" => 11,
        "Store page check" => 12,
        "Seller track record" => 13,
        "Registration consistency" => 14,
        "Company profile completeness" => 15,
        "Listing completeness" => 16,

        _ => 255,
    }
}

pub fn sort_signals_by_table(signals: &mut [Signal]) {
    signals.sort_by_key(|s| table_rank(&s.label));
}
