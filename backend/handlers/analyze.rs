use crate::{
    errors::analyze::AnalyzeError,
    models::{
        analysis::{AnalyzeRequest, AnalyzeResponse, RiskLevel},
        sellers::Sellers,
    },
    services::{
        analysis::{
            BuildResponseData, authorize_request, build_all_signals, build_b2b_analysis_path,
            build_requests, resolve_seller, run_claude_analysis, save_and_build_response,
        },
        b2b_scrapers::get_scraper_for_platform,
        b2c_scrapers::{check_listing_page, requires_client_side_scraping},
        listings::{create_listing, update_listing_from_b2b},
        osint::{PlatformCheckResult, SellerIdentifiers, verify_social_link},
        scoring::calculate_risk_score,
        sellers::update_seller_from_b2b,
        signals::sort_signals_by_table,
    },
};
use axum::{Json, extract::State, http::HeaderMap};
use chrono::NaiveDate;
use sqlx::{Pool, Postgres, query};
use uuid::Uuid;

#[derive(Debug, serde::Deserialize)]
pub struct VerifySocialLinkRequest {
    pub seller_id: Uuid,
    pub url: String,
}

#[derive(Debug, serde::Serialize)]
pub struct VerifySocialLinkResponse {
    pub matched: bool,
    pub matched_identifiers: Vec<String>,
    pub confidence: String,
    pub message: String,
}

/// POST /api/v1/analyze
///
/// It's the actual, real endpoint your extension calls, it runs the entire
/// fraud-analysis process, step by step, from checking who's asking, all the way
/// to sending back a complete, saved risk report.
///
/// It confirms who's calling, and that they're allowed to right now, splits the
/// incoming request into its two separate pieces, finds or creates the seller,
/// with correctly-set verification, creates the listing itself, runs the actual
/// Claude analysis, builds the complete signal list, domain check included,
/// calculates the actual risk score, and converts it into a risk level and
/// saves everything, and builds the final response.
pub async fn analyze(
    State(pool): State<Pool<Postgres>>,
    headers: HeaderMap,
    Json(request): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, AnalyzeError> {
    let user_id = authorize_request(&headers, &pool).await?;
    let mut request = request;
    if !requires_client_side_scraping(&request.platform) {
        if let Some(scraped) = check_listing_page(&request.platform, &request.listing_url).await {
            if request.title.is_none() {
                request.title = scraped.title;
            }
            if request.price.is_none() {
                request.price = scraped.price;
            }
            if request.description.is_none() {
                request.description = scraped.description;
            }
            if request.seller_name.is_none() {
                request.seller_name = scraped.seller_name;
            }
            if request.seller_location.is_none() {
                request.seller_location = scraped.location;
            }
            if request.platform_id.is_none() {
                request.platform_id = scraped.platform_id;
            }
            if request.seller_profile_url.is_none() {
                request.seller_profile_url = scraped.seller_profile_url;
            }
            if request.seller_last_active.is_none() {
                request.seller_last_active = scraped.last_active;
            }
            request.seller_verified = Some(scraped.seller_verified);
            if request.seller_rating.is_none() {
                request.seller_rating = scraped.seller_rating;
            }
            if request.seller_total_products.is_none() {
                request.seller_total_products = scraped.seller_total_products;
            }
            if request.seller_join_date.is_none() {
                request.seller_join_date = scraped.seller_join_date;
            }
            if request.image_urls.is_none() && !scraped.image_urls.is_empty() {
                request.image_urls = Some(scraped.image_urls);
            }
            if request.seller_website.is_none() {
                request.seller_website = scraped.seller_website;
            }
        }
    }

    let (mut seller_req, listing_req) = build_requests(&request);
    if seller_req.platform_id.is_none() && request.platform == "b2brazil" {
        seller_req.platform_id = request
            .listing_url
            .split("/hotsite/")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .map(|s| s.to_string());
    }
    let platform_id = seller_req.platform_id.as_deref().unwrap_or("unknown");
    let resolved = resolve_seller(&pool, &seller_req, &request.platform, platform_id).await?;

    let listing = create_listing(&pool, &listing_req, resolved.seller.id)
        .await
        .map_err(|e| AnalyzeError::Database(e.to_string()))?;

    let is_b2b = get_scraper_for_platform(&request.platform).is_some();

    let mut resolved = resolved;

    let mut social_candidates: Vec<PlatformCheckResult> = Vec::new();
    let (signals, risk_score, overall_risk_notes) = if is_b2b {
        let (signals, risk_score, notes, supplier, listing_data, candidates_from_b2b) =
            build_b2b_analysis_path(&pool, &request, resolved.fraud_count, resolved.seller.id)
                .await?;
        let join_date = supplier.year_established.as_deref().and_then(|y| {
            y.trim()
                .parse::<i32>()
                .ok()
                .and_then(|year| NaiveDate::from_ymd_opt(year, 1, 1))
        });
        let clean_contact_name = supplier
            .contact_name
            .as_deref()
            .map(|n| n.replace('*', "").trim().to_string());
        let _ = update_seller_from_b2b(
            &pool,
            resolved.seller.id,
            supplier.company_name.as_deref(),
            supplier.country.as_deref(),
            join_date,
            clean_contact_name.as_deref(),
            supplier.contact_phone.as_deref(),
            Some(&request.listing_url),
        )
        .await;
        let _ = update_listing_from_b2b(
            &pool,
            listing.id,
            listing_data.title.as_deref(),
            listing_data.description.as_deref(),
        )
        .await;
        if supplier.company_name.is_some() {
            resolved.seller.name = supplier.company_name.clone();
        }
        if supplier.country.is_some() {
            resolved.seller.location = supplier.country.clone();
        }
        if let Some(year_str) = supplier.year_established.as_deref() {
            if let Ok(year) = year_str.trim().parse::<i32>() {
                if let Some(date) = chrono::NaiveDate::from_ymd_opt(year, 1, 1) {
                    resolved.seller.join_date = Some(date);
                }
            }
        }
        if let Some(name) = &supplier.contact_name {
            resolved.seller.handle = Some(name.replace('*', "").trim().to_string());
        }
        if let Some(phone) = &supplier.contact_phone {
            if !phone.contains('*') {
                resolved.seller.phone = Some(phone.clone());
            }
        }
        social_candidates = candidates_from_b2b;
        (signals, risk_score, notes)
    } else {
        let claude_analysis = run_claude_analysis(&listing, &resolved.seller).await?;
        if let Some(phone) = &claude_analysis.extracted_phone_number {
            resolved.seller.phone = Some(phone.clone());
            let _ = query("UPDATE sellers SET phone = $1, updated_at = NOW() WHERE id = $2")
                .bind(phone)
                .bind(resolved.seller.id)
                .execute(&pool)
                .await;
        }
        let signals = build_all_signals(&pool, &claude_analysis, &resolved.seller, &request).await;
        let risk_score = calculate_risk_score(&claude_analysis, resolved.fraud_count);
        let notes = claude_analysis.overall_risk_notes.clone();
        (signals, risk_score, notes)
    };

    let mut signals = signals;
    sort_signals_by_table(&mut signals);

    let risk_level = match risk_score {
        0..=33 => RiskLevel::Low,
        34..=66 => RiskLevel::Caution,
        _ => RiskLevel::High,
    };

    let data = BuildResponseData {
        pool: &pool,
        listing_id: listing.id,
        risk_score,
        risk_level,
        signals,
        overall_risk_notes,
        user_id,
        seller: resolved.seller,
        fraud_count: resolved.fraud_count,
        network_summary: resolved.network_summary,
        is_b2b,
        social_candidates,
    };

    save_and_build_response(data).await
}

pub async fn verify_social_link_handler(
    State(pool): State<Pool<Postgres>>,
    headers: HeaderMap,
    Json(body): Json<VerifySocialLinkRequest>,
) -> Result<Json<VerifySocialLinkResponse>, AnalyzeError> {
    let _user_id = authorize_request(&headers, &pool).await?;

    let seller = sqlx::query_as::<_, Sellers>("SELECT * FROM sellers WHERE id = $1")
        .bind(body.seller_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| AnalyzeError::Database(e.to_string()))?;

    let identifiers = SellerIdentifiers {
        name: seller.name.clone().or(seller.handle.clone()),
        phone: seller.phone.clone(),
        email: None,
        website: None,
        location: seller.location.clone(),
    };

    let result = verify_social_link(&body.url, &identifiers)
        .await
        .map_err(AnalyzeError::ClaudeAnalysisFailed)?;

    let has_scam_language = result
        .matched_identifiers
        .contains(&"scam_language".to_string());
    let has_profile_identifiers = result
        .matched_identifiers
        .iter()
        .any(|id| id == "name" || id == "location" || id == "phone");

    let message = match (has_profile_identifiers, has_scam_language) {
        (true, true) => "This page mentions the company and also contains scam-related language - review it carefully.".to_string(),
        (true, false) => "This appears to be a genuine profile or page for this company.".to_string(),
        (false, true) => "A complaint or scam-related mention was found, though the company's own identifying details weren't directly confirmed here.".to_string(),
        (false, false) => "No genuine match was found on this page.".to_string(),
    };

    Ok(Json(VerifySocialLinkResponse {
        matched: result.confidence != "none",
        matched_identifiers: result.matched_identifiers,
        confidence: result.confidence,
        message,
    }))
}
