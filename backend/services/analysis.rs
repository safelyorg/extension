use crate::{
    errors::analyze::AnalyzeError,
    models::{
        analysis::{Analysis, AnalyzeRequest, AnalyzeResponse, RiskLevel, Signal},
        helpers::format_account_age,
        listings::{Listings, ListingsRequest},
        sellers::{SellerVerification, Sellers, SellersRequest, SellersResponse},
    },
    services::{
        auth::extract_user_id,
        b2b_scrapers::{B2bListingProfile, B2bSupplierProfile, check_b2b_page},
        b2c_scrapers::check_store_page,
        claude::{
            CallB2bClaudeArguments, CallClaudeArguments, ClaudeAnalysis, call_b2b_claude,
            call_b2c_claude,
        },
        confidence::calculate_confidence,
        entity_detection::classify_entity,
        evidence::{record_evidence, record_risk_factors},
        fraud_reports::{build_network_summary, count_fraud_reports},
        listings::get_monthly_visit_activity,
        network_memory::build_network_memory_signal,
        osint::{PlatformCheckResult, build_social_presence_matrix},
        risk_factors::derive_risk_factors,
        sellers::{create_seller, find_seller},
        signals::{
            build_b2b_claude_signals, build_b2b_company_age_signal,
            build_b2b_listing_completeness_signal, build_b2b_transparency_signal,
            build_b2b_verification_signal, build_domain_signal, build_seller_verification_signals,
            build_signals, build_store_page_signal, build_whois_signal,
        },
        whois::check_domain_whois,
    },
};
use axum::{Json, http::HeaderMap};
use serde_json::{Value, to_value};
use sqlx::{Error, Pool, Postgres, query_as};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use uuid::Uuid;

// This stops any one person from calling the /analyze endpoint more than 10 times within any 5-minute stretch.
// It sets up a way to track how many times each logged-in user has called the expensive /analyze endpoint recently.
pub static RATE_LIMITS: OnceLock<Mutex<HashMap<Uuid, (u32, Instant)>>> = OnceLock::new();
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(300);
const RATE_LIMIT_MAX_REQUESTS: u32 = 10;

pub struct CreateAnalysisData<'a> {
    pub pool: &'a Pool<Postgres>,
    pub listing_id: Uuid,
    pub risk_score: i16,
    pub risk_level: RiskLevel,
    pub signals: Value,
    pub network_summary: String,
    pub claude_raw: String,
    pub user_id: Uuid,
    pub confidence_level: String,
    pub confidence_reasoning: String,
    pub risk_factors: Value,
}

pub struct ResolvedSeller {
    pub seller: Sellers,
    pub fraud_count: i64,
    pub network_summary: String,
}

pub struct BuildResponseData<'a> {
    pub pool: &'a Pool<Postgres>,
    pub listing_id: Uuid,
    pub risk_score: i16,
    pub risk_level: RiskLevel,
    pub signals: Vec<Signal>,
    pub overall_risk_notes: String,
    pub user_id: Uuid,
    pub seller: Sellers,
    pub fraud_count: i64,
    pub network_summary: String,
    pub is_b2b: bool,
    pub social_candidates: Vec<PlatformCheckResult>,
}

/// Confirms the caller is genuinely signed in, then checks they haven't
/// exceeded their request rate limit. Real analysis costs real Claude
/// API money per request, so this endpoint must actually reject an
/// anonymous or over-limit caller, not just proceed anyway.
///
/// It checks if this is a genuinely signed-in person, checks if they've
/// already hit their rate limit and if both checks passed, hand back their real user ID.
pub async fn authorize_request(
    headers: &HeaderMap,
    pool: &Pool<Postgres>,
) -> Result<Uuid, AnalyzeError> {
    let user_id = extract_user_id(headers, pool)
        .await
        .map_err(|_| AnalyzeError::Unauthorized)?
        .ok_or(AnalyzeError::Unauthorized)?;

    check_rate_limit(user_id)?;

    Ok(user_id)
}

/// Every time someone tries to use /analyze, this checks their notebook entry, lets them
/// through and counts it, unless they've already hit 10 within the last 5 minutes, in which
/// case it tells them exactly how many seconds until they can try again.
///
/// Gets the notebook (creating it, if this is the very first time), finds this person's
/// page in the notebook — or creates one, if they've never called before, checks
/// if their 5-minute window has already run out and counts the current request,
/// checks if they're still under the limit. If they've gone over and calculate
/// exactly how long they need to wait.
pub fn check_rate_limit(user_id: Uuid) -> Result<(), AnalyzeError> {
    let map = RATE_LIMITS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().expect("expected to lock the map");
    let now = Instant::now();
    let entry = map.entry(user_id).or_insert((0, now));

    if now.duration_since(entry.1) > RATE_LIMIT_WINDOW {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 += 1;

    if entry.0 <= RATE_LIMIT_MAX_REQUESTS {
        Ok(())
    } else {
        let elapsed = now.duration_since(entry.1);
        let remaining = RATE_LIMIT_WINDOW.saturating_sub(elapsed);
        Err(AnalyzeError::RateLimited(remaining.as_secs()))
    }
}

/// It takes the one big request that arrives from your extension, and splits it into two separate,
/// smaller pieces. One containing just the seller's information, and one containing just
/// the listing's information.
///
/// It builds the seller-specific piece, builds the listing-specific piece
/// and returns both pieces together, as a pair.
pub fn build_requests(r: &AnalyzeRequest) -> (SellersRequest, ListingsRequest) {
    let seller_request = SellersRequest {
        platform: r.platform.clone(),
        platform_id: r.platform_id.clone(),
        name: r.seller_name.clone(),
        handle: r.seller_handle.clone(),
        phone: r.seller_phone.clone(),
        profile_url: r.seller_profile_url.clone(),
        join_date: r.seller_join_date.clone(),
        location: r.seller_location.clone(),
        last_active: r.seller_last_active.clone(),
    };

    let listing_request = ListingsRequest {
        seller_id: r.seller_id,
        platform: r.platform.clone(),
        listing_url: r.listing_url.clone(),
        listing_id: r.listing_id.clone(),
        title: r.title.clone(),
        price: r.price,
        description: r.description.clone(),
        category: r.category.clone(),
        image_urls: r.image_urls.clone(),
        posted_date: r.posted_date.clone(),
    };

    (seller_request, listing_request)
}

/// Before writing anything to the database, first check if this seller already has fraud
/// reports against them so their very first database record is already correct, never briefly,
/// incorrectly saying 'Unknown' about someone who's already known to be a problem.
///
/// It checks if this seller already exists in the database. If they already exist,
/// checks how many fraud reports they have — before doing anything else, decides their
/// verification status, based on that count, creates (or updates) the seller row,
/// using that correctly-determined verification, counts their fraud reports again,
/// this time for the real, final result.
pub async fn resolve_seller(
    pool: &Pool<Postgres>,
    seller_req: &SellersRequest,
    platform: &str,
    platform_id: &str,
) -> Result<ResolvedSeller, AnalyzeError> {
    let existing_seller = find_seller(pool, platform, platform_id)
        .await
        .map_err(|e| AnalyzeError::Database(e.to_string()))?;

    let preliminary_fraud_count = if let Some(ref s) = existing_seller {
        count_fraud_reports(pool, s.id)
            .await
            .map_err(|e| AnalyzeError::Database(e.to_string()))?
    } else {
        0
    };

    let verification = if preliminary_fraud_count > 0 {
        SellerVerification::Reported
    } else {
        SellerVerification::Unknown
    };

    let seller = create_seller(pool, seller_req, verification)
        .await
        .map_err(|e| AnalyzeError::Database(e.to_string()))?;

    let fraud_count = count_fraud_reports(pool, seller.id)
        .await
        .map_err(|e| AnalyzeError::Database(e.to_string()))?;

    let network_summary = build_network_summary(fraud_count);

    Ok(ResolvedSeller {
        seller,
        fraud_count,
        network_summary,
    })
}

/// It sends the listing's real details to Claude, asking it to analyze
/// whether this looks like a genuine or fraudulent listing by filling in
/// sensible defaults for anything that's missing, so Claude always gets
/// something usable, even if the original listing had gaps.
///
/// It calculates the seller's account age, from their real join date, gets
/// the listing's images, or an empty list if there are none, actually calls
/// Claude, with everything it needs and it waits for Claude's response,
/// and handles failure clearly
pub async fn run_claude_analysis(
    listing: &Listings,
    seller: &Sellers,
) -> Result<ClaudeAnalysis, AnalyzeError> {
    let account_age = seller
        .join_date
        .map(format_account_age)
        .unwrap_or_else(|| "Unknown".to_string());

    let image_urls = listing.image_urls.as_deref().unwrap_or(&[]);

    call_b2c_claude(CallClaudeArguments {
        platform: &listing.platform,
        seller_name: seller.name.as_deref().unwrap_or("Unknown"),
        seller_account_age: &account_age,
        title: listing.title.as_deref().unwrap_or("Untitled"),
        price: listing.price.unwrap_or(0),
        description: listing.description.as_deref().unwrap_or("No Description"),
        image_urls,
    })
    .await
    .map_err(|e| AnalyzeError::ClaudeAnalysisFailed(e.to_string()))
}

/// It builds the complete list of warning signals shown on the dashboard
/// starting with everything Claude's analysis found, then adding a domain-mismatch
/// check at the very top, if one was detected.
///
/// It builds the main signal list from Claude's analysis, checks if a domain
/// mismatch was detected and returns the complete list.
pub async fn build_all_signals(
    pool: &Pool<Postgres>,
    claude_analysis: &ClaudeAnalysis,
    seller: &Sellers,
    request: &AnalyzeRequest,
) -> Vec<Signal> {
    let mut signals = build_signals(claude_analysis, seller);

    if let Some(domain_signal) = build_domain_signal(
        request.domain_check_status.as_deref(),
        request.domain_check_real_name.as_deref(),
        request.domain_check_real_domain.as_deref(),
        request.domain_check_current_domain.as_deref(),
        request.domain_check_current_html.as_deref(),
        request.domain_check_real_html.as_deref(),
    ) {
        signals.insert(0, domain_signal);
    }

    if let Some(memory_signal) = build_network_memory_signal(pool, seller.id).await {
        signals.push(memory_signal);
    }

    // Layer 3, Active collection - if the seller mentioned a real
    // website, check its genuine registration via WHOIS. Most
    // listings won't have one at all, so this only fires when Tier
    // 1's extraction actually found something real.
    if let Some(website) = request.seller_website.as_deref() {
        let whois_result = check_domain_whois(website).await;
        if let Some(whois_signal) = build_whois_signal(whois_result.as_ref()) {
            signals.push(whois_signal);
        }
    } else {
        signals.push(Signal {
            label: "Seller website check".to_string(),
            sub: "No website was mentioned or claimed by this seller.".to_string(),
            value: "No website found".to_string(),
            signal_type: "info".to_string(),
            category: "website".to_string(),
            check_type: "existence".to_string(),
        });
    }

    // Genuinely free, real trust data for OLX's verified-seller
    // accounts - member duration, listing count, real rating -
    // already present on the listing page for these sellers.
    signals.extend(build_seller_verification_signals(
        request.seller_verified.unwrap_or(false),
        request.seller_rating,
        request.seller_total_products,
    ));

    // Tier 2 - visits the seller's own, separate store/profile page,
    // confirming whether their real name genuinely appears there, and
    // checking for any self-referenced website mentioned on that page.
    if let Some(profile_url) = request.seller_profile_url.as_deref() {
        let seller_name = request.seller_name.as_deref().unwrap_or("");
        if let Some(store_result) =
            check_store_page(&request.platform, profile_url, seller_name).await
        {
            if let Some(store_signal) =
                build_store_page_signal(&store_result, request.seller_website.as_deref())
            {
                signals.push(store_signal);
            }
        }
    } else {
        signals.push(Signal {
            label: "Store page check".to_string(),
            sub: "No separate store or profile page was found for this seller.".to_string(),
            value: "No store page found".to_string(),
            signal_type: "info".to_string(),
            category: "identity".to_string(),
            check_type: "consistency".to_string(),
        });
    }

    signals
}

/// It saves the complete analysis result to the database, fetches the seller's
/// real visit-history chart, and packages everything together into the final
/// response the extension actually receives.
///
/// It converts the signals list into a format the database can store, actually
/// saves the analysis to the database, fetches the seller's real visit history,
/// for the chart, builds the seller portion of the response, assembles and returns
/// the complete, final response.
pub async fn save_and_build_response(
    data: BuildResponseData<'_>,
) -> Result<Json<AnalyzeResponse>, AnalyzeError> {
    let signals_json =
        to_value(&data.signals).map_err(|e| AnalyzeError::SerializationFailed(e.to_string()))?;

    let entity_type = if data.is_b2b {
        "business".to_string()
    } else {
        let website_fully_confirmed = data
            .signals
            .iter()
            .any(|s| s.label == "Store page check" && s.value == "Fully confirmed");
        classify_entity(data.seller.name.as_deref(), website_fully_confirmed)
    };
    let (confidence_level, confidence_reasoning) = calculate_confidence(&data.signals);

    // Layer 7 - translates this analysis's signals into named,
    // human-readable risk factor conclusions. Computed before saving,
    // so it can be stored directly on the analysis row itself -
    // otherwise,
    let risk_factors = derive_risk_factors(&data.signals);
    let risk_factors_json =
        to_value(&risk_factors).map_err(|e| AnalyzeError::SerializationFailed(e.to_string()))?;

    let saved_analysis = create_analysis(CreateAnalysisData {
        pool: data.pool,
        listing_id: data.listing_id,
        risk_score: data.risk_score,
        risk_level: data.risk_level,
        signals: signals_json,
        network_summary: data.overall_risk_notes.clone(),
        claude_raw: String::new(),
        user_id: data.user_id,
        confidence_level: confidence_level.clone(),
        confidence_reasoning: confidence_reasoning.clone(),
        risk_factors: risk_factors_json,
    })
    .await
    .map_err(|e| AnalyzeError::Database(e.to_string()))?;

    record_evidence(
        data.pool,
        saved_analysis.id,
        data.seller.id,
        &data.signals,
        data.risk_score,
    )
    .await;

    record_risk_factors(data.pool, saved_analysis.id, data.seller.id, &risk_factors).await;

    let monthly_activity = get_monthly_visit_activity(data.pool, data.seller.id)
        .await
        .unwrap_or_else(|_| vec![0i32; 12]);

    let mut seller_response = SellersResponse::from(data.seller);
    seller_response.network_summary = data.network_summary;
    seller_response.monthly_activity = monthly_activity;

    Ok(Json(AnalyzeResponse {
        analysis_id: saved_analysis.id,
        risk_score: saved_analysis.risk_score,
        risk_level: saved_analysis.risk_level,
        seller: seller_response,
        signals: data.signals,
        network_summary: data.overall_risk_notes,
        fraud_report_count: data.fraud_count,
        entity_type,
        confidence_level,
        confidence_reasoning,
        risk_factors,
        social_candidates: data.social_candidates,
    }))
}

// This only ever fails for one genuine reason - a real database
// problem (e.g. a bad foreign key on listing_id/user_id) - so plain
// sqlx::Error is honest here; a custom error type isn't needed.
pub async fn create_analysis(data: CreateAnalysisData<'_>) -> Result<Analysis, Error> {
    let id = Uuid::now_v7();
    let analysis = query_as::<_, Analysis>(
        "
        INSERT INTO analysis (
            id,
            listing_id,
            risk_score,
            risk_level,
            signals,
            network_summary,
            claude_raw,
            user_id,
            confidence_level,
            confidence_reasoning,
            risk_factors,
            created_at
        )
        VALUES (
            $1,  $2,  $3,  $4,   $5,
            $6,  $7,  $8,  $9,   $10, $11, NOW()
        )
        RETURNING *
        ",
    )
    .bind(id)
    .bind(&data.listing_id)
    .bind(&data.risk_score)
    .bind(&data.risk_level)
    .bind(&data.signals)
    .bind(&data.network_summary)
    .bind(&data.claude_raw)
    .bind(&data.user_id)
    .bind(&data.confidence_level)
    .bind(&data.confidence_reasoning)
    .bind(&data.risk_factors)
    .fetch_one(data.pool)
    .await?;

    Ok(analysis)
}

/// The complete, separate B2B analysis path - fetches the real
/// supplier page, calls Claude with B2B-specific due-diligence
/// questions, and builds an entirely separate set of signals. This
/// never touches build_signals or ClaudeAnalysis at all, since B2B
/// due diligence asks fundamentally different questions than
/// consumer-marketplace fraud detection.
pub async fn build_b2b_analysis_path(
    pool: &Pool<Postgres>,
    request: &AnalyzeRequest,
    fraud_count: i64,
    seller_id: Uuid,
) -> Result<
    (
        Vec<Signal>,
        i16,
        String,
        B2bSupplierProfile,
        B2bListingProfile,
        Vec<PlatformCheckResult>,
    ),
    AnalyzeError,
> {
    let mut signals = Vec::new();

    if let Some(memory_signal) = build_network_memory_signal(pool, seller_id).await {
        signals.push(memory_signal);
    }

    if let Some(domain_signal) = build_domain_signal(
        request.domain_check_status.as_deref(),
        request.domain_check_real_name.as_deref(),
        request.domain_check_real_domain.as_deref(),
        request.domain_check_current_domain.as_deref(),
        request.domain_check_current_html.as_deref(),
        request.domain_check_real_html.as_deref(),
    ) {
        signals.push(domain_signal);
    }

    signals.push(Signal {
        label: "Seller website check".to_string(),
        sub: "No website was found for this supplier on this platform.".to_string(),
        value: "No website found".to_string(),
        signal_type: "info".to_string(),
        category: "website".to_string(),
        check_type: "existence".to_string(),
    });

    let (supplier, listing) = check_b2b_page(&request.platform, &request.listing_url)
        .await
        .ok_or_else(|| {
            AnalyzeError::ClaudeAnalysisFailed("Could not fetch B2B supplier page".to_string())
        })?;

    let claude_result = call_b2b_claude(CallB2bClaudeArguments {
        platform: &request.platform,
        company_name: supplier.company_name.as_deref().unwrap_or("Unknown"),
        year_established: supplier.year_established.as_deref().unwrap_or("Unknown"),
        platform_verified: supplier.platform_verified_badge,
        employee_count: supplier.employee_count.as_deref().unwrap_or("Unknown"),
        product_title: listing.title.as_deref().unwrap_or("Unknown"),
        product_description: listing.description.as_deref().unwrap_or("None provided"),
        image_urls: &listing.image_urls,
    })
    .await
    .map_err(|e| AnalyzeError::ClaudeAnalysisFailed(e.to_string()))?;

    signals.extend(build_b2b_claude_signals(&claude_result));
    signals.push(build_b2b_verification_signal(&supplier));
    signals.push(build_b2b_company_age_signal(&supplier));
    signals.push(build_b2b_transparency_signal(&supplier));
    signals.push(build_b2b_listing_completeness_signal(&listing));
    let (social_presence_signal, social_candidates) = build_social_presence_matrix(
        supplier.company_name.as_deref(),
        supplier.contact_name.as_deref(),
        supplier.country.as_deref(),
        supplier.contact_phone.as_deref(),
    )
    .await;
    signals.push(social_presence_signal);

    let caution_count = signals
        .iter()
        .filter(|s| s.signal_type == "caution")
        .count();
    let risk_score = ((caution_count as i16) * 15).min(100) + (fraud_count as i16 * 5).min(20);

    let overall_risk_notes = claude_result.overall_risk_notes.clone();
    Ok((
        signals,
        risk_score.min(100),
        overall_risk_notes,
        supplier,
        listing,
        social_candidates,
    ))
}
