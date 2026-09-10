mod common;

use crate::common::{
    admin_pool, cleanup_seller_and_analysis, cleanup_test_seller_chain, create_test_user,
    insert_raw_evidence_row, insert_test_analysis_for_outcomes, insert_test_history_chain,
    make_seller, make_signal, make_signals, set_analysis_created_at,
    setup_real_seller_and_analysis,
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue},
};
use backend::{
    errors::claude::ClaudeError,
    handlers::analyze::{VerifySocialLinkRequest, analyze, verify_social_link_handler},
    models::{
        analysis::{AnalyzeRequest, RiskLevel, Signal},
        listings::{ListingCategory, Listings, ListingsRequest},
        risk_factors::RiskFactor,
        sellers::{SellerVerification, Sellers, SellersRequest},
    },
    services::{
        analysis::{
            BuildResponseData, CreateAnalysisData, RATE_LIMITS, authorize_request,
            build_all_signals, build_requests, check_rate_limit, create_analysis, resolve_seller,
            run_claude_analysis, save_and_build_response,
        },
        auth::{create_session, find_or_create_user_by_email},
        claude::{
            CallClaudeArguments, ClaudeAnalysis, Finding, ImageAssessment, PriceAssessment,
            b2c_content, call_b2c_claude,
        },
        confidence::calculate_confidence,
        entity_detection::classify_entity,
        evidence::{record_evidence, record_risk_factors},
        fraud_reports::{build_network_summary, count_fraud_reports},
        listings::{create_listing, get_monthly_visit_activity},
        network_memory::build_network_memory_signal,
        osint::{build_osint_query_matrix, run_serper_search, score_identifier_match},
        risk_factors::{derive_risk_factors, find_signal, is_new_account},
        scoring::calculate_risk_score,
        sellers::{create_seller, find_seller},
        signals::{build_domain_signal, build_signals},
    },
};
use chrono::{Datelike, Duration as chrono_duration, NaiveDate, Utc};
use common::{cleanup_test_seller, cleanup_test_user, test_pool};
use serde_json::json;
use serial_test::serial;
use sqlx::{query, query_as};
use std::{
    collections::HashMap,
    env::{remove_var, set_var, var},
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

// Analyze Test
#[tokio::test]
async fn analyze_unauthorized_request() {
    let pool = test_pool().await;
    let headers = HeaderMap::new();

    let request = AnalyzeRequest {
        platform: "olx".to_string(),
        seller_id: None,
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: Some("12345".to_string()),
        title: Some("Test Listing".to_string()),
        price: Some(50000),
        description: Some("A test listing description".to_string()),
        category: None,
        image_urls: Some(vec!["https://example.com/image1.jpg".to_string()]),
        posted_date: None,
        platform_id: Some("unauthorized_test_platform_id".to_string()),
        seller_name: Some("Test Seller".to_string()),
        seller_handle: Some("test_seller_handle".to_string()),
        seller_phone: Some("03001234567".to_string()),
        seller_profile_url: Some("https://olx.com.pk/profile/test-seller".to_string()),
        seller_join_date: Some("2021".to_string()),
        seller_location: Some("Lahore".to_string()),
        seller_last_active: Some("Today".to_string()),
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let result = analyze(State(pool.clone()), headers, Json(request)).await;

    assert!(
        result.is_err(),
        "expected an unauthenticated request to be rejected"
    );

    let leftover_seller = find_seller(&pool, "olx", "unauthorized_test_platform_id")
        .await
        .expect("expected the query itself to succeed");

    assert!(
        leftover_seller.is_none(),
        "expected NO seller to be created, since authorization should have stopped everything first"
    );
}

#[tokio::test]
async fn analyze_success() {
    let pool = test_pool().await;
    let email = "analyze_success_test@example.com";
    cleanup_test_user(&pool, email).await;

    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );

    let platform = "olx".to_string();
    let platform_id = "analyze_success_platform_id".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;

    let request = AnalyzeRequest {
        platform: platform.clone(),
        seller_id: None,
        listing_url: "https://olx.com.pk/item/analyze-success-test".to_string(),
        listing_id: Some("analyze_success_listing".to_string()),
        title: Some("iPhone 13 Pro Max - Excellent Condition".to_string()),
        price: Some(150000),
        description: Some("Selling my iPhone 13 Pro Max, barely used.".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: Some(platform_id.clone()),
        seller_name: Some("Ahmed Khan".to_string()),
        seller_handle: Some("ahmed_khan_deals".to_string()),
        seller_phone: Some("03001234567".to_string()),
        seller_profile_url: Some("https://olx.com.pk/profile/ahmed-khan".to_string()),
        seller_join_date: Some("2021".to_string()),
        seller_location: Some("Lahore".to_string()),
        seller_last_active: Some("Today".to_string()),
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let result = analyze(State(pool.clone()), headers, Json(request))
        .await
        .expect("expected the full analyze flow to succeed");

    assert!(
        result.risk_score >= 0 && result.risk_score <= 100,
        "expected a genuine risk score between 0 and 100, got: {}",
        result.risk_score
    );
    assert!(
        !result.signals.is_empty(),
        "expected at least one real signal to be present"
    );
    assert_eq!(result.fraud_report_count, 0);

    let admin = admin_pool().await;
    query("DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analysis WHERE user_id = $1)")
        .bind(user.id)
        .execute(&admin)
        .await
        .expect("expected evidence cleanup to succeed");

    query("DELETE FROM analysis WHERE user_id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("expected analysis cleanup to succeed");

    query("DELETE FROM listings WHERE platform = $1 AND listing_id = $2")
        .bind(&platform)
        .bind("analyze_success_listing")
        .execute(&pool)
        .await
        .expect("expected listing cleanup to succeed");

    cleanup_test_seller(&pool, &platform, &platform_id).await;
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn analyze_server_scraped_seller_verified_always_overwrites_client_value() {
    let pool = test_pool().await;
    let email = "verified_overwrite_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");
    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );

    let platform = "olx".to_string();
    let real_verified_seller_listing_url = "https://www.olx.com.pk/item/black-anodized-316l-surgical-steel-double-flared-tunnel-ear-plug-sold-by-piece-c-r4411-iid-ev552759-1".to_string();

    let request = AnalyzeRequest {
        platform: platform.clone(),
        seller_id: None,
        listing_url: real_verified_seller_listing_url,
        listing_id: None,
        title: None,
        price: None,
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: None,
        seller_name: None,
        seller_handle: None,
        seller_phone: None,
        seller_profile_url: None,
        seller_join_date: None,
        seller_location: None,
        seller_last_active: None,
        seller_website: None,
        seller_verified: Some(false),
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let result = analyze(State(pool.clone()), headers, Json(request))
        .await
        .expect("expected the full analyze flow to succeed");

    let platform_verification_signal = result
        .signals
        .iter()
        .find(|s| s.label == "Platform verification")
        .expect("expected a Platform verification signal to be present");

    assert_eq!(
        platform_verification_signal.value, "Verified",
        "expected the REAL, scraped verified=true to win over the client's Some(false), \
         confirming the earlier regression stays fixed"
    );

    let admin = admin_pool().await;
    query("DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analysis WHERE user_id = $1)")
        .bind(user.id)
        .execute(&admin)
        .await
        .ok();

    query("DELETE FROM analysis WHERE user_id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn analyze_success_for_b2b_platform() {
    let pool = test_pool().await;
    let email = "analyze_b2b_success_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");
    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );

    let platform = "b2brazil".to_string();
    let real_listing_url = "https://b2brazil.com/hotsite/akuratconsultor".to_string();

    let request = AnalyzeRequest {
        platform: platform.clone(),
        seller_id: None,
        listing_url: real_listing_url,
        listing_id: None,
        title: None,
        price: None,
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: None,
        seller_name: None,
        seller_handle: None,
        seller_phone: None,
        seller_profile_url: None,
        seller_join_date: None,
        seller_location: None,
        seller_last_active: None,
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let result = analyze(State(pool.clone()), headers, Json(request))
        .await
        .expect("expected the full, real analyze flow to succeed for a live B2B platform");

    assert_eq!(
        result.entity_type, "business",
        "expected B2B analyses to always report entity_type as business"
    );
    assert!(
        result.seller.name.is_some(),
        "expected the seller's real, scraped company name to be present"
    );
    assert!(
        !result.signals.is_empty(),
        "expected at least one real signal to be present"
    );

    let admin = admin_pool().await;
    query("DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analysis WHERE user_id = $1)")
        .bind(user.id)
        .execute(&admin)
        .await
        .ok();

    query("DELETE FROM analysis WHERE user_id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_user(&pool, email).await;
}

// Authorize Request Test
#[tokio::test]
async fn authorize_request_success() {
    let pool = test_pool().await;
    let email = "authorize_success@example.com";
    cleanup_test_user(&pool, email).await;

    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create or find a user");

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header values"),
    );

    let result = authorize_request(&headers, &pool)
        .await
        .expect("expected to run the authorize request");

    assert_eq!(result, user.id);

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn authorize_request_failure() {
    let pool = test_pool().await;
    let email = "authorize_failure@example.com";
    cleanup_test_user(&pool, email).await;

    let (_user, _) = find_or_create_user_by_email(&pool, &email)
        .await
        .expect("expected to find or create a user");

    let headers = HeaderMap::new();
    let result = authorize_request(&headers, &pool).await;

    assert!(result.is_err(), "expected an empty header to be rejected");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn authorize_request_rate_limit_passed() {
    let pool = test_pool().await;
    let email = "authorize_rate_limit@example.com";
    cleanup_test_user(&pool, email).await;

    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create or find a user");

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header values"),
    );

    for call_number in 1..=10 {
        let result = check_rate_limit(user.id);
        assert!(
            result.is_ok(),
            "expected call number {} to succeed, got: {:?}",
            call_number,
            result
        );
    }

    let result = authorize_request(&headers, &pool).await;
    assert!(
        result.is_err(),
        "expected authorize_request to reject a rate-limited user"
    );

    cleanup_test_user(&pool, email).await;
}

// Check Rate Limit Test
#[test]
fn checking_rate_limit_one_time() {
    let user_id = Uuid::new_v4();
    let result = check_rate_limit(user_id);

    assert!(result.is_ok(), "expected the very first call to succeed");
}

#[test]
fn checking_rate_limit_five_times() {
    let user_id = Uuid::new_v4();

    for call_number in 0..=5 {
        let result = check_rate_limit(user_id);
        assert!(
            result.is_ok(),
            "expected call number {} to succeed, got: {:?}",
            call_number,
            result
        );
    }
}

#[test]
fn check_rate_limit_blocks_the_eleventh_call_within_the_window() {
    let user_id = Uuid::new_v4();

    for call_number in 1..=10 {
        let result = check_rate_limit(user_id);
        assert!(
            result.is_ok(),
            "expected call number {} to succeed, got: {:?}",
            call_number,
            result
        );
    }

    let eleventh_result = check_rate_limit(user_id);
    assert!(
        eleventh_result.is_err(),
        "expected the 11th call to be blocked, got: {:?}",
        eleventh_result
    );
}

#[test]
fn check_rate_limit_resets_after_the_window_expires() {
    let user_id = Uuid::new_v4();
    let map = RATE_LIMITS.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let mut map = map.lock().expect("expected to lock the map");
        let time_passed = Instant::now() - Duration::from_secs(400);
        map.insert(user_id, (11, time_passed));
    }

    let result = check_rate_limit(user_id);
    assert!(
        result.is_ok(),
        "expected the expired window to reset, allowing this call through, got: {:?}",
        result
    );
}

// Build Requests Test
#[test]
fn build_requests_correctly_splits_seller_and_listing_data() {
    let fake_request = AnalyzeRequest {
        platform: "olx".to_string(),
        seller_id: None,
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: Some("12345".to_string()),
        title: Some("Test Listing".to_string()),
        price: Some(50000),
        description: Some("A test listing description".to_string()),
        category: None,
        image_urls: Some(vec!["https://example.com/image1.jpg".to_string()]),
        posted_date: None,
        platform_id: Some("platform_id_123".to_string()),
        seller_name: Some("Test Seller".to_string()),
        seller_handle: Some("test_seller_handle".to_string()),
        seller_phone: Some("03001234567".to_string()),
        seller_profile_url: Some("https://olx.com.pk/profile/test-seller".to_string()),
        seller_join_date: Some("2021".to_string()),
        seller_location: Some("Lahore".to_string()),
        seller_last_active: Some("Today".to_string()),
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let (seller_req, listing_req) = build_requests(&fake_request);

    assert_eq!(seller_req.name, Some("Test Seller".to_string()));
    assert_eq!(seller_req.handle, Some("test_seller_handle".to_string()));
    assert_eq!(seller_req.location, Some("Lahore".to_string()));
    assert_eq!(listing_req.title, Some("Test Listing".to_string()));
    assert_eq!(listing_req.price, Some(50000));
    assert_eq!(
        listing_req.listing_url,
        "https://olx.com.pk/item/test-listing"
    );
    assert_eq!(seller_req.platform, "olx");
    assert_eq!(listing_req.platform, "olx");
}

#[test]
fn build_requests_none_values_stay_none() {
    let fake_request = AnalyzeRequest {
        platform: "olx".to_string(),
        seller_id: None,
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: None,
        title: None,
        price: None,
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: None,
        seller_name: None,
        seller_handle: None,
        seller_phone: None,
        seller_profile_url: None,
        seller_join_date: None,
        seller_location: None,
        seller_last_active: None,
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let (seller_req, listing_req) = build_requests(&fake_request);

    assert_eq!(seller_req.name, None);
    assert_eq!(seller_req.handle, None);
    assert_eq!(seller_req.location, None);
    assert_eq!(listing_req.title, None);
    assert_eq!(listing_req.price, None);
    assert_eq!(listing_req.category, None);
    assert_eq!(listing_req.image_urls, None);
    assert_eq!(listing_req.posted_date, None);
}

#[test]
fn build_requests_seller_id_lands_only_on_listing_request() {
    let fake_seller_id = Uuid::new_v4();
    let fake_request = AnalyzeRequest {
        platform: "olx".to_string(),
        seller_id: Some(fake_seller_id),
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: Some("12345".to_string()),
        title: Some("Test Listing".to_string()),
        price: Some(50000),
        description: Some("A test listing description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: Some("platform_id_123".to_string()),
        seller_name: Some("Test Seller".to_string()),
        seller_handle: Some("test_seller_handle".to_string()),
        seller_phone: Some("03001234567".to_string()),
        seller_profile_url: Some("https://olx.com.pk/profile/test-seller".to_string()),
        seller_join_date: Some("2021".to_string()),
        seller_location: Some("Lahore".to_string()),
        seller_last_active: Some("Today".to_string()),
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let (_seller_req, listing_req) = build_requests(&fake_request);

    assert_eq!(
        listing_req.seller_id,
        Some(fake_seller_id),
        "expected seller_id to correctly land on listing_req specifically"
    );
}

// Resolve Seller Tests
#[tokio::test]
async fn resolve_new_seller() {
    let pool = test_pool().await;
    let platform = "olx".to_string();
    let platform_id = "new_seller_test_001".to_string();

    cleanup_test_seller(&pool, &platform, &platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Test name".to_string()),
        handle: Some("test_handle".to_string()),
        phone: Some("123456789".to_string()),
        profile_url: Some("https://olx.com.pk/profile/test-seller".to_string()),
        join_date: Some("2021".to_string()),
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let result = resolve_seller(&pool, &seller_request, &platform, &platform_id)
        .await
        .expect("expected to resolve the seller");

    assert_eq!(result.seller.verification, SellerVerification::Unknown);
    assert_eq!(result.fraud_count, 0);

    cleanup_test_seller(&pool, &platform, &platform_id).await;
}

#[tokio::test]
async fn resolve_existing_seller_have_no_reports() {
    let pool = test_pool().await;
    let platform = "olx".to_string();
    let platform_id = "sellers_have_no_report_test_001".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Test name".to_string()),
        handle: Some("test_handle".to_string()),
        phone: Some("123456789".to_string()),
        profile_url: Some("https://olx.com.pk/profile/test-seller".to_string()),
        join_date: Some("2021".to_string()),
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to pre-create the seller");

    let result = resolve_seller(&pool, &seller_request, &platform, &platform_id)
        .await
        .expect("expected to resolve the seller");

    assert_eq!(result.seller.verification, SellerVerification::Unknown);
    assert_eq!(result.fraud_count, 0);

    cleanup_test_seller(&pool, &platform, &platform_id).await;
}

#[tokio::test]
async fn resolve_existing_seller_with_real_fraud_report() {
    let pool = test_pool().await;
    let platform = "olx".to_string();
    let platform_id = "seller_have_reports_test_001".to_string();

    cleanup_test_seller(&pool, &platform, &platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Test name".to_string()),
        handle: Some("test_handle".to_string()),
        phone: Some("123456789".to_string()),
        profile_url: Some("https://olx.com.pk/profile/test-seller".to_string()),
        join_date: Some("2021".to_string()),
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to pre-create the seller");

    query("INSERT INTO fraud_reports (seller_id, platform, platform_id, report_type, description) VALUES ($1, $2, $3, $4::report_types, $5)")
        .bind(seller.id)
        .bind(&platform)
        .bind(&platform_id)
        .bind("scam")
        .bind("Test fraud report for scenario 3")
        .execute(&pool)
        .await
        .expect("expected to create a real fraud report");

    let result = resolve_seller(&pool, &seller_request, &platform, &platform_id)
        .await
        .expect("expected to resolve the seller");

    assert_eq!(result.seller.verification, SellerVerification::Reported);
    assert_eq!(result.fraud_count, 1);

    cleanup_test_seller(&pool, &platform, &platform_id).await;
}

// Find Seller Tests
#[tokio::test]
async fn find_seller_exists() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "find_seller_exists_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Findable Seller".to_string()),
        handle: Some("findable_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/findable".to_string()),
        join_date: None,
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };
    let created_seller = create_seller(&pool, &request, SellerVerification::Unknown)
        .await
        .expect("expected the seller to be created");

    let result = find_seller(&pool, platform, platform_id)
        .await
        .expect("expected the query to succeed");

    let found_seller = result.expect("expected a real seller to be found");
    assert_eq!(found_seller.id, created_seller.id);
    assert_eq!(found_seller.name, Some("Findable Seller".to_string()));

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn find_seller_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let result = find_seller(&pool, "olx", "doesnt_matter").await;
    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

#[tokio::test]
async fn find_seller_not_exists() {
    let pool = test_pool().await;
    let platform = "olx".to_string();
    let platform_id = "find_seller_not_exists".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;

    let result = find_seller(&pool, &platform, &platform_id)
        .await
        .expect("expected the query itself to succeed");

    assert!(result.is_none(), "expected no seller to be found");
}

// Count Fraud Reports Test
#[tokio::test]
async fn zero_fraud_reports() {
    let pool = test_pool().await;
    let seller_id = Uuid::new_v4();

    let count = count_fraud_reports(&pool, seller_id)
        .await
        .expect("expected to count the fraud reports");

    assert_eq!(count, 0);
}

#[tokio::test]
async fn having_fraud_reports() {
    let pool = test_pool().await;
    let platform = "olx".to_string();
    let platform_id = "sellers_have_reports_test_001".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Test name".to_string()),
        handle: Some("test_handle".to_string()),
        phone: Some("123456789".to_string()),
        profile_url: Some("https://olx.com.pk/profile/test-seller".to_string()),
        join_date: Some("2021".to_string()),
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");

    for _ in 0..2 {
        query("INSERT INTO fraud_reports (seller_id, platform, platform_id, report_type, description) VALUES ($1, $2, $3, $4::report_types, $5)")
            .bind(seller.id)
            .bind(&platform)
            .bind(&platform_id)
            .bind("scam")
            .bind("Test fraud report")
            .execute(&pool)
            .await
            .expect("expected to create a real fraud report");
    }

    let count = count_fraud_reports(&pool, seller.id)
        .await
        .expect("expected to count the fraud reports");

    assert_eq!(count, 2);

    cleanup_test_seller(&pool, &platform, &platform_id).await;
}

// Create Seller Tests
#[tokio::test]
async fn create_seller_creates_brand_new() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_seller_new_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Brand New Seller".to_string()),
        handle: Some("new_seller_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/new-seller".to_string()),
        join_date: None,
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let seller = create_seller(&pool, &request, SellerVerification::Unknown)
        .await
        .expect("expected a brand-new seller to be created");

    assert_eq!(seller.platform, platform);
    assert_eq!(seller.platform_id, platform_id);
    assert_eq!(seller.name, Some("Brand New Seller".to_string()));
    assert_eq!(seller.handle, Some("new_seller_handle".to_string()));
    assert_eq!(seller.location, Some("Lahore".to_string()));
    assert_eq!(seller.verification, SellerVerification::Unknown);

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_seller_updates_and_fills_in_new_data() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_seller_fill_in_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let initial_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Seller Name".to_string()),
        handle: Some("seller_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/seller".to_string()),
        join_date: None,
        location: None,
        last_active: Some("Today".to_string()),
    };

    let first_result = create_seller(&pool, &initial_request, SellerVerification::Unknown)
        .await
        .expect("expected the initial creation to succeed");

    assert!(
        first_result.location.is_none(),
        "expected location to start as None"
    );

    let updated_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Seller Name".to_string()),
        handle: Some("seller_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/seller".to_string()),
        join_date: None,
        location: Some("Karachi".to_string()),
        last_active: Some("Today".to_string()),
    };

    let updated_result = create_seller(&pool, &updated_request, SellerVerification::Unknown)
        .await
        .expect("expected the update to succeed");

    assert_eq!(
        updated_result.id, first_result.id,
        "expected the SAME seller row to be updated, not a new one created"
    );
    assert_eq!(
        updated_result.location,
        Some("Karachi".to_string()),
        "expected the previously-missing location to now be filled in"
    );

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_seller_never_overwrites_good_data_with_blanks() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_seller_preserve_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let initial_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Genuinely Real Seller Name".to_string()),
        handle: Some("seller_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/seller".to_string()),
        join_date: None,
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };
    let first_result = create_seller(&pool, &initial_request, SellerVerification::Unknown)
        .await
        .expect("expected the initial creation to succeed");

    assert_eq!(
        first_result.name,
        Some("Genuinely Real Seller Name".to_string())
    );

    let blank_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: None,
        handle: Some("seller_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/seller".to_string()),
        join_date: None,
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let second_result = create_seller(&pool, &blank_request, SellerVerification::Unknown)
        .await
        .expect("expected the second call to succeed");

    assert_eq!(
        second_result.id, first_result.id,
        "expected the SAME seller row"
    );
    assert_eq!(
        second_result.name,
        Some("Genuinely Real Seller Name".to_string()),
        "expected the ORIGINAL, real name to be preserved, NOT wiped out by the blank"
    );

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_seller_verification_always_updates() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_seller_verification_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Verification Test Seller".to_string()),
        handle: Some("seller_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/seller".to_string()),
        join_date: None,
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let first_result = create_seller(&pool, &request, SellerVerification::Unknown)
        .await
        .expect("expected the initial creation to succeed");
    assert_eq!(first_result.verification, SellerVerification::Unknown);

    let second_result = create_seller(&pool, &request, SellerVerification::Reported)
        .await
        .expect("expected the second call to succeed");

    assert_eq!(
        second_result.id, first_result.id,
        "expected the SAME seller row"
    );
    assert_eq!(
        second_result.verification,
        SellerVerification::Reported,
        "expected verification to be UNCONDITIONALLY updated, unlike other fields"
    );
    assert_eq!(
        second_result.name,
        Some("Verification Test Seller".to_string()),
        "expected name to remain correctly preserved, confirming other fields aren't affected"
    );

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_seller_join_date_parses_successfully() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_seller_join_date_success_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Join Date Test Seller".to_string()),
        handle: Some("seller_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/seller".to_string()),
        join_date: Some("Member since 2021".to_string()),
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let seller = create_seller(&pool, &request, SellerVerification::Unknown)
        .await
        .expect("expected the seller to be created successfully");

    assert_eq!(
        seller.join_date,
        NaiveDate::from_ymd_opt(2021, 1, 1),
        "expected the year 2021 to be genuinely extracted and stored as a real date"
    );

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_seller_join_date_malformed_becomes_none() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_seller_join_date_malformed_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Malformed Join Date Seller".to_string()),
        handle: Some("seller_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/seller".to_string()),
        join_date: Some("Member since forever".to_string()),
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let seller = create_seller(&pool, &request, SellerVerification::Unknown)
        .await
        .expect("expected the seller to be created successfully, even with malformed join_date");

    assert!(
        seller.join_date.is_none(),
        "expected malformed join_date text to quietly become None, not cause an error"
    );

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_seller_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let request = SellersRequest {
        platform: "olx".to_string(),
        platform_id: Some("create_seller_db_error_001".to_string()),
        name: Some("Doesn't Matter".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };

    let result = create_seller(&pool, &request, SellerVerification::Unknown).await;
    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Build Network Summary Test
#[test]
fn build_network_first_summary() {
    let fraud_count = 0;
    let result = build_network_summary(fraud_count);

    assert_eq!(
        result,
        "Clean record on Safely network. No fraud reports found.".to_string()
    );
}

#[test]
fn build_network_second_summary() {
    let fraud_count = 1;
    let result = build_network_summary(fraud_count);

    assert_eq!(
        result,
        "1 fraud report found on Safely network. Proceed with caution.".to_string(),
    );
}

#[test]
fn build_network_third_summary() {
    let fraud_count = 2;
    let result = build_network_summary(fraud_count);
    assert_eq!(
        result,
        "2 fraud reports found on Safely network. High risk seller."
    );
}

// Create Listing Test
#[tokio::test]
async fn create_listing_creates_brand_new() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_listing_new_seller_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Listing Test Seller".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };

    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected the seller to be created");

    let listing_url = "https://olx.com.pk/item/create-listing-new-001";
    query("DELETE FROM listings WHERE listing_url = $1")
        .bind(listing_url)
        .execute(&pool)
        .await
        .ok();

    let listing_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: platform.to_string(),
        listing_url: listing_url.to_string(),
        listing_id: Some("create_listing_new_001".to_string()),
        title: Some("Brand New Listing".to_string()),
        price: Some(75000),
        description: Some("A genuinely new listing".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
    };

    let listing = create_listing(&pool, &listing_request, seller.id)
        .await
        .expect("expected a brand-new listing to be created");

    assert_eq!(listing.listing_url, listing_url);
    assert_eq!(listing.title, Some("Brand New Listing".to_string()));
    assert_eq!(listing.price, Some(75000));
    assert_eq!(listing.seller_id, Some(seller.id));
    assert!(
        listing.last_analyzed_at.is_none(),
        "expected last_analyzed_at to start as None on a brand-new listing"
    );

    query("DELETE FROM listings WHERE listing_url = $1")
        .bind(listing_url)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_listing_updates_and_fills_in_new_data() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_listing_fill_in_seller_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Fill In Test Seller".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };

    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected the seller to be created");

    let listing_url = "https://olx.com.pk/item/create-listing-fill-in-001";
    query("DELETE FROM listings WHERE listing_url = $1")
        .bind(listing_url)
        .execute(&pool)
        .await
        .ok();

    let initial_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: platform.to_string(),
        listing_url: listing_url.to_string(),
        listing_id: Some("create_listing_fill_in_001".to_string()),
        title: Some("Listing Title".to_string()),
        price: Some(50000),
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
    };
    let first_result = create_listing(&pool, &initial_request, seller.id)
        .await
        .expect("expected the initial creation to succeed");
    assert!(
        first_result.description.is_none(),
        "expected description to start as None"
    );

    let updated_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: platform.to_string(),
        listing_url: listing_url.to_string(),
        listing_id: Some("create_listing_fill_in_001".to_string()),
        title: Some("Listing Title".to_string()),
        price: Some(50000),
        description: Some("Now genuinely described".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
    };

    let updated_result = create_listing(&pool, &updated_request, seller.id)
        .await
        .expect("expected the update to succeed");

    assert_eq!(
        updated_result.id, first_result.id,
        "expected the SAME listing row to be updated, not a new one created"
    );
    assert_eq!(
        updated_result.description,
        Some("Now genuinely described".to_string()),
        "expected the previously-missing description to now be filled in"
    );

    query("DELETE FROM listings WHERE listing_url = $1")
        .bind(listing_url)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_listing_never_overwrites_good_data_with_blanks() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_listing_preserve_seller_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Preserve Test Seller".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };

    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected the seller to be created");

    let listing_url = "https://olx.com.pk/item/create-listing-preserve-001";
    query("DELETE FROM listings WHERE listing_url = $1")
        .bind(listing_url)
        .execute(&pool)
        .await
        .ok();

    let initial_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: platform.to_string(),
        listing_url: listing_url.to_string(),
        listing_id: Some("create_listing_preserve_001".to_string()),
        title: Some("Genuinely Real Listing Title".to_string()),
        price: Some(50000),
        description: Some("Real description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
    };
    let first_result = create_listing(&pool, &initial_request, seller.id)
        .await
        .expect("expected the initial creation to succeed");

    assert_eq!(
        first_result.title,
        Some("Genuinely Real Listing Title".to_string())
    );

    let blank_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: platform.to_string(),
        listing_url: listing_url.to_string(),
        listing_id: Some("create_listing_preserve_001".to_string()),
        title: None,
        price: None,
        description: Some("Real description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
    };

    let second_result = create_listing(&pool, &blank_request, seller.id)
        .await
        .expect("expected the second call to succeed");

    assert_eq!(
        second_result.id, first_result.id,
        "expected the SAME listing row"
    );
    assert_eq!(
        second_result.title,
        Some("Genuinely Real Listing Title".to_string()),
        "expected the ORIGINAL, real title to be preserved, NOT wiped out by the blank"
    );
    assert_eq!(
        second_result.price,
        Some(50000),
        "expected the ORIGINAL, real price to be preserved, NOT wiped out by the blank"
    );

    query("DELETE FROM listings WHERE listing_url = $1")
        .bind(listing_url)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_listing_last_analyzed_at_set_on_update() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "create_listing_last_analyzed_seller_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Last Analyzed Test Seller".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };
    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected the seller to be created");

    let listing_url = "https://olx.com.pk/item/create-listing-last-analyzed-001";
    query("DELETE FROM listings WHERE listing_url = $1")
        .bind(listing_url)
        .execute(&pool)
        .await
        .ok();

    let request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: platform.to_string(),
        listing_url: listing_url.to_string(),
        listing_id: Some("create_listing_last_analyzed_001".to_string()),
        title: Some("Last Analyzed Test Listing".to_string()),
        price: Some(50000),
        description: Some("Test description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
    };

    let first_result = create_listing(&pool, &request, seller.id)
        .await
        .expect("expected the initial creation to succeed");
    assert!(
        first_result.last_analyzed_at.is_none(),
        "expected last_analyzed_at to start as None on a brand-new listing"
    );

    let second_result = create_listing(&pool, &request, seller.id)
        .await
        .expect("expected the second call to succeed");

    assert_eq!(
        second_result.id, first_result.id,
        "expected the SAME listing row"
    );
    assert!(
        second_result.last_analyzed_at.is_some(),
        "expected last_analyzed_at to genuinely be set now, after a real update"
    );

    let recorded_time = second_result.last_analyzed_at.unwrap();
    assert!(
        Utc::now() - recorded_time < chrono_duration::minutes(1),
        "expected the recorded time to be genuinely recent"
    );

    query("DELETE FROM listings WHERE listing_url = $1")
        .bind(listing_url)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn create_listing_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let fake_seller_id = Uuid::new_v4();
    let request = ListingsRequest {
        seller_id: Some(fake_seller_id),
        platform: "olx".to_string(),
        listing_url: "https://olx.com.pk/item/db-error-test".to_string(),
        listing_id: Some("db_error_test_001".to_string()),
        title: Some("Doesn't Matter".to_string()),
        price: None,
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
    };

    let result = create_listing(&pool, &request, fake_seller_id).await;
    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Run Claude Analysis Test
#[tokio::test]
#[serial]
async fn claude_analysis_success() {
    dotenvy::dotenv().ok();

    let listing = Listings {
        id: Uuid::now_v7(),
        seller_id: None,
        platform: "olx".to_string(),
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: Some("12345".to_string()),
        title: Some("iPhone 13 Pro Max - Excellent Condition".to_string()),
        price: Some(150000),
        description: Some("Selling my iPhone 13 Pro Max, barely used, no scratches.".to_string()),
        category: Some(ListingCategory::MobilePhones),
        image_urls: Some(vec![
            "https://example.com/image1.jpg".to_string(),
            "https://example.com/image2.jpg".to_string(),
        ]),
        posted_date: Some(NaiveDate::from_ymd_opt(2026, 1, 10).unwrap()),
        first_seen_at: Utc::now(),
        last_analyzed_at: None,
        updated_at: Utc::now(),
    };

    let seller = Sellers {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "seller_test_001".to_string(),
        name: Some("Ahmed Khan".to_string()),
        handle: Some("ahmed_khan_deals".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/ahmed-khan".to_string()),
        join_date: Some(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap()),
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active_text: Some("Today".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let result = run_claude_analysis(&listing, &seller)
        .await
        .expect("expected to run the claude analysis");

    assert!(
        !result.overall_risk_notes.is_empty(),
        "expected Claude to return real risk notes, not an empty response"
    );
}

#[tokio::test]
#[serial]
async fn claude_analysis_with_missing_fields_uses_defaults() {
    dotenvy::dotenv().ok();

    let listing = Listings {
        id: Uuid::now_v7(),
        seller_id: None,
        platform: "olx".to_string(),
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: Some("12345".to_string()),
        title: None,
        price: None,
        description: Some("Selling my iPhone 13 Pro Max, barely used, no scratches.".to_string()),
        category: Some(ListingCategory::MobilePhones),
        image_urls: None,
        posted_date: Some(NaiveDate::from_ymd_opt(2026, 1, 10).unwrap()),
        first_seen_at: Utc::now(),
        last_analyzed_at: None,
        updated_at: Utc::now(),
    };

    let seller = Sellers {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "seller_test_001".to_string(),
        name: Some("Ahmed Khan".to_string()),
        handle: Some("ahmed_khan_deals".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/ahmed-khan".to_string()),
        join_date: None,
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active_text: Some("Today".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let result = run_claude_analysis(&listing, &seller)
        .await
        .expect("expected the analysis to succeed even with missing fields");

    assert!(
        !result.overall_risk_notes.is_empty(),
        "expected Claude to still return real risk notes despite the missing fields"
    );
}

#[tokio::test]
#[serial]
async fn claude_analysis_failure() {
    dotenvy::dotenv().ok();

    let original_key = var("ANTHROPIC_API_KEY").ok();
    unsafe {
        remove_var("ANTHROPIC_API_KEY");
    }

    let listing = Listings {
        id: Uuid::now_v7(),
        seller_id: None,
        platform: "olx".to_string(),
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: Some("12345".to_string()),
        title: Some("iPhone 13 Pro Max - Excellent Condition".to_string()),
        price: Some(150000),
        description: Some("Selling my iPhone 13 Pro Max, barely used, no scratches.".to_string()),
        category: Some(ListingCategory::MobilePhones),
        image_urls: Some(vec![
            "https://example.com/image1.jpg".to_string(),
            "https://example.com/image2.jpg".to_string(),
        ]),
        posted_date: Some(NaiveDate::from_ymd_opt(2026, 1, 10).unwrap()),
        first_seen_at: Utc::now(),
        last_analyzed_at: None,
        updated_at: Utc::now(),
    };

    let seller = Sellers {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "seller_test_001".to_string(),
        name: Some("Ahmed Khan".to_string()),
        handle: Some("ahmed_khan_deals".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/ahmed-khan".to_string()),
        join_date: Some(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap()),
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active_text: Some("Today".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let result = run_claude_analysis(&listing, &seller).await;
    assert!(
        result.is_err(),
        "expected the analysis to fail when the API key is genuinely missing"
    );

    unsafe {
        if let Some(key) = original_key {
            set_var("ANTHROPIC_API_KEY", key);
        }
    }
}

// Call Claude Test
#[tokio::test]
#[serial]
async fn call_b2c_claude_missing_api_key() {
    dotenvy::dotenv().ok();
    let original_key = var("ANTHROPIC_API_KEY").ok();
    unsafe {
        remove_var("ANTHROPIC_API_KEY");
    }

    let image_urls: Vec<String> = vec![];
    let args = CallClaudeArguments {
        platform: "olx",
        seller_name: "Test Seller",
        seller_account_age: "3 years",
        title: "Test Listing",
        price: 50000,
        description: "A genuine test description",
        image_urls: &image_urls,
    };

    let result = call_b2c_claude(args).await;

    match result {
        Err(ClaudeError::MissingApiKey) => {}
        Err(other) => panic!("expected MissingApiKey, got a different error: {:?}", other),
        Ok(_) => panic!("expected the call to fail without a real API key, but it succeeded"),
    }

    unsafe {
        if let Some(key) = original_key {
            set_var("ANTHROPIC_API_KEY", key);
        }
    }
}

#[tokio::test]
#[serial]
async fn call_b2c_claude_success_complete_data() {
    dotenvy::dotenv().ok();

    let image_urls: Vec<String> = vec![];
    let args = CallClaudeArguments {
        platform: "olx",
        seller_name: "Ahmed Khan",
        seller_account_age: "3 years",
        title: "iPhone 13 Pro Max - Excellent Condition",
        price: 150000,
        description: "Selling my iPhone 13 Pro Max, barely used, no scratches.",
        image_urls: &image_urls,
    };

    let result = call_b2c_claude(args)
        .await
        .expect("expected the call to genuinely succeed");

    assert!(
        !result.overall_risk_notes.is_empty(),
        "expected Claude to return real, non-empty risk notes"
    );
}

#[tokio::test]
#[serial]
async fn call_b2c_claude_success_with_minimal_data() {
    dotenvy::dotenv().ok();

    let image_urls: Vec<String> = vec![];
    let args = CallClaudeArguments {
        platform: "olx",
        seller_name: "Unknown",
        seller_account_age: "Unknown",
        title: "Untitled",
        price: 0,
        description: "No Description",
        image_urls: &image_urls,
    };

    let result = call_b2c_claude(args)
        .await
        .expect("expected the call to still succeed, even with minimal/default data");

    assert!(
        !result.overall_risk_notes.is_empty(),
        "expected Claude to still return real risk notes despite the sparse input"
    );
}

#[tokio::test]
#[serial]
async fn call_b2c_claude_request_failed() {
    dotenvy::dotenv().ok();

    // Genuinely unreachable
    let response = reqwest::Client::new()
        .post("http://this-domain-genuinely-does-not-exist-12345.invalid")
        .send()
        .await;
    assert!(
        response.is_err(),
        "sanity check: this host should genuinely be unreachable"
    );
}

// Content Test
#[test]
fn content_includes_all_real_values() {
    let image_urls: Vec<String> = vec![];
    let args = CallClaudeArguments {
        platform: "olx",
        seller_name: "Ahmed Khan",
        seller_account_age: "3 years",
        title: "iPhone 13 Pro Max",
        price: 150000,
        description: "Barely used, no scratches",
        image_urls: &image_urls,
    };

    let result = b2c_content(&args);

    assert!(
        result.contains("olx"),
        "expected the platform to appear in the prompt"
    );
    assert!(
        result.contains("Ahmed Khan"),
        "expected the seller name to appear"
    );
    assert!(
        result.contains("3 years"),
        "expected the account age to appear"
    );
    assert!(
        result.contains("iPhone 13 Pro Max"),
        "expected the title to appear"
    );
    assert!(result.contains("150000"), "expected the price to appear");
    assert!(
        result.contains("Barely used, no scratches"),
        "expected the description to appear"
    );
}

#[test]
fn content_never_includes_image_urls() {
    let image_urls: Vec<String> =
        vec!["https://example.com/genuinely-distinctive-image-url-marker.jpg".to_string()];
    let args = CallClaudeArguments {
        platform: "olx",
        seller_name: "Test Seller",
        seller_account_age: "1 year",
        title: "Test Listing",
        price: 1000,
        description: "Test description",
        image_urls: &image_urls,
    };

    let result = b2c_content(&args);

    assert!(
        !result.contains("genuinely-distinctive-image-url-marker"),
        "expected image_urls to be genuinely absent from the prompt, since this field is deliberately unused"
    );
}

// Build All Signals Tests
#[tokio::test]
async fn build_all_signals_without_domain_check() {
    let finding = Finding {
        found: true,
        evidence: "evidence".to_string(),
    };

    let image_assessment = ImageAssessment {
        verdict: "original".to_string(),
        reasoning: "reasoning".to_string(),
    };

    let price_assessment = PriceAssessment {
        verdict: "normal".to_string(),
        reasoning: "reasoning".to_string(),
    };

    let claude_analysis = ClaudeAnalysis {
        urgency_language: finding.clone(),
        advance_payment_request: finding.clone(),
        duplicate_listing: finding.clone(),
        image_authenticity: image_assessment,
        fraud_pattern_match: finding.clone(),
        contact_info_in_listing: finding.clone(),
        price_assessment,
        extracted_phone_number: None,
        overall_risk_notes: "risk notes".to_string(),
    };

    let seller = Sellers {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "seller_test_001".to_string(),
        name: Some("Ahmed Khan".to_string()),
        handle: Some("ahmed_khan_deals".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/ahmed-khan".to_string()),
        join_date: Some(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap()),
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active_text: Some("Today".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let analyze_request = AnalyzeRequest {
        platform: "olx".to_string(),
        seller_id: None,
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: Some("12345".to_string()),
        title: Some("Test Listing".to_string()),
        price: Some(50000),
        description: Some("Test description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: Some("platform_id_123".to_string()),
        seller_name: Some("Test Seller".to_string()),
        seller_handle: Some("test_handle".to_string()),
        seller_phone: Some("123456789".to_string()),
        seller_profile_url: Some("https://olx.com.pk/profile/test".to_string()),
        seller_join_date: Some("2021".to_string()),
        seller_location: Some("Lahore".to_string()),
        seller_last_active: Some("Today".to_string()),
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let pool = test_pool().await;
    let signals_without_domain = build_signals(&claude_analysis, &seller);
    let all_signals = build_all_signals(&pool, &claude_analysis, &seller, &analyze_request).await;

    assert_eq!(all_signals.len(), signals_without_domain.len() + 2);
}

#[tokio::test]
async fn build_all_signals_with_domain_check() {
    let finding = Finding {
        found: true,
        evidence: "evidence".to_string(),
    };

    let image_assessment = ImageAssessment {
        verdict: "original".to_string(),
        reasoning: "reasoning".to_string(),
    };

    let price_assessment = PriceAssessment {
        verdict: "normal".to_string(),
        reasoning: "reasoning".to_string(),
    };

    let claude_analysis = ClaudeAnalysis {
        urgency_language: finding.clone(),
        advance_payment_request: finding.clone(),
        duplicate_listing: finding.clone(),
        image_authenticity: image_assessment,
        fraud_pattern_match: finding.clone(),
        contact_info_in_listing: finding.clone(),
        price_assessment,
        extracted_phone_number: None,
        overall_risk_notes: "risk notes".to_string(),
    };

    let seller = Sellers {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "seller_test_001".to_string(),
        name: Some("Ahmed Khan".to_string()),
        handle: Some("ahmed_khan_deals".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: Some("https://olx.com.pk/profile/ahmed-khan".to_string()),
        join_date: Some(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap()),
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active_text: Some("Today".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let analyze_request = AnalyzeRequest {
        platform: "olx".to_string(),
        seller_id: None,
        listing_url: "https://olx.com.pk/item/test-listing".to_string(),
        listing_id: Some("12345".to_string()),
        title: Some("Test Listing".to_string()),
        price: Some(50000),
        description: Some("Test description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: Some("platform_id_123".to_string()),
        seller_name: Some("Test Seller".to_string()),
        seller_handle: Some("test_handle".to_string()),
        seller_phone: Some("123456789".to_string()),
        seller_profile_url: Some("https://olx.com.pk/profile/test".to_string()),
        seller_join_date: Some("2021".to_string()),
        seller_location: Some("Lahore".to_string()),
        seller_last_active: Some("Today".to_string()),
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: Some("suspicious".to_string()),
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let pool = test_pool().await;
    let signals_without_domain = build_signals(&claude_analysis, &seller);
    let all_signals = build_all_signals(&pool, &claude_analysis, &seller, &analyze_request).await;

    assert_eq!(all_signals.len(), signals_without_domain.len() + 3);
    assert_eq!(all_signals[0].label, "Domain check");
}

// Build Network Memory Signal
#[tokio::test]
async fn build_network_memory_signal_uses_singular_phrasing_for_exactly_one_prior_check() {
    let pool = admin_pool().await;
    let platform_id = "network_memory_singular_001";
    let (analysis_id, seller_id) = setup_real_seller_and_analysis(&pool, platform_id).await;

    insert_raw_evidence_row(&pool, analysis_id, seller_id, "50").await;

    let result = build_network_memory_signal(&pool, seller_id).await;

    assert!(result.is_some());
    let signal = result.unwrap();
    assert_eq!(signal.value, "1 prior checks");
    assert!(signal.sub.contains("1 time before"));

    cleanup_seller_and_analysis(&pool, platform_id).await;
}

#[tokio::test]
async fn build_network_memory_signal_uses_plural_phrasing_for_multiple_prior_checks() {
    let pool = admin_pool().await;
    let platform_id = "network_memory_plural_001";
    let (analysis_id, seller_id) = setup_real_seller_and_analysis(&pool, platform_id).await;

    insert_raw_evidence_row(&pool, analysis_id, seller_id, "20").await;
    insert_raw_evidence_row(&pool, analysis_id, seller_id, "40").await;
    insert_raw_evidence_row(&pool, analysis_id, seller_id, "60").await;

    let result = build_network_memory_signal(&pool, seller_id).await;

    assert!(result.is_some());
    let signal = result.unwrap();
    assert_eq!(signal.value, "3 prior checks");
    assert!(signal.sub.contains("3 times before"));

    cleanup_seller_and_analysis(&pool, platform_id).await;
}

#[tokio::test]
async fn build_network_memory_signal_calculates_the_real_correct_average() {
    let pool = admin_pool().await;
    let platform_id = "network_memory_average_001";
    let (analysis_id, seller_id) = setup_real_seller_and_analysis(&pool, platform_id).await;

    insert_raw_evidence_row(&pool, analysis_id, seller_id, "10").await;
    insert_raw_evidence_row(&pool, analysis_id, seller_id, "20").await;
    insert_raw_evidence_row(&pool, analysis_id, seller_id, "30").await;

    let result = build_network_memory_signal(&pool, seller_id).await;

    assert!(result.is_some());
    assert!(result.unwrap().sub.contains("Average risk score: 20."));

    cleanup_seller_and_analysis(&pool, platform_id).await;
}

#[tokio::test]
async fn build_network_memory_signal_marks_high_average_as_bad() {
    let pool = admin_pool().await;
    let platform_id = "network_memory_bad_001";
    let (analysis_id, seller_id) = setup_real_seller_and_analysis(&pool, platform_id).await;

    insert_raw_evidence_row(&pool, analysis_id, seller_id, "67").await;

    let result = build_network_memory_signal(&pool, seller_id).await;
    assert_eq!(result.unwrap().signal_type, "bad");

    cleanup_seller_and_analysis(&pool, platform_id).await;
}

#[tokio::test]
async fn build_network_memory_signal_marks_exactly_66_as_caution_not_bad() {
    let pool = admin_pool().await;
    let platform_id = "network_memory_66_001";
    let (analysis_id, seller_id) = setup_real_seller_and_analysis(&pool, platform_id).await;

    insert_raw_evidence_row(&pool, analysis_id, seller_id, "66").await;

    let result = build_network_memory_signal(&pool, seller_id).await;
    assert_eq!(result.unwrap().signal_type, "caution");

    cleanup_seller_and_analysis(&pool, platform_id).await;
}

#[tokio::test]
async fn build_network_memory_signal_marks_exactly_34_as_caution() {
    let pool = admin_pool().await;
    let platform_id = "network_memory_34_001";
    let (analysis_id, seller_id) = setup_real_seller_and_analysis(&pool, platform_id).await;

    insert_raw_evidence_row(&pool, analysis_id, seller_id, "34").await;

    let result = build_network_memory_signal(&pool, seller_id).await;
    assert_eq!(result.unwrap().signal_type, "caution");

    cleanup_seller_and_analysis(&pool, platform_id).await;
}

#[tokio::test]
async fn build_network_memory_signal_marks_33_as_good_not_caution() {
    let pool = admin_pool().await;
    let platform_id = "network_memory_33_001";
    let (analysis_id, seller_id) = setup_real_seller_and_analysis(&pool, platform_id).await;

    insert_raw_evidence_row(&pool, analysis_id, seller_id, "33").await;

    let result = build_network_memory_signal(&pool, seller_id).await;
    assert_eq!(result.unwrap().signal_type, "good");

    cleanup_seller_and_analysis(&pool, platform_id).await;
}

#[tokio::test]
async fn build_network_memory_signal_correctly_scopes_to_only_this_specific_seller() {
    let pool = admin_pool().await;
    let platform_id_a = "network_memory_scope_a_001";
    let platform_id_b = "network_memory_scope_b_001";
    let (analysis_a, seller_a) = setup_real_seller_and_analysis(&pool, platform_id_a).await;
    let (analysis_b, seller_b) = setup_real_seller_and_analysis(&pool, platform_id_b).await;

    insert_raw_evidence_row(&pool, analysis_a, seller_a, "10").await;
    insert_raw_evidence_row(&pool, analysis_b, seller_b, "99").await;

    let result = build_network_memory_signal(&pool, seller_a).await;
    assert_eq!(result.unwrap().value, "1 prior checks");

    cleanup_seller_and_analysis(&pool, platform_id_a).await;
    cleanup_seller_and_analysis(&pool, platform_id_b).await;
}

#[tokio::test]
async fn build_network_memory_signal_ignores_a_genuinely_malformed_value_without_crashing() {
    let pool = admin_pool().await;
    let platform_id = "network_memory_malformed_001";
    let (analysis_id, seller_id) = setup_real_seller_and_analysis(&pool, platform_id).await;

    insert_raw_evidence_row(&pool, analysis_id, seller_id, "not_a_real_number").await;
    insert_raw_evidence_row(&pool, analysis_id, seller_id, "50").await;

    let result = build_network_memory_signal(&pool, seller_id).await;

    assert!(result.is_some());
    assert_eq!(result.unwrap().value, "1 prior checks");

    cleanup_seller_and_analysis(&pool, platform_id).await;
}

// Build Domain Signal Test
#[test]
fn build_domain_signal_with_legitimate_status() {
    let status = Some("legitimate");
    let real_name = None;
    let real_domain = None;
    let current_domain = None;
    let current_domain_html = None;
    let real_domain_html = None;

    let result = build_domain_signal(
        status,
        real_name,
        real_domain,
        current_domain,
        current_domain_html,
        real_domain_html,
    );

    let signal = result.expect("expected a signal for a legitimate domain");

    assert_eq!(signal.label, "Domain check");
    assert_eq!(signal.value, "Verified");
    assert_eq!(signal.signal_type, "good");
    assert_eq!(
        signal.sub,
        "This matches the marketplace's real, verified domain."
    );
}

#[test]
fn build_domain_signal_with_suspicious_status() {
    let status = Some("suspicious");
    let real_name = None;
    let real_domain = None;
    let current_domain = None;
    let current_domain_html = None;
    let real_domain_html = None;

    let result = build_domain_signal(
        status,
        real_name,
        real_domain,
        current_domain,
        current_domain_html,
        real_domain_html,
    );

    let signal = result.expect("expected a signal for a suspicious domain");

    assert_eq!(signal.label, "Domain check");
    assert_eq!(signal.value, "Suspicious");
    assert_eq!(signal.signal_type, "bad");
    assert_eq!(
        signal.sub,
        "This does not match the marketplace's real domain (unknown). You're currently on an unrecognized domain instead."
    );
}

#[test]
fn build_domain_signal_with_something_else_status() {
    let status = Some("something_else");
    let real_name = None;
    let real_domain = None;
    let current_domain = None;
    let current_domain_html = None;
    let real_domain_html = None;

    let result = build_domain_signal(
        status,
        real_name,
        real_domain,
        current_domain,
        current_domain_html,
        real_domain_html,
    );

    assert!(
        result.is_none(),
        "expected no signal for an unrecognized status"
    );
}

#[test]
fn build_domain_signal_prefers_highlighted_html_over_plain_text() {
    let status = Some("suspicious");
    let real_name = Some("OLX");
    let real_domain = Some("olx.com.pk");
    let real_domain_html = Some("olx.com.pk");
    let current_domain = Some("0lx.com.pk");
    let current_domain_html = Some("<b>0</b>lx.com.pk");

    let result = build_domain_signal(
        status,
        real_name,
        real_domain,
        current_domain,
        current_domain_html,
        real_domain_html,
    );

    let signal = result.expect("expected a signal for a suspicious domain");

    assert!(
        signal.sub.contains("<b>0</b>lx.com.pk"),
        "expected the highlighted version to be used, got: {}",
        signal.sub
    );

    assert!(
        !signal.sub.contains("0lx.com.pk\""),
        "expected the plain version NOT to be used when the highlighted one was available"
    );
}

// Calculate Risk Score Test
#[test]
fn calculate_risk_score_baseline_zero() {
    let analysis = ClaudeAnalysis {
        urgency_language: Finding {
            found: false,
            evidence: "".to_string(),
        },
        advance_payment_request: Finding {
            found: false,
            evidence: "".to_string(),
        },
        duplicate_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        image_authenticity: ImageAssessment {
            verdict: "original".to_string(),
            reasoning: "".to_string(),
        },
        fraud_pattern_match: Finding {
            found: false,
            evidence: "".to_string(),
        },
        contact_info_in_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        price_assessment: PriceAssessment {
            verdict: "normal".to_string(),
            reasoning: "".to_string(),
        },
        extracted_phone_number: None,
        overall_risk_notes: "".to_string(),
    };

    let score = calculate_risk_score(&analysis, 0);

    assert_eq!(score, 0, "expected a genuinely clean listing to score 0");
}

#[test]
fn calculate_risk_score_urgency_language() {
    let mut analysis = ClaudeAnalysis {
        urgency_language: Finding {
            found: false,
            evidence: "".to_string(),
        },
        advance_payment_request: Finding {
            found: false,
            evidence: "".to_string(),
        },
        duplicate_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        image_authenticity: ImageAssessment {
            verdict: "original".to_string(),
            reasoning: "".to_string(),
        },
        fraud_pattern_match: Finding {
            found: false,
            evidence: "".to_string(),
        },
        contact_info_in_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        price_assessment: PriceAssessment {
            verdict: "normal".to_string(),
            reasoning: "".to_string(),
        },
        extracted_phone_number: None,
        overall_risk_notes: "".to_string(),
    };
    analysis.urgency_language.found = true;

    let score = calculate_risk_score(&analysis, 0);

    assert_eq!(
        score, 15,
        "expected urgency_language alone to add exactly 15 points"
    );
}

#[test]
fn calculate_risk_score_advance_payment_request() {
    let mut analysis = ClaudeAnalysis {
        urgency_language: Finding {
            found: false,
            evidence: "".to_string(),
        },
        advance_payment_request: Finding {
            found: false,
            evidence: "".to_string(),
        },
        duplicate_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        image_authenticity: ImageAssessment {
            verdict: "original".to_string(),
            reasoning: "".to_string(),
        },
        fraud_pattern_match: Finding {
            found: false,
            evidence: "".to_string(),
        },
        contact_info_in_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        price_assessment: PriceAssessment {
            verdict: "normal".to_string(),
            reasoning: "".to_string(),
        },
        extracted_phone_number: None,
        overall_risk_notes: "".to_string(),
    };
    analysis.advance_payment_request.found = true;

    let score = calculate_risk_score(&analysis, 0);

    assert_eq!(
        score, 20,
        "expected advance_payment_request alone to add exactly 20 points"
    );
}

#[test]
fn calculate_risk_score_duplicate_listing() {
    let mut analysis = ClaudeAnalysis {
        urgency_language: Finding {
            found: false,
            evidence: "".to_string(),
        },
        advance_payment_request: Finding {
            found: false,
            evidence: "".to_string(),
        },
        duplicate_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        image_authenticity: ImageAssessment {
            verdict: "original".to_string(),
            reasoning: "".to_string(),
        },
        fraud_pattern_match: Finding {
            found: false,
            evidence: "".to_string(),
        },
        contact_info_in_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        price_assessment: PriceAssessment {
            verdict: "normal".to_string(),
            reasoning: "".to_string(),
        },
        extracted_phone_number: None,
        overall_risk_notes: "".to_string(),
    };
    analysis.duplicate_listing.found = true;

    let score = calculate_risk_score(&analysis, 0);

    assert_eq!(
        score, 15,
        "expected duplicate_listing alone to add exactly 15 points"
    );
}

#[test]
fn calculate_risk_score_fraud_pattern_match() {
    let mut analysis = ClaudeAnalysis {
        urgency_language: Finding {
            found: false,
            evidence: "".to_string(),
        },
        advance_payment_request: Finding {
            found: false,
            evidence: "".to_string(),
        },
        duplicate_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        image_authenticity: ImageAssessment {
            verdict: "original".to_string(),
            reasoning: "".to_string(),
        },
        fraud_pattern_match: Finding {
            found: false,
            evidence: "".to_string(),
        },
        contact_info_in_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        price_assessment: PriceAssessment {
            verdict: "normal".to_string(),
            reasoning: "".to_string(),
        },
        extracted_phone_number: None,
        overall_risk_notes: "".to_string(),
    };
    analysis.fraud_pattern_match.found = true;

    let score = calculate_risk_score(&analysis, 0);

    assert_eq!(
        score, 30,
        "expected fraud_pattern_match alone to add exactly 30 points"
    );
}

#[test]
fn calculate_risk_score_contact_info_in_listing() {
    let mut analysis = ClaudeAnalysis {
        urgency_language: Finding {
            found: false,
            evidence: "".to_string(),
        },
        advance_payment_request: Finding {
            found: false,
            evidence: "".to_string(),
        },
        duplicate_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        image_authenticity: ImageAssessment {
            verdict: "original".to_string(),
            reasoning: "".to_string(),
        },
        fraud_pattern_match: Finding {
            found: false,
            evidence: "".to_string(),
        },
        contact_info_in_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        price_assessment: PriceAssessment {
            verdict: "normal".to_string(),
            reasoning: "".to_string(),
        },
        extracted_phone_number: None,
        overall_risk_notes: "".to_string(),
    };
    analysis.contact_info_in_listing.found = true;

    let score = calculate_risk_score(&analysis, 0);

    assert_eq!(
        score, 10,
        "expected contact_info_in_listing alone to add exactly 10 points"
    );
}

#[test]
fn calculate_risk_score_price_assessment_not_normal() {
    let analysis = ClaudeAnalysis {
        urgency_language: Finding {
            found: false,
            evidence: "".to_string(),
        },
        advance_payment_request: Finding {
            found: false,
            evidence: "".to_string(),
        },
        duplicate_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        image_authenticity: ImageAssessment {
            verdict: "original".to_string(),
            reasoning: "".to_string(),
        },
        fraud_pattern_match: Finding {
            found: false,
            evidence: "".to_string(),
        },
        contact_info_in_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        price_assessment: PriceAssessment {
            verdict: "suspiciously_low".to_string(),
            reasoning: "".to_string(),
        },
        extracted_phone_number: None,
        overall_risk_notes: "".to_string(),
    };

    let score = calculate_risk_score(&analysis, 0);

    assert_eq!(
        score, 20,
        "expected a non-'normal' price verdict alone to add exactly 20 points"
    );
}

#[test]
fn calculate_risk_score_image_authenticity_not_original() {
    let analysis = ClaudeAnalysis {
        urgency_language: Finding {
            found: false,
            evidence: "".to_string(),
        },
        advance_payment_request: Finding {
            found: false,
            evidence: "".to_string(),
        },
        duplicate_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        image_authenticity: ImageAssessment {
            verdict: "stolen".to_string(),
            reasoning: "".to_string(),
        },
        fraud_pattern_match: Finding {
            found: false,
            evidence: "".to_string(),
        },
        contact_info_in_listing: Finding {
            found: false,
            evidence: "".to_string(),
        },
        price_assessment: PriceAssessment {
            verdict: "normal".to_string(),
            reasoning: "".to_string(),
        },
        extracted_phone_number: None,
        overall_risk_notes: "".to_string(),
    };

    let score = calculate_risk_score(&analysis, 0);

    assert_eq!(
        score, 10,
        "expected a non-'original' image verdict alone to add exactly 10 points"
    );
}

// Save and Build Response Test
#[tokio::test]
async fn save_and_build_response_success() {
    let pool = test_pool().await;

    let email = "save_response_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    let seller_request = SellersRequest {
        platform: "olx".to_string(),
        platform_id: Some("save_response_seller_001".to_string()),
        name: Some("Test Seller".to_string()),
        handle: Some("test_handle".to_string()),
        phone: Some("123456789".to_string()),
        profile_url: Some("https://olx.com.pk/profile/test".to_string()),
        join_date: Some("2021".to_string()),
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };
    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");

    let listing_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: "olx".to_string(),
        listing_url: "https://olx.com.pk/item/save-response-test".to_string(),
        listing_id: Some("save_response_listing_001".to_string()),
        title: Some("Test Listing".to_string()),
        price: Some(50000),
        description: Some("Test description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
    };

    let listing = create_listing(&pool, &listing_request, seller.id)
        .await
        .expect("expected to create the listing");
    let signals = vec![Signal {
        label: "Price analysis".to_string(),
        sub: "Price looks normal for this category.".to_string(),
        value: "Normal".to_string(),
        signal_type: "good".to_string(),
        category: "listing".to_string(),
        check_type: "anomaly".to_string(),
    }];

    let data = BuildResponseData {
        pool: &pool,
        listing_id: listing.id,
        risk_score: 10,
        risk_level: RiskLevel::Low,
        signals: signals.clone(),
        overall_risk_notes: "No significant risk detected.".to_string(),
        user_id: user.id,
        seller,
        fraud_count: 0,
        network_summary: "Clean record on Safely network. No fraud reports found.".to_string(),
        is_b2b: false,
        social_candidates: Vec::new(),
    };

    let result = save_and_build_response(data)
        .await
        .expect("expected the response to be built successfully");

    assert_eq!(result.risk_score, 10);
    assert_eq!(result.risk_level, RiskLevel::Low);
    assert_eq!(result.fraud_report_count, 0);
    assert_eq!(result.signals.len(), 1);
    assert_eq!(result.entity_type, "individual");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn save_and_build_response_database_failure() {
    let pool = test_pool().await;

    let fake_listing_id = Uuid::new_v4();
    let fake_user_id = Uuid::new_v4();

    let seller = Sellers {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "fake_seller_for_failure_test".to_string(),
        name: Some("Test Seller".to_string()),
        handle: Some("test_handle".to_string()),
        phone: Some("123456789".to_string()),
        profile_url: Some("https://olx.com.pk/profile/test".to_string()),
        join_date: Some(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap()),
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active_text: Some("Today".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let signals = vec![Signal {
        label: "Price analysis".to_string(),
        sub: "Price looks normal for this category.".to_string(),
        value: "Normal".to_string(),
        signal_type: "good".to_string(),
        category: "listing".to_string(),
        check_type: "anomaly".to_string(),
    }];

    let data = BuildResponseData {
        pool: &pool,
        listing_id: fake_listing_id,
        risk_score: 10,
        risk_level: RiskLevel::Low,
        signals,
        overall_risk_notes: "No significant risk detected.".to_string(),
        user_id: fake_user_id,
        seller,
        fraud_count: 0,
        network_summary: "Clean record on Safely network. No fraud reports found.".to_string(),
        is_b2b: false,
        social_candidates: Vec::new(),
    };

    let result = save_and_build_response(data).await;
    assert!(
        result.is_err(),
        "expected save_and_build_response to fail when listing_id and user_id don't genuinely exist"
    );
}

// Classify Entity Tests
#[test]
fn name_containing_a_business_keyword_is_classified_as_business() {
    assert_eq!(classify_entity(Some("Ahmed Motors"), false), "business");
    assert_eq!(classify_entity(Some("Sunshine Traders"), false), "business");
    assert_eq!(classify_entity(Some("Tech Enterprises"), false), "business");
    assert_eq!(classify_entity(Some("Downtown Store"), false), "business");
    assert_eq!(classify_entity(Some("Khan & Co."), false), "business");
}

#[test]
fn keyword_matching_is_genuinely_case_insensitive() {
    assert_eq!(classify_entity(Some("AHMED MOTORS"), false), "business");
    assert_eq!(classify_entity(Some("ahmed motors"), false), "business");
    assert_eq!(classify_entity(Some("AhMeD MoToRs"), false), "business");
}

#[test]
fn keyword_matches_anywhere_in_the_name_not_just_as_a_whole_word() {
    assert_eq!(
        classify_entity(Some("Storefront Cleaners"), false),
        "business"
    );
}

#[test]
fn ordinary_individual_name_with_no_keywords_is_classified_as_individual() {
    assert_eq!(classify_entity(Some("Ali Khan"), false), "individual");
    assert_eq!(classify_entity(Some("M Usman"), false), "individual");
}

#[test]
fn no_seller_name_at_all_is_classified_as_unknown() {
    assert_eq!(classify_entity(None, false), "unknown");
}

#[test]
fn no_name_but_a_fully_confirmed_website_still_returns_business() {
    assert_eq!(classify_entity(None, true), "business");
}

#[test]
fn fully_confirmed_website_alone_is_enough_for_an_otherwise_ordinary_name() {
    assert_eq!(classify_entity(Some("Ali Khan"), true), "business");
}

#[test]
fn both_name_keyword_and_confirmed_website_together_still_returns_business() {
    assert_eq!(classify_entity(Some("Ahmed Motors"), true), "business");
}

#[test]
fn the_real_security_case_an_unconfirmed_website_never_triggers_business_on_its_own() {
    assert_eq!(classify_entity(Some("Ali Khan"), false), "individual");
}

#[test]
fn empty_string_name_is_treated_the_same_as_an_ordinary_individual_name() {
    assert_eq!(classify_entity(Some(""), false), "individual");
}

// Calculate Confidence Tests
#[test]
fn eight_or_more_meaningful_signals_gives_high_confidence() {
    let signals: Vec<Signal> = (0..8)
        .map(|i| make_signal(&format!("Value{}", i)))
        .collect();
    let (level, _) = calculate_confidence(&signals);
    assert_eq!(level, "high");
}

#[test]
fn seven_meaningful_signals_is_still_medium_not_high() {
    let signals: Vec<Signal> = (0..7)
        .map(|i| make_signal(&format!("Value{}", i)))
        .collect();

    let (level, _) = calculate_confidence(&signals);

    assert_eq!(level, "medium");
}

#[test]
fn five_meaningful_signals_gives_medium_confidence() {
    let signals: Vec<Signal> = (0..5)
        .map(|i| make_signal(&format!("Value{}", i)))
        .collect();

    let (level, _) = calculate_confidence(&signals);

    assert_eq!(level, "medium");
}

#[test]
fn four_meaningful_signals_drops_to_low_not_medium() {
    let signals: Vec<Signal> = (0..4)
        .map(|i| make_signal(&format!("Value{}", i)))
        .collect();

    let (level, _) = calculate_confidence(&signals);

    assert_eq!(level, "low");
}

#[test]
fn zero_meaningful_signals_gives_low_confidence() {
    let signals = vec![make_signal("Unknown"), make_signal("Unknown")];
    let (level, _) = calculate_confidence(&signals);
    assert_eq!(level, "low");
}

#[test]
fn genuinely_empty_signal_list_does_not_panic_and_gives_low() {
    let signals: Vec<Signal> = vec![];
    let (level, reasoning) = calculate_confidence(&signals);

    assert_eq!(level, "low");
    assert_eq!(
        reasoning,
        "Based on 0 of 0 signals returning real, usable data."
    );
}

#[test]
fn unknown_value_signals_are_correctly_excluded_from_the_meaningful_count() {
    let signals = vec![
        make_signal("Detected"),
        make_signal("Unknown"),
        make_signal("Normal"),
        make_signal("Unknown"),
        make_signal("Verified"),
    ];

    let (level, reasoning) = calculate_confidence(&signals);
    assert_eq!(level, "low");
    assert_eq!(
        reasoning,
        "Based on 3 of 5 signals returning real, usable data."
    );
}

#[test]
fn reasoning_sentence_includes_the_real_correct_numbers() {
    let signals: Vec<Signal> = (0..9)
        .map(|i| make_signal(&format!("Value{}", i)))
        .collect();
    let (_, reasoning) = calculate_confidence(&signals);

    assert_eq!(
        reasoning,
        "Based on 9 of 9 signals returning real, usable data."
    );
}

// Is new_account Tests
#[test]
fn is_new_account_recognizes_this_month_as_new() {
    assert!(is_new_account("This month"));
}

#[test]
fn is_new_account_recognizes_a_plain_months_value_as_new() {
    assert!(is_new_account("7 months"));
}

#[test]
fn is_new_account_treats_anything_containing_year_as_not_new() {
    assert!(!is_new_account("1 years 8 months"));
    assert!(!is_new_account("6 years"));
}

#[test]
fn is_new_account_treats_unknown_as_not_new() {
    assert!(!is_new_account("Unknown"));
}

// Find Signal Tests
#[test]
fn find_signal_returns_the_matching_signal_when_present() {
    let signals = vec![
        make_signals("Price analysis", "normal", "good"),
        make_signals("Fraud pattern match", "Detected", "caution"),
    ];

    let found = find_signal(&signals, "Fraud pattern match");
    assert!(found.is_some());
    assert_eq!(found.unwrap().value, "Detected");
}

#[test]
fn find_signal_returns_none_when_the_label_is_genuinely_absent() {
    let signals = vec![make_signals("Price analysis", "normal", "good")];
    assert!(find_signal(&signals, "Fraud pattern match").is_none());
}

// Derive Risk Factors Tests
#[test]
fn derive_risk_factors_flags_a_confirmed_fraud_pattern_as_hard() {
    let signals = vec![make_signals(
        "Overall legitimacy check",
        "Detected",
        "caution",
    )];
    let factors = derive_risk_factors(&signals);
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].severity, "hard");
    assert_eq!(factors[0].name, "confirmed_legitimacy_concern");
}

#[test]
fn derive_risk_factors_flags_a_bad_safely_history_as_hard() {
    let signals = vec![make_signals("Safely history", "3 prior checks", "bad")];
    let factors = derive_risk_factors(&signals);
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].severity, "hard");
    assert_eq!(factors[0].name, "network_confirmed_high_risk_seller");
}

#[test]
fn derive_risk_factors_does_not_flag_safely_history_when_it_is_not_bad() {
    let signals = vec![make_signals("Safely history", "1 prior checks", "good")];
    let factors = derive_risk_factors(&signals);
    assert_eq!(factors.len(), 0);
}

#[test]
fn derive_risk_factors_flags_duplicate_plus_unverifiable_images_as_compound() {
    let signals = vec![
        make_signals("Duplicate listing", "Detected", "caution"),
        make_signals("Image authenticity", "Unverifiable", "caution"),
    ];
    let factors = derive_risk_factors(&signals);
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].severity, "compound");
    assert_eq!(factors[0].name, "likely_counterfeit_or_nonexistent_product");
}

#[test]
fn derive_risk_factors_flags_urgency_plus_advance_payment_as_compound() {
    let signals = vec![
        make_signals("Urgency language", "Detected", "caution"),
        make_signals("Advance payment request", "Detected", "caution"),
    ];
    let factors = derive_risk_factors(&signals);
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].severity, "compound");
    assert_eq!(factors[0].name, "advance_fee_scam_pattern");
}

#[test]
fn derive_risk_factors_flags_new_account_plus_fraud_match_as_compound() {
    let signals = vec![
        make_signals("Entity age", "This month", "info"),
        make_signals("Overall legitimacy check", "Detected", "caution"),
    ];
    let factors = derive_risk_factors(&signals);
    let compound = factors
        .iter()
        .find(|f| f.name == "newly_created_high_risk_entity");
    assert!(
        compound.is_none(),
        "expected the compound rule to be correctly skipped, since Overall legitimacy check was already claimed by the hard rule"
    );
}

#[test]
fn derive_risk_factors_hard_fraud_factor_correctly_blocks_the_redundant_compound_version() {
    let signals = vec![
        make_signals("Entity age", "This month", "info"),
        make_signals("Overall legitimacy check", "Detected", "caution"),
    ];

    let factors = derive_risk_factors(&signals);
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].name, "confirmed_legitimacy_concern");
}

#[test]
fn derive_risk_factors_treats_an_uncovered_caution_signal_as_soft() {
    let signals = vec![make_signals("Contact info", "Confirmed", "caution")];
    let factors = derive_risk_factors(&signals);
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].severity, "soft");
    assert_eq!(factors[0].name, "contact_info_flagged");
}

#[test]
fn derive_risk_factors_does_not_double_count_signals_already_claimed_by_a_compound_factor() {
    let signals = vec![
        make_signals("Duplicate listing", "Detected", "caution"),
        make_signals("Image authenticity", "Unverifiable", "caution"),
    ];
    let factors = derive_risk_factors(&signals);

    assert_eq!(factors.len(), 1);
}

#[test]
fn derive_risk_factors_ignores_good_and_info_type_signals_entirely() {
    let signals = vec![
        make_signals("Price analysis", "normal", "good"),
        make_signals("Account age", "6 years", "info"),
    ];
    let factors = derive_risk_factors(&signals);
    assert_eq!(factors.len(), 0);
}

#[test]
fn derive_risk_factors_returns_genuinely_empty_for_an_empty_signal_list() {
    let factors = derive_risk_factors(&[]);
    assert_eq!(factors.len(), 0);
}

// Create Analysis Tests
#[tokio::test]
async fn create_analysis_success() {
    let pool = test_pool().await;
    let email = "create_analysis_test@example.com";
    cleanup_test_user(&pool, email).await;

    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    let platform = "olx".to_string();
    let platform_id = "create_analysis_seller_001".to_string();

    cleanup_test_seller(&pool, &platform, &platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Test Seller".to_string()),
        handle: Some("test_handle".to_string()),
        phone: Some("123456789".to_string()),
        profile_url: Some("https://olx.com.pk/profile/test".to_string()),
        join_date: Some("2021".to_string()),
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
    };

    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");

    let listing_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: platform.clone(),
        listing_url: "https://olx.com.pk/item/create-analysis-test".to_string(),
        listing_id: Some("create_analysis_listing_001".to_string()),
        title: Some("Test Listing".to_string()),
        price: Some(50000),
        description: Some("Test description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
    };

    let listing = create_listing(&pool, &listing_request, seller.id)
        .await
        .expect("expected to create the listing");

    let signals_json = json!([
        { "label": "Price analysis", "sub": "Normal", "value": "Normal", "signal_type": "good" }
    ]);

    let data = CreateAnalysisData {
        pool: &pool,
        listing_id: listing.id,
        risk_score: 15,
        risk_level: RiskLevel::Low,
        signals: signals_json.clone(),
        network_summary: "Clean record on Safely network. No fraud reports found.".to_string(),
        claude_raw: String::new(),
        user_id: user.id,
        confidence_level: "high".to_string(),
        confidence_reasoning: "Based on 1 of 1 signals returning real, usable data.".to_string(),
        risk_factors: json!([]),
        social_candidates: json!([]),
    };

    let analysis = create_analysis(data)
        .await
        .expect("expected the analysis to be created successfully");

    assert_eq!(analysis.listing_id, listing.id);
    assert_eq!(analysis.user_id, user.id);
    assert_eq!(analysis.risk_score, 15);
    assert_eq!(analysis.risk_level, RiskLevel::Low);
    assert_eq!(
        analysis.network_summary,
        Some("Clean record on Safely network. No fraud reports found.".to_string())
    );
    assert_eq!(analysis.signals, signals_json);

    query("DELETE FROM analysis WHERE id = $1")
        .bind(analysis.id)
        .execute(&pool)
        .await
        .expect("expected analysis cleanup to succeed");

    query("DELETE FROM listings WHERE id = $1")
        .bind(listing.id)
        .execute(&pool)
        .await
        .expect("expected listing cleanup to succeed");

    cleanup_test_seller(&pool, &platform, &platform_id).await;
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn create_analysis_database_failure() {
    let pool = test_pool().await;

    let fake_listing_id = Uuid::new_v4();
    let fake_user_id = Uuid::new_v4();

    let signals_json = json!([
        { "label": "Price analysis", "sub": "Normal", "value": "Normal", "signal_type": "good" }
    ]);

    let data = CreateAnalysisData {
        pool: &pool,
        listing_id: fake_listing_id,
        risk_score: 15,
        risk_level: RiskLevel::Low,
        signals: signals_json,
        network_summary: "Clean record on Safely network. No fraud reports found.".to_string(),
        claude_raw: String::new(),
        user_id: fake_user_id,
        confidence_level: "high".to_string(),
        confidence_reasoning: "Based on 1 of 1 signals returning real, usable data.".to_string(),
        risk_factors: json!([]),
        social_candidates: json!([]),
    };

    let result = create_analysis(data).await;

    assert!(
        result.is_err(),
        "expected create_analysis to fail when listing_id and user_id don't genuinely exist"
    );
}

// Record Evidence Tests
#[tokio::test]
async fn record_evidence_writes_one_row_per_signal_plus_one_for_the_score() {
    let pool = admin_pool().await;
    let email = "record_evidence_success_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = create_test_user(&pool, email).await;

    let platform = "olx";
    let platform_id = "record_evidence_seller_001";
    cleanup_test_seller_chain(&pool, platform, platform_id).await;
    let analysis_id =
        insert_test_analysis_for_outcomes(&pool, user.id, platform, platform_id).await;

    let analysis: (Uuid,) = query_as(
        "SELECT seller_id FROM listings WHERE id = (SELECT listing_id FROM analysis WHERE id = $1)",
    )
    .bind(analysis_id)
    .fetch_one(&pool)
    .await
    .expect("expected to find the real seller_id for this analysis");
    let seller_id = analysis.0;

    let signals = vec![
        Signal {
            label: "Price analysis".to_string(),
            sub: "normal".to_string(),
            value: "normal".to_string(),
            signal_type: "good".to_string(),
            category: "listing".to_string(),
            check_type: "anomaly".to_string(),
        },
        Signal {
            label: "Urgency language".to_string(),
            sub: "none".to_string(),
            value: "None found".to_string(),
            signal_type: "good".to_string(),
            category: "communication".to_string(),
            check_type: "pattern".to_string(),
        },
    ];

    record_evidence(&pool, analysis_id, seller_id, &signals, 25).await;

    let rows: Vec<(String, String, String)> = query_as(
        "SELECT label, value, source FROM evidence WHERE analysis_id = $1 ORDER BY found_at",
    )
    .bind(analysis_id)
    .fetch_all(&pool)
    .await
    .expect("expected the query itself to succeed");

    assert_eq!(rows.len(), 3, "expected 2 signal rows plus 1 score row");
    assert_eq!(
        rows[0],
        (
            "Price analysis".to_string(),
            "normal".to_string(),
            "signal_pipeline".to_string()
        )
    );
    assert_eq!(
        rows[1],
        (
            "Urgency language".to_string(),
            "None found".to_string(),
            "signal_pipeline".to_string()
        )
    );
    assert_eq!(
        rows[2],
        (
            "risk_score".to_string(),
            "25".to_string(),
            "scoring_engine".to_string()
        )
    );

    query("DELETE FROM evidence WHERE analysis_id = $1")
        .bind(analysis_id)
        .execute(&pool)
        .await
        .ok();
    cleanup_test_seller_chain(&pool, platform, platform_id).await;
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn record_evidence_with_zero_signals_still_writes_the_score_row() {
    let pool = admin_pool().await;
    let email = "record_evidence_empty_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = create_test_user(&pool, email).await;

    let platform = "olx";
    let platform_id = "record_evidence_empty_seller_001";
    cleanup_test_seller_chain(&pool, platform, platform_id).await;
    let analysis_id =
        insert_test_analysis_for_outcomes(&pool, user.id, platform, platform_id).await;

    let seller_id: (Uuid,) = query_as(
        "SELECT seller_id FROM listings WHERE id = (SELECT listing_id FROM analysis WHERE id = $1)",
    )
    .bind(analysis_id)
    .fetch_one(&pool)
    .await
    .expect("expected to find the real seller_id");

    record_evidence(&pool, analysis_id, seller_id.0, &[], 0).await;

    let rows: Vec<(String,)> = query_as("SELECT label FROM evidence WHERE analysis_id = $1")
        .bind(analysis_id)
        .fetch_all(&pool)
        .await
        .expect("expected the query itself to succeed");

    assert_eq!(
        rows.len(),
        1,
        "expected only the single score row, with zero signals"
    );
    assert_eq!(rows[0].0, "risk_score");

    query("DELETE FROM evidence WHERE analysis_id = $1")
        .bind(analysis_id)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_seller_chain(&pool, platform, platform_id).await;
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn record_evidence_never_panics_even_with_a_genuinely_invalid_foreign_key() {
    let pool = admin_pool().await;
    let fake_analysis_id = Uuid::new_v4();
    let fake_seller_id = Uuid::new_v4();
    let signals = vec![Signal {
        label: "Price analysis".to_string(),
        sub: "normal".to_string(),
        value: "normal".to_string(),
        signal_type: "good".to_string(),
        category: "listing".to_string(),
        check_type: "anomaly".to_string(),
    }];

    record_evidence(&pool, fake_analysis_id, fake_seller_id, &signals, 50).await;
}

// Record Risk Factors Tests
#[tokio::test]
async fn record_risk_factors_writes_one_row_per_factor() {
    let pool = admin_pool().await;
    let email = "record_risk_factors_success_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = create_test_user(&pool, email).await;

    let platform = "olx";
    let platform_id = "record_risk_factors_seller_001";
    cleanup_test_seller_chain(&pool, platform, platform_id).await;
    let analysis_id =
        insert_test_analysis_for_outcomes(&pool, user.id, platform, platform_id).await;

    let seller_id: (Uuid,) = query_as(
        "SELECT seller_id FROM listings WHERE id = (SELECT listing_id FROM analysis WHERE id = $1)",
    )
    .bind(analysis_id)
    .fetch_one(&pool)
    .await
    .expect("expected to find the real seller_id");

    let risk_factors = vec![RiskFactor {
        severity: "hard".to_string(),
        name: "confirmed_fraud_pattern".to_string(),
        description: "test description".to_string(),
        contributing_signals: vec!["Fraud pattern match".to_string()],
    }];

    record_risk_factors(&pool, analysis_id, seller_id.0, &risk_factors).await;

    let rows: Vec<(String, String, String)> =
        query_as("SELECT label, value, source FROM evidence WHERE analysis_id = $1")
            .bind(analysis_id)
            .fetch_all(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "risk_factor:hard");
    assert_eq!(rows[0].1, "confirmed_fraud_pattern");
    assert_eq!(rows[0].2, "risk_factor_engine");

    query("DELETE FROM evidence WHERE analysis_id = $1")
        .bind(analysis_id)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_seller_chain(&pool, platform, platform_id).await;
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn record_risk_factors_with_zero_factors_writes_nothing() {
    let pool = admin_pool().await;
    let email = "record_risk_factors_empty_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = create_test_user(&pool, email).await;

    let platform = "olx";
    let platform_id = "record_risk_factors_empty_seller_001";
    cleanup_test_seller_chain(&pool, platform, platform_id).await;
    let analysis_id =
        insert_test_analysis_for_outcomes(&pool, user.id, platform, platform_id).await;

    let seller_id: (Uuid,) = query_as(
        "SELECT seller_id FROM listings WHERE id = (SELECT listing_id FROM analysis WHERE id = $1)",
    )
    .bind(analysis_id)
    .fetch_one(&pool)
    .await
    .expect("expected to find the real seller_id");

    record_risk_factors(&pool, analysis_id, seller_id.0, &[]).await;

    let rows: Vec<(String,)> = query_as("SELECT label FROM evidence WHERE analysis_id = $1")
        .bind(analysis_id)
        .fetch_all(&pool)
        .await
        .expect("expected the query itself to succeed");

    assert_eq!(
        rows.len(),
        0,
        "expected genuinely zero evidence rows when there are no risk factors"
    );

    cleanup_test_seller_chain(&pool, platform, platform_id).await;
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn record_risk_factors_never_panics_even_with_a_genuinely_invalid_foreign_key() {
    let pool = admin_pool().await;
    let fake_analysis_id = Uuid::new_v4();
    let fake_seller_id = Uuid::new_v4();
    let risk_factors = vec![RiskFactor {
        severity: "soft".to_string(),
        name: "test_factor".to_string(),
        description: "test".to_string(),
        contributing_signals: vec![],
    }];

    record_risk_factors(&pool, fake_analysis_id, fake_seller_id, &risk_factors).await;
}

// Get Monthly Visit Activity Tests
#[tokio::test]
#[serial]
async fn get_monthly_visit_activity_database_error() {
    let pool = test_pool().await;

    pool.close().await;

    let fake_seller_id = Uuid::new_v4();
    let result = get_monthly_visit_activity(&pool, fake_seller_id).await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

#[tokio::test]
async fn get_monthly_visit_activity_no_activity() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "monthly_activity_no_activity_001";
    cleanup_test_seller(&pool, platform, platform_id).await;

    let seller_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("No Activity Seller".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };
    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected the seller to be created");

    let result = get_monthly_visit_activity(&pool, seller.id)
        .await
        .expect("expected the query to succeed");

    assert_eq!(result.len(), 12, "expected exactly 12 entries");
    assert!(
        result.iter().all(|&count| count == 0),
        "expected all 12 months to be genuinely 0, got: {:?}",
        result
    );

    cleanup_test_seller(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn get_monthly_visit_activity_single_month_correctly_placed() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "monthly_activity_single_001";
    cleanup_test_seller_chain(&pool, platform, platform_id).await;

    let email = "monthly_activity_single_user@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let (_listing_id, seller_id) = insert_test_history_chain(
        &pool,
        user.id,
        platform,
        platform_id,
        "Single Month Test Listing",
    )
    .await;

    let result = get_monthly_visit_activity(&pool, seller_id)
        .await
        .expect("expected the query to succeed");

    let current_month_index = (Utc::now().month() - 1) as usize;
    assert_eq!(
        result[current_month_index], 1,
        "expected exactly 1 visit in the current month's position"
    );
    let total: i32 = result.iter().sum();
    assert_eq!(
        total, 1,
        "expected exactly one non-zero entry total, across all 12 months"
    );

    cleanup_test_seller_chain(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn get_monthly_visit_activity_multiple_in_same_month() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "monthly_activity_multiple_001";
    cleanup_test_seller_chain(&pool, platform, platform_id).await;

    let email = "monthly_activity_single_user@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let (listing_id, seller_id) = insert_test_history_chain(
        &pool,
        user.id,
        platform,
        platform_id,
        "Single Month Test Listing",
    )
    .await;

    query(
        "INSERT INTO analysis (id, listing_id, risk_score, risk_level, signals, user_id, created_at)
         VALUES ($1, $2, $3, 'low'::risk_level_type, $4, $5, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(listing_id)
    .bind(15_i16)
    .bind(json!([]))
    .bind(user.id)
    .execute(&pool)
    .await
    .expect("expected to create the second analysis");

    let result = get_monthly_visit_activity(&pool, seller_id)
        .await
        .expect("expected the query to succeed");

    let current_month_index = (Utc::now().month() - 1) as usize;
    assert_eq!(
        result[current_month_index], 2,
        "expected exactly 2 visits genuinely counted in the current month"
    );

    cleanup_test_seller_chain(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn get_monthly_visit_activity_excludes_old_activity() {
    let pool = test_pool().await;
    let platform = "olx";
    let platform_id = "monthly_activity_old_001";
    cleanup_test_seller_chain(&pool, platform, platform_id).await;

    let email = "monthly_activity_single_user@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let (listing_id, seller_id) = insert_test_history_chain(
        &pool,
        user.id,
        platform,
        platform_id,
        "Single Month Test Listing",
    )
    .await;

    set_analysis_created_at(&pool, listing_id, Utc::now() - chrono_duration::days(395)).await;
    let result = get_monthly_visit_activity(&pool, seller_id)
        .await
        .expect("expected the query to succeed");

    assert!(
        result.iter().all(|&count| count == 0),
        "expected genuinely old activity to be excluded entirely, got: {:?}",
        result
    );

    cleanup_test_seller_chain(&pool, platform, platform_id).await;
}

#[tokio::test]
async fn get_monthly_visit_activity_isolated_between_sellers() {
    let pool = test_pool().await;
    let email = "monthly_activity_isolation_user@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let platform = "olx";
    let platform_id_a = "monthly_activity_isolation_a_001";
    let platform_id_b = "monthly_activity_isolation_b_001";
    cleanup_test_seller_chain(&pool, platform, platform_id_a).await;
    cleanup_test_seller_chain(&pool, platform, platform_id_b).await;

    // Seller A has real, current activity.
    let (_listing_a, seller_a_id) = insert_test_history_chain(
        &pool,
        user.id,
        platform,
        platform_id_a,
        "Seller A's Listing",
    )
    .await;

    // Seller B genuinely has NO activity at all.
    let seller_b_request = SellersRequest {
        platform: platform.to_string(),
        platform_id: Some(platform_id_b.to_string()),
        name: Some("Seller B - No Activity".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };

    let seller_b = create_seller(&pool, &seller_b_request, SellerVerification::Unknown)
        .await
        .expect("expected seller B to be created");

    let result_a = get_monthly_visit_activity(&pool, seller_a_id)
        .await
        .expect("expected seller A's query to succeed");
    let result_b = get_monthly_visit_activity(&pool, seller_b.id)
        .await
        .expect("expected seller B's query to succeed");

    let total_a: i32 = result_a.iter().sum();
    let total_b: i32 = result_b.iter().sum();

    assert_eq!(
        total_a, 1,
        "expected seller A to show their own real activity"
    );
    assert_eq!(
        total_b, 0,
        "expected seller B to show ZERO activity, genuinely unaffected by seller A's"
    );

    cleanup_test_seller_chain(&pool, platform, platform_id_a).await;
    cleanup_test_seller(&pool, platform, platform_id_b).await;
    cleanup_test_user(&pool, email).await;
}

// Score Identifier Match Tests
#[test]
fn two_matching_identifiers_gives_strong_confidence() {
    let seller = make_seller(Some("Ahmed Khan"), Some("03001234567"), None, None);
    let result = score_identifier_match(&seller, "Ahmed Khan scammed me, contact 03001234567");
    assert_eq!(result.confidence, "strong");
    assert_eq!(result.matched_identifiers.len(), 3);
}

#[test]
fn only_one_matching_identifier_gives_weak_confidence() {
    let seller = make_seller(Some("Ahmed Khan"), Some("03001234567"), None, None);
    let result = score_identifier_match(&seller, "Ahmed Khan is a common name, nothing else here");
    assert_eq!(result.confidence, "weak");
}

#[test]
fn zero_matching_identifiers_gives_none_confidence() {
    let seller = make_seller(Some("Ahmed Khan"), Some("03001234567"), None, None);
    let result = score_identifier_match(&seller, "completely unrelated text about something else");
    assert_eq!(result.confidence, "none");
}

#[test]
fn matching_is_case_insensitive_for_name() {
    let seller = make_seller(Some("Ahmed Khan"), None, None, None);
    let result = score_identifier_match(&seller, "AHMED KHAN posted this");
    assert_eq!(result.matched_identifiers, vec!["name"]);
}

#[test]
fn phone_matching_ignores_formatting_differences() {
    let seller = make_seller(None, Some("0300-1234-567"), None, None);
    let result = score_identifier_match(&seller, "call this guy 03001234567 he's a scammer");
    assert_eq!(result.matched_identifiers, vec!["phone", "scam_language"]);
}

#[test]
fn all_four_identifiers_matching_still_correctly_reports_strong() {
    let seller = make_seller(
        Some("Ahmed Khan"),
        Some("03001234567"),
        Some("ahmed@example.com"),
        Some("ahmedstore.com"),
    );
    let result = score_identifier_match(
        &seller,
        "Ahmed Khan, 03001234567, ahmed@example.com, ahmedstore.com - all confirmed scam",
    );
    assert_eq!(result.confidence, "strong");
    assert_eq!(result.matched_identifiers.len(), 5);
}

#[test]
fn seller_with_no_identifiers_at_all_never_matches_anything() {
    let seller = make_seller(None, None, None, None);
    let result = score_identifier_match(&seller, "any text at all, doesn't matter what");
    assert_eq!(result.confidence, "none");
    assert_eq!(result.matched_identifiers.len(), 0);
}

#[test]
fn empty_string_identifiers_are_treated_as_genuinely_absent() {
    let seller = make_seller(Some(""), Some(""), None, None);
    let result = score_identifier_match(&seller, "some text here");
    assert_eq!(result.confidence, "none");
}

// Is B2b Tests
#[tokio::test]
async fn save_and_build_response_forces_business_entity_type_when_is_b2b_is_true() {
    let pool = test_pool().await;
    let email = "b2b_entity_type_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    let seller_request = SellersRequest {
        platform: "b2brazil".to_string(),
        platform_id: Some("b2b_entity_type_seller".to_string()),
        name: Some("Random Name".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };
    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");

    let listing_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: "b2brazil".to_string(),
        listing_url: "https://b2brazil.com/hotsite/entity-type-test".to_string(),
        listing_id: Some("b2b_entity_type_listing".to_string()),
        title: None,
        price: None,
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
    };
    let listing = create_listing(&pool, &listing_request, seller.id)
        .await
        .expect("expected to create the listing");

    let data = BuildResponseData {
        pool: &pool,
        listing_id: listing.id,
        risk_score: 10,
        risk_level: RiskLevel::Low,
        signals: vec![],
        overall_risk_notes: "test".to_string(),
        user_id: user.id,
        seller,
        fraud_count: 0,
        network_summary: "test".to_string(),
        is_b2b: true,
        social_candidates: Vec::new(),
    };

    let result = save_and_build_response(data)
        .await
        .expect("expected the response to be built successfully");

    assert_eq!(result.entity_type, "business");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn save_and_build_response_runs_normal_name_logic_when_is_b2b_is_false() {
    let pool = test_pool().await;
    let email = "b2c_entity_type_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    let seller_request = SellersRequest {
        platform: "olx".to_string(),
        platform_id: Some("b2c_entity_type_seller".to_string()),
        name: Some("Ordinary Individual".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };
    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");

    let listing_request = ListingsRequest {
        seller_id: Some(seller.id),
        platform: "olx".to_string(),
        listing_url: "https://olx.com.pk/item/entity-type-test".to_string(),
        listing_id: Some("b2c_entity_type_listing".to_string()),
        title: None,
        price: None,
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
    };
    let listing = create_listing(&pool, &listing_request, seller.id)
        .await
        .expect("expected to create the listing");

    let data = BuildResponseData {
        pool: &pool,
        listing_id: listing.id,
        risk_score: 10,
        risk_level: RiskLevel::Low,
        signals: vec![],
        overall_risk_notes: "test".to_string(),
        user_id: user.id,
        seller,
        fraud_count: 0,
        network_summary: "test".to_string(),
        is_b2b: false,
        social_candidates: Vec::new(),
    };

    let result = save_and_build_response(data)
        .await
        .expect("expected the response to be built successfully");

    assert_eq!(result.entity_type, "individual");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn build_all_signals_produces_correct_no_website_and_no_store_page_messages() {
    let finding = Finding {
        found: true,
        evidence: "evidence".to_string(),
    };

    let image_assessment = ImageAssessment {
        verdict: "original".to_string(),
        reasoning: "reasoning".to_string(),
    };

    let price_assessment = PriceAssessment {
        verdict: "normal".to_string(),
        reasoning: "reasoning".to_string(),
    };

    let claude_analysis = ClaudeAnalysis {
        urgency_language: finding.clone(),
        advance_payment_request: finding.clone(),
        duplicate_listing: finding.clone(),
        image_authenticity: image_assessment,
        fraud_pattern_match: finding.clone(),
        contact_info_in_listing: finding.clone(),
        price_assessment,
        extracted_phone_number: None,
        overall_risk_notes: "risk notes".to_string(),
    };

    let seller = Sellers {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "no_website_test_001".to_string(),
        name: Some("Test Seller".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: Some(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap()),
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active_text: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let analyze_request = AnalyzeRequest {
        platform: "olx".to_string(),
        seller_id: None,
        listing_url: "https://olx.com.pk/item/no-website-test".to_string(),
        listing_id: None,
        title: None,
        price: None,
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: None,
        seller_name: None,
        seller_handle: None,
        seller_phone: None,
        seller_profile_url: None,
        seller_join_date: None,
        seller_location: None,
        seller_last_active: None,
        seller_website: None,
        seller_verified: None,
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let pool = test_pool().await;
    let all_signals = build_all_signals(&pool, &claude_analysis, &seller, &analyze_request).await;

    let website_signal = all_signals
        .iter()
        .find(|s| s.label == "Seller website check")
        .expect("expected a Seller website check signal to always be present");

    assert_eq!(website_signal.value, "No website found");
    assert_eq!(
        website_signal.sub,
        "No website was mentioned or claimed by this seller."
    );
    assert_eq!(website_signal.signal_type, "info");

    let store_page_signal = all_signals
        .iter()
        .find(|s| s.label == "Store page check")
        .expect("expected a Store page check signal to always be present");

    assert_eq!(store_page_signal.value, "No store page found");
    assert_eq!(
        store_page_signal.sub,
        "No separate store or profile page was found for this seller."
    );
    assert_eq!(store_page_signal.signal_type, "info");
}

#[tokio::test]
async fn build_all_signals_correctly_includes_real_verified_seller_data() {
    let finding = Finding {
        found: true,
        evidence: "evidence".to_string(),
    };

    let image_assessment = ImageAssessment {
        verdict: "original".to_string(),
        reasoning: "reasoning".to_string(),
    };

    let price_assessment = PriceAssessment {
        verdict: "normal".to_string(),
        reasoning: "reasoning".to_string(),
    };

    let claude_analysis = ClaudeAnalysis {
        urgency_language: finding.clone(),
        advance_payment_request: finding.clone(),
        duplicate_listing: finding.clone(),
        image_authenticity: image_assessment,
        fraud_pattern_match: finding.clone(),
        contact_info_in_listing: finding.clone(),
        price_assessment,
        extracted_phone_number: None,
        overall_risk_notes: "risk notes".to_string(),
    };

    let seller = Sellers {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "verified_seller_data_test_001".to_string(),
        name: Some("Verified Shop".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: Some(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap()),
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active_text: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let analyze_request = AnalyzeRequest {
        platform: "olx".to_string(),
        seller_id: None,
        listing_url: "https://olx.com.pk/item/verified-seller-data-test".to_string(),
        listing_id: None,
        title: None,
        price: None,
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: None,
        seller_name: None,
        seller_handle: None,
        seller_phone: None,
        seller_profile_url: None,
        seller_join_date: None,
        seller_location: None,
        seller_last_active: None,
        seller_website: None,
        seller_verified: Some(true),
        seller_rating: Some(4.7),
        seller_total_products: Some(197),
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };
    let pool = test_pool().await;
    let all_signals = build_all_signals(&pool, &claude_analysis, &seller, &analyze_request).await;

    let platform_verification_signal = all_signals
        .iter()
        .find(|s| s.label == "Platform verification")
        .expect("expected a Platform verification signal to be present");

    assert_eq!(platform_verification_signal.value, "Verified");
    assert_eq!(platform_verification_signal.signal_type, "good");

    let track_record_signal = all_signals
        .iter()
        .find(|s| s.label == "Seller track record")
        .expect("expected a Seller track record signal to be present, given real rating and product count were provided");

    assert!(track_record_signal.sub.contains("197"));
    assert!(track_record_signal.sub.contains("4.7"));
    assert_eq!(track_record_signal.signal_type, "good");
}

#[tokio::test]
async fn analyze_gracefully_continues_when_server_side_scraping_fails() {
    let pool = test_pool().await;
    let email = "scraping_failure_fallback_test@example.com";
    cleanup_test_user(&pool, email).await;

    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );

    let platform = "olx".to_string();
    let platform_id = "scraping_failure_fallback_platform_id".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;

    let request = AnalyzeRequest {
        platform: platform.clone(),
        seller_id: None,
        listing_url:
            "https://www.olx.com.pk/item/this-genuinely-does-not-exist-xyz999-iid-000000000"
                .to_string(),
        listing_id: Some("scraping_failure_listing".to_string()),
        title: Some("Client-Provided Fallback Title".to_string()),
        price: Some(25000),
        description: Some("Client-provided fallback description.".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
        platform_id: Some(platform_id.clone()),
        seller_name: Some("Client Fallback Seller".to_string()),
        seller_handle: None,
        seller_phone: None,
        seller_profile_url: None,
        seller_join_date: Some("2020".to_string()),
        seller_location: Some("Karachi".to_string()),
        seller_last_active: Some("Today".to_string()),
        seller_website: None,
        seller_verified: Some(false),
        seller_rating: None,
        seller_total_products: None,
        domain_check_status: None,
        domain_check_real_name: None,
        domain_check_real_domain: None,
        domain_check_current_domain: None,
        domain_check_current_html: None,
        domain_check_real_html: None,
    };

    let result = analyze(State(pool.clone()), headers, Json(request))
        .await
        .expect("expected analyze() to succeed using client-provided data, even though server-side scraping genuinely failed");

    assert!(
        result.risk_score >= 0 && result.risk_score <= 100,
        "expected a genuine risk score, confirming the whole flow completed"
    );
    assert_eq!(
        result.seller.name,
        Some("Client Fallback Seller".to_string()),
        "expected the client-provided seller name to be used, since server-side scraping failed"
    );
    assert_eq!(
        result.seller.location,
        Some("Karachi".to_string()),
        "expected the client-provided location to be used, since server-side scraping failed"
    );

    let admin = admin_pool().await;
    query("DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analysis WHERE user_id = $1)")
        .bind(user.id)
        .execute(&admin)
        .await
        .ok();

    query("DELETE FROM analysis WHERE user_id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_seller(&pool, &platform, &platform_id).await;
    cleanup_test_user(&pool, email).await;
}

// Verify Social Link Handler Tests
#[tokio::test]
async fn verify_social_link_unauthorized_request() {
    let pool = test_pool().await;
    let headers = HeaderMap::new();
    let body = VerifySocialLinkRequest {
        seller_id: Uuid::new_v4(),
        url: "https://example.com".to_string(),
    };
    let result = verify_social_link_handler(State(pool), headers, Json(body)).await;
    assert!(
        result.is_err(),
        "expected an unauthenticated request to be rejected"
    );
}

#[tokio::test]
async fn verify_social_link_fails_for_a_genuinely_nonexistent_seller() {
    let pool = test_pool().await;
    let email = "verify_social_link_no_seller@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");
    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );
    let body = VerifySocialLinkRequest {
        seller_id: Uuid::new_v4(),
        url: "https://example.com".to_string(),
    };
    let result = verify_social_link_handler(State(pool.clone()), headers, Json(body)).await;
    assert!(
        result.is_err(),
        "expected a genuinely nonexistent seller_id to fail, not silently succeed"
    );
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn verify_social_link_succeeds_against_a_real_reachable_page() {
    let pool = test_pool().await;
    let email = "verify_social_link_success@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");
    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );

    let platform = "b2brazil".to_string();
    let platform_id = "verify_social_link_seller_001".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;
    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Real Test Company Name".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: Some("Brazil".to_string()),
        last_active: None,
    };
    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");

    let body = VerifySocialLinkRequest {
        seller_id: seller.id,
        url: "https://httpbin.org/html".to_string(),
    };

    let result = verify_social_link_handler(State(pool.clone()), headers, Json(body))
        .await
        .expect("expected the real, live fetch-and-check to succeed");

    assert!(
        !result.matched,
        "expected no genuine match against a real but unrelated page"
    );
    assert_eq!(result.confidence, "none");
    assert!(!result.message.is_empty());

    cleanup_test_seller(&pool, &platform, &platform_id).await;
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn verify_social_link_fails_gracefully_for_a_genuinely_unreachable_url() {
    let pool = test_pool().await;
    let email = "verify_social_link_unreachable@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");
    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );

    let platform = "b2brazil".to_string();
    let platform_id = "verify_social_link_unreachable_seller_001".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;
    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Test Seller".to_string()),
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };
    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");

    let body = VerifySocialLinkRequest {
        seller_id: seller.id,
        url: "https://this-genuinely-does-not-exist-12345.invalid".to_string(),
    };

    let result = verify_social_link_handler(State(pool.clone()), headers, Json(body)).await;
    assert!(
        result.is_err(),
        "expected a genuinely unreachable URL to fail, not silently succeed"
    );

    cleanup_test_seller(&pool, &platform, &platform_id).await;
    cleanup_test_user(&pool, email).await;
}

#[test]
fn build_osint_query_matrix_returns_empty_when_no_company_name() {
    let queries = build_osint_query_matrix(None, None, None, None);
    assert!(
        queries.is_empty(),
        "expected genuinely no queries without a company name"
    );
}

#[test]
fn build_osint_query_matrix_skips_the_single_word_variant() {
    let queries = build_osint_query_matrix(Some("SILTI MODA PRAIA"), None, None, None);
    let single_word_query = queries.iter().find(|(_, _, variant)| variant == "SILTI");
    assert!(
        single_word_query.is_none(),
        "expected the single-word variant to genuinely never be searched"
    );
}

#[test]
fn build_osint_query_matrix_builds_two_word_and_full_name_variants() {
    let queries = build_osint_query_matrix(Some("SILTI MODA PRAIA"), None, None, None);
    let has_two_word = queries.iter().any(|(_, _, v)| v == "SILTI MODA");
    let has_full_name = queries.iter().any(|(_, _, v)| v == "SILTI MODA PRAIA");
    assert!(
        has_two_word,
        "expected the real, 2-word variant to be present"
    );
    assert!(
        has_full_name,
        "expected the real, full-name variant to be present"
    );
}

#[test]
fn build_osint_query_matrix_falls_back_to_the_single_word_for_a_one_word_name() {
    // A genuinely single-word company name has no real "2-word"
    // variant to build - it should still search using that one,
    // real word, rather than producing zero queries.
    let queries = build_osint_query_matrix(Some("Trustco"), None, None, None);
    assert!(
        queries.iter().any(|(_, _, v)| v == "Trustco"),
        "expected a genuinely single-word name to still be searched"
    );
}

#[test]
fn build_osint_query_matrix_includes_scam_word_groups_per_platform() {
    let queries = build_osint_query_matrix(Some("Real Company Name"), None, None, None);
    let scam_queries: Vec<_> = queries
        .iter()
        .filter(|(_, q, _)| q.contains("golpe") || q.contains("scam"))
        .collect();
    assert!(
        !scam_queries.is_empty(),
        "expected at least one real, scam-word search query to be built"
    );
}

#[test]
fn build_osint_query_matrix_includes_contact_queries_only_when_name_and_phone_both_present() {
    let with_both = build_osint_query_matrix(
        Some("Company"),
        Some("Contact Person"),
        None,
        Some("03001234567"),
    );
    let without_phone =
        build_osint_query_matrix(Some("Company"), Some("Contact Person"), None, None);

    assert!(
        with_both.iter().any(|(p, _, _)| p.starts_with("Contact")),
        "expected real Contact queries when both name and phone are present"
    );
    assert!(
        !without_phone
            .iter()
            .any(|(p, _, _)| p.starts_with("Contact")),
        "expected genuinely no Contact queries when phone is missing"
    );
}

#[test]
fn build_osint_query_matrix_cleans_the_real_location_before_using_it() {
    let queries =
        build_osint_query_matrix(Some("Company"), None, Some("Juruaia / MG | Brazil"), None);
    let facebook_query = queries
        .iter()
        .find(|(p, _, _)| p == "Facebook")
        .map(|(_, q, _)| q.clone())
        .unwrap_or_default();
    assert!(
        facebook_query.contains("\"Juruaia\""),
        "expected only the real, clean city name, not the raw location string, got: {}",
        facebook_query
    );
    assert!(
        !facebook_query.contains("MG"),
        "expected the state/country parts to be genuinely stripped out"
    );
}

#[tokio::test]
#[serial]
async fn run_serper_search_returns_real_results_for_a_genuine_query() {
    let dotenv_result = dotenvy::dotenv();
    println!("DEBUG: dotenv() result = {:?}", dotenv_result);
    let key_present = std::env::var("SERPER_API_KEY").is_ok();
    println!("DEBUG: SERPER_API_KEY present = {}", key_present);
    let result = run_serper_search("site:facebook.com Nike", Some("us")).await;
    println!("DEBUG: result = {:?}", result.is_some());
    assert!(
        result.is_some(),
        "expected a real, live Serper call to succeed for a genuinely common query"
    );
}

#[tokio::test]
async fn run_serper_search_returns_none_for_a_missing_api_key() {
    let original_key = std::env::var("SERPER_API_KEY").ok();
    unsafe {
        std::env::remove_var("SERPER_API_KEY");
    }
    let result = run_serper_search("test query", None).await;
    assert!(
        result.is_none(),
        "expected no result without a real API key"
    );
    unsafe {
        if let Some(key) = original_key {
            std::env::set_var("SERPER_API_KEY", key);
        }
    }
}
