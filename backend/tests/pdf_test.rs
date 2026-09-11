mod common;

use crate::common::{cleanup_test_seller, cleanup_test_user, test_pool};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use backend::{
    handlers::pdf::download_evidence_pdf,
    models::{
        analysis::RiskLevel,
        history::{HistoryDetailResponse, ReportSummary},
        listings::ListingsRequest,
        sellers::{SellerVerification, SellersRequest, SellersResponse},
    },
    services::{
        analysis::{CreateAnalysisData, create_analysis},
        auth::{create_session, find_or_create_user_by_email},
        listings::create_listing,
        pdf_report::{capitalize, generate_evidence_pdf, risk_color_and_label, status_color},
        sellers::create_seller,
    },
};
use chrono::Utc;
use reqwest::{StatusCode, header};
use serde_json::json;
use sqlx::query;
use uuid::Uuid;

fn make_seller_response() -> SellersResponse {
    SellersResponse {
        id: Uuid::now_v7(),
        platform: "olx".to_string(),
        platform_id: "test_seller".to_string(),
        name: Some("Test Seller".to_string()),
        handle: Some("test_handle".to_string()),
        phone: Some("03001234567".to_string()),
        account_age: "2 years".to_string(),
        verification: SellerVerification::Unknown,
        location: Some("Lahore".to_string()),
        last_active: Some("Today".to_string()),
        network_summary: "Clean record.".to_string(),
        monthly_activity: vec![0, 1, 2, 3, 0, 0, 0, 0, 5, 0, 0, 0],
    }
}

fn make_detail(
    risk_score: i16,
    risk_level: RiskLevel,
    signals: serde_json::Value,
    risk_factors: Option<serde_json::Value>,
    social_candidates: Option<serde_json::Value>,
    reports: Vec<ReportSummary>,
) -> HistoryDetailResponse {
    HistoryDetailResponse {
        id: Uuid::now_v7(),
        created_at: Utc::now(),
        listing_title: Some("Test Listing".to_string()),
        listing_url: "https://olx.com.pk/item/test".to_string(),
        platform: "olx".to_string(),
        risk_score,
        risk_level,
        signals,
        risk_factors,
        social_candidates,
        seller: make_seller_response(),
        fraud_report_count: 0,
        reported: false,
        reports,
    }
}

#[tokio::test]
async fn download_evidence_pdf_unauthorized_request() {
    let pool = test_pool().await;
    let headers = HeaderMap::new();
    let result = download_evidence_pdf(State(pool), headers, Path(Uuid::new_v4())).await;
    assert!(
        result.is_err(),
        "expected an unauthenticated request to be rejected"
    );
}

#[tokio::test]
async fn download_evidence_pdf_fails_for_a_genuinely_nonexistent_analysis() {
    let pool = test_pool().await;
    let email = "download_pdf_no_analysis@example.com";
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

    let result = download_evidence_pdf(State(pool.clone()), headers, Path(Uuid::new_v4())).await;
    assert!(
        result.is_err(),
        "expected a genuinely nonexistent analysis_id to fail, not silently succeed"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn download_evidence_pdf_fails_when_the_analysis_belongs_to_someone_else() {
    let pool = test_pool().await;
    let owner_email = "download_pdf_owner@example.com";
    let requester_email = "download_pdf_requester@example.com";
    cleanup_test_user(&pool, owner_email).await;
    cleanup_test_user(&pool, requester_email).await;

    let (owner, _) = find_or_create_user_by_email(&pool, owner_email)
        .await
        .expect("expected to create the owner");
    let (requester, _) = find_or_create_user_by_email(&pool, requester_email)
        .await
        .expect("expected to create the requester");
    let requester_token = create_session(&pool, requester.id)
        .await
        .expect("expected to create a real session");

    let platform = "olx".to_string();
    let platform_id = "download_pdf_owner_seller_001".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;
    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Owner's Seller".to_string()),
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
        platform: platform.clone(),
        listing_url: "https://olx.com.pk/item/download-pdf-owner-test".to_string(),
        listing_id: Some("download_pdf_owner_listing_001".to_string()),
        title: Some("Owner's Listing".to_string()),
        price: Some(1000),
        description: None,
        category: None,
        image_urls: None,
        posted_date: None,
    };
    let listing = create_listing(&pool, &listing_request, seller.id)
        .await
        .expect("expected to create the listing");

    let analysis = create_analysis(CreateAnalysisData {
        pool: &pool,
        listing_id: listing.id,
        risk_score: 10,
        risk_level: RiskLevel::Low,
        signals: json!([]),
        network_summary: "test".to_string(),
        claude_raw: String::new(),
        user_id: owner.id,
        confidence_level: "high".to_string(),
        confidence_reasoning: "test".to_string(),
        risk_factors: json!([]),
        social_candidates: json!([]),
    })
    .await
    .expect("expected the analysis to be created");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", requester_token))
            .expect("expected to insert the header value"),
    );

    let result = download_evidence_pdf(State(pool.clone()), headers, Path(analysis.id)).await;
    assert!(
        result.is_err(),
        "expected someone else's real analysis to be genuinely inaccessible, not returned"
    );

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
    cleanup_test_user(&pool, owner_email).await;
    cleanup_test_user(&pool, requester_email).await;
}

#[tokio::test]
async fn download_evidence_pdf_succeeds_and_returns_real_pdf_bytes() {
    let pool = test_pool().await;
    let email = "download_pdf_success@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");
    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let platform = "olx".to_string();
    let platform_id = "download_pdf_success_seller_001".to_string();
    cleanup_test_seller(&pool, &platform, &platform_id).await;
    let seller_request = SellersRequest {
        platform: platform.clone(),
        platform_id: Some(platform_id.clone()),
        name: Some("Real Test Seller".to_string()),
        handle: Some("real_handle".to_string()),
        phone: Some("03001234567".to_string()),
        profile_url: None,
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
        listing_url: "https://olx.com.pk/item/download-pdf-success-test".to_string(),
        listing_id: Some("download_pdf_success_listing_001".to_string()),
        title: Some("Real Test Listing".to_string()),
        price: Some(50000),
        description: Some("Test description".to_string()),
        category: None,
        image_urls: None,
        posted_date: None,
    };
    let listing = create_listing(&pool, &listing_request, seller.id)
        .await
        .expect("expected to create the listing");

    let signals = json!([
        { "label": "Price analysis", "sub": "Normal for this category.", "value": "normal", "type": "good" },
        { "label": "Domain check", "sub": "Matches the real domain.", "value": "Verified", "type": "good" }
    ]);
    let risk_factors = json!([
        { "severity": "soft", "name": "safely_history_flagged", "description": "Checked before.", "contributing_signals": ["Safely history"] }
    ]);

    let analysis = create_analysis(CreateAnalysisData {
        pool: &pool,
        listing_id: listing.id,
        risk_score: 45,
        risk_level: RiskLevel::Caution,
        signals,
        network_summary: "test".to_string(),
        claude_raw: String::new(),
        user_id: user.id,
        confidence_level: "high".to_string(),
        confidence_reasoning: "test".to_string(),
        risk_factors,
        social_candidates: json!([]),
    })
    .await
    .expect("expected the analysis to be created");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );

    let response = download_evidence_pdf(State(pool.clone()), headers, Path(analysis.id))
        .await
        .expect("expected the real PDF to be generated successfully")
        .into_response();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("expected a real Content-Type header")
        .to_str()
        .expect("expected the header to be valid text");
    assert_eq!(content_type, "application/pdf");

    let content_disposition = response
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .expect("expected a real Content-Disposition header")
        .to_str()
        .expect("expected the header to be valid text");
    assert!(content_disposition.contains("attachment"));
    assert!(content_disposition.contains(&analysis.id.to_string()));

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("expected to read the real, generated PDF bytes");
    assert!(
        !body_bytes.is_empty(),
        "expected the real PDF to contain actual, non-empty content"
    );
    // A genuine PDF file's real, raw bytes always begin with this
    // exact, standard magic-number header.
    assert!(
        body_bytes.starts_with(b"%PDF"),
        "expected the real, returned bytes to genuinely be a valid PDF file"
    );

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

#[test]
fn generate_evidence_pdf_succeeds_with_full_data() {
    let detail = make_detail(
        45,
        RiskLevel::Caution,
        json!([
            { "label": "Price analysis", "sub": "Normal for this category.", "value": "normal", "type": "good" },
            { "label": "Domain check", "sub": "Matches the real domain.", "value": "Verified", "type": "good" },
        ]),
        Some(json!([
            { "severity": "soft", "name": "safely_history_flagged", "description": "Checked before.", "contributing_signals": ["Safely history"] }
        ])),
        Some(json!([
            { "platform": "Facebook", "variant_searched": "Test", "found": true, "candidates": [] }
        ])),
        vec![],
    );

    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a full, real data set to generate successfully"
    );

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "expected genuine, non-empty PDF bytes");
    assert!(
        bytes.starts_with(b"%PDF"),
        "expected a real, valid PDF file signature"
    );
}

// Missing / minimal optional data

#[test]
fn generate_evidence_pdf_succeeds_with_no_risk_factors() {
    let detail = make_detail(10, RiskLevel::Low, json!([]), None, None, vec![]);
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a missing risk_factors field to still generate correctly"
    );
    assert!(result.unwrap().starts_with(b"%PDF"));
}

#[test]
fn generate_evidence_pdf_succeeds_with_empty_risk_factors_array() {
    let detail = make_detail(10, RiskLevel::Low, json!([]), Some(json!([])), None, vec![]);
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a genuinely empty risk_factors array to still generate correctly"
    );
}

#[test]
fn generate_evidence_pdf_succeeds_with_empty_signals_array() {
    let detail = make_detail(0, RiskLevel::Low, json!([]), None, None, vec![]);
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a genuinely empty signals array to still generate correctly"
    );
}

#[test]
fn generate_evidence_pdf_succeeds_with_no_social_candidates() {
    let detail = make_detail(10, RiskLevel::Low, json!([]), None, None, vec![]);
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a missing social_candidates field to still generate correctly"
    );
}

#[test]
fn generate_evidence_pdf_succeeds_with_empty_social_candidates_array() {
    let detail = make_detail(10, RiskLevel::Low, json!([]), None, Some(json!([])), vec![]);
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a genuinely empty social_candidates array to still generate correctly"
    );
}

#[test]
fn generate_evidence_pdf_succeeds_when_seller_has_no_optional_fields() {
    let mut detail = make_detail(10, RiskLevel::Low, json!([]), None, None, vec![]);
    detail.seller.name = None;
    detail.seller.handle = None;
    detail.seller.phone = None;
    detail.seller.location = None;
    detail.seller.last_active = None;
    detail.listing_title = None;

    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected every genuinely missing seller/listing field to fall back correctly, not panic"
    );
}

// Every real risk level

#[test]
fn generate_evidence_pdf_succeeds_for_low_risk() {
    let detail = make_detail(10, RiskLevel::Low, json!([]), None, None, vec![]);
    assert!(generate_evidence_pdf(&detail).is_ok());
}

#[test]
fn generate_evidence_pdf_succeeds_for_caution_risk() {
    let detail = make_detail(50, RiskLevel::Caution, json!([]), None, None, vec![]);
    assert!(generate_evidence_pdf(&detail).is_ok());
}

#[test]
fn generate_evidence_pdf_succeeds_for_high_risk() {
    let detail = make_detail(90, RiskLevel::High, json!([]), None, None, vec![]);
    assert!(generate_evidence_pdf(&detail).is_ok());
}

// Every real signal type

#[test]
fn generate_evidence_pdf_succeeds_with_every_real_signal_type() {
    let detail = make_detail(
        50,
        RiskLevel::Caution,
        json!([
            { "label": "A", "sub": "sub a", "value": "v", "type": "good" },
            { "label": "B", "sub": "sub b", "value": "v", "type": "caution" },
            { "label": "C", "sub": "sub c", "value": "v", "type": "info" },
            { "label": "D", "sub": "sub d", "value": "v", "type": "bad" },
            { "label": "E", "sub": "sub e", "value": "v", "type": "some_genuinely_unrecognized_type" },
        ]),
        None,
        None,
        vec![],
    );
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected every real signal type, including an unrecognized one, to generate correctly"
    );
}

#[test]
fn generate_evidence_pdf_succeeds_with_a_signal_missing_all_optional_fields() {
    let detail = make_detail(10, RiskLevel::Low, json!([{}]), None, None, vec![]);
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a genuinely empty signal object (no label/value/sub/type) to fall back correctly"
    );
}

// Every real risk factor severity

#[test]
fn generate_evidence_pdf_succeeds_with_every_real_risk_factor_severity() {
    let detail = make_detail(
        70,
        RiskLevel::High,
        json!([]),
        Some(json!([
            { "severity": "hard", "name": "confirmed_fraud", "description": "desc", "contributing_signals": [] },
            { "severity": "compound", "name": "likely_issue", "description": "desc", "contributing_signals": [] },
            { "severity": "soft", "name": "worth_noting", "description": "desc", "contributing_signals": [] },
            { "severity": "some_unrecognized_severity", "name": "unknown_case", "description": "desc", "contributing_signals": [] },
        ])),
        None,
        vec![],
    );
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected every real severity, including an unrecognized one, to generate correctly"
    );
}

#[test]
fn generate_evidence_pdf_succeeds_with_a_risk_factor_missing_description() {
    let detail = make_detail(
        50,
        RiskLevel::Caution,
        json!([]),
        Some(json!([{ "severity": "soft", "name": "no_description_case" }])),
        None,
        vec![],
    );
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a genuinely missing description to fall back correctly"
    );
}

// Reports

#[test]
fn generate_evidence_pdf_succeeds_with_no_reports_filed() {
    let detail = make_detail(10, RiskLevel::Low, json!([]), None, None, vec![]);
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a genuinely empty reports list to generate correctly"
    );
}

// Social presence found-count math

#[test]
fn generate_evidence_pdf_succeeds_with_a_mix_of_found_and_not_found_platforms() {
    let detail = make_detail(
        50,
        RiskLevel::Caution,
        json!([]),
        None,
        Some(json!([
            { "platform": "Facebook", "variant_searched": "x", "found": true, "candidates": [] },
            { "platform": "LinkedIn", "variant_searched": "x", "found": false, "candidates": [] },
            { "platform": "Reddit", "variant_searched": "x", "found": true, "candidates": [] },
        ])),
        vec![],
    );
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a genuine mix of found/not-found platforms to generate correctly"
    );
}

// Long / unusual text content

#[test]
fn generate_evidence_pdf_succeeds_with_very_long_text_values() {
    let long_text = "A".repeat(2000);
    let detail = make_detail(
        50,
        RiskLevel::Caution,
        json!([
            { "label": "Long signal", "sub": long_text.clone(), "value": "flagged", "type": "caution" }
        ]),
        None,
        None,
        vec![],
    );
    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected a very long, real sub-text to wrap correctly, not panic"
    );
}

#[test]
fn generate_evidence_pdf_succeeds_with_unicode_and_special_characters() {
    let mut detail = make_detail(10, RiskLevel::Low, json!([]), None, None, vec![]);
    detail.seller.name = Some("Açaí & Café Ltda. — 100% Orgânico".to_string());
    detail.listing_title = Some("Café ☕ Beans — São Paulo".to_string());

    let result = generate_evidence_pdf(&detail);
    assert!(
        result.is_ok(),
        "expected genuine, real Portuguese/accented characters to render without panicking"
    );
}

#[test]
fn generate_evidence_pdf_produces_different_byte_content_for_different_real_data() {
    let detail_a = make_detail(10, RiskLevel::Low, json!([]), None, None, vec![]);
    let detail_b = make_detail(90, RiskLevel::High, json!([]), None, None, vec![]);

    let bytes_a = generate_evidence_pdf(&detail_a).expect("expected detail_a to generate");
    let bytes_b = generate_evidence_pdf(&detail_b).expect("expected detail_b to generate");

    assert_ne!(
        bytes_a, bytes_b,
        "expected genuinely different risk data to produce a genuinely different, real PDF"
    );
}

#[test]
fn status_color_returns_good_for_good_type() {
    let (color, label) = status_color("good");
    assert_eq!(label, "Good");
    let _ = color;
}

#[test]
fn status_color_returns_caution_for_caution_type() {
    let (_, label) = status_color("caution");
    assert_eq!(label, "Caution");
}

#[test]
fn status_color_returns_info_label_for_info_type() {
    let (_, label) = status_color("info");
    assert_eq!(label, "Info");
}

#[test]
fn status_color_falls_back_to_flag_for_bad() {
    let (_, label) = status_color("bad");
    assert_eq!(label, "Flag");
}

#[test]
fn status_color_falls_back_to_flag_for_a_genuinely_unrecognized_type() {
    let (_, label) = status_color("something_totally_unknown");
    assert_eq!(label, "Flag");
}

#[test]
fn status_color_is_genuinely_case_sensitive() {
    let (_, label) = status_color("Good");
    assert_eq!(label, "Flag");
}

#[test]
fn risk_color_and_label_returns_low_risk_label() {
    let (_, label) = risk_color_and_label(&RiskLevel::Low);
    assert_eq!(label, "Low risk");
}

#[test]
fn risk_color_and_label_returns_caution_label() {
    let (_, label) = risk_color_and_label(&RiskLevel::Caution);
    assert_eq!(label, "Caution");
}

#[test]
fn risk_color_and_label_returns_high_risk_label() {
    let (_, label) = risk_color_and_label(&RiskLevel::High);
    assert_eq!(label, "High risk");
}

// capitalize

#[test]
fn capitalize_capitalizes_the_first_letter_of_a_lowercase_string() {
    assert_eq!(capitalize("hello world"), "Hello world");
}

#[test]
fn capitalize_returns_an_empty_string_unchanged() {
    assert_eq!(capitalize(""), "");
}

#[test]
fn capitalize_leaves_an_already_capitalized_string_unchanged() {
    assert_eq!(capitalize("Already capitalized"), "Already capitalized");
}

#[test]
fn capitalize_only_touches_the_first_character_not_the_whole_string() {
    assert_eq!(capitalize("hELLO"), "HELLO");
}

#[test]
fn capitalize_handles_a_genuinely_single_character_string() {
    assert_eq!(capitalize("a"), "A");
}

#[test]
fn capitalize_handles_real_unicode_characters_correctly() {
    assert_eq!(capitalize("écran"), "Écran");
}

#[test]
fn capitalize_handles_a_string_that_starts_with_a_number() {
    assert_eq!(capitalize("123abc"), "123abc");
}
