mod common;
use crate::common::test_pool;
use backend::{
    models::analysis::AnalyzeRequest,
    services::{analysis::build_b2b_analysis_path, b2b_scrapers::check_b2b_page},
};
use uuid::Uuid;

#[tokio::test]
async fn check_b2b_page_fetches_and_parses_a_real_live_b2brazil_page() {
    let real_url = "https://b2brazil.com/hotsite/akuratconsultor";

    let result = check_b2b_page("b2brazil", real_url).await;

    assert!(
        result.is_some(),
        "expected a real, successful fetch and parse against B2Brazil's live site"
    );

    let (supplier, listing) = result.expect("expected to get the suplier and listing");

    assert_eq!(
        supplier.company_name,
        Some("Akurat Consultoria Empresarial".to_string())
    );
    assert_eq!(supplier.source_platform, "b2brazil");
    assert_eq!(listing.source_platform, "b2brazil");
}

#[tokio::test]
async fn check_b2b_page_returns_none_for_a_genuinely_unrecognized_platform() {
    let result = check_b2b_page("some_platform_that_does_not_exist", "https://example.com").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn check_b2b_page_returns_none_for_a_genuinely_broken_url() {
    let result = check_b2b_page(
        "b2brazil",
        "https://this-domain-genuinely-does-not-exist-xyz123.com",
    )
    .await;
    assert!(result.is_none());
}

// Build B2B Analysis Path Tests
#[tokio::test]
async fn build_b2b_analysis_path_produces_a_real_complete_result_from_the_live_site() {
    let pool = test_pool().await;
    let request = AnalyzeRequest {
        platform: "b2brazil".to_string(),
        seller_id: None,
        listing_url: "https://b2brazil.com/hotsite/akuratconsultor".to_string(),
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

    let result = build_b2b_analysis_path(&pool, &request, 0, Uuid::new_v4()).await;

    assert!(
        result.is_ok(),
        "expected the full, real B2B analysis path to succeed against the live site"
    );

    let (signals, risk_score, notes, supplier, _listing, _social_candidates) = result.unwrap();

    assert_eq!(signals.len(), 14);
    assert!(risk_score >= 0 && risk_score <= 100);
    assert!(!notes.is_empty());
    assert_eq!(
        supplier.company_name,
        Some("Akurat Consultoria Empresarial".to_string())
    );
}

#[tokio::test]
async fn build_b2b_analysis_path_fails_gracefully_for_a_genuinely_broken_url() {
    let pool = test_pool().await;
    let request = AnalyzeRequest {
        platform: "b2brazil".to_string(),
        listing_url: "https://this-domain-genuinely-does-not-exist-xyz789.com".to_string(),
        seller_id: None,
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

    let result = build_b2b_analysis_path(&pool, &request, 0, Uuid::new_v4()).await;
    assert!(
        result.is_err(),
        "expected the analysis to fail gracefully for a genuinely broken URL, but it succeeded"
    );
}

#[tokio::test]
async fn build_b2b_analysis_path_returns_real_social_candidates() {
    let pool = test_pool().await;
    let request = AnalyzeRequest {
        platform: "b2brazil".to_string(),
        seller_id: None,
        listing_url: "https://b2brazil.com/hotsite/akuratconsultor".to_string(),
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

    let result = build_b2b_analysis_path(&pool, &request, 0, Uuid::new_v4())
        .await
        .expect("expected the full, real B2B analysis path to succeed");

    let (_signals, _risk_score, _notes, _supplier, _listing, social_candidates) = result;

    assert!(
        !social_candidates.is_empty(),
        "expected the real, live OSINT matrix to return at least some platform check results"
    );
    assert!(
        social_candidates.iter().any(|r| r.platform == "Facebook"),
        "expected Facebook to genuinely be among the checked platforms"
    );
}
