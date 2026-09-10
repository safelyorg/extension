use axum::http::{HeaderMap, HeaderValue};
use backend::{
    models::{analysis::Signal, users::User},
    services::{
        auth::{create_session, find_or_create_user_by_email},
        b2b_scrapers::{B2bListingProfile, B2bSupplierProfile},
        osint::SellerIdentifiers,
    },
};
use chrono::{DateTime, Utc};
use dotenvy::dotenv;
use hex::encode;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use sqlx::{Pool, Postgres, query, query_as, query_scalar};
use std::env::var;
use std::sync::Once;
use uuid::Uuid;

static DOTENV_INIT: Once = Once::new();

type HmacSha256 = Hmac<Sha256>;

#[allow(dead_code)]
pub struct TestSubscriptionOptions {
    pub current_period_end: Option<DateTime<Utc>>,
    pub scheduled_product_id: Option<&'static str>,
    pub scheduled_plan_name: Option<&'static str>,
}

#[allow(dead_code)]
pub async fn admin_pool() -> Pool<Postgres> {
    dotenv().ok();
    let url = var("DATABASE_URL").expect("admin database URL needed for test cleanup");
    Pool::<Postgres>::connect(&url)
        .await
        .expect("failed to connect with admin privileges")
}

#[allow(dead_code)]
pub async fn test_pool() -> Pool<Postgres> {
    dotenv().ok();
    let url = var("APP_URL").expect("the url needs to set in the .env file");
    Pool::<Postgres>::connect(&url)
        .await
        .expect("failed to connect to the real database")
}

pub async fn cleanup_test_user(pool: &Pool<Postgres>, email: &str) {
    let _ = query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await;
}

#[allow(dead_code)]
pub fn make_signal(value: &str) -> Signal {
    Signal {
        label: "Test signal".to_string(),
        sub: "".to_string(),
        value: value.to_string(),
        signal_type: "good".to_string(),
        category: "listing".to_string(),
        check_type: "existence".to_string(),
    }
}

#[allow(dead_code)]
pub fn make_signals(label: &str, value: &str, signal_type: &str) -> Signal {
    Signal {
        label: label.to_string(),
        sub: format!("{} explanation", label),
        value: value.to_string(),
        signal_type: signal_type.to_string(),
        category: "listing".to_string(),
        check_type: "pattern".to_string(),
    }
}

#[allow(dead_code)]
pub async fn cleanup_test_seller(pool: &Pool<Postgres>, platform: &str, platform_id: &str) {
    let _ = query("DELETE FROM sellers WHERE platform = $1 AND platform_id = $2")
        .bind(platform)
        .bind(platform_id)
        .execute(pool)
        .await;
}

#[allow(dead_code)]
pub async fn create_test_user(pool: &Pool<Postgres>, email: &str) -> (User, bool) {
    cleanup_test_user(pool, email).await;
    let (user, yes) = find_or_create_user_by_email(pool, email)
        .await
        .expect("expected to create the test user");

    (user, yes)
}

#[allow(dead_code)]
pub async fn auth_headers_for(pool: &Pool<Postgres>, user_id: Uuid) -> HeaderMap {
    let token = create_session(pool, user_id)
        .await
        .expect("expected to create a real session");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", token))
            .expect("expected to insert the header value"),
    );

    headers
}

#[allow(dead_code)]
pub async fn get_subscription_status_text(pool: &Pool<Postgres>, sub_id: &str) -> Option<String> {
    query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .fetch_optional(pool)
        .await
        .expect("expected the query itself to succeed")
}

#[allow(dead_code)]
pub fn compute_creem_signature(secret: &str, raw_body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("expected to build a real HMAC instance");
    mac.update(raw_body.as_bytes());
    encode(mac.finalize().into_bytes())
}

/// Deletes any subscription row matching this creem_subscription_id, if
/// one exists. Used both before a test (guarding against leftover data
/// from a previous run) and after (cleaning up what the test itself
/// created).
#[allow(dead_code)]
pub async fn cleanup_test_subscription(pool: &Pool<Postgres>, sub_id: &str) {
    let _ = query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(pool)
        .await;
}

/// Inserts a real, minimal subscription row for testing - filling in
/// every column the real `subscriptions` table requires (including
/// creem_customer_id and creem_product_id, both NOT NULL), using
/// plain, made-up values for the fields a given test doesn't actually
/// care about.
#[allow(dead_code)]
pub async fn insert_test_subscription(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    sub_id: &str,
    plan_name: &str,
    status: &str,
) {
    let _ = query(
        "INSERT INTO subscriptions (
            id, user_id, creem_subscription_id, creem_customer_id, creem_product_id,
            plan_name, status, created_at, updated_at
        )
         VALUES ($1, $2, $3, $4, $5, $6, $7::subscription_status, NOW(), NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(sub_id)
    .bind("cust_fake_test_001")
    .bind(format!("prod_{}_test", plan_name.to_lowercase()))
    .bind(plan_name)
    .bind(status)
    .execute(pool)
    .await;
}

#[allow(dead_code)]
pub async fn insert_test_subscription_full(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    sub_id: &str,
    plan_name: &str,
    status: &str,
    options: TestSubscriptionOptions,
) {
    let _ = query(
        "INSERT INTO subscriptions (
            id, user_id, creem_subscription_id, creem_customer_id, creem_product_id,
            plan_name, status, current_period_end, scheduled_product_id, scheduled_plan_name,
            created_at, updated_at
        )
         VALUES ($1, $2, $3, $4, $5, $6, $7::subscription_status, $8, $9, $10, NOW(), NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(sub_id)
    .bind("cust_fake_test_001")
    .bind(format!("prod_{}_test", plan_name.to_lowercase()))
    .bind(plan_name)
    .bind(status)
    .bind(options.current_period_end)
    .bind(options.scheduled_product_id)
    .bind(options.scheduled_plan_name)
    .execute(pool)
    .await;
}

// auth

#[allow(dead_code)]
pub async fn session_exists(pool: &Pool<Postgres>, token: &str) -> bool {
    let row: Option<(String,)> = query_as("SELECT token FROM sessions WHERE token = $1")
        .bind(token)
        .fetch_optional(pool)
        .await
        .expect("expected the query itself to succeed");

    row.is_some()
}

#[allow(dead_code)]
pub async fn magic_link_exists_for_email(pool: &Pool<Postgres>, email: &str) -> bool {
    let row: Option<(String,)> =
        query_as("SELECT email FROM magic_links WHERE email = $1 ORDER BY created_at DESC LIMIT 1")
            .bind(email)
            .fetch_optional(pool)
            .await
            .expect("expected the query itself to succeed");

    row.is_some()
}

// Outcomes now has its own real foreign key to analysis, added
// today - it must be cleaned up FIRST, or the analysis delete
// below silently fails, leaving orphaned seller/listing rows
// behind for the next test run to collide with.
#[allow(dead_code)]
pub async fn cleanup_test_seller_chain(pool: &Pool<Postgres>, platform: &str, platform_id: &str) {
    let _ = query(
        "DELETE FROM outcomes WHERE analysis_id IN (
            SELECT id FROM analysis WHERE listing_id IN (
                SELECT id FROM listings WHERE seller_id IN (
                    SELECT id FROM sellers WHERE platform = $1 AND platform_id = $2
                )
            )
        )",
    )
    .bind(platform)
    .bind(platform_id)
    .execute(pool)
    .await;

    let _ = query(
        "DELETE FROM analysis WHERE listing_id IN (
            SELECT id FROM listings WHERE seller_id IN (
                SELECT id FROM sellers WHERE platform = $1 AND platform_id = $2
            )
        )",
    )
    .bind(platform)
    .bind(platform_id)
    .execute(pool)
    .await;

    let _ = query(
        "DELETE FROM listings WHERE seller_id IN (
            SELECT id FROM sellers WHERE platform = $1 AND platform_id = $2
        )",
    )
    .bind(platform)
    .bind(platform_id)
    .execute(pool)
    .await;

    let _ = query("DELETE FROM sellers WHERE platform = $1 AND platform_id = $2")
        .bind(platform)
        .bind(platform_id)
        .execute(pool)
        .await;
}

// dashboard

/// Inserts a real, connected chain for testing anything that reads
/// analysis history - a seller, a listing tied to that seller, and an
/// analysis row tied to both the listing and a real user. Returns the
/// listing_id and seller_id, since callers often need them for
/// assertions or further setup.
#[allow(dead_code)]
pub async fn insert_test_history_chain(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    platform: &str,
    platform_id: &str,
    listing_title: &str,
) -> (Uuid, Uuid) {
    let seller_id = Uuid::now_v7();
    query(
        "INSERT INTO sellers (id, platform, platform_id, name, verification, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'unknown'::seller_verification, NOW(), NOW())",
    )
    .bind(seller_id)
    .bind(platform)
    .bind(platform_id)
    .bind("Test Seller")
    .execute(pool)
    .await
    .expect("expected to create the test seller");

    let listing_id = Uuid::now_v7();
    let listing_url = format!("https://{}.com/item/{}", platform, platform_id);
    query(
        "INSERT INTO listings (id, seller_id, platform, listing_url, listing_id, title, first_seen_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
    )
    .bind(listing_id)
    .bind(seller_id)
    .bind(platform)
    .bind(&listing_url)
    .bind(platform_id)
    .bind(listing_title)
    .execute(pool)
    .await
    .expect("expected to create the test listing");

    query(
        "INSERT INTO analysis (id, listing_id, risk_score, risk_level, signals, user_id, created_at)
         VALUES ($1, $2, $3, 'low'::risk_level_type, $4, $5, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(listing_id)
    .bind(15_i16)
    .bind(serde_json::json!([]))
    .bind(user_id)
    .execute(pool)
    .await
    .expect("expected to create the test analysis");

    (listing_id, seller_id)
}

/// Deletes a seller and any fraud reports genuinely tied to them - fraud
/// reports first, then the seller itself, since the report references
/// the seller. Safe to call before a test too, as a guard against
/// leftover data from a previous failed run.
#[allow(dead_code)]
pub async fn cleanup_test_seller_with_reports(
    pool: &Pool<Postgres>,
    platform: &str,
    platform_id: &str,
) {
    let _ = query(
        "DELETE FROM fraud_reports WHERE seller_id IN (
            SELECT id FROM sellers WHERE platform = $1 AND platform_id = $2
        )",
    )
    .bind(platform)
    .bind(platform_id)
    .execute(pool)
    .await;

    let _ = query("DELETE FROM sellers WHERE platform = $1 AND platform_id = $2")
        .bind(platform)
        .bind(platform_id)
        .execute(pool)
        .await;
}

/// Overwrites an analysis row's created_at to a specific, deliberately
/// chosen timestamp - used to build deterministic ordering tests,
/// rather than relying on the natural (and potentially flaky) timing
/// gaps between consecutive inserts.
#[allow(dead_code)]
pub async fn set_analysis_created_at(
    pool: &Pool<Postgres>,
    listing_id: Uuid,
    created_at: DateTime<Utc>,
) {
    let _ = query("UPDATE analysis SET created_at = $1 WHERE listing_id = $2")
        .bind(created_at)
        .bind(listing_id)
        .execute(pool)
        .await;
}

#[allow(dead_code)]
pub async fn insert_test_analysis_for_outcomes(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    platform: &str,
    platform_id: &str,
) -> Uuid {
    let seller_id = Uuid::now_v7();
    query(
        "INSERT INTO sellers (id, platform, platform_id, name, verification, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'unknown'::seller_verification, NOW(), NOW())",
    )
    .bind(seller_id)
    .bind(platform)
    .bind(platform_id)
    .bind("Test Seller")
    .execute(pool)
    .await
    .expect("expected to create the test seller");

    let listing_id = Uuid::now_v7();
    let listing_url = format!("https://{}.com/item/{}", platform, platform_id);
    query(
        "INSERT INTO listings (id, seller_id, platform, listing_url, listing_id, title, first_seen_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
    )
    .bind(listing_id)
    .bind(seller_id)
    .bind(platform)
    .bind(&listing_url)
    .bind(platform_id)
    .bind("Test Listing")
    .execute(pool)
    .await
    .expect("expected to create the test listing");

    let analysis_id = Uuid::now_v7();
    query(
        "INSERT INTO analysis (id, listing_id, risk_score, risk_level, signals, user_id, created_at)
         VALUES ($1, $2, $3, 'low'::risk_level_type, $4, $5, NOW())",
    )
    .bind(analysis_id)
    .bind(listing_id)
    .bind(15_i16)
    .bind(json!([]))
    .bind(user_id)
    .execute(pool)
    .await
    .expect("expected to create the test analysis");

    analysis_id
}

#[allow(dead_code)]
pub async fn insert_raw_evidence_row(
    pool: &Pool<Postgres>,
    analysis_id: Uuid,
    seller_id: Uuid,
    value: &str,
) {
    let _ = query(
        "INSERT INTO evidence (id, analysis_id, seller_id, evidence_type, label, value, source, found_at)
         VALUES ($1, $2, $3, 'check', 'risk_score', $4, 'scoring_engine', NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(analysis_id)
    .bind(seller_id)
    .bind(value)
    .execute(pool)
    .await;
}

#[allow(dead_code)]
pub async fn setup_real_seller_and_analysis(
    pool: &Pool<Postgres>,
    platform_id: &str,
) -> (Uuid, Uuid) {
    let email = format!("{}@example.com", platform_id);
    cleanup_test_user(pool, &email).await;
    let (user, _) = create_test_user(pool, &email).await;

    cleanup_test_seller_chain(pool, "olx", platform_id).await;
    let analysis_id = insert_test_analysis_for_outcomes(pool, user.id, "olx", platform_id).await;

    let seller_row: (Uuid,) = query_as(
        "SELECT seller_id FROM listings WHERE id = (SELECT listing_id FROM analysis WHERE id = $1)",
    )
    .bind(analysis_id)
    .fetch_one(pool)
    .await
    .expect("expected to find the real seller_id for this analysis");

    (analysis_id, seller_row.0)
}

#[allow(dead_code)]
pub async fn cleanup_seller_and_analysis(pool: &Pool<Postgres>, platform_id: &str) {
    let _ = query(
        "DELETE FROM evidence WHERE seller_id IN (SELECT id FROM sellers WHERE platform_id = $1)",
    )
    .bind(platform_id)
    .execute(pool)
    .await;
    cleanup_test_seller_chain(pool, "olx", platform_id).await;
}

#[allow(dead_code)]
pub fn make_seller(
    name: Option<&str>,
    phone: Option<&str>,
    email: Option<&str>,
    website: Option<&str>,
) -> SellerIdentifiers {
    SellerIdentifiers {
        name: name.map(|s| s.to_string()),
        phone: phone.map(|s| s.to_string()),
        email: email.map(|s| s.to_string()),
        website: website.map(|s| s.to_string()),
        location: None,
    }
}

#[allow(dead_code)]
pub fn make_supplier(
    verified: bool,
    year: Option<&str>,
    employees: Option<&str>,
    revenue: Option<&str>,
    export: Option<&str>,
) -> B2bSupplierProfile {
    B2bSupplierProfile {
        company_name: Some("Test Co".to_string()),
        platform_verified_badge: verified,
        year_established: year.map(|s| s.to_string()),
        employee_count: employees.map(|s| s.to_string()),
        sales_revenue: revenue.map(|s| s.to_string()),
        export_percentage: export.map(|s| s.to_string()),
        source_platform: "b2brazil".to_string(),
        ..Default::default()
    }
}

#[allow(dead_code)]
pub fn make_listing(filled_count: usize) -> B2bListingProfile {
    let mut listing = B2bListingProfile {
        source_platform: "b2brazil".to_string(),
        ..Default::default()
    };
    let value = Some("some value".to_string());
    if filled_count >= 1 {
        listing.unit_price = value.clone();
    }
    if filled_count >= 2 {
        listing.fob_price = value.clone();
    }
    if filled_count >= 3 {
        listing.minimum_order_quantity = value.clone();
    }

    listing
}

#[allow(dead_code)]
pub fn load_env_once() {
    DOTENV_INIT.call_once(|| {
        dotenvy::dotenv().ok();
    });
}
