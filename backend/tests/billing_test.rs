mod common;

use crate::common::{
    TestSubscriptionOptions, auth_headers_for, cleanup_test_subscription, cleanup_test_user,
    compute_creem_signature, create_test_user, get_subscription_status_text,
    insert_test_subscription, insert_test_subscription_full, load_env_once, test_pool,
};
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue},
};
use backend::{
    errors::{
        auth::AuthError,
        billing::{BillingError, WebhookError},
    },
    handlers::billing::{
        ChangePlanBody, CreateCheckoutBody, cancel_subscription_handler, change_plan_handler,
        create_checkout_handler, creem_webhook, get_product_ids, get_subscription_status,
    },
    models::billing::{ParsedCustomer, ParsedMetadata, ParsedProduct, ParsedSubscription},
    services::{
        auth::find_or_create_user_by_email,
        billing::{
            CreateCheckoutError, apply_scheduled_downgrade_if_due, apply_upgrade,
            cancel_with_creem, change_creem_subscription_product, create_checkout,
            extract_metadata_user_id, extract_subscription, fetch_subscriber_email,
            handle_subscription_granted, handle_subscription_lost, handle_subscription_past_due,
            handle_subscription_update, mark_event_processed_if_new, upsert_subscription,
            verify_and_parse_webhook, verify_creem_signature,
        },
        email::{
            send_payment_failed_email, send_subscription_canceled_email,
            send_subscription_ended_email,
        },
    },
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;
use sha2::Sha256;
use sqlx::{query, query_as, query_scalar};
use std::env::{remove_var, set_var, var};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// Checkout Handler Tests
#[tokio::test]
#[serial]
async fn checkout_handler_success() {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    load_env_once();

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkouts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "fake_checkout_id_123",
            "checkout_url": "https://creem.io/test/checkout/fake_product_id/ch_fake123"
        })))
        .mount(&mock_server)
        .await;

    let original_base_url = var("CREEM_API_BASE_URL").ok();
    unsafe {
        set_var("CREEM_API_BASE_URL", mock_server.uri());
    }

    let pool = test_pool().await;
    let email = "checkout_handler@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let checkout_body = CreateCheckoutBody {
        product_id: "prod_6qDjyvwKbCZvWTgIztzqz4".to_string(),
    };

    let result = create_checkout_handler(State(pool.clone()), headers, Json(checkout_body))
        .await
        .expect("expected to create the checkout");

    let checkout_url = result["checkout_url"]
        .as_str()
        .expect("expected checkout_url to be a real string");

    assert!(
        checkout_url.contains("creem.io"),
        "expected a genuine-looking Creem checkout URL, got: {}",
        checkout_url
    );

    unsafe {
        match original_base_url {
            Some(url) => set_var("CREEM_API_BASE_URL", url),
            None => remove_var("CREEM_API_BASE_URL"),
        }
    }

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn checkout_handler_unauthorized() {
    load_env_once();
    let pool = test_pool().await;
    let headers = HeaderMap::new();

    let checkout_body = CreateCheckoutBody {
        product_id: "prod_6qDjyvwKbCZvWTgIztzqz4".to_string(),
    };

    let result = create_checkout_handler(State(pool), headers, Json(checkout_body)).await;

    match result {
        Err(BillingError::Unauthorized) => {}
        Err(other) => panic!("expected Unauthorized, got a different error: {:?}", other),
        Ok(_) => panic!("expected an unauthenticated request to be rejected, but it succeeded"),
    }
}

#[tokio::test]
#[serial]
async fn checkout_handler_creem_rejects_invalid_product() {
    let pool = test_pool().await;
    let email = "checkout_rejected@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let checkout_body = CreateCheckoutBody {
        product_id: "definitely_not_a_real_product_id".to_string(),
    };

    let result = create_checkout_handler(State(pool.clone()), headers, Json(checkout_body)).await;

    match result {
        Err(BillingError::InvalidRequest(_)) => {}
        Err(other) => panic!(
            "expected InvalidRequest (Creem rejection), got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected Creem to reject a fake product_id, but it succeeded"),
    }

    cleanup_test_user(&pool, email).await;
}

// Create Checkout Tests
#[tokio::test]
#[serial]
async fn create_checkout_success() {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    // A genuine, local, fake server standing in for Creem
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/checkouts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "fake_checkout_id_123",
            "checkout_url": "https://fake-checkout-url.test/abc123"
        })))
        .mount(&mock_server)
        .await;

    let original_base_url = var("CREEM_API_BASE_URL").ok();
    unsafe {
        set_var("CREEM_API_BASE_URL", mock_server.uri());
    }

    let pool = test_pool().await;
    let email = "create_checkout_mocked_test@example.com";
    cleanup_test_user(&pool, email).await;
    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    let result = create_checkout("prod_6qDjyvwKbCZvWTgIztzqz4", user.id)
        .await
        .expect("expected the mocked checkout call to succeed");

    assert_eq!(result.checkout_url, "https://fake-checkout-url.test/abc123");

    unsafe {
        match original_base_url {
            Some(url) => set_var("CREEM_API_BASE_URL", url),
            None => remove_var("CREEM_API_BASE_URL"),
        }
    }
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn create_checkout_creem_rejected() {
    let pool = test_pool().await;
    let email = "checkout_creem_rejected@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let result = create_checkout("definitely_not_a_real_product_id", user.id).await;

    match result {
        Err(CreateCheckoutError::CreemRejected(_)) => {}
        Err(other) => panic!("expected CreemRejected, got a different error: {:?}", other),
        Ok(_) => panic!("expected Creem to reject a fake product_id, but it succeeded"),
    }

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn create_checkout_missing_api_key() {
    load_env_once();
    let original_key = var("CREEM_API_KEY").ok();
    unsafe {
        remove_var("CREEM_API_KEY");
    }

    let fake_user_id = Uuid::new_v4();
    let result = create_checkout("prod_6qDjyvwKbCZvWTgIztzqz4", fake_user_id).await;

    match result {
        Err(CreateCheckoutError::MissingApiKey) => {}
        Err(other) => panic!("expected MissingApiKey, got a different error: {:?}", other),
        Ok(_) => panic!("expected the checkout to fail without a real API key, but it succeeded"),
    }

    unsafe {
        if let Some(key) = original_key {
            set_var("CREEM_API_KEY", key);
        }
    }
}

#[tokio::test]
#[serial]
async fn create_checkout_request_failed() {
    load_env_once();
    let original_base_url = var("CREEM_API_BASE_URL").ok();

    unsafe {
        set_var(
            "CREEM_API_BASE_URL",
            "http://this-domain-genuinely-does-not-exist-12345.invalid",
        );
    }

    let fake_user_id = Uuid::new_v4();
    let result = create_checkout("prod_6qDjyvwKbCZvWTgIztzqz4", fake_user_id).await;

    match result {
        Err(CreateCheckoutError::RequestFailed(_)) => {}
        Err(other) => panic!("expected RequestFailed, got a different error: {:?}", other),
        Ok(_) => panic!("expected the request to genuinely fail, but it succeeded"),
    }

    unsafe {
        match original_base_url {
            Some(url) => set_var("CREEM_API_BASE_URL", url),
            None => remove_var("CREEM_API_BASE_URL"),
        }
    }
}

// Creem Webhook Tests
#[tokio::test]
#[serial]
async fn creem_webhook_verification_failure_propagates() {
    load_env_once();

    let pool = test_pool().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        "creem-signature",
        HeaderValue::from_str("clearly-wrong-signature-that-cannot-match")
            .expect("expected to insert the header value"),
    );

    let body = Bytes::from(
        r#"{"id":"evt_test","eventType":"refund.created","created_at":1700000000,"object":{}}"#,
    );

    let result = creem_webhook(State(pool), headers, body).await;

    match result {
        Err(WebhookError::InvalidSignature) => {}
        Err(other) => panic!(
            "expected InvalidSignature, got a different error: {:?}",
            other
        ),
        Ok(_) => {
            panic!("expected the whole webhook to be rejected on a bad signature, but it succeeded")
        }
    }
}

#[tokio::test]
#[serial]
async fn creem_webhook_success_refund_created() {
    load_env_once();

    let pool = test_pool().await;

    let secret = var("CREEM_WEBHOOK_SECRET")
        .expect("expected CREEM_WEBHOOK_SECRET to be genuinely set for this test");

    let raw_body = r#"{"id":"evt_refund_test_001","eventType":"refund.created","created_at":1700000000,"object":{}}"#;

    let real_signature = compute_creem_signature(&secret, raw_body);

    let mut headers = HeaderMap::new();
    headers.insert(
        "creem-signature",
        HeaderValue::from_str(&real_signature).expect("expected to insert the header value"),
    );

    let body = Bytes::from(raw_body);

    let result = creem_webhook(State(pool), headers, body)
        .await
        .expect("expected the whole webhook to succeed end-to-end");

    assert_eq!(result, StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn creem_webhook_unrecognized_event_type_still_ok() {
    load_env_once();

    let pool = test_pool().await;

    let secret = var("CREEM_WEBHOOK_SECRET")
        .expect("expected CREEM_WEBHOOK_SECRET to be genuinely set for this test");

    let raw_body = r#"{"id":"evt_unknown_test_001","eventType":"some.future.event","created_at":1700000000,"object":{}}"#;

    let real_signature = compute_creem_signature(&secret, raw_body);

    let mut headers = HeaderMap::new();
    headers.insert(
        "creem-signature",
        HeaderValue::from_str(&real_signature).expect("expected to insert the header value"),
    );

    let body = Bytes::from(raw_body);

    let result = creem_webhook(State(pool), headers, body)
        .await
        .expect("expected an unrecognized event type to still succeed, not fail");

    assert_eq!(result, StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn creem_webhook_inner_handler_failure_still_returns_ok() {
    load_env_once();
    let pool = test_pool().await;

    let secret = var("CREEM_WEBHOOK_SECRET")
        .expect("expected CREEM_WEBHOOK_SECRET to be genuinely set for this test");

    let sub_id = "sub_webhook_inner_failure_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let fake_user_id = Uuid::new_v4();

    let raw_body = format!(
        r#"{{"id":"evt_inner_failure_001","eventType":"subscription.paid","created_at":1700000000,"object":{{"id":"{}","status":"active","current_period_end_date":null,"canceled_at":null,"product":{{"id":"prod_test","name":"Team"}},"customer":{{"id":"cust_test","email":"test@example.com"}},"metadata":{{"safely_user_id":"{}"}}}}}}"#,
        sub_id, fake_user_id
    );

    let real_signature = compute_creem_signature(&secret, &raw_body);

    let mut headers = HeaderMap::new();
    headers.insert(
        "creem-signature",
        HeaderValue::from_str(&real_signature).expect("expected to insert the header value"),
    );

    let body = Bytes::from(raw_body);

    let result = creem_webhook(State(pool.clone()), headers, body)
        .await
        .expect("expected the whole webhook to still return Ok, despite the inner failure");

    assert_eq!(result, StatusCode::OK);

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to exist, confirming the inner failure was genuine"
    );
}

// Verify and Parse Webhook Tests
#[tokio::test]
#[serial]
async fn verify_and_parse_webhook_secret_missing() {
    load_env_once();

    let original_secret = var("CREEM_WEBHOOK_SECRET").ok();
    unsafe {
        remove_var("CREEM_WEBHOOK_SECRET");
    }

    let headers = HeaderMap::new();
    let body = Bytes::from("{}");

    let result = verify_and_parse_webhook(&headers, &body).await;

    match result {
        Err(WebhookError::Misconfigured(_)) => {}
        Err(other) => panic!("expected Misconfigured, got a different error: {:?}", other),
        Ok(_) => panic!("expected verification to fail without a real secret, but it succeeded"),
    }

    unsafe {
        if let Some(secret) = original_secret {
            set_var("CREEM_WEBHOOK_SECRET", secret);
        }
    }
}

#[tokio::test]
#[serial]
async fn verify_and_parse_webhook_missing_signature() {
    load_env_once();

    let headers = HeaderMap::new();
    let body = Bytes::from("{}");

    let result = verify_and_parse_webhook(&headers, &body).await;

    match result {
        Err(WebhookError::MissingSignature) => {}
        Err(other) => panic!(
            "expected MissingSignature, got a different error: {:?}",
            other
        ),
        Ok(_) => {
            panic!("expected verification to fail without a signature header, but it succeeded")
        }
    }
}

#[tokio::test]
#[serial]
async fn verify_and_parse_webhook_invalid_body() {
    load_env_once();

    let mut headers = HeaderMap::new();
    headers.insert(
        "creem-signature",
        HeaderValue::from_str("some-signature-value").expect("expected to insert the header value"),
    );

    // invalid UTF-8
    let body = Bytes::from(vec![0xFF, 0xFE, 0xFD]);

    let result = verify_and_parse_webhook(&headers, &body).await;
    match result {
        Err(WebhookError::InvalidBody) => {}
        Err(other) => panic!("expected InvalidBody, got a different error: {:?}", other),
        Ok(_) => panic!("expected verification to fail on invalid UTF-8, but it succeeded"),
    }
}

#[tokio::test]
#[serial]
async fn verify_and_parse_webhook_invalid_signature() {
    load_env_once();

    let mut headers = HeaderMap::new();
    headers.insert(
        "creem-signature",
        HeaderValue::from_str("clearly-wrong-signature-that-cannot-match")
            .expect("expected to insert the header value"),
    );
    let body = Bytes::from(r#"{"id":"evt_test","event_type":"test.event","object":{}}"#);

    let result = verify_and_parse_webhook(&headers, &body).await;
    match result {
        Err(WebhookError::InvalidSignature) => {}
        Err(other) => panic!(
            "expected InvalidSignature, got a different error: {:?}",
            other
        ),
        Ok(_) => {
            panic!("expected verification to fail on a mismatched signature, but it succeeded")
        }
    }
}

#[tokio::test]
#[serial]
async fn verify_and_parse_webhook_invalid_payload() {
    load_env_once();

    let secret = var("CREEM_WEBHOOK_SECRET")
        .expect("expected CREEM_WEBHOOK_SECRET to be genuinely set for this test");
    let raw_body = "not valid json{{{";
    let real_signature = compute_creem_signature(&secret, raw_body);

    let mut headers = HeaderMap::new();
    headers.insert(
        "creem-signature",
        HeaderValue::from_str(&real_signature).expect("expected to insert the header value"),
    );

    let body = Bytes::from(raw_body);

    let result = verify_and_parse_webhook(&headers, &body).await;
    match result {
        Err(WebhookError::InvalidPayload(_)) => {}
        Err(other) => panic!(
            "expected InvalidPayload, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected parsing to fail on malformed JSON, but it succeeded"),
    }
}

#[tokio::test]
#[serial]
async fn verify_and_parse_webhook_success() {
    load_env_once();

    let secret = var("CREEM_WEBHOOK_SECRET")
        .expect("expected CREEM_WEBHOOK_SECRET to be genuinely set for this test");
    let raw_body = r#"{"id":"evt_test_success_001","eventType":"checkout.completed","created_at":1700000000,"object":{}}"#;
    let real_signature = compute_creem_signature(&secret, raw_body);

    let mut headers = HeaderMap::new();
    headers.insert(
        "creem-signature",
        HeaderValue::from_str(&real_signature).expect("expected to insert the header value"),
    );

    let body = Bytes::from(raw_body);

    let event = verify_and_parse_webhook(&headers, &body)
        .await
        .expect("expected verification and parsing to genuinely succeed");

    assert_eq!(event.id, "evt_test_success_001");
    assert_eq!(event.event_type, "checkout.completed");
}

// Verify Creem Signature Tests
#[test]
fn verify_creem_signature_genuine_match() {
    let secret = "test_secret_001";
    let body = r#"{"id":"evt_test","eventType":"refund.created"}"#;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("expected to build a real HMAC instance");

    mac.update(body.as_bytes());
    let real_signature = hex::encode(mac.finalize().into_bytes());

    let result = verify_creem_signature(body, &real_signature, secret);
    assert!(
        result,
        "expected a genuinely correct signature to verify successfully"
    );
}

#[test]
fn verify_creem_signature_genuine_mismatch() {
    let secret = "test_secret_001";
    let body = r#"{"id":"evt_test","eventType":"refund.created"}"#;

    let result = verify_creem_signature(body, "clearly_wrong_signature_00000", secret);

    assert!(
        !result,
        "expected a genuinely wrong signature to fail verification"
    );
}

#[test]
fn verify_creem_signature_different_body_fails() {
    let secret = "test_secret_001";
    let original_body = r#"{"id":"evt_test","eventType":"refund.created"}"#;
    let tampered_body = r#"{"id":"evt_test","eventType":"subscription.canceled"}"#;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("expected to build a real HMAC instance");

    mac.update(original_body.as_bytes());
    let signature_for_original = hex::encode(mac.finalize().into_bytes());

    let result = verify_creem_signature(tampered_body, &signature_for_original, secret);
    assert!(
        !result,
        "expected a signature computed for one body to fail against a genuinely different body"
    );
}

#[test]
fn verify_creem_signature_different_secret_fails() {
    let body = r#"{"id":"evt_test","eventType":"refund.created"}"#;
    let real_secret = "the_real_secret_001";
    let wrong_secret = "a_completely_different_secret_002";

    let mut mac = HmacSha256::new_from_slice(real_secret.as_bytes())
        .expect("expected to build a real HMAC instance");

    mac.update(body.as_bytes());
    let real_signature = hex::encode(mac.finalize().into_bytes());

    let result = verify_creem_signature(body, &real_signature, wrong_secret);
    assert!(
        !result,
        "expected verification to fail when checked against the WRONG secret"
    );
}

#[test]
fn verify_creem_signature_case_sensitive() {
    let secret = "test_secret_001";
    let body = r#"{"id":"evt_test","eventType":"refund.created"}"#;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("expected to build a real HMAC instance");

    mac.update(body.as_bytes());
    let real_signature = hex::encode(mac.finalize().into_bytes());
    let uppercased_signature = real_signature.to_uppercase();

    let result = verify_creem_signature(body, &uppercased_signature, secret);
    assert!(
        !result,
        "expected an uppercased version of a correct signature to fail, since comparison is case-sensitive"
    );
}

// Extract Subscription Tests
#[test]
fn extract_subscription_subscription_shape_success() {
    let object = serde_json::json!({
        "id": "sub_test_001",
        "status": "active",
        "current_period_end_date": null,
        "canceled_at": null,
        "product": { "id": "prod_test", "name": "Team" },
        "customer": { "id": "cust_test", "email": "test@example.com" },
        "metadata": null
    });

    let result = extract_subscription("subscription.paid", &object);
    let parsed = result.expect("expected the subscription to be extracted successfully");
    assert_eq!(parsed.id, "sub_test_001");
    assert_eq!(parsed.status, "active");
}

#[test]
fn extract_subscription_checkout_completed_shape_success() {
    let object = json!({
        "subscription": {
            "id": "sub_nested_001",
            "status": "trialing",
            "current_period_end_date": null,
            "canceled_at": null,
            "product": { "id": "prod_test", "name": "Team" },
            "customer": { "id": "cust_test", "email": "test@example.com" },
            "metadata": null
        }
    });

    let result = extract_subscription("checkout.completed", &object);
    let parsed = result.expect("expected the NESTED subscription to be extracted successfully");

    assert_eq!(parsed.id, "sub_nested_001");
    assert_eq!(parsed.status, "trialing");
}

#[test]
fn extract_subscription_checkout_completed_missing_nested_field() {
    let object = serde_json::json!({
        "id": "evt_test_001"
    });

    let result = extract_subscription("checkout.completed", &object);
    assert!(
        result.is_none(),
        "expected None when checkout.completed genuinely lacks a nested subscription field"
    );
}

#[test]
fn extract_subscription_unrecognized_event_type() {
    let object = serde_json::json!({
        "id": "evt_test_001"
    });

    let result = extract_subscription("refund.created", &object);

    assert!(
        result.is_none(),
        "expected None for an event type that's neither shape"
    );
}

#[test]
fn extract_subscription_malformed_data_returns_none() {
    let object = json!({
        "id": "sub_malformed_001",
        "status": "active"
    });

    let result = extract_subscription("subscription.paid", &object);
    assert!(
        result.is_none(),
        "expected None when the data doesn't genuinely match ParsedSubscription's real shape"
    );
}

// Handle Subscription Granted Tests
#[tokio::test]
async fn subscription_granted_success() {
    let pool = test_pool().await;

    let email = "subscription_granted_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_granted_test_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: email.to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(user.id.to_string()),
        }),
    };

    handle_subscription_granted(&pool, &parsed).await;
    let saved_status = get_subscription_status_text(&pool, sub_id).await;

    assert_eq!(
        saved_status,
        Some("active".to_string()),
        "expected a real subscription row to exist with status 'active'"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn subscription_granted_missing_user_id() {
    let pool = test_pool().await;

    let sub_id = "sub_granted_missing_user_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: None,
        }),
    };

    handle_subscription_granted(&pool, &parsed).await;

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to be created when safely_user_id is missing"
    );
}

#[tokio::test]
async fn subscription_granted_upsert_fails() {
    let pool = test_pool().await;

    let sub_id = "sub_granted_upsert_fails_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let fake_user_id = Uuid::new_v4();
    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(fake_user_id.to_string()),
        }),
    };

    handle_subscription_granted(&pool, &parsed).await;

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to exist, since the foreign key genuinely failed"
    );
}

// Extract Metadata User ID Tests
#[test]
fn extract_metadata_user_id_missing_metadata() {
    let parsed = ParsedSubscription {
        id: "sub_test_001".to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: None,
    };

    let result = extract_metadata_user_id(&parsed);
    assert!(
        result.is_none(),
        "expected None when metadata itself is missing"
    );
}

#[test]
fn extract_metadata_user_id_missing_safely_user_id() {
    let parsed = ParsedSubscription {
        id: "sub_test_001".to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: None,
        }),
    };

    let result = extract_metadata_user_id(&parsed);
    assert!(
        result.is_none(),
        "expected None when safely_user_id itself is missing"
    );
}

#[test]
fn extract_metadata_user_id_invalid_uuid() {
    let parsed = ParsedSubscription {
        id: "sub_test_001".to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some("this-is-genuinely-not-a-uuid".to_string()),
        }),
    };

    let result = extract_metadata_user_id(&parsed);
    assert!(
        result.is_none(),
        "expected None when the string isn't a genuinely valid UUID"
    );
}

#[test]
fn extract_metadata_user_id_success() {
    let real_uuid = Uuid::new_v4();

    let parsed = ParsedSubscription {
        id: "sub_test_001".to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(real_uuid.to_string()),
        }),
    };

    let result = extract_metadata_user_id(&parsed);
    assert_eq!(result, Some(real_uuid), "expected the exact same UUID back");
}

// Upsert Subscription
#[tokio::test]
async fn upsert_subscription_creates_new_row_with_full_data() {
    let pool = test_pool().await;
    let email = "upsert_sub_create_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_upsert_create_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: Some("2026-12-31T23:59:59Z".to_string()),
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: email.to_string(),
        },
        metadata: None,
    };

    upsert_subscription(&pool, user.id, &parsed, "active")
        .await
        .expect("expected the upsert to succeed");

    let (saved_status, saved_period_end): (String, Option<DateTime<Utc>>) = query_as(
        "SELECT status::text, current_period_end FROM subscriptions WHERE creem_subscription_id = $1",
    )
    .bind(sub_id)
    .fetch_one(&pool)
    .await
    .expect("expected the row to exist");

    assert_eq!(saved_status, "active");
    assert!(
        saved_period_end.is_some(),
        "expected the period end to be genuinely parsed and saved"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .ok();
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn upsert_subscription_update_unconditionally_overwrites() {
    let pool = test_pool().await;
    let email = "upsert_sub_overwrite_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_upsert_overwrite_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: email.to_string(),
        },
        metadata: None,
    };

    upsert_subscription(&pool, user.id, &parsed, "active")
        .await
        .expect("expected the first upsert to succeed");

    upsert_subscription(&pool, user.id, &parsed, "canceled")
        .await
        .expect("expected the second upsert to succeed");

    let saved_status: String =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_one(&pool)
            .await
            .expect("expected the row to exist");

    assert_eq!(
        saved_status, "canceled",
        "expected the status to be UNCONDITIONALLY overwritten, with no preservation logic"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn upsert_subscription_missing_period_end_saves_as_null() {
    let pool = test_pool().await;
    let email = "upsert_sub_missing_period_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_upsert_missing_period_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "trialing".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: email.to_string(),
        },
        metadata: None,
    };

    upsert_subscription(&pool, user.id, &parsed, "trialing")
        .await
        .expect("expected the upsert to succeed");

    let saved_period_end: Option<DateTime<Utc>> = query_scalar(
        "SELECT current_period_end FROM subscriptions WHERE creem_subscription_id = $1",
    )
    .bind(sub_id)
    .fetch_one(&pool)
    .await
    .expect("expected the row to exist");

    assert!(
        saved_period_end.is_none(),
        "expected NULL when current_period_end_date is None"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .ok();

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn upsert_subscription_malformed_period_end_saves_as_null() {
    let pool = test_pool().await;
    let email = "upsert_sub_malformed_period_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_upsert_malformed_period_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: Some("not-a-real-date".to_string()),
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: email.to_string(),
        },
        metadata: None,
    };

    upsert_subscription(&pool, user.id, &parsed, "active")
        .await
        .expect("expected the upsert to succeed DESPITE the malformed date");

    let saved_period_end: Option<DateTime<Utc>> = query_scalar(
        "SELECT current_period_end FROM subscriptions WHERE creem_subscription_id = $1",
    )
    .bind(sub_id)
    .fetch_one(&pool)
    .await
    .expect("expected the row to exist");

    assert!(
        saved_period_end.is_none(),
        "expected a malformed date to quietly become NULL, not cause an error"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .ok();
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn upsert_subscription_fails_for_nonexistent_user() {
    let pool = test_pool().await;
    let sub_id = "sub_upsert_fake_user_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let fake_user_id = Uuid::new_v4();
    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: None,
    };

    let result = upsert_subscription(&pool, fake_user_id, &parsed, "active").await;
    assert!(
        result.is_err(),
        "expected a genuine foreign-key failure for a user that doesn't exist"
    );
}

// Handle Subscription Past Due Tests
#[tokio::test]
async fn subscription_past_due_success() {
    let pool = test_pool().await;
    let email = "past_due_test_user@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_past_due_test_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "past_due".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "delivered@resend.dev".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(user.id.to_string()),
        }),
    };

    handle_subscription_past_due(&pool, &parsed).await;
    let saved_status = get_subscription_status_text(&pool, sub_id).await;

    assert_eq!(
        saved_status,
        Some("past_due".to_string()),
        "expected a real subscription row to exist with status 'past_due'"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn subscription_past_due_missing_user_id() {
    let pool = test_pool().await;

    let sub_id = "sub_past_due_missing_user_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "past_due".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "delivered@resend.dev".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: None,
        }),
    };

    handle_subscription_past_due(&pool, &parsed).await;

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to be created when safely_user_id is missing"
    );
}

#[tokio::test]
async fn subscription_past_due_upsert_fails() {
    let pool = test_pool().await;

    let sub_id = "sub_past_due_upsert_fails_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let fake_user_id = Uuid::new_v4();

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "past_due".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "delivered@resend.dev".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(fake_user_id.to_string()),
        }),
    };

    handle_subscription_past_due(&pool, &parsed).await;

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to exist, since the foreign key genuinely failed"
    );
}

#[tokio::test]
async fn subscription_past_due_email_fails_but_upsert_still_succeeds() {
    let pool = test_pool().await;
    let email = "past_due_email_fails_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_past_due_email_fails_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "past_due".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "genuinely_blocked@example.com".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(user.id.to_string()),
        }),
    };

    handle_subscription_past_due(&pool, &parsed).await;
    let saved_status = get_subscription_status_text(&pool, sub_id).await;

    assert_eq!(
        saved_status,
        Some("past_due".to_string()),
        "expected the subscription to still be upserted, even though the email genuinely failed"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

// Send Payment Failed Email Tests
#[tokio::test]
#[serial]
async fn send_payment_failed_email_missing_api_key() {
    load_env_once();
    let original_key = var("RESEND_API_KEY").ok();
    unsafe {
        remove_var("RESEND_API_KEY");
    }

    let result = send_payment_failed_email(
        "delivered@resend.dev",
        "http://localhost:3000/dashboard/?manage_billing=1",
    )
    .await;

    match result {
        Err(AuthError::InternalServerError(_)) => {}
        Err(other) => panic!(
            "expected InternalServerError, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected the email to fail without a real API key, but it succeeded"),
    }

    unsafe {
        if let Some(key) = original_key {
            set_var("RESEND_API_KEY", key);
        }
    }
}

#[tokio::test]
#[serial]
async fn send_payment_failed_email_succeeds() {
    load_env_once();

    let result = send_payment_failed_email(
        "delivered@resend.dev",
        "http://localhost:3000/dashboard/?manage_billing=1",
    )
    .await;

    assert!(
        result.is_ok(),
        "expected the payment-failed email to send successfully, got: {:?}",
        result
    );
}

#[tokio::test]
#[serial]
async fn send_payment_failed_email_fails_for_a_blocked_domain() {
    load_env_once();

    let result = send_payment_failed_email(
        "test_user@example.com",
        "http://localhost:3000/dashboard/?manage_billing=1",
    )
    .await;

    match result {
        Err(AuthError::InternalServerError(message)) => {
            assert!(
                message.contains("Invalid `to` field"),
                "expected Resend's specific rejection message, got: {}",
                message
            )
        }
        other => panic!("expected an InternalServerError, got: {:?}", other),
    }
}

// Handle Subscription Lost Tests
#[tokio::test]
async fn subscription_lost_paused() {
    let pool = test_pool().await;
    let email = "subscription_lost_paused_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_lost_paused_test_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: email.to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(user.id.to_string()),
        }),
    };

    let event_type = "subscription.paused";
    handle_subscription_lost(&pool, &parsed, event_type).await;
    let saved_status = get_subscription_status_text(&pool, sub_id).await;

    assert_eq!(
        saved_status,
        Some("paused".to_string()),
        "expected a real subscription row to exist with status 'paused'"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn subscription_lost_expired() {
    let pool = test_pool().await;
    let email = "subscription_lost_expired_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_lost_expired_test_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: email.to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(user.id.to_string()),
        }),
    };

    let event_type = "subscription.expired";
    handle_subscription_lost(&pool, &parsed, event_type).await;
    let saved_status = get_subscription_status_text(&pool, sub_id).await;

    assert_eq!(
        saved_status,
        Some("expired".to_string()),
        "expected a real subscription row to exist with status 'expired'"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn subscription_lost_canceled_genuinely_new() {
    let pool = test_pool().await;
    let email = "subscription_lost_canceled_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_lost_canceled_new_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "delivered@resend.dev".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(user.id.to_string()),
        }),
    };

    let event_type = "subscription.canceled";
    handle_subscription_lost(&pool, &parsed, event_type).await;
    let saved_status = get_subscription_status_text(&pool, sub_id).await;

    assert_eq!(
        saved_status,
        Some("canceled".to_string()),
        "expected a real subscription row to exist with status 'canceled'"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn subscription_lost_canceled_already_canceled() {
    let pool = test_pool().await;
    let email = "subscription_lost_already_canceled_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_lost_already_canceled_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "canceled".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "delivered@resend.dev".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(user.id.to_string()),
        }),
    };

    upsert_subscription(&pool, user.id, &parsed, "canceled")
        .await
        .expect("expected to pre-seed the already-canceled subscription");

    let event_type = "subscription.canceled";
    handle_subscription_lost(&pool, &parsed, event_type).await;
    let saved_status = get_subscription_status_text(&pool, sub_id).await;

    assert_eq!(
        saved_status,
        Some("canceled".to_string()),
        "expected the subscription to genuinely remain 'canceled'"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn subscription_lost_missing_user_id() {
    let pool = test_pool().await;

    let sub_id = "sub_lost_missing_user_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "delivered@resend.dev".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: None,
        }),
    };

    let event_type = "subscription.paused";
    handle_subscription_lost(&pool, &parsed, event_type).await;

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to be created when safely_user_id is missing"
    );
}

#[tokio::test]
async fn subscription_lost_upsert_fails() {
    let pool = test_pool().await;

    let sub_id = "sub_lost_upsert_fails_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let fake_user_id = Uuid::new_v4();

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "active".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "delivered@resend.dev".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(fake_user_id.to_string()),
        }),
    };

    let event_type = "subscription.expired";

    handle_subscription_lost(&pool, &parsed, event_type).await;

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to exist, since the foreign key genuinely failed"
    );
}

// Send Subscripton Ended Email Tests
#[tokio::test]
#[serial]
async fn send_subscription_ended_email_missing_api_key() {
    load_env_once();
    let original_key = var("RESEND_API_KEY").ok();
    unsafe {
        remove_var("RESEND_API_KEY");
    }

    let result = send_subscription_ended_email("delivered@resend.dev").await;
    match result {
        Err(AuthError::InternalServerError(_)) => {}
        Err(other) => panic!(
            "expected InternalServerError, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected the email to fail without a real API key, but it succeeded"),
    }

    unsafe {
        if let Some(key) = original_key {
            set_var("RESEND_API_KEY", key);
        }
    }
}

#[tokio::test]
#[serial]
async fn send_subscription_ended_email_missing_base_url() {
    load_env_once();
    let original_url = var("PUBLIC_BASE_URL").ok();
    unsafe {
        remove_var("PUBLIC_BASE_URL");
    }

    let result = send_subscription_ended_email("delivered@resend.dev").await;
    match result {
        Err(AuthError::InternalServerError(_)) => {}
        Err(other) => panic!(
            "expected InternalServerError, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected the email to fail without PUBLIC_BASE_URL, but it succeeded"),
    }

    unsafe {
        if let Some(url) = original_url {
            set_var("PUBLIC_BASE_URL", url);
        }
    }
}

#[tokio::test]
#[serial]
async fn send_subscription_ended_email_succeeds() {
    load_env_once();

    let result = send_subscription_ended_email("delivered@resend.dev").await;
    assert!(
        result.is_ok(),
        "expected the subscription-ended email to send successfully, got: {:?}",
        result
    );
}

#[tokio::test]
#[serial]
async fn send_subscription_ended_email_fails_for_a_blocked_domain() {
    load_env_once();

    let result = send_subscription_ended_email("test_user@example.com").await;
    match result {
        Err(AuthError::InternalServerError(message)) => {
            assert!(
                message.contains("Invalid `to` field"),
                "expected Resend's specific rejection message, got: {}",
                message
            )
        }
        other => panic!("expected an InternalServerError, got: {:?}", other),
    }
}

// Handle Subscription Update Tests
#[tokio::test]
async fn subscription_update_success() {
    let pool = test_pool().await;
    let email = "subscription_update_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_update_test_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "trialing".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: email.to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(user.id.to_string()),
        }),
    };

    handle_subscription_update(&pool, &parsed).await;
    let saved_status = get_subscription_status_text(&pool, sub_id).await;

    assert_eq!(
        saved_status,
        Some("trialing".to_string()),
        "expected the exact status from parsed.status to be saved, unchanged"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn subscription_update_missing_user_id() {
    let pool = test_pool().await;

    let sub_id = "sub_update_missing_user_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "trialing".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: None,
        }),
    };

    handle_subscription_update(&pool, &parsed).await;

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to be created when safely_user_id is missing"
    );
}

#[tokio::test]
async fn subscription_update_upsert_fails() {
    let pool = test_pool().await;

    let sub_id = "sub_update_upsert_fails_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let fake_user_id = Uuid::new_v4();

    let parsed = ParsedSubscription {
        id: sub_id.to_string(),
        status: "trialing".to_string(),
        current_period_end_date: None,
        canceled_at: None,
        product: ParsedProduct {
            id: "prod_test".to_string(),
            name: "Team".to_string(),
        },
        customer: ParsedCustomer {
            id: "cust_test".to_string(),
            email: "test@example.com".to_string(),
        },
        metadata: Some(ParsedMetadata {
            safely_user_id: Some(fake_user_id.to_string()),
        }),
    };

    handle_subscription_update(&pool, &parsed).await;

    let saved_row: Option<String> =
        query_scalar("SELECT status::text FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert!(
        saved_row.is_none(),
        "expected NO subscription row to exist, since the foreign key genuinely failed"
    );
}

// Cancel Subscription Handler Tests
#[tokio::test]
async fn cancel_subscription_unauthorized() {
    let pool = test_pool().await;

    let headers = HeaderMap::new();

    let result = cancel_subscription_handler(State(pool), headers).await;
    match result {
        Err(BillingError::Unauthorized) => {}
        Err(other) => panic!("expected Unauthorized, got a different error: {:?}", other),
        Ok(_) => panic!("expected an unauthenticated request to be rejected, but it succeeded"),
    }
}

#[tokio::test]
async fn cancel_subscription_not_found() {
    let pool = test_pool().await;
    let email = "cancel_not_found_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;
    let result = cancel_subscription_handler(State(pool.clone()), headers).await;

    match result {
        Err(BillingError::NotFound(_)) => {}
        Err(other) => panic!("expected NotFound, got a different error: {:?}", other),
        Ok(_) => {
            panic!("expected cancellation to fail with no subscription to cancel, but it succeeded")
        }
    }

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn cancel_subscription_creem_rejects() {
    let pool = test_pool().await;
    let email = "cancel_creem_rejects_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let sub_id = "sub_creem_rejects_fake_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    insert_test_subscription(&pool, user.id, sub_id, "Team", "active").await;

    let result = cancel_subscription_handler(State(pool.clone()), headers).await;
    match result {
        Err(BillingError::ServiceUnavailable(_)) => {}
        Err(other) => panic!(
            "expected ServiceUnavailable, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected Creem to reject the cancellation, but it succeeded"),
    }

    let saved_status = get_subscription_status_text(&pool, sub_id).await;
    assert_eq!(
        saved_status,
        Some("active".to_string()),
        "expected the status to remain 'active', unchanged, since the cancellation genuinely failed"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

// Cancel with Creem Tests
#[tokio::test]
#[serial]
async fn cancel_with_creem_missing_api_key() {
    load_env_once();

    let original_key = var("CREEM_API_KEY").ok();
    unsafe {
        remove_var("CREEM_API_KEY");
    }

    let result = cancel_with_creem("sub_does_not_matter_here").await;
    match result {
        Err(BillingError::InternalError(_)) => {}
        Err(other) => panic!("expected InternalError, got a different error: {:?}", other),
        Ok(_) => panic!("expected cancellation to fail without a real API key, but it succeeded"),
    }

    unsafe {
        if let Some(key) = original_key {
            set_var("CREEM_API_KEY", key);
        }
    }
}

#[tokio::test]
#[serial]
async fn cancel_with_creem_request_failed() {
    load_env_once();

    let original_base_url = var("CREEM_API_BASE_URL").ok();

    unsafe {
        set_var(
            "CREEM_API_BASE_URL",
            "http://this-domain-genuinely-does-not-exist-12345.invalid",
        );
    }

    let result = cancel_with_creem("sub_does_not_matter_here").await;

    match result {
        Err(BillingError::ServiceUnavailable(msg)) => {
            assert_eq!(
                msg, "Could not reach Creem",
                "expected the 'could not reach' message specifically, got: {}",
                msg
            );
        }
        Err(other) => panic!(
            "expected ServiceUnavailable, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected the request to genuinely fail, but it succeeded"),
    }

    unsafe {
        match original_base_url {
            Some(url) => set_var("CREEM_API_BASE_URL", url),
            None => remove_var("CREEM_API_BASE_URL"),
        }
    }
}

#[tokio::test]
#[serial]
async fn cancel_with_creem_rejected() {
    load_env_once();
    let result = cancel_with_creem("sub_definitely_does_not_exist_on_creem").await;

    match result {
        Err(BillingError::ServiceUnavailable(msg)) => {
            assert_eq!(
                msg, "Creem rejected the cancellation",
                "expected the 'rejected' message specifically, got: {}",
                msg
            );
        }
        Err(other) => panic!(
            "expected ServiceUnavailable, got a different error: {:?}",
            other
        ),
        Ok(_) => {
            panic!("expected Creem to genuinely reject a fake subscription ID, but it succeeded")
        }
    }
}

// Fetch Subscriber Email Tests
#[tokio::test]
async fn fetch_subscriber_email_found() {
    let pool = test_pool().await;
    let email = "fetch_subscriber_email_scenario_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let sub_id = "sub_fetch_email_scenario_001";
    cleanup_test_subscription(&pool, sub_id).await;
    insert_test_subscription(&pool, user.id, sub_id, "Team", "active").await;

    let result = fetch_subscriber_email(&pool, sub_id).await;
    assert_eq!(
        result,
        Some(email.to_string()),
        "expected the real subscriber's email to be found"
    );

    cleanup_test_subscription(&pool, sub_id).await;
    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn fetch_subscriber_email_not_found() {
    let pool = test_pool().await;
    let sub_id = "sub_fetch_email_scenario_not_found_001";
    cleanup_test_subscription(&pool, sub_id).await;

    let result = fetch_subscriber_email(&pool, sub_id).await;
    assert!(
        result.is_none(),
        "expected None when no subscription matches this sub_id"
    );
}

#[tokio::test]
async fn fetch_subscriber_email_database_error_still_returns_none() {
    let pool = test_pool().await;
    pool.close().await;

    let result = fetch_subscriber_email(&pool, "doesnt_matter").await;
    assert!(
        result.is_none(),
        "expected None even on a genuine database error, since this function never hard-fails"
    );
}

// Send Subscription Cancel Email Tests
#[tokio::test]
#[serial]
async fn send_subscription_canceled_email_missing_api_key() {
    load_env_once();
    let original_key = var("RESEND_API_KEY").ok();
    unsafe {
        remove_var("RESEND_API_KEY");
    }

    let result = send_subscription_canceled_email("delivered@resend.dev").await;
    match result {
        Err(AuthError::InternalServerError(_)) => {}
        Err(other) => panic!(
            "expected InternalServerError, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected the email to fail without a real API key, but it succeeded"),
    }

    unsafe {
        if let Some(key) = original_key {
            set_var("RESEND_API_KEY", key);
        }
    }
}

#[tokio::test]
#[serial]
async fn send_subscription_canceled_email_missing_base_url() {
    load_env_once();

    let original_url = var("PUBLIC_BASE_URL").ok();
    unsafe {
        remove_var("PUBLIC_BASE_URL");
    }

    let result = send_subscription_canceled_email("delivered@resend.dev").await;
    match result {
        Err(AuthError::InternalServerError(_)) => {}
        Err(other) => panic!(
            "expected InternalServerError, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected the email to fail without PUBLIC_BASE_URL, but it succeeded"),
    }

    unsafe {
        if let Some(url) = original_url {
            set_var("PUBLIC_BASE_URL", url);
        }
    }
}

#[tokio::test]
#[serial]
async fn send_subscription_canceled_email_succeeds() {
    load_env_once();

    let result = send_subscription_canceled_email("delivered@resend.dev").await;
    assert!(
        result.is_ok(),
        "expected the subscription-canceled email to send successfully, got: {:?}",
        result
    );
}

#[tokio::test]
#[serial]
async fn send_subscription_canceled_email_fails_for_a_blocked_domain() {
    load_env_once();

    let result = send_subscription_canceled_email("test_user@example.com").await;
    match result {
        Err(AuthError::InternalServerError(message)) => {
            assert!(
                message.contains("Invalid `to` field"),
                "expected Resend's specific rejection message, got: {}",
                message
            )
        }
        other => panic!("expected an InternalServerError, got: {:?}", other),
    }
}

// Get Subscription Status
#[tokio::test]
async fn get_subscription_status_unauthorized() {
    let pool = test_pool().await;
    let headers = HeaderMap::new();

    let result = get_subscription_status(State(pool), headers).await;
    match result {
        Err(BillingError::Unauthorized) => {}
        Err(other) => panic!("expected Unauthorized, got a different error: {:?}", other),
        Ok(_) => panic!("expected an unauthenticated request to be rejected, but it succeeded"),
    }
}

#[tokio::test]
async fn get_subscription_status_no_subscription() {
    let pool = test_pool().await;
    let email = "get_status_no_sub_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;
    let result = get_subscription_status(State(pool.clone()), headers)
        .await
        .expect("expected the request itself to succeed, even with no subscription")
        .0;

    assert_eq!(
        result,
        json!({
            "plan_name": null,
            "status": null,
            "current_period_end": null,
            "scheduled_plan_name": null,
        }),
        "expected the exact, hardcoded all-null response"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn get_subscription_status_no_scheduled_downgrade() {
    let pool = test_pool().await;
    let email = "get_status_no_downgrade_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let sub_id = "sub_status_no_downgrade_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let period_end = Utc::now() + Duration::days(20);

    insert_test_subscription_full(
        &pool,
        user.id,
        sub_id,
        "Team",
        "active",
        TestSubscriptionOptions {
            current_period_end: Some(period_end),
            scheduled_product_id: None,
            scheduled_plan_name: None,
        },
    )
    .await;

    let result = get_subscription_status(State(pool.clone()), headers)
        .await
        .expect("expected the request to succeed");

    assert_eq!(result["plan_name"], json!("Team"));
    assert_eq!(result["status"], json!("active"));
    assert_eq!(result["scheduled_plan_name"], json!(null));

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn get_subscription_status_downgrade_not_yet_due() {
    let pool = test_pool().await;
    let email = "get_status_downgrade_not_due_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let sub_id = "sub_status_downgrade_not_due_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let period_end = Utc::now() + Duration::days(20);

    insert_test_subscription_full(
        &pool,
        user.id,
        sub_id,
        "Enterprise",
        "active",
        TestSubscriptionOptions {
            current_period_end: Some(period_end),
            scheduled_product_id: Some("prod_team_scheduled"),
            scheduled_plan_name: Some("Team"),
        },
    )
    .await;

    let result = get_subscription_status(State(pool.clone()), headers)
        .await
        .expect("expected the request to succeed");

    assert_eq!(result["plan_name"], json!("Enterprise"));
    assert_eq!(result["status"], json!("active"));
    assert_eq!(result["scheduled_plan_name"], json!("Team"));

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn get_subscription_status_downgrade_due_but_creem_rejects() {
    let pool = test_pool().await;
    let email = "get_status_downgrade_due_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let sub_id = "sub_status_downgrade_due_fake_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let period_end = Utc::now() - Duration::days(1);

    insert_test_subscription_full(
        &pool,
        user.id,
        sub_id,
        "Enterprise",
        "active",
        TestSubscriptionOptions {
            current_period_end: Some(period_end),
            scheduled_product_id: Some("prod_team_scheduled"),
            scheduled_plan_name: Some("Team"),
        },
    )
    .await;

    let result = get_subscription_status(State(pool.clone()), headers)
        .await
        .expect("expected the request to still succeed, even though Creem rejected the downgrade");

    assert_eq!(
        result["plan_name"],
        json!("Enterprise"),
        "expected the ORIGINAL plan to still be reported, since the downgrade genuinely failed"
    );
    assert_eq!(result["status"], json!("active"));
    assert_eq!(
        result["scheduled_plan_name"],
        json!("Team"),
        "expected the schedule to remain, since it was never successfully applied"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

// Apply Scheduled Downgrade If Due Tests
#[tokio::test]
async fn apply_scheduled_downgrade_missing_product_id() {
    let pool = test_pool().await;

    let result = apply_scheduled_downgrade_if_due(
        &pool,
        "sub_does_not_matter",
        None,
        Some("Team"),
        Some(Utc::now() - Duration::days(1)),
    )
    .await;

    assert!(
        result.is_none(),
        "expected None when scheduled_product_id is missing"
    );
}

#[tokio::test]
async fn apply_scheduled_downgrade_missing_plan_name() {
    let pool = test_pool().await;

    let result = apply_scheduled_downgrade_if_due(
        &pool,
        "sub_does_not_matter",
        Some("prod_team"),
        None,
        Some(Utc::now() - Duration::days(1)),
    )
    .await;

    assert!(
        result.is_none(),
        "expected None when scheduled_plan_name is missing"
    );
}

#[tokio::test]
async fn apply_scheduled_downgrade_missing_period_end() {
    let pool = test_pool().await;

    let result = apply_scheduled_downgrade_if_due(
        &pool,
        "sub_does_not_matter",
        Some("prod_team"),
        Some("Team"),
        None,
    )
    .await;

    assert!(
        result.is_none(),
        "expected None when current_period_end is missing"
    );
}

#[tokio::test]
async fn apply_scheduled_downgrade_not_yet_due() {
    let pool = test_pool().await;

    let result = apply_scheduled_downgrade_if_due(
        &pool,
        "sub_does_not_matter",
        Some("prod_team"),
        Some("Team"),
        Some(Utc::now() + Duration::days(20)),
    )
    .await;

    assert!(
        result.is_none(),
        "expected None when the deferred period hasn't ended yet"
    );
}

#[tokio::test]
async fn apply_scheduled_downgrade_creem_rejects() {
    let pool = test_pool().await;
    let email = "apply_downgrade_creem_rejects_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_apply_downgrade_fake_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    let period_end = Utc::now() - Duration::days(1);

    insert_test_subscription_full(
        &pool,
        user.id,
        sub_id,
        "Enterprise",
        "active",
        TestSubscriptionOptions {
            current_period_end: Some(period_end),
            scheduled_product_id: Some("prod_team_scheduled"),
            scheduled_plan_name: Some("Team"),
        },
    )
    .await;

    let result = apply_scheduled_downgrade_if_due(
        &pool,
        sub_id,
        Some("prod_team_scheduled"),
        Some("Team"),
        Some(period_end),
    )
    .await;

    assert!(
        result.is_none(),
        "expected None when Creem genuinely rejects the downgrade"
    );

    let (plan_name, scheduled_plan_name): (String, Option<String>) = query_as(
        "SELECT plan_name, scheduled_plan_name FROM subscriptions WHERE creem_subscription_id = $1",
    )
    .bind(sub_id)
    .fetch_one(&pool)
    .await
    .expect("expected the query itself to succeed");

    assert_eq!(
        plan_name, "Enterprise",
        "expected the plan_name to remain unchanged, since the update never ran"
    );
    assert_eq!(
        scheduled_plan_name,
        Some("Team".to_string()),
        "expected the schedule to remain, since it was never successfully cleared"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

// Change Creem Subscription Product Tests
#[tokio::test]
#[serial]
async fn change_creem_subscription_product_missing_api_key() {
    load_env_once();
    let original_key = var("CREEM_API_KEY").ok();
    unsafe {
        remove_var("CREEM_API_KEY");
    }

    let result = change_creem_subscription_product(
        "sub_doesnt_matter",
        "prod_doesnt_matter",
        "proration-charge-immediately",
    )
    .await;

    assert!(
        result.is_err(),
        "expected the request to fail without a real API key"
    );

    unsafe {
        if let Some(key) = original_key {
            set_var("CREEM_API_KEY", key);
        }
    }
}

#[tokio::test]
#[serial]
async fn change_creem_subscription_product_request_failed() {
    load_env_once();
    let original_base_url = var("CREEM_API_BASE_URL").ok();
    unsafe {
        set_var(
            "CREEM_API_BASE_URL",
            "http://this-domain-genuinely-does-not-exist-12345.invalid",
        );
    }

    let result = change_creem_subscription_product(
        "sub_doesnt_matter",
        "prod_doesnt_matter",
        "proration-charge-immediately",
    )
    .await;

    assert!(
        result.is_err(),
        "expected the request to genuinely fail against an unreachable host"
    );

    unsafe {
        match original_base_url {
            Some(url) => set_var("CREEM_API_BASE_URL", url),
            None => remove_var("CREEM_API_BASE_URL"),
        }
    }
}

#[tokio::test]
#[serial]
async fn change_creem_subscription_product_creem_rejects() {
    load_env_once();

    let result = change_creem_subscription_product(
        "sub_definitely_does_not_exist_on_creem",
        "prod_doesnt_matter",
        "proration-charge-immediately",
    )
    .await;

    match result {
        Err(message) => {
            assert!(
                message.contains("Creem rejected plan change"),
                "expected the specific rejection message, got: {}",
                message
            );
        }
        Ok(_) => {
            panic!("expected Creem to genuinely reject a fake subscription ID, but it succeeded")
        }
    }
}

// Change Plan Handler Tests
#[tokio::test]
async fn change_plan_unauthorized() {
    let pool = test_pool().await;
    let headers = HeaderMap::new();

    let body = ChangePlanBody {
        product_id: "prod_does_not_matter".to_string(),
        plan_name: "Enterprise".to_string(),
    };

    let result = change_plan_handler(State(pool), headers, Json(body)).await;

    match result {
        Err(BillingError::Unauthorized) => {}
        Err(other) => panic!("expected Unauthorized, got a different error: {:?}", other),
        Ok(_) => panic!("expected an unauthenticated request to be rejected, but it succeeded"),
    }
}

#[tokio::test]
async fn change_plan_not_found() {
    let pool = test_pool().await;
    let email = "change_plan_not_found_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let body = ChangePlanBody {
        product_id: "prod_does_not_matter".to_string(),
        plan_name: "Enterprise".to_string(),
    };

    let result = change_plan_handler(State(pool.clone()), headers, Json(body)).await;

    match result {
        Err(BillingError::NotFound(_)) => {}
        Err(other) => panic!("expected NotFound, got a different error: {:?}", other),
        Ok(_) => {
            panic!("expected the change to fail with no subscription to modify, but it succeeded")
        }
    }

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn change_plan_conflict_while_trialing() {
    let pool = test_pool().await;
    let email = "change_plan_trialing_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let sub_id = "sub_change_plan_trialing_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    insert_test_subscription(&pool, user.id, sub_id, "Team", "trialing").await;

    let body = ChangePlanBody {
        product_id: "prod_enterprise_target".to_string(),
        plan_name: "Enterprise".to_string(),
    };

    let result = change_plan_handler(State(pool.clone()), headers, Json(body)).await;

    match result {
        Err(BillingError::Conflict(_)) => {}
        Err(other) => panic!("expected Conflict, got a different error: {:?}", other),
        Ok(_) => panic!("expected trialing status to block the change, but it succeeded"),
    }

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn change_plan_invalid_request() {
    let pool = test_pool().await;
    let email = "change_plan_invalid_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let sub_id = "sub_change_plan_invalid_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    insert_test_subscription(&pool, user.id, sub_id, "Team", "active").await;

    let body = ChangePlanBody {
        product_id: "prod_team_current".to_string(),
        plan_name: "Team".to_string(),
    };

    let result = change_plan_handler(State(pool.clone()), headers, Json(body)).await;

    match result {
        Err(BillingError::InvalidRequest(_)) => {}
        Err(other) => panic!(
            "expected InvalidRequest, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected a nonsensical plan change to be rejected, but it succeeded"),
    }

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn change_plan_downgrade_success() {
    let pool = test_pool().await;
    let email = "change_plan_downgrade_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let sub_id = "sub_change_plan_downgrade_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    insert_test_subscription(&pool, user.id, sub_id, "Enterprise", "active").await;

    let body = ChangePlanBody {
        product_id: "prod_team_target".to_string(),
        plan_name: "Team".to_string(),
    };

    let result = change_plan_handler(State(pool.clone()), headers, Json(body))
        .await
        .expect("expected the downgrade to be scheduled successfully");

    assert_eq!(result.0, json!({ "applied": "scheduled" }));

    let (plan_name, scheduled_product_id, scheduled_plan_name): (
        String,
        Option<String>,
        Option<String>,
    ) = query_as(
        "SELECT plan_name, scheduled_product_id, scheduled_plan_name
         FROM subscriptions WHERE creem_subscription_id = $1",
    )
    .bind(sub_id)
    .fetch_one(&pool)
    .await
    .expect("expected the query itself to succeed");

    assert_eq!(
        plan_name, "Enterprise",
        "expected the CURRENT plan to remain Enterprise - the downgrade is only scheduled"
    );
    assert_eq!(scheduled_product_id, Some("prod_team_target".to_string()));
    assert_eq!(scheduled_plan_name, Some("Team".to_string()));

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn change_plan_upgrade_creem_rejects() {
    let pool = test_pool().await;
    let email = "change_plan_upgrade_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;
    let headers = auth_headers_for(&pool, user.id).await;

    let sub_id = "sub_change_plan_upgrade_fake_001";
    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected cleanup to succeed");

    insert_test_subscription(&pool, user.id, sub_id, "Team", "active").await;

    let body = ChangePlanBody {
        product_id: "prod_enterprise_target".to_string(),
        plan_name: "Enterprise".to_string(),
    };

    let result = change_plan_handler(State(pool.clone()), headers, Json(body)).await;

    match result {
        Err(BillingError::ServiceUnavailable(_)) => {}
        Err(other) => panic!(
            "expected ServiceUnavailable, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected Creem to reject the upgrade, but it succeeded"),
    }

    let plan_name: String =
        query_scalar("SELECT plan_name FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_one(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert_eq!(
        plan_name, "Team",
        "expected the plan to remain 'Team', unchanged, since the upgrade genuinely failed"
    );

    query("DELETE FROM subscriptions WHERE creem_subscription_id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .expect("expected final cleanup to succeed");

    cleanup_test_user(&pool, email).await;
}

// Apply Upgrade Tests
#[tokio::test]
async fn apply_upgrade_creem_rejects() {
    let pool = test_pool().await;
    let email = "apply_upgrade_rejects_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let sub_id = "sub_apply_upgrade_fake_001";
    cleanup_test_subscription(&pool, sub_id).await;
    insert_test_subscription(&pool, user.id, sub_id, "Team", "active").await;

    let body = ChangePlanBody {
        product_id: "prod_enterprise_target".to_string(),
        plan_name: "Enterprise".to_string(),
    };

    let result = apply_upgrade(&pool, sub_id, &body).await;
    match result {
        Err(BillingError::ServiceUnavailable(_)) => {}
        Err(other) => panic!("expected ServiceUnavailable, got: {:?}", other),
        Ok(_) => panic!("expected Creem to reject the upgrade, but it succeeded"),
    }

    let plan_name: String =
        query_scalar("SELECT plan_name FROM subscriptions WHERE creem_subscription_id = $1")
            .bind(sub_id)
            .fetch_one(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert_eq!(plan_name, "Team", "expected the plan to remain unchanged");

    cleanup_test_subscription(&pool, sub_id).await;
    cleanup_test_user(&pool, email).await;
}

// Get Product IDs Tests
#[tokio::test]
#[serial]
async fn get_product_ids_success() {
    load_env_once();

    let expected_team_id = var("CREEM_TEAM_PRODUCT_ID")
        .expect("expected CREEM_TEAM_PRODUCT_ID to be genuinely set for this test");
    let expected_enterprise_id = var("CREEM_ENTERPRISE_PRODUCT_ID")
        .expect("expected CREEM_ENTERPRISE_PRODUCT_ID to be genuinely set for this test");

    let result = get_product_ids()
        .await
        .expect("expected the request to succeed with both real IDs present")
        .0;

    assert_eq!(
        result,
        json!({
            "Team": expected_team_id,
            "Enterprise": expected_enterprise_id,
        }),
        "expected the real, actual product IDs to be returned"
    );
}

#[tokio::test]
#[serial]
async fn get_product_ids_missing_team_id() {
    load_env_once();

    let original_team_id = var("CREEM_TEAM_PRODUCT_ID").ok();
    unsafe {
        remove_var("CREEM_TEAM_PRODUCT_ID");
    }

    let result = get_product_ids().await;

    match result {
        Err(BillingError::InternalError(_)) => {}
        Err(other) => panic!("expected InternalError, got a different error: {:?}", other),
        Ok(_) => {
            panic!("expected the request to fail without CREEM_TEAM_PRODUCT_ID, but it succeeded")
        }
    }

    unsafe {
        if let Some(id) = original_team_id {
            set_var("CREEM_TEAM_PRODUCT_ID", id);
        }
    }
}

#[tokio::test]
#[serial]
async fn get_product_ids_missing_enterprise_id() {
    load_env_once();

    let original_enterprise_id = var("CREEM_ENTERPRISE_PRODUCT_ID").ok();
    unsafe {
        remove_var("CREEM_ENTERPRISE_PRODUCT_ID");
    }

    let result = get_product_ids().await;

    match result {
        Err(BillingError::InternalError(_)) => {}
        Err(other) => panic!("expected InternalError, got a different error: {:?}", other),
        Ok(_) => panic!(
            "expected the request to fail without CREEM_ENTERPRISE_PRODUCT_ID, but it succeeded"
        ),
    }

    unsafe {
        if let Some(id) = original_enterprise_id {
            set_var("CREEM_ENTERPRISE_PRODUCT_ID", id);
        }
    }
}

// Mark Event Processed If New Tests
#[tokio::test]
async fn mark_event_processed_returns_true_for_a_genuinely_new_event() {
    let pool = test_pool().await;
    let event_id = "evt_genuinely_new_001";
    query("DELETE FROM webhook_events_processed WHERE event_id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .ok();

    let result = mark_event_processed_if_new(&pool, event_id).await;
    assert!(
        result,
        "expected true for a genuinely new, never-before-seen event ID"
    );

    query("DELETE FROM webhook_events_processed WHERE event_id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn mark_event_processed_returns_false_for_a_genuinely_repeated_event() {
    let pool = test_pool().await;
    let event_id = "evt_genuinely_repeated_001";
    query("DELETE FROM webhook_events_processed WHERE event_id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .ok();

    let first_result = mark_event_processed_if_new(&pool, event_id).await;
    assert!(first_result, "expected the first call to genuinely be new");

    let second_result = mark_event_processed_if_new(&pool, event_id).await;
    assert!(
        !second_result,
        "expected the SAME event ID, seen a second time, to correctly report false"
    );

    query("DELETE FROM webhook_events_processed WHERE event_id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn mark_event_processed_correctly_writes_a_real_row_to_the_database() {
    let pool = test_pool().await;
    let event_id = "evt_real_row_check_001";
    query("DELETE FROM webhook_events_processed WHERE event_id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .ok();

    mark_event_processed_if_new(&pool, event_id).await;

    let row_exists: Option<String> =
        query_scalar("SELECT event_id FROM webhook_events_processed WHERE event_id = $1")
            .bind(event_id)
            .fetch_optional(&pool)
            .await
            .expect("expected the query itself to succeed");

    assert_eq!(
        row_exists,
        Some(event_id.to_string()),
        "expected a real, permanent row to genuinely exist in the database"
    );

    query("DELETE FROM webhook_events_processed WHERE event_id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn mark_event_processed_treats_different_event_ids_as_genuinely_independent() {
    let pool = test_pool().await;
    let event_a = "evt_independent_a_001";
    let event_b = "evt_independent_b_001";
    query("DELETE FROM webhook_events_processed WHERE event_id IN ($1, $2)")
        .bind(event_a)
        .bind(event_b)
        .execute(&pool)
        .await
        .ok();

    let result_a = mark_event_processed_if_new(&pool, event_a).await;
    let result_b = mark_event_processed_if_new(&pool, event_b).await;

    assert!(result_a, "expected event A to be genuinely new");
    assert!(
        result_b,
        "expected event B to ALSO be genuinely new, unaffected by event A already being recorded"
    );

    query("DELETE FROM webhook_events_processed WHERE event_id IN ($1, $2)")
        .bind(event_a)
        .bind(event_b)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn mark_event_processed_correctly_handles_two_genuinely_simultaneous_attempts() {
    let pool = test_pool().await;
    let event_id = "evt_concurrent_race_001";
    query("DELETE FROM webhook_events_processed WHERE event_id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .ok();

    let pool_a = pool.clone();
    let pool_b = pool.clone();
    let event_id_a = event_id.to_string();
    let event_id_b = event_id.to_string();

    let (result_a, result_b) = tokio::join!(
        mark_event_processed_if_new(&pool_a, &event_id_a),
        mark_event_processed_if_new(&pool_b, &event_id_b)
    );

    let true_count = [result_a, result_b].iter().filter(|&&r| r).count();
    assert_eq!(
        true_count, 1,
        "expected EXACTLY one of the two genuinely simultaneous attempts to succeed, got: a={}, b={}",
        result_a, result_b
    );

    query("DELETE FROM webhook_events_processed WHERE event_id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .ok();
}
