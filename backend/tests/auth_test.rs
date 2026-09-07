mod common;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    response::IntoResponse,
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use backend::{
    errors::{
        auth::{AuthError, AuthServiceError},
        google_oauth::GoogleOauthConfigError,
    },
    handlers::auth::{
        OAUTH_LINK_USER_COOKIE, OAUTH_STATE_COOKIE, google_callback, google_connect_redirect,
        google_redirect, logout, request_magic_link, verify_magic_link,
    },
    models::users::{
        GoogleAfterLoginQuery, GoogleConnectQuery, GoogleUserInfoEndpoint, MagicLinkRequest,
        VerifyMagicLinkToken,
    },
    routes::auth::auth_routes,
    services::{
        auth::{
            check_last_login, create_session, delete_session, extract_user_id,
            find_or_create_user_by_email, find_user_by_email, find_user_by_id, finish_sign_in,
            get_user_from_token, handle_google_connect, insert_magic_link, set_login_method,
            validate_email_format, validate_magic_link,
        },
        email::{send_magic_link_email, send_welcome_email},
        google_oauth::{
            build_google_authorize_url, exchange_code_for_user, find_or_create_user_by_google,
            find_user_by_google_id, link_google_account,
        },
        templates::get_tera,
    },
};
use chrono::{DateTime, Duration as chrono_duration, Utc};
use common::{cleanup_test_user, create_test_user, test_pool};
use dotenvy::{dotenv, var};
use reqwest::Body;
use serial_test::serial;
use sqlx::{query, query_as, query_scalar};
use std::env::{remove_var, set_var};
use tower::ServiceExt;
use uuid::Uuid;

// Request Magic Link Test
#[tokio::test]
async fn requesting_magic_link() {
    let test_email = "delivered@resend.dev ";
    let pool = test_pool().await;
    let formatted_email = validate_email_format(test_email).expect("email needs to be trimmed");
    cleanup_test_user(&pool, &formatted_email).await;

    let email_token = insert_magic_link(&pool, formatted_email.as_str())
        .await
        .expect("the magic link needs to be inserted");
    let base_url = var("PUBLIC_BASE_URL").expect("public base url needs to be configured");
    let verify_url = format!("{}/api/v1/auth/verify?token={}", base_url, email_token);

    send_magic_link_email(&formatted_email, &verify_url)
        .await
        .expect("magic link needs to be sent");

    let row: Option<(String,)> =
        query_as("SELECT email FROM magic_links WHERE email = $1 ORDER BY created_at DESC LIMIT 1")
            .bind(&formatted_email)
            .fetch_optional(&pool)
            .await
            .expect("query is expecting email from magic link");

    assert!(
        row.is_some(),
        "expected a magic link row to actually exist in the database"
    );

    let result = request_magic_link(
        State(pool.clone()),
        Json(MagicLinkRequest {
            email: formatted_email.clone(),
        }),
    )
    .await
    .expect("expected the magic link request to succeed");

    assert_eq!(result.success, true);
    assert_eq!(
        result.message,
        "If that email is valid, a sign-in link is on its way."
    );

    cleanup_test_user(&pool, &formatted_email).await;
}

#[tokio::test]
async fn requesting_a_magic_link_succeeds_for_a_valid_email() {
    let pool = test_pool().await;
    let test_email = "test_user@example.com";
    cleanup_test_user(&pool, test_email).await;

    let app = auth_routes().with_state(pool.clone());
    let body_test_email = format!(r#"{{"email": "{}"}}"#, test_email);

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/magic-link")
        .header("content-type", "application/json")
        .body(Body::from(body_test_email))
        .expect("the request needs to be built");

    let response = app
        .oneshot(request)
        .await
        .expect("expected to get the response");

    assert_eq!(response.status(), StatusCode::OK);

    let row: Option<(String,)> =
        query_as("SELECT email FROM magic_links WHERE email = $1 ORDER BY created_at DESC LIMIT 1")
            .bind(test_email)
            .fetch_optional(&pool)
            .await
            .expect("expected to select a query from magic link");

    assert!(row.is_some(), "expected a magic link to be inserted");

    let magic_link_response = request_magic_link(
        State(pool.clone()),
        Json(MagicLinkRequest {
            email: test_email.to_string(),
        }),
    )
    .await
    .expect("expected to request the magic link");

    assert!(magic_link_response.success);

    cleanup_test_user(&pool, test_email).await;
}

#[tokio::test]
async fn requesting_a_magic_link_rejects_an_invalid_email() {
    let pool = test_pool().await;
    let app = auth_routes().with_state(pool.clone());

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/magic-link")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email": "not-an-email"}"#))
        .expect("expected to build the request");

    let response = app
        .oneshot(request)
        .await
        .expect("expected to get the response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let result = request_magic_link(
        State(pool.clone()),
        Json(MagicLinkRequest {
            email: "not-an-email".to_string(),
        }),
    )
    .await;

    assert!(
        result.is_err(),
        "expected the invalid email address to be rejected"
    );
}

// Validate Email Format Test
#[test]
fn validate_email_format_already_clean() {
    let result = validate_email_format("test_user@example.com")
        .expect("expected a valid, clean email to be accepted");
    assert_eq!(result, "test_user@example.com");
}

#[test]
fn validate_email_format_trims_whitespace() {
    let result = validate_email_format("  test_user@example.com  ")
        .expect("expected whitespace to be trimmed, not rejected");
    assert_eq!(result, "test_user@example.com");
}

#[test]
fn validate_email_format_lowercases_uppercase() {
    let result = validate_email_format("Test_User@Example.COM")
        .expect("expected uppercase letters to be lowercased, not rejected");
    assert_eq!(result, "test_user@example.com");
}

#[test]
fn validate_email_format_trims_and_lowercases_together() {
    let result = validate_email_format("  Test_User@Example.COM  ")
        .expect("expected both trimming and lowercasing to apply together");
    assert_eq!(result, "test_user@example.com");
}

#[test]
fn validate_email_format_rejects_empty_string() {
    let result = validate_email_format("");
    assert!(
        matches!(result, Err(AuthError::BadRequest)),
        "expected a genuinely empty string to be rejected"
    );
}

#[test]
fn validate_email_format_rejects_whitespace_only() {
    let result = validate_email_format("   ");
    assert!(
        matches!(result, Err(AuthError::BadRequest)),
        "expected whitespace-only input to be rejected, since it trims to empty"
    );
}

#[test]
fn validate_email_format_rejects_missing_at_symbol() {
    let result = validate_email_format("not_an_email_at_all");
    assert!(
        matches!(result, Err(AuthError::BadRequest)),
        "expected a string with no '@' to be rejected"
    );
}

// Insert Magic Link Test
#[tokio::test]
async fn checking_magic_link_insertion() {
    let pool = test_pool().await;
    let email = "test_user@example.com";
    cleanup_test_user(&pool, email).await;

    // Method 1 - manual, direct SQL insert
    let manual_id = Uuid::now_v7();
    let manual_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono_duration::minutes(15);

    query("INSERT INTO magic_links (id, email, token, expires_at) VALUES($1, $2, $3, $4)")
        .bind(manual_id)
        .bind(email)
        .bind(&manual_token)
        .bind(expires_at)
        .execute(&pool)
        .await
        .expect("manual magic link needs to be inserted");

    // Method 2 - calling the real, actual function
    let function_token = insert_magic_link(&pool, email)
        .await
        .expect("expected insert_magic_link to succeed");

    let manual_row_email: String = query_scalar("SELECT email FROM magic_links WHERE token = $1")
        .bind(&manual_token)
        .fetch_one(&pool)
        .await
        .expect("manual row should exist");

    let function_row_email: String = query_scalar("SELECT email FROM magic_links WHERE token = $1")
        .bind(&function_token)
        .fetch_one(&pool)
        .await
        .expect("function-created row should exist");

    assert_eq!(manual_row_email, email);
    assert_eq!(function_row_email, email);
    assert_ne!(
        manual_token, function_token,
        "expected two genuinely distinct tokens"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn insert_magic_link_success_direct_verification() {
    let pool = test_pool().await;
    let email = "insert_magic_link_success_test@example.com";
    cleanup_test_user(&pool, email).await;

    let before_call = Utc::now();
    let token = insert_magic_link(&pool, email)
        .await
        .expect("expected the magic link to be inserted successfully");

    let (saved_email, expires_at): (String, DateTime<Utc>) =
        query_as("SELECT email, expires_at FROM magic_links WHERE token = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .expect("expected the real row to exist");

    assert_eq!(saved_email, email, "expected the correct email to be saved");

    let expected_expiry = before_call + chrono_duration::minutes(15);
    let difference = (expected_expiry - expires_at).num_seconds().abs();
    assert!(
        difference < 60,
        "expected expires_at to be genuinely ~15 minutes out, off by {} seconds",
        difference
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn insert_magic_link_invalid_email() {
    let pool = test_pool().await;
    let malformed_email = "not_an_email_at_all";

    let result = insert_magic_link(&pool, malformed_email).await;

    match result {
        Err(AuthServiceError::InvalidEmail) => {}
        Err(other) => panic!("expected InvalidEmail, got a different error: {:?}", other),
        Ok(_) => panic!("expected a malformed email to be rejected, but it succeeded"),
    }

    let row_exists: Option<String> = query_scalar("SELECT email FROM magic_links WHERE email = $1")
        .bind(malformed_email)
        .fetch_optional(&pool)
        .await
        .expect("expected the query to succeed");

    assert!(
        row_exists.is_none(),
        "expected no magic link row to be created for an invalid email"
    );
}

#[tokio::test]
async fn insert_magic_link_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let result = insert_magic_link(&pool, "delivered@resend.dev").await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Send Magic Link Test
#[tokio::test]
#[serial]
async fn sending_magic_link_email_succeeds() {
    dotenv().ok();

    let base_url = "http://localhost:3000";
    let to_email = "delivered@resend.dev";
    let to_formatted =
        validate_email_format(to_email).expect("needs to have a validated email address");
    let verify_url = format!("{}/api/v1/auth/verify?token=1234", base_url);

    let result = send_magic_link_email(&to_formatted, &verify_url).await;
    assert!(
        result.is_ok(),
        "expected the email to send successfully, got: {:?}",
        result
    );
}

#[tokio::test]
#[serial]
async fn sending_magic_link_email_fails_for_a_blocked_domain() {
    dotenvy::dotenv().ok();

    let to_email = "test_user@example.com";
    let to_validated =
        validate_email_format(to_email).expect("needs to have a validated email address");
    let base_url = "http://localhost:3000";
    let verify_url = format!("{}/api/v1/auth/verify?token=1234", base_url);

    let result = send_magic_link_email(&to_validated, &verify_url).await;

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

#[tokio::test]
#[serial]
async fn sending_magic_link_email_missing_api_key() {
    dotenvy::dotenv().ok();
    let original_key = var("RESEND_API_KEY").ok();
    unsafe {
        remove_var("RESEND_API_KEY");
    }

    let to_email = "delivered@resend.dev";
    let verify_url = "http://localhost:3000/api/v1/auth/verify?token=1234";
    let result = send_magic_link_email(to_email, verify_url).await;

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
async fn sending_magic_link_email_missing_base_url() {
    dotenvy::dotenv().ok();
    let original_url = var("PUBLIC_BASE_URL").ok();
    unsafe {
        remove_var("PUBLIC_BASE_URL");
    }

    let to_email = "delivered@resend.dev";
    let verify_url = "http://localhost:3000/api/v1/auth/verify?token=1234";
    let result = send_magic_link_email(to_email, verify_url).await;

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

// Get Tera Test
#[test]
fn get_tera_loads_all_five_email_templates() {
    let tera = get_tera();
    let registered_names: Vec<&str> = tera.get_template_names().collect();

    let expected_templates = [
        "email.html",
        "welcome_email.html",
        "payment_failed_email.html",
        "subscription_ended_email.html",
        "subscription_canceled_email.html",
    ];

    for name in expected_templates {
        assert!(
            registered_names.contains(&name),
            "expected template '{}' to be registered, found: {:?}",
            name,
            registered_names
        )
    }
}

#[test]
fn get_tera_returns_the_same_singleton_instance() {
    let first_call = get_tera();
    let second_call = get_tera();

    assert!(
        std::ptr::eq(first_call, second_call),
        "expected get_tera() to return the exact same instance on every call"
    );
}

// Verify Magic Link
#[tokio::test]
async fn checking_email_link_verification() {
    let pool = test_pool().await;
    let email = "test_user_verify_link@example.com";
    let formatted_email = validate_email_format(email).expect("required to have a formatted email");
    cleanup_test_user(&pool, email).await;

    let real_token = insert_magic_link(&pool, &formatted_email)
        .await
        .expect("it's expected to have the magic link inserted into the database");

    let validate = validate_magic_link(&pool, &real_token)
        .await
        .expect("expected the query to succeed")
        .expect("expected a valid, unexpired magic link to be found");

    assert_eq!(validate.email, email);

    let (user, is_new) = create_test_user(&pool, &validate.email).await;

    let session_token = finish_sign_in(&pool, user.id, is_new, &validate.email, "email")
        .await
        .expect("expected sign-in to complete successfully");

    assert!(!session_token.is_empty(), "expected a real session token");

    cleanup_test_user(&pool, &formatted_email).await;
}

#[tokio::test]
async fn verify_magic_link_succeeds_with_a_real_token() {
    let pool = test_pool().await;
    let email = "test_user_verify_handler@example.com";
    cleanup_test_user(&pool, email).await;

    let real_token = insert_magic_link(&pool, email)
        .await
        .expect("expected to insert a real magic link");

    let result = verify_magic_link(
        State(pool.clone()),
        Query(VerifyMagicLinkToken { token: real_token }),
    )
    .await;

    assert!(
        result.is_ok(),
        "expected verify_magic_link to succeed, got: {:?}",
        result
    );

    let response = result.unwrap().into_response();
    let location = response
        .headers()
        .get("location")
        .expect("expected a Location header")
        .to_str()
        .unwrap();

    assert!(location.starts_with("/dashboard/#session="));

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn verify_magic_link_rejects_a_token_that_was_never_inserted() {
    let pool = test_pool().await;
    let fake_token = Uuid::new_v4().to_string();

    let result = verify_magic_link(
        State(pool.clone()),
        Query(VerifyMagicLinkToken { token: fake_token }),
    )
    .await;

    assert!(
        result.is_err(),
        "expected a nonexistent token to be rejected"
    );
}

#[tokio::test]
async fn verify_magic_link_rejects_a_token_that_was_already_used() {
    let pool = test_pool().await;
    let email = "test_user2@example.com";
    cleanup_test_user(&pool, email).await;

    let real_token = insert_magic_link(&pool, email)
        .await
        .expect("expected to insert a real magic link");

    let first_result = verify_magic_link(
        State(pool.clone()),
        Query(VerifyMagicLinkToken {
            token: real_token.clone(),
        }),
    )
    .await;
    assert!(first_result.is_ok(), "expected the first use to succeed");

    let second_result = verify_magic_link(
        State(pool.clone()),
        Query(VerifyMagicLinkToken { token: real_token }),
    )
    .await;

    assert!(
        second_result.is_err(),
        "expected a reused token to be rejected"
    );

    cleanup_test_user(&pool, email).await;
}

// Find or Create User by Email Test
#[tokio::test]
async fn find_or_create_user_by_email_creates_a_new_user_when_none_exists() {
    let pool = test_pool().await;
    let email = "find_or_create_new@example.com";
    let (user, is_new) = create_test_user(&pool, email).await;

    assert!(is_new, "expected a brand-new user to be reported as new");
    assert_eq!(user.email, email);

    // Confirm the row genuinely exists now, independent of the
    // function's own return value.
    let found = find_user_by_email(&pool, email)
        .await
        .expect("expected the query to succeed");

    assert!(
        found.is_some(),
        "expected the new user to actually be in the database"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn find_or_create_user_by_email_returns_the_existing_user_when_one_already_exists() {
    let pool = test_pool().await;
    let email = "find_or_create_existing@example.com";
    let (first_user, first_is_new) = create_test_user(&pool, email).await;

    assert!(first_is_new, "expected the first call to report a new user");

    // Second call, same email - should find the SAME user, not create another.
    let (second_user, second_is_new) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected the second call to succeed");

    assert!(
        !second_is_new,
        "expected the second call to report an existing user, not new"
    );
    assert_eq!(
        second_user.id, first_user.id,
        "expected the exact same user to be returned"
    );

    cleanup_test_user(&pool, email).await;
}

// Find User By Email Test
#[tokio::test]
async fn find_user_by_email_finds_an_existing_user() {
    let pool = test_pool().await;
    let email = "test_user_find@example.com";
    let formatted_email = validate_email_format(email).expect("expected to format the email");
    let (created_user, _) = create_test_user(&pool, &formatted_email).await;

    let found = find_user_by_email(&pool, email)
        .await
        .expect("expected the query to succeed");

    let found_user = found.expect("expected to find the user that was just created");
    assert_eq!(found_user.id, created_user.id);
    assert_eq!(found_user.email, email);

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn find_user_by_email_returns_none_for_a_nonexistent_user() {
    let pool = test_pool().await;
    let email = "definitely_does_not_exist_anywhere@example.com";
    let formatted_email = validate_email_format(email).expect("expected to format the email");
    cleanup_test_user(&pool, email).await;

    let found = find_user_by_email(&pool, &formatted_email)
        .await
        .expect("expected the query itself to succeed");

    assert!(found.is_none(), "expected no user to be found");
}

#[tokio::test]
async fn find_user_by_email_invalid_email() {
    let pool = test_pool().await;

    let result = find_user_by_email(&pool, "not_an_email_at_all").await;

    match result {
        Err(AuthServiceError::InvalidEmail) => {}
        Err(other) => panic!("expected InvalidEmail, got a different error: {:?}", other),
        Ok(_) => panic!("expected a malformed email to be rejected, but it succeeded"),
    }
}

#[tokio::test]
async fn find_user_by_email_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let result = find_user_by_email(&pool, "delivered@resend.dev").await;
    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Finish Sign In Test
#[tokio::test]
#[serial]
async fn finish_sign_in_with_new_user() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;
    let email = "signin_with_new_user@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let session_token = finish_sign_in(&pool, user.id, true, email, "google")
        .await
        .expect("expected sign-in to complete successfully");

    assert!(
        !session_token.is_empty(),
        "expected a real, non-empty session token"
    );

    let found: Option<(String,)> = query_as("SELECT token FROM sessions WHERE token = $1")
        .bind(&session_token)
        .fetch_optional(&pool)
        .await
        .expect("expected the query to succeed");

    assert!(
        found.is_some(),
        "expected the session to genuinely exist in the database"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn finish_sign_in_with_old_user() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;
    let email = "signin_with_old_user@example.com";
    cleanup_test_user(&pool, email).await;

    let (user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    let session_token = finish_sign_in(&pool, user.id, false, email, "google")
        .await
        .expect("expected sign-in to complete successfully");

    assert!(
        !session_token.is_empty(),
        "expected a real, non-empty session token"
    );

    let found: Option<(String,)> = query_as("SELECT token FROM sessions WHERE token = $1")
        .bind(&session_token)
        .fetch_optional(&pool)
        .await
        .expect("expected the query to succeed");

    assert!(
        found.is_some(),
        "expected the session to genuinely exist in the database"
    );

    cleanup_test_user(&pool, email).await;
}

// Send Welcome Email Test
#[tokio::test]
#[serial]
async fn send_welcome_email_missing_api_key() {
    dotenvy::dotenv().ok();
    let original_key = var("RESEND_API_KEY").ok();
    unsafe {
        remove_var("RESEND_API_KEY");
    }

    let result = send_welcome_email("delivered@resend.dev").await;

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
async fn send_welcome_email_missing_base_url() {
    dotenvy::dotenv().ok();
    let original_url = var("PUBLIC_BASE_URL").ok();
    unsafe {
        remove_var("PUBLIC_BASE_URL");
    }

    let result = send_welcome_email("delivered@resend.dev").await;

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
async fn send_welcome_email_succeeds() {
    dotenv().ok();

    let result = send_welcome_email("delivered@resend.dev").await;
    assert!(
        result.is_ok(),
        "expected the welcome email to send successfully, got: {:?}",
        result
    );
}

#[tokio::test]
#[serial]
async fn send_welcome_email_fails_for_a_blocked_domain() {
    dotenvy::dotenv().ok();

    let result = send_welcome_email("test_user@example.com").await;
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

// Check Last Login Test
#[tokio::test]
async fn check_last_login_success() {
    let pool = test_pool().await;
    let email = "check_last_login_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let before: Option<DateTime<Utc>> =
        query_scalar("SELECT last_login_at FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .expect("expected the query to succeed");

    assert!(before.is_none(), "expected last_login_at to start as None");

    check_last_login(&pool, user.id)
        .await
        .expect("expected the update to succeed");

    let after: Option<DateTime<Utc>> =
        query_scalar("SELECT last_login_at FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .expect("expected the query to succeed");

    assert!(
        after.is_some(),
        "expected last_login_at to genuinely be set now"
    );
    assert!(
        Utc::now() - after.unwrap() < chrono_duration::minutes(1),
        "expected the recorded time to be genuinely recent"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn check_last_login_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let fake_user_id = Uuid::new_v4();
    let result = check_last_login(&pool, fake_user_id).await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Set Login Method Test
#[tokio::test]
async fn set_login_method_success_email() {
    let pool = test_pool().await;
    let email = "set_login_method_email_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    set_login_method(&pool, user.id, "email")
        .await
        .expect("expected the update to succeed");

    let saved_method: Option<String> =
        query_scalar("SELECT last_login_method FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .expect("expected the query to succeed");

    assert_eq!(
        saved_method,
        Some("email".to_string()),
        "expected the real database row to genuinely reflect 'email'"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn set_login_method_success_google() {
    let pool = test_pool().await;
    let email = "set_login_method_google_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    set_login_method(&pool, user.id, "google")
        .await
        .expect("expected the update to succeed");

    let saved_method: Option<String> =
        query_scalar("SELECT last_login_method FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .expect("expected the query to succeed");

    assert_eq!(
        saved_method,
        Some("google".to_string()),
        "expected the real database row to genuinely reflect 'google'"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn set_login_method_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let fake_user_id = Uuid::new_v4();
    let result = set_login_method(&pool, fake_user_id, "email").await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Create Session
#[tokio::test]
async fn create_session_success_correct_shape_and_expiry() {
    let pool = test_pool().await;
    let email = "create_session_shape_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let token = create_session(&pool, user.id)
        .await
        .expect("expected the session to be created successfully");

    assert_eq!(
        token.len(),
        64,
        "expected the token to be exactly 64 characters, got: {}",
        token.len()
    );
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "expected the token to contain only hex characters, got: {}",
        token
    );

    let expires_at: DateTime<Utc> =
        query_scalar("SELECT expires_at FROM sessions WHERE token = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .expect("expected the query to succeed");

    let expected_expiry = Utc::now() + chrono_duration::days(30);
    let difference = (expected_expiry - expires_at).num_seconds().abs();
    assert!(
        difference < 60,
        "expected expires_at to be genuinely ~30 days out, off by {} seconds",
        difference
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn create_session_produces_unique_tokens() {
    let pool = test_pool().await;
    let email = "create_session_uniqueness_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let first_token = create_session(&pool, user.id)
        .await
        .expect("expected the first session to be created");

    let second_token = create_session(&pool, user.id)
        .await
        .expect("expected the second session to be created");

    assert_ne!(
        first_token, second_token,
        "expected two genuinely distinct tokens, since each call should produce fresh randomness"
    );

    let first_exists: Option<String> = query_scalar("SELECT token FROM sessions WHERE token = $1")
        .bind(&first_token)
        .fetch_optional(&pool)
        .await
        .expect("expected the query to succeed");

    let second_exists: Option<String> = query_scalar("SELECT token FROM sessions WHERE token = $1")
        .bind(&second_token)
        .fetch_optional(&pool)
        .await
        .expect("expected the query to succeed");

    assert!(
        first_exists.is_some(),
        "expected the first session to genuinely exist"
    );
    assert!(
        second_exists.is_some(),
        "expected the second session to genuinely exist"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn create_session_fails_for_nonexistent_user() {
    let pool = test_pool().await;
    let fake_user_id = Uuid::new_v4();
    let result = create_session(&pool, fake_user_id).await;

    assert!(
        result.is_err(),
        "expected session creation to fail for a user that genuinely doesn't exist"
    );
}

// Google Redirect Test
#[tokio::test]
#[serial]
async fn google_redirect_success() {
    dotenvy::dotenv().ok();

    let jar = CookieJar::new();
    let (returned_jar, _redirect) = google_redirect(jar)
        .await
        .expect("expected google_redirect to succeed");

    let cookie = returned_jar
        .get(OAUTH_STATE_COOKIE)
        .expect("expected an oauth_state cookie to be present");

    assert!(
        !cookie.value().is_empty(),
        "expected the cookie's value to be a real, non-empty code"
    );
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    assert_eq!(cookie.max_age(), Some(time::Duration::minutes(10)));

    let expected_secure = var("PUBLIC_BASE_URL")
        .map(|url| url.starts_with("https://"))
        .unwrap_or(false);

    assert_eq!(cookie.secure(), Some(expected_secure))
}

#[tokio::test]
#[serial]
async fn google_redirect_failure() {
    dotenvy::dotenv().ok();
    let original_value = var("GOOGLE_CLIENT_ID").ok();

    unsafe {
        remove_var("GOOGLE_CLIENT_ID");
    }

    let jar = CookieJar::new();
    let result = google_redirect(jar).await;

    assert!(
        result.is_err(),
        "expected google_redirect to fail when GOOGLE_CLIENT_ID is missing"
    );

    unsafe {
        if let Some(value) = original_value {
            set_var("GOOGLE_CLIENT_ID", value);
        }
    }
}

#[tokio::test]
#[serial]
async fn google_redirect_failure_missing_redirect_uri() {
    dotenvy::dotenv().ok();
    let original_value = var("GOOGLE_REDIRECT_URI").ok();
    unsafe {
        remove_var("GOOGLE_REDIRECT_URI");
    }

    let jar = CookieJar::new();
    let result = google_redirect(jar).await;

    assert!(
        result.is_err(),
        "expected google_redirect to fail when GOOGLE_REDIRECT_URI is missing"
    );

    unsafe {
        if let Some(value) = original_value {
            set_var("GOOGLE_REDIRECT_URI", value);
        }
    }
}

#[tokio::test]
#[serial]
async fn google_redirect_success_url_contains_real_values() {
    dotenvy::dotenv().ok();

    let real_client_id = var("GOOGLE_CLIENT_ID")
        .expect("expected GOOGLE_CLIENT_ID to be genuinely set for this test");

    let jar = CookieJar::new();
    let (returned_jar, redirect) = google_redirect(jar)
        .await
        .expect("expected google_redirect to succeed");

    // Extract the real, actual redirect destination.
    let response = redirect.into_response();
    let location = response
        .headers()
        .get("location")
        .expect("expected a real Location header")
        .to_str()
        .expect("expected the header to be valid text");

    assert!(
        location.starts_with("https://accounts.google.com"),
        "expected a genuine Google authorization URL, got: {}",
        location
    );
    assert!(
        location.contains(&real_client_id),
        "expected the real client_id to genuinely appear in the redirect URL"
    );

    // Confirm the state code embedded in the URL matches the real
    // cookie value that was just set.
    let state_cookie = returned_jar
        .get(OAUTH_STATE_COOKIE)
        .expect("expected the state cookie to be present");

    assert!(
        location.contains(state_cookie.value()),
        "expected the redirect URL's state parameter to match the cookie's real value"
    );
}

#[tokio::test]
#[serial]
async fn google_redirect_produces_unique_state_codes() {
    dotenvy::dotenv().ok();

    let (first_jar, _) = google_redirect(CookieJar::new())
        .await
        .expect("expected the first call to succeed");
    let (second_jar, _) = google_redirect(CookieJar::new())
        .await
        .expect("expected the second call to succeed");

    let first_code = first_jar
        .get(OAUTH_STATE_COOKIE)
        .expect("expected the first state cookie to be present")
        .value()
        .to_string();

    let second_code = second_jar
        .get(OAUTH_STATE_COOKIE)
        .expect("expected the second state cookie to be present")
        .value()
        .to_string();

    assert_ne!(
        first_code, second_code,
        "expected two genuinely distinct state codes, since each call should produce fresh randomness"
    );
}

// Google Authorize URL Test
#[test]
#[serial]
fn google_authorize_url_success() {
    let client_key = "GOOGLE_CLIENT_ID";
    let uri_key = "GOOGLE_REDIRECT_URI";
    let random_code = Uuid::new_v4().to_string();
    let check_code = random_code.trim();

    unsafe {
        set_var(client_key, "CLIENT_VALUE");
        set_var(uri_key, "URI_VALUE");
    }

    let result = build_google_authorize_url(check_code);
    let url = result.expect("expected the URL to build successfully");

    assert!(
        url.contains("CLIENT_VALUE"),
        "expected the URL to contain the client id"
    );
    assert!(
        url.contains("URI_VALUE"),
        "expected the URL to contain the redirect uri"
    );
    assert!(
        url.contains(check_code),
        "expected the URL to contain the state code"
    );

    unsafe {
        remove_var(client_key);
        remove_var(uri_key);
    }
}

#[tokio::test]
#[serial]
async fn google_authorize_url_failure_on_client_id_missing() {
    dotenvy::dotenv().ok();

    let client_key = "GOOGLE_CLIENT_ID";
    let uri_key = "GOOGLE_REDIRECT_URI";
    let random_code = Uuid::new_v4().to_string();
    let check_code = random_code.trim();

    let original_client_id = var(client_key).ok();

    unsafe {
        remove_var(client_key);
        set_var(uri_key, "URI_VALUE");
    }

    let result = build_google_authorize_url(check_code);
    assert!(
        result.is_err(),
        "expected the URL building to fail when GOOGLE_CLIENT_ID is missing"
    );

    unsafe {
        remove_var(uri_key);
        if let Some(value) = original_client_id {
            set_var(client_key, value);
        }
    }
}

#[test]
#[serial]
fn google_authorize_url_failure_on_redirect_uri_missing() {
    let client_key = "GOOGLE_CLIENT_ID";
    let uri_key = "GOOGLE_REDIRECT_URI";
    let random_code = Uuid::new_v4().to_string();
    let check_code = random_code.trim();

    unsafe {
        set_var(client_key, "CLIENT_VALUE");
        remove_var(uri_key);
    }

    let result = build_google_authorize_url(check_code);
    assert!(
        result.is_err(),
        "expected the URL building to fail when GOOGLE_REDIRECT_URI is missing"
    );

    unsafe {
        remove_var(client_key);
    }
}

#[test]
#[serial]
fn google_authorize_url_specific_error_variants() {
    let client_key = "GOOGLE_CLIENT_ID";
    let uri_key = "GOOGLE_REDIRECT_URI";

    // Missing client_id specifically.
    unsafe {
        remove_var(client_key);
        set_var(uri_key, "URI_VALUE");
    }
    let result = build_google_authorize_url("state123");
    match result {
        Err(GoogleOauthConfigError::GoogleClientId) => {}
        other => panic!(
            "expected GoogleClientId variant specifically, got: {:?}",
            other
        ),
    }

    // Missing redirect_uri specifically.
    unsafe {
        set_var(client_key, "CLIENT_VALUE");
        remove_var(uri_key);
    }
    let result = build_google_authorize_url("state123");
    match result {
        Err(GoogleOauthConfigError::GoogleRedirectUri) => {
            // This is the correct, expected outcome.
        }
        other => panic!(
            "expected GoogleRedirectUri variant specifically, got: {:?}",
            other
        ),
    }

    unsafe {
        remove_var(client_key);
        remove_var(uri_key);
    }
}

#[test]
#[serial]
fn google_authorize_url_encodes_special_characters_correctly() {
    let client_key = "GOOGLE_CLIENT_ID";
    let uri_key = "GOOGLE_REDIRECT_URI";

    // A genuinely real-shaped redirect_uri, containing characters that
    // MUST be percent-encoded for a valid URL - "://" specifically.
    let real_redirect_uri = "http://localhost:3000/api/v1/auth/google/callback";
    unsafe {
        set_var(client_key, "CLIENT_VALUE");
        set_var(uri_key, real_redirect_uri);
    }

    let result =
        build_google_authorize_url("state123").expect("expected the URL to build successfully");

    assert!(
        !result.contains("redirect_uri=http://localhost"),
        "expected the redirect_uri to be genuinely percent-encoded, not embedded raw"
    );
    assert!(
        result.contains("redirect_uri=http%3A%2F%2Flocalhost"),
        "expected the redirect_uri to be correctly percent-encoded, got: {}",
        result
    );

    unsafe {
        remove_var(client_key);
        remove_var(uri_key);
    }
}

#[test]
#[serial]
fn google_authorize_url_contains_correct_fixed_parameters() {
    let client_key = "GOOGLE_CLIENT_ID";
    let uri_key = "GOOGLE_REDIRECT_URI";
    unsafe {
        set_var(client_key, "CLIENT_VALUE");
        set_var(uri_key, "URI_VALUE");
    }

    let result =
        build_google_authorize_url("state123").expect("expected the URL to build successfully");

    assert!(
        result.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"),
        "expected the correct real Google OAuth base URL"
    );
    assert!(
        result.contains("response_type=code"),
        "expected response_type=code"
    );
    assert!(
        result.contains("scope=openid%20email%20profile"),
        "expected the correct, exact scope parameter"
    );
    assert!(
        result.contains("prompt=select_account"),
        "expected prompt=select_account"
    );

    unsafe {
        remove_var(client_key);
        remove_var(uri_key);
    }
}

// Google Connect Redirect Test
#[tokio::test]
#[serial]
async fn google_connect_redirect_succeeds_with_a_valid_session() {
    dotenvy::dotenv().ok();

    let pool = test_pool().await;
    let email = "google_connect_success@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    // Step 2 - call the actual function, using that real token.
    let jar = CookieJar::new();
    let result = google_connect_redirect(
        State(pool.clone()),
        Query(GoogleConnectQuery {
            session: real_session_token,
        }),
        jar,
    )
    .await;

    assert!(
        result.is_ok(),
        "expected the connect flow to succeed, got: {:?}",
        result
    );

    // Step 3 - confirm the special link_cookie contains the CORRECT
    // user's real ID, not just that some cookie exists.
    let (returned_jar, _redirect) = result.unwrap();
    let link_cookie = returned_jar
        .get(OAUTH_LINK_USER_COOKIE)
        .expect("expected an oauth_link_user_id cookie to be present");

    assert_eq!(link_cookie.value(), user.id.to_string());

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn google_connect_redirect_fails_with_an_invalid_session() {
    dotenvy::dotenv().ok();

    let pool = test_pool().await;
    let fake_token = Uuid::new_v4().to_string();

    let jar = CookieJar::new();
    let result = google_connect_redirect(
        State(pool.clone()),
        Query(GoogleConnectQuery {
            session: fake_token,
        }),
        jar,
    )
    .await;

    assert!(
        result.is_err(),
        "expected an invalid session to be rejected"
    );
}

#[tokio::test]
#[serial]
async fn google_connect_redirect_success_sets_state_cookie_correctly() {
    dotenvy::dotenv().ok();

    let pool = test_pool().await;
    let email = "google_connect_state_cookie_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let jar = CookieJar::new();
    let (returned_jar, _redirect) = google_connect_redirect(
        State(pool.clone()),
        Query(GoogleConnectQuery {
            session: real_session_token,
        }),
        jar,
    )
    .await
    .expect("expected the connect flow to succeed");

    let state_cookie = returned_jar
        .get(OAUTH_STATE_COOKIE)
        .expect("expected an oauth_state cookie to be present");

    assert!(
        !state_cookie.value().is_empty(),
        "expected the state cookie's value to be a real, non-empty code"
    );
    assert_eq!(state_cookie.path(), Some("/"));
    assert_eq!(state_cookie.http_only(), Some(true));
    assert_eq!(state_cookie.same_site(), Some(SameSite::Lax));
    assert_eq!(state_cookie.max_age(), Some(time::Duration::minutes(10)));

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn google_connect_redirect_fails_when_google_config_missing() {
    dotenvy::dotenv().ok();

    let pool = test_pool().await;
    let email = "google_connect_config_missing_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let original_client_id = var("GOOGLE_CLIENT_ID").ok();
    unsafe {
        remove_var("GOOGLE_CLIENT_ID");
    }

    let jar = CookieJar::new();
    let result = google_connect_redirect(
        State(pool.clone()),
        Query(GoogleConnectQuery {
            session: real_session_token,
        }),
        jar,
    )
    .await;

    assert!(
        result.is_err(),
        "expected the redirect to fail when GOOGLE_CLIENT_ID is missing"
    );

    unsafe {
        if let Some(value) = original_client_id {
            set_var("GOOGLE_CLIENT_ID", value);
        }
    }

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn google_connect_redirect_database_error() {
    dotenvy::dotenv().ok();

    let pool = test_pool().await;
    let email = "google_connect_db_error_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    cleanup_test_user(&pool, email).await;
    pool.close().await;

    let jar = CookieJar::new();
    let result = google_connect_redirect(
        State(pool),
        Query(GoogleConnectQuery {
            session: real_session_token,
        }),
        jar,
    )
    .await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Extract User ID Test
#[tokio::test]
async fn extract_user_id_missing_authorization() {
    let pool = test_pool().await;
    let headers = HeaderMap::new();
    let result = extract_user_id(&headers, &pool)
        .await
        .expect("expected the query itself to succeed");

    assert!(
        result.is_none(),
        "expected no user to be found for a missing header"
    );
}

#[tokio::test]
async fn extract_user_id_malformed_authorization() {
    let pool = test_pool().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str("not-a-bearer-token").expect("expected to insert the header values"),
    );

    let result = extract_user_id(&headers, &pool)
        .await
        .expect("expected the user id to be extracted");

    assert!(
        result.is_none(),
        "expected no user to be found for a malformed header"
    );
}

#[tokio::test]
async fn extract_user_id_token_mismatch() {
    let pool = test_pool().await;
    let fake_token = Uuid::new_v4().to_string();

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", fake_token))
            .expect("expected to insert the header value"),
    );

    let result = extract_user_id(&headers, &pool)
        .await
        .expect("expected the user id to be extracted");

    assert!(
        result.is_none(),
        "expected no user to be found for a token that doesn't match any real session"
    );
}

#[tokio::test]
async fn extract_user_id_token_match() {
    let pool = test_pool().await;
    let email = "token_match@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to get the real session token");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to insert the header value"),
    );

    let result = extract_user_id(&headers, &pool)
        .await
        .expect("expected the user id to be extracted");

    assert_eq!(
        result,
        Some(user.id),
        "expected the correct user's ID to be found for a genuinely valid token"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn extract_user_db_error() {
    let pool = test_pool().await;
    pool.close().await;
    let fake_token = Uuid::new_v4().to_string();

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", fake_token))
            .expect("expected to insert the header value"),
    );

    let result = extract_user_id(&headers, &pool).await;
    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Get User from Token Test
#[tokio::test]
async fn get_user_from_token_no_match() {
    let pool = test_pool().await;
    let fake_token = Uuid::new_v4().to_string();

    let result = get_user_from_token(&pool, &fake_token)
        .await
        .expect("expected the query itself to succeed");

    assert!(
        result.is_none(),
        "expected None when no session matches this token"
    );
}

#[tokio::test]
async fn get_user_from_token_expired_session() {
    let pool = test_pool().await;
    let email = "get_user_from_token_expired_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let expired_token = format!("{}{}", Uuid::new_v4(), Uuid::new_v4()).replace('-', "");
    query("INSERT INTO sessions (id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::now_v7())
        .bind(user.id)
        .bind(&expired_token)
        .bind(Utc::now() - chrono_duration::days(1))
        .execute(&pool)
        .await
        .expect("expected to create the expired session");

    let result = get_user_from_token(&pool, &expired_token)
        .await
        .expect("expected the query itself to succeed");

    assert!(
        result.is_none(),
        "expected an expired session to be treated as if it doesn't exist"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn get_user_from_token_success_no_unnecessary_extension() {
    let pool = test_pool().await;
    let email = "get_user_from_token_fresh_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let expires_before: DateTime<Utc> =
        query_scalar("SELECT expires_at FROM sessions WHERE token = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .expect("expected the query to succeed");

    let result = get_user_from_token(&pool, &token)
        .await
        .expect("expected the query to succeed")
        .expect("expected the real user to be found");

    assert_eq!(
        result.id, user.id,
        "expected the correct user to be returned"
    );

    let expires_after: DateTime<Utc> =
        query_scalar("SELECT expires_at FROM sessions WHERE token = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .expect("expected the query to succeed");

    assert_eq!(
        expires_before, expires_after,
        "expected expires_at to remain genuinely UNCHANGED, since this session wasn't near expiry"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn get_user_from_token_success_extends_when_near_expiry() {
    let pool = test_pool().await;
    let email = "get_user_from_token_near_expiry_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let token = format!("{}{}", Uuid::new_v4(), Uuid::new_v4()).replace('-', "");
    let near_expiry = Utc::now() + chrono_duration::days(24);
    query("INSERT INTO sessions (id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::now_v7())
        .bind(user.id)
        .bind(&token)
        .bind(near_expiry)
        .execute(&pool)
        .await
        .expect("expected to create the near-expiry session");

    let result = get_user_from_token(&pool, &token)
        .await
        .expect("expected the query to succeed")
        .expect("expected the real user to be found");

    assert_eq!(
        result.id, user.id,
        "expected the correct user to be returned"
    );

    let expires_after: DateTime<Utc> =
        query_scalar("SELECT expires_at FROM sessions WHERE token = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .expect("expected the query to succeed");

    assert!(
        expires_after > near_expiry,
        "expected expires_at to be genuinely extended, not left as-is"
    );

    let expected_new_expiry = Utc::now() + chrono_duration::days(30);
    let difference = (expected_new_expiry - expires_after).num_seconds().abs();
    assert!(
        difference < 60,
        "expected the new expiry to be genuinely ~30 days out, off by {} seconds",
        difference
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn get_user_from_token_database_error() {
    let pool = test_pool().await;
    pool.close().await;
    let fake_token = Uuid::new_v4().to_string();

    let result = get_user_from_token(&pool, &fake_token).await;
    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Google Callback Test
#[tokio::test]
#[serial]
async fn google_callback_error_reported() {
    let pool = test_pool().await;
    let jar = CookieJar::new();
    let query = GoogleAfterLoginQuery {
        error: Some("access_denied".to_string()),
        code: None,
        state: None,
    };

    let result = google_callback(State(pool), jar, Query(query)).await;

    assert!(
        result.is_err(),
        "expected google_callback to reject a Google-reported error"
    );
}

#[tokio::test]
#[serial]
async fn google_callback_code_missing() {
    let pool = test_pool().await;
    let jar = CookieJar::new();
    let query = GoogleAfterLoginQuery {
        error: None,
        code: None,
        state: None,
    };
    let result = google_callback(State(pool), jar, Query(query)).await;
    assert!(
        result.is_err(),
        "expected google_callback to reject a request with no authorization code"
    );
}

#[tokio::test]
#[serial]
async fn google_callback_state_mismatch() {
    let pool = test_pool().await;
    let jar = CookieJar::new();
    let query = GoogleAfterLoginQuery {
        error: None,
        code: Some("some_real_looking_code".to_string()),
        state: Some("state_mismatch".to_string()),
    };
    let result = google_callback(State(pool), jar, Query(query)).await;
    assert!(
        result.is_err(),
        "expected google_callback to reject a request with a mismatched or missing state"
    );
}

#[tokio::test]
#[serial]
async fn google_callback_state_present_but_mismatched() {
    let pool = test_pool().await;

    let mut jar = CookieJar::new();
    let real_cookie = Cookie::new(OAUTH_STATE_COOKIE, "genuine_saved_state_value");
    jar = jar.add(real_cookie);

    let query = GoogleAfterLoginQuery {
        error: None,
        code: Some("some_real_looking_code".to_string()),
        state: Some("a_completely_different_state_value".to_string()),
    };

    let result = google_callback(State(pool), jar, Query(query)).await;

    assert!(
        result.is_err(),
        "expected a genuinely present but mismatched state to be rejected"
    );
}

#[tokio::test]
#[serial]
async fn google_callback_exchange_fails_for_a_fake_code() {
    let pool = test_pool().await;

    let state_value = "matching_state_value_001";
    let mut jar = CookieJar::new();
    let real_cookie = Cookie::new(OAUTH_STATE_COOKIE, state_value);
    jar = jar.add(real_cookie);

    let query = GoogleAfterLoginQuery {
        error: None,
        code: Some("genuinely_fake_authorization_code_00000".to_string()),
        state: Some(state_value.to_string()),
    };

    let result = google_callback(State(pool), jar, Query(query)).await;

    assert!(
        result.is_err(),
        "expected Google to genuinely reject a fake authorization code"
    );
}

// Exchange Code of User Test
#[tokio::test]
#[serial]
async fn exchange_code_for_user_missing_client_id() {
    let client_key = "GOOGLE_CLIENT_ID";
    let secret_key = "GOOGLE_CLIENT_SECRET";
    let uri_key = "GOOGLE_REDIRECT_URI";
    let original_client_id = var(client_key).ok();

    unsafe {
        remove_var(client_key);
        set_var(secret_key, "SECRET_VALUE");
        set_var(uri_key, "URI_VALUE");
    }

    let result = exchange_code_for_user("doesnt_matter").await;

    match result {
        Err(GoogleOauthConfigError::GoogleClientId) => {}
        other => panic!(
            "expected GoogleClientId, got a different result: {:?}",
            other
        ),
    }

    unsafe {
        remove_var(secret_key);
        remove_var(uri_key);
        if let Some(value) = original_client_id {
            set_var(client_key, value);
        }
    }
}

#[tokio::test]
#[serial]
async fn exchange_code_for_user_missing_client_secret() {
    let client_key = "GOOGLE_CLIENT_ID";
    let secret_key = "GOOGLE_CLIENT_SECRET";
    let uri_key = "GOOGLE_REDIRECT_URI";
    let original_secret = var(secret_key).ok();

    unsafe {
        set_var(client_key, "CLIENT_VALUE");
        remove_var(secret_key);
        set_var(uri_key, "URI_VALUE");
    }

    let result = exchange_code_for_user("doesnt_matter").await;

    match result {
        Err(GoogleOauthConfigError::GoogleClientSecret) => {}
        other => panic!(
            "expected GoogleClientSecret, got a different result: {:?}",
            other
        ),
    }

    unsafe {
        remove_var(client_key);
        remove_var(uri_key);
        if let Some(value) = original_secret {
            set_var(secret_key, value);
        }
    }
}

#[tokio::test]
#[serial]
async fn exchange_code_for_user_missing_redirect_uri() {
    let client_key = "GOOGLE_CLIENT_ID";
    let secret_key = "GOOGLE_CLIENT_SECRET";
    let uri_key = "GOOGLE_REDIRECT_URI";
    let original_uri = var(uri_key).ok();

    unsafe {
        set_var(client_key, "CLIENT_VALUE");
        set_var(secret_key, "SECRET_VALUE");
        remove_var(uri_key);
    }

    let result = exchange_code_for_user("doesnt_matter").await;
    match result {
        Err(GoogleOauthConfigError::GoogleRedirectUri) => {}
        other => panic!(
            "expected GoogleRedirectUri, got a different result: {:?}",
            other
        ),
    }

    unsafe {
        remove_var(client_key);
        remove_var(secret_key);
        if let Some(value) = original_uri {
            set_var(uri_key, value);
        }
    }
}

#[tokio::test]
#[serial]
async fn exchange_code_for_user_token_exchange_genuinely_rejected() {
    dotenvy::dotenv().ok();

    let result = exchange_code_for_user("genuinely_fake_code_00000_never_real").await;
    match result {
        Err(GoogleOauthConfigError::TokenExchangeFailed(_)) => {}
        Err(other) => panic!(
            "expected TokenExchangeFailed, got a different error: {:?}",
            other
        ),
        Ok(_) => panic!("expected Google to reject a fake code, but it succeeded"),
    }
}

// Handle Google Connect
#[tokio::test]
async fn handle_google_connect_succeeds_when_emails_match() {
    let pool = test_pool().await;
    let email = "google_link_success@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let link_cookie = Cookie::new(OAUTH_LINK_USER_COOKIE, user.id.to_string());
    let google_user = GoogleUserInfoEndpoint {
        id: "google_id_success_123".to_string(),
        email: email.to_string(),
        name: Some("Test User".to_string()),
    };

    let jar = CookieJar::new();
    let result = handle_google_connect(&pool, jar, link_cookie, &google_user).await;

    assert!(
        result.is_ok(),
        "expected linking to succeed, got: {:?}",
        result
    );

    // Confirm the actual database was genuinely updated.
    let linked = find_user_by_google_id(&pool, "google_id_success_123")
        .await
        .expect("expected the query to succeed");

    assert!(
        linked.is_some(),
        "expected the user to now have a linked Google account"
    );
    assert_eq!(linked.unwrap().id, user.id);

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn handle_google_connect_rejects_a_mismatched_email() {
    let pool = test_pool().await;
    let email = "google_link_mismatch@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let link_cookie = Cookie::new(OAUTH_LINK_USER_COOKIE, user.id.to_string());
    let google_user = GoogleUserInfoEndpoint {
        id: "google_id_mismatch_456".to_string(),
        email: "a_totally_different_email@example.com".to_string(), // deliberately different
        name: None,
    };

    let jar = CookieJar::new();
    let result = handle_google_connect(&pool, jar, link_cookie, &google_user).await;

    assert!(result.is_err(), "expected mismatched emails to be rejected");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn handle_google_connect_rejects_a_google_account_already_linked_elsewhere() {
    let pool = test_pool().await;
    let email_a = "google_link_owner@example.com";
    let email_b = "google_link_intruder@example.com";
    let (user_a, _) = create_test_user(&pool, email_a).await;
    let (user_b, _) = create_test_user(&pool, email_b).await;

    let shared_google_id = "google_id_already_taken_789";

    link_google_account(&pool, user_a.id, shared_google_id)
        .await
        .expect("expected the first link to succeed");

    let link_cookie = Cookie::new(OAUTH_LINK_USER_COOKIE, user_b.id.to_string());
    let google_user = GoogleUserInfoEndpoint {
        id: shared_google_id.to_string(),
        email: email_b.to_string(),
        name: None,
    };

    let jar = CookieJar::new();
    let result = handle_google_connect(&pool, jar, link_cookie, &google_user).await;

    assert!(
        result.is_err(),
        "expected an already-linked Google account to be rejected"
    );

    cleanup_test_user(&pool, email_a).await;
    cleanup_test_user(&pool, email_b).await;
}

#[tokio::test]
async fn handle_google_connect_rejects_a_malformed_link_cookie() {
    let pool = test_pool().await;

    let link_cookie = Cookie::new(OAUTH_LINK_USER_COOKIE, "not-a-real-uuid");
    let google_user = GoogleUserInfoEndpoint {
        id: "google_id_whatever".to_string(),
        email: "irrelevant@example.com".to_string(),
        name: None,
    };

    let jar = CookieJar::new();
    let result = handle_google_connect(&pool, jar, link_cookie, &google_user).await;

    assert!(
        result.is_err(),
        "expected a malformed cookie value to be rejected"
    );
}

// Find User by ID Test
#[tokio::test]
async fn find_user_by_id_found() {
    let pool = test_pool().await;
    let email = "find_user_by_id_found_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let result = find_user_by_id(&pool, user.id)
        .await
        .expect("expected the query to succeed");

    let found_user = result.expect("expected the user to genuinely be found");
    assert_eq!(found_user.id, user.id);
    assert_eq!(found_user.email, email);

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn find_user_by_id_not_found() {
    let pool = test_pool().await;
    let fake_id = Uuid::new_v4();

    let result = find_user_by_id(&pool, fake_id)
        .await
        .expect("expected the query itself to succeed");

    assert!(
        result.is_none(),
        "expected None when no user matches this ID"
    );
}

#[tokio::test]
async fn find_user_by_id_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let fake_id = Uuid::new_v4();
    let result = find_user_by_id(&pool, fake_id).await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Find User By Google ID Test
#[tokio::test]
async fn find_user_by_google_id_not_found() {
    let pool = test_pool().await;

    let result = find_user_by_google_id(&pool, "definitely_never_linked_google_id_001")
        .await
        .expect("expected the query itself to succeed");

    assert!(
        result.is_none(),
        "expected None when no user has this Google ID linked"
    );
}

#[tokio::test]
async fn find_user_by_google_id_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let result = find_user_by_google_id(&pool, "doesnt_matter").await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

#[tokio::test]
#[serial]
async fn google_signin_links_onto_an_existing_email_match() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;
    let email = "existing_magic_link_user@example.com";
    let google_id = "google_id_linking_to_existing_001";
    let (existing_user, _) = create_test_user(&pool, email).await;

    let (user, is_new) =
        find_or_create_user_by_google(&pool, google_id, email, Some("Existing User"))
            .await
            .expect("expected the call to succeed");

    assert!(
        !is_new,
        "expected this to link onto an existing account, not create a new one"
    );
    assert_eq!(
        user.id, existing_user.id,
        "expected the SAME user, not a new one"
    );

    let linked = find_user_by_google_id(&pool, google_id)
        .await
        .expect("expected the query to succeed");

    assert!(
        linked.is_some(),
        "expected the existing user to now have this Google ID linked"
    );
    assert_eq!(linked.unwrap().id, existing_user.id);

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn find_user_by_google_id_found() {
    let pool = test_pool().await;
    let email = "find_by_google_id_found_test@example.com";
    let google_id = "find_by_google_id_test_001";
    let (user, _) = create_test_user(&pool, email).await;

    query("UPDATE users SET google_id = $1 WHERE id = $2")
        .bind(google_id)
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("expected to link the google id");

    let result = find_user_by_google_id(&pool, google_id)
        .await
        .expect("expected the query to succeed");

    let found_user = result.expect("expected the user to genuinely be found");
    assert_eq!(found_user.id, user.id);
    assert_eq!(found_user.email, email);

    cleanup_test_user(&pool, email).await;
}

// Link Google Account Test
#[tokio::test]
async fn link_google_account_success() {
    let pool = test_pool().await;
    let email = "link_google_account_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    link_google_account(&pool, user.id, "link_test_google_id_001")
        .await
        .expect("expected the link to succeed");

    let saved_google_id: Option<String> = query_scalar("SELECT google_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .expect("expected the query to succeed");

    assert_eq!(
        saved_google_id,
        Some("link_test_google_id_001".to_string()),
        "expected the real database row to genuinely reflect the linked google_id"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn link_google_account_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let fake_user_id = Uuid::new_v4();
    let result = link_google_account(&pool, fake_user_id, "doesnt_matter").await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

// Find or Create User by Google Test
#[tokio::test]
#[serial]
async fn fresh_google_signin_creates_account_and_session() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;
    let email = "fresh_google_signin@example.com";
    let google_id = "google_id_fresh_signin_001";
    cleanup_test_user(&pool, email).await;

    let (user, is_new) = find_or_create_user_by_google(&pool, google_id, email, Some("Test User"))
        .await
        .expect("expected to create a new user from Google info");

    assert!(is_new, "expected a brand-new user to be created");
    assert_eq!(user.email, email);

    let session_token = finish_sign_in(&pool, user.id, is_new, email, "google")
        .await
        .expect("expected sign-in to complete");

    assert!(!session_token.is_empty(), "expected a real session token");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn google_signin_finds_existing_google_id_immediately() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;
    let email = "existing_google_id_user@example.com";
    let google_id = "google_id_already_linked_001";
    let (existing_user, _) = create_test_user(&pool, email).await;

    query("UPDATE users SET google_id = $1 WHERE id = $2")
        .bind(google_id)
        .bind(existing_user.id)
        .execute(&pool)
        .await
        .expect("expected to link the google id directly");

    let (user, is_new) = find_or_create_user_by_google(
        &pool,
        google_id,
        "a_totally_different_email@example.com",
        Some("Some Name"),
    )
    .await
    .expect("expected the call to succeed");

    assert!(
        !is_new,
        "expected the existing account to be found, not a new one created"
    );
    assert_eq!(
        user.id, existing_user.id,
        "expected the SAME user, matched purely by google_id"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn google_signin_preserves_existing_name_when_linking_by_email() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;
    let email = "preserve_name_test@example.com";
    let google_id = "google_id_preserve_name_001";
    cleanup_test_user(&pool, email).await;

    let (existing_user, _) = find_or_create_user_by_email(&pool, email)
        .await
        .expect("expected to create the user");

    query("UPDATE users SET name = $1 WHERE id = $2")
        .bind("Genuinely Real Original Name")
        .bind(existing_user.id)
        .execute(&pool)
        .await
        .expect("expected to set the real name");

    let (user, is_new) =
        find_or_create_user_by_google(&pool, google_id, email, Some("A Different Google Name"))
            .await
            .expect("expected the call to succeed");

    assert!(!is_new);
    assert_eq!(
        user.name,
        Some("Genuinely Real Original Name".to_string()),
        "expected the ORIGINAL name to be preserved, NOT overwritten by Google's name"
    );
    assert_eq!(
        user.google_id,
        Some(google_id.to_string()),
        "expected the google_id to genuinely be saved during the email-match linking"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn find_or_create_user_by_google_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let result =
        find_or_create_user_by_google(&pool, "doesnt_matter", "doesnt_matter@example.com", None)
            .await;

    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}

#[tokio::test]
#[serial]
async fn logout_with_session_present() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;
    let email = "logged_out_success@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", real_session_token))
            .expect("expected to enter the header value"),
    );

    let response = logout(State(pool.clone()), headers).await;
    assert_eq!(response.0["success"], true);

    let still_exists: Option<(String,)> = query_as("SELECT token FROM sessions WHERE token = $1")
        .bind(&real_session_token)
        .fetch_optional(&pool)
        .await
        .expect("expected the query to succeed");

    assert!(still_exists.is_none(), "expected the session to be deleted");

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn logout_with_no_header() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;
    let email = "logged_out_success@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let real_session_token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    let headers = HeaderMap::new();

    let response = logout(State(pool.clone()), headers).await;
    assert_eq!(response.0["success"], true);

    let still_exists: Option<(String,)> = query_as("SELECT token FROM sessions WHERE token = $1")
        .bind(&real_session_token)
        .fetch_optional(&pool)
        .await
        .expect("expected the query to succeed");

    assert!(
        still_exists.is_some(),
        "expected the session to remain untouched, since no header was provided"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
#[serial]
async fn logout_with_fake_token() {
    dotenvy::dotenv().ok();
    let pool = test_pool().await;

    let fake_session_token = Uuid::new_v4().to_string();

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", fake_session_token)).unwrap(),
    );

    let response = logout(State(pool.clone()), headers).await;
    assert_eq!(response.0["success"], true);
}

// Delete Session Test
#[tokio::test]
async fn delete_session_success_genuinely_deletes() {
    let pool = test_pool().await;
    let email = "delete_session_success_test@example.com";
    let (user, _) = create_test_user(&pool, email).await;

    let token = create_session(&pool, user.id)
        .await
        .expect("expected to create a real session");

    delete_session(&pool, &token)
        .await
        .expect("expected the deletion to succeed");

    let still_exists: Option<String> = query_scalar("SELECT token FROM sessions WHERE token = $1")
        .bind(&token)
        .fetch_optional(&pool)
        .await
        .expect("expected the query to succeed");

    assert!(
        still_exists.is_none(),
        "expected the session to genuinely be deleted"
    );

    cleanup_test_user(&pool, email).await;
}

#[tokio::test]
async fn delete_session_success_even_for_nonexistent_token() {
    let pool = test_pool().await;
    let fake_token = Uuid::new_v4().to_string();

    let result = delete_session(&pool, &fake_token).await;
    assert!(
        result.is_ok(),
        "expected deleting a nonexistent token to still succeed, not error"
    );
}

#[tokio::test]
async fn delete_session_database_error() {
    let pool = test_pool().await;
    pool.close().await;

    let result = delete_session(&pool, "doesnt_matter").await;
    assert!(
        result.is_err(),
        "expected a genuine database error when the connection pool is closed"
    );
}
