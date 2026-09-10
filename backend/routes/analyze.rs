use crate::handlers::analyze::{analyze, verify_social_link_handler};
use axum::{Router, routing::post};
use sqlx::{Pool, Postgres};

pub fn analyze_routes() -> Router<Pool<Postgres>> {
    Router::new().route("/api/v1/analyze", post(analyze)).route(
        "/api/v1/verify-social-link",
        post(verify_social_link_handler),
    )
}
