use crate::handlers::dashboard::{
    delete_account, disconnect_google, get_avatar, get_history, get_history_html, get_history_item,
    get_me, get_reports, get_reports_html, update_me, upload_avatar,
};
use crate::handlers::pdf::download_evidence_pdf;
use axum::{
    Router,
    routing::{get, post},
};
use sqlx::{Pool, Postgres};

pub fn dashboard_routes() -> Router<Pool<Postgres>> {
    Router::new()
        .route("/api/v1/history", get(get_history))
        .route("/api/v1/history/html", get(get_history_html))
        .route("/api/v1/history/{id}", get(get_history_item))
        .route("/api/v1/history/{id}/pdf", get(download_evidence_pdf))
        .route("/api/v1/reports", get(get_reports))
        .route("/api/v1/reports/html", get(get_reports_html))
        .route(
            "/api/v1/me",
            get(get_me).patch(update_me).delete(delete_account),
        )
        .route("/api/v1/me/avatar", get(get_avatar).post(upload_avatar))
        .route("/api/v1/me/google/disconnect", post(disconnect_google))
}
