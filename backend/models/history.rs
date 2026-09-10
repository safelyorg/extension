use crate::models::{analysis::RiskLevel, fraud_reports::ReportTypes, sellers::SellersResponse};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::prelude::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, FromRow)]
pub struct HistoryItem {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub risk_score: i16,
    pub risk_level: RiskLevel,
    pub platform: String,
    pub listing_title: Option<String>,
    pub listing_url: String,
    pub seller_name: Option<String>,
    pub seller_id: Uuid,
    pub reported: bool,
}

#[derive(Debug, Serialize, FromRow)]
pub struct ReportItem {
    pub id: Uuid,
    pub reported_at: DateTime<Utc>,
    pub report_type: ReportTypes,
    pub platform: String,
    pub seller_name: Option<String>,
    pub seller_id: Uuid,
    pub listing_url: Option<String>,
}

#[derive(Debug, FromRow)]
pub struct AnalysisDetailRow {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub risk_score: i16,
    pub risk_level: RiskLevel,
    pub signals: Value,
    pub risk_factors: Option<Value>,
    pub social_candidates: Option<Value>,
    pub listing_title: Option<String>,
    pub listing_url: String,
    pub platform: String,
    pub seller_id: Uuid,
}

#[derive(Debug, FromRow, Serialize)]
pub struct ReportSummary {
    pub report_type: ReportTypes,
    pub reported_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct HistoryDetailResponse {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub listing_title: Option<String>,
    pub listing_url: String,
    pub platform: String,
    pub risk_score: i16,
    pub risk_level: RiskLevel,
    pub signals: Value,
    pub risk_factors: Option<Value>,
    pub social_candidates: Option<Value>,
    pub seller: SellersResponse,
    pub fraud_report_count: i64,
    pub reported: bool,
    pub reports: Vec<ReportSummary>,
}
