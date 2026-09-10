use crate::{
    models::{listings::ListingCategory, risk_factors::RiskFactor, sellers::SellersResponse},
    services::osint::PlatformCheckResult,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Type, prelude::FromRow};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, PartialEq, Type)]
#[sqlx(type_name = "risk_level_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Caution,
    High,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Analysis {
    pub id: Uuid,
    pub listing_id: Uuid,
    pub risk_score: i16,
    pub risk_level: RiskLevel,
    pub signals: Value,
    pub network_summary: Option<String>,
    pub claude_raw: Option<String>,
    pub user_id: Uuid,
    pub confidence_level: Option<String>,
    pub confidence_reasoning: Option<String>,
    pub risk_factors: Option<Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    // shared
    pub platform: String,
    // listing fields
    pub seller_id: Option<Uuid>,
    pub listing_url: String,
    pub listing_id: Option<String>,
    pub title: Option<String>,
    pub price: Option<i64>,
    pub description: Option<String>,
    pub category: Option<ListingCategory>,
    pub image_urls: Option<Vec<String>>,
    pub posted_date: Option<NaiveDate>,
    // seller fields
    pub platform_id: Option<String>,
    pub seller_name: Option<String>,
    pub seller_handle: Option<String>,
    pub seller_phone: Option<String>,
    pub seller_profile_url: Option<String>,
    pub seller_join_date: Option<String>,
    pub seller_location: Option<String>,
    pub seller_last_active: Option<String>,

    #[serde(default)]
    pub seller_website: Option<String>,
    #[serde(default)]
    pub seller_verified: Option<bool>,
    #[serde(default)]
    pub seller_rating: Option<f64>,
    #[serde(default)]
    pub seller_total_products: Option<i32>,
    #[serde(default)]
    pub domain_check_status: Option<String>,
    #[serde(default)]
    pub domain_check_real_name: Option<String>,
    #[serde(default)]
    pub domain_check_real_domain: Option<String>,
    #[serde(default)]
    pub domain_check_current_domain: Option<String>,
    #[serde(default)]
    pub domain_check_current_html: Option<String>,
    #[serde(default)]
    pub domain_check_real_html: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub analysis_id: Uuid,
    pub risk_score: i16,
    pub risk_level: RiskLevel,
    pub seller: SellersResponse,
    pub signals: Vec<Signal>,
    pub network_summary: String,
    pub fraud_report_count: i64,
    pub entity_type: String,
    pub confidence_level: String,
    pub confidence_reasoning: String,
    pub risk_factors: Vec<RiskFactor>,
    #[serde(default)]
    pub social_candidates: Vec<PlatformCheckResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub label: String,
    pub sub: String,
    pub value: String,
    #[serde(rename = "type")]
    pub signal_type: String,
    pub category: String,
    pub check_type: String,
}
