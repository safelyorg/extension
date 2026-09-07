use super::helpers::format_account_age;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Type, prelude::FromRow};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "seller_verification", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SellerVerification {
    Verified,
    Reported,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Sellers {
    pub id: Uuid,
    pub platform: String,
    pub platform_id: String,
    pub name: Option<String>,
    pub handle: Option<String>,
    pub phone: Option<String>,
    pub profile_url: Option<String>,
    pub join_date: Option<NaiveDate>,
    pub verification: SellerVerification,
    pub location: Option<String>,
    pub last_active_text: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct SellersRequest {
    pub platform: String,
    pub platform_id: Option<String>,
    pub name: Option<String>,
    pub handle: Option<String>,
    pub phone: Option<String>,
    pub profile_url: Option<String>,
    pub join_date: Option<String>,
    pub location: Option<String>,
    // The scraped "3 hours ago" style text - the only source of this
    // value, since there's no way to compute it server-side. Sent fresh
    // on every analyze call and overwritten each time, same as location.
    pub last_active: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SellersResponse {
    pub id: Uuid,
    pub platform: String,
    pub platform_id: String,
    pub name: Option<String>,
    pub handle: Option<String>,
    pub phone: Option<String>,
    pub account_age: String,
    pub verification: SellerVerification,
    pub location: Option<String>,
    pub last_active: Option<String>,
    pub network_summary: String,
    pub monthly_activity: Vec<i32>,
}

impl From<Sellers> for SellersResponse {
    fn from(s: Sellers) -> Self {
        Self {
            id: s.id,
            platform: s.platform.clone(),
            platform_id: s.platform_id,
            name: s.name,
            handle: s.handle,
            phone: s.phone,
            account_age: s
                .join_date
                .map(|d| format_account_age(d))
                .unwrap_or_else(|| "Unknown".to_string()),
            verification: s.verification,
            location: s.location,
            last_active: s.last_active_text,
            network_summary: String::new(),
            monthly_activity: vec![],
        }
    }
}
