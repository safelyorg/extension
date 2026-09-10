use crate::models::history::{
    AnalysisDetailRow, HistoryDetailResponse, HistoryItem, ReportItem, ReportSummary,
};
use crate::models::sellers::{Sellers, SellersResponse};
use crate::services::fraud_reports::{build_network_summary, count_fraud_reports};
use crate::services::listings::get_monthly_visit_activity;
use sqlx::{Error, Pool, Postgres, query_as};
use uuid::Uuid;

/// Gets every listing this person has ever analyzed, newest first.
///
/// Each listing only appears once, even if it was analyzed several
/// times - matched by its real scraped ID (like OLX's "iid-..." number),
/// or its full URL if that ID wasn't captured. This is NOT the same as
/// the listing's internal database row ID, since the same real ad could
/// technically end up with more than one row over time.
///
/// "reported" means "did I file a report on THIS exact listing" - not
/// just this seller in general. A seller can have five listings, with
/// one reported and four not, and this correctly shows that difference,
/// instead of marking all five as reported the moment any one of them
/// gets flagged.
pub async fn get_user_history(
    pool: &Pool<Postgres>,
    user_id: Uuid,
) -> Result<Vec<HistoryItem>, Error> {
    query_as::<_, HistoryItem>(
        "
        SELECT * FROM (
            SELECT DISTINCT ON (s.id, COALESCE(l.listing_id, l.listing_url))
                a.id,
                a.created_at,
                a.risk_score,
                a.risk_level,
                l.platform,
                l.title AS listing_title,
                l.listing_url,
                s.name AS seller_name,
                s.id AS seller_id,
                EXISTS (
                    SELECT 1 FROM fraud_reports fr
                    WHERE fr.seller_id = s.id
                      AND fr.user_id = a.user_id
                      AND fr.listing_url = l.listing_url
                ) AS reported
            FROM analysis a
            JOIN listings l ON a.listing_id = l.id
            JOIN sellers s ON l.seller_id = s.id
            WHERE a.user_id = $1
            ORDER BY s.id, COALESCE(l.listing_id, l.listing_url), a.created_at DESC
        ) sub
        ORDER BY created_at DESC
        LIMIT 200
        ",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Gets the full, detailed record for one specific analysis - everything
/// that was originally shown, plus EVERY report this person has filed
/// against this exact listing (not just the seller's most recent report
/// from anywhere else).
///
/// It looks up the analysis, matched by BOTH its ID and the requesting
/// person's own user ID together - so a genuinely nonexistent analysis,
/// and someone else's real analysis, both correctly come back as
/// "nothing found," rather than accidentally revealing that a given ID
/// belongs to someone. If found, it fetches the seller's real profile,
/// their fraud-report count, their real visit-activity chart, and every
/// report this specific person has filed against this specific listing,
/// then assembles it all into the final, complete response.
pub async fn get_history_detail(
    pool: &Pool<Postgres>,
    analysis_id: Uuid,
    user_id: Uuid,
) -> Result<Option<HistoryDetailResponse>, Error> {
    let row = query_as::<_, AnalysisDetailRow>(
        "
        SELECT
            a.id,
            a.created_at,
            a.risk_score,
            a.risk_level,
            a.signals,
            a.risk_factors,
            a.social_candidates,
            l.title AS listing_title,
            l.listing_url,
            l.platform,
            l.seller_id
        FROM analysis a
        JOIN listings l ON a.listing_id = l.id
        WHERE a.id = $1 AND a.user_id = $2
        ",
    )
    .bind(analysis_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let seller = query_as::<_, Sellers>("SELECT * FROM sellers WHERE id = $1")
        .bind(row.seller_id)
        .fetch_one(pool)
        .await?;

    let fraud_count = count_fraud_reports(pool, seller.id).await?;
    let network_summary = build_network_summary(fraud_count);
    let monthly_activity = get_monthly_visit_activity(pool, seller.id)
        .await
        .unwrap_or_else(|_| vec![0i32; 12]);

    let reports = query_as::<_, ReportSummary>(
        "SELECT report_type, reported_at FROM fraud_reports
         WHERE user_id = $1 AND seller_id = $2 AND listing_url = $3
         ORDER BY reported_at DESC",
    )
    .bind(user_id)
    .bind(seller.id)
    .bind(&row.listing_url)
    .fetch_all(pool)
    .await?;

    let reported = !reports.is_empty();
    let mut seller_response = SellersResponse::from(seller);
    seller_response.network_summary = network_summary;
    seller_response.monthly_activity = monthly_activity;

    Ok(Some(HistoryDetailResponse {
        id: row.id,
        created_at: row.created_at,
        listing_title: row.listing_title,
        listing_url: row.listing_url,
        platform: row.platform,
        risk_score: row.risk_score,
        risk_level: row.risk_level,
        signals: row.signals,
        risk_factors: row.risk_factors,
        social_candidates: row.social_candidates,
        seller: seller_response,
        fraud_report_count: fraud_count,
        reported,
        reports,
    }))
}

/// Gets every fraud report this person has ever filed, across every
/// listing and seller they've ever reported - this is the "My Reports"
/// tab.
///
/// Unlike get_history_detail, this is deliberately NOT limited to one
/// specific listing - it shows this person's entire reporting history
/// at once, joined with each seller's name so the list is readable
/// without needing a separate lookup.
pub async fn get_user_reports(
    pool: &Pool<Postgres>,
    user_id: Uuid,
) -> Result<Vec<ReportItem>, Error> {
    sqlx::query_as::<_, ReportItem>(
        "
        SELECT
            fr.id,
            fr.reported_at,
            fr.report_type,
            fr.platform,
            s.name AS seller_name,
            s.id AS seller_id,
            fr.listing_url
        FROM fraud_reports fr
        JOIN sellers s ON fr.seller_id = s.id
        WHERE fr.user_id = $1
        ORDER BY fr.reported_at DESC
        LIMIT 200
        ",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}
