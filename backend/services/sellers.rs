use crate::models::sellers::{SellerVerification, Sellers, SellersRequest};
use chrono::NaiveDate;
use sqlx::{Error, Pool, Postgres, query, query_as};
use uuid::Uuid;

/// It looks up a seller by which marketplace they're on, and their specific ID
/// on that marketplace, returning them if found, or nothing if they've
/// never been seen before.
///
/// It runs the lookup query and returns whatever was found.
pub async fn find_seller(
    pool: &Pool<Postgres>,
    platform: &str,
    platform_id: &str,
) -> Result<Option<Sellers>, Error> {
    let seller = query_as::<_, Sellers>(
        "SELECT * FROM sellers
         WHERE platform = $1 AND platform_id = $2
         LIMIT 1",
    )
    .bind(platform)
    .bind(platform_id)
    .fetch_optional(pool)
    .await?;

    Ok(seller)
}

/// It either creates a brand-new seller, or if one already exists for this exact platform and ID,
/// updates their existing record with any new, better information, without ever overwriting
/// good data with blanks.
///
/// It generates an ID, ready in case a new seller is created, extracts just the
/// year from the seller's "join date" text, do the The actual database operation
/// genuinely both an insert AND a possible update, in one statement, binds all the
/// real values into the query and returns the real, final row.
pub async fn create_seller(
    pool: &Pool<Postgres>,
    request: &SellersRequest,
    verification: SellerVerification,
) -> Result<Sellers, Error> {
    let id = Uuid::now_v7();
    let join_date = request.join_date.as_deref().and_then(|s| {
        let year_str = s.split_whitespace().last()?;
        let year: i32 = year_str.parse().ok()?;
        NaiveDate::from_ymd_opt(year, 1, 1)
    });

    let seller = query_as::<_, Sellers>(
        "
        INSERT INTO sellers (
            id,
            platform,
            platform_id,
            name,
            handle,
            phone,
            profile_url,
            join_date,
            verification,
            location,
            last_active_text,
            created_at,
            updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            $11, NOW(), NOW()
        )
        ON CONFLICT (platform, platform_id)
        DO UPDATE SET
            name = COALESCE(EXCLUDED.name, sellers.name),
            join_date = COALESCE(EXCLUDED.join_date, sellers.join_date),
            location = COALESCE(EXCLUDED.location, sellers.location),
            last_active_text = COALESCE(EXCLUDED.last_active_text, sellers.last_active_text),
            verification = EXCLUDED.verification,
            updated_at = NOW()
        RETURNING *
        ",
    )
    .bind(id)
    .bind(&request.platform)
    .bind(request.platform_id.as_deref().unwrap_or("unknown"))
    .bind(&request.name)
    .bind(&request.handle)
    .bind(&request.phone)
    .bind(&request.profile_url)
    .bind(join_date)
    .bind(verification)
    .bind(&request.location)
    .bind(&request.last_active)
    .fetch_one(pool)
    .await?;

    Ok(seller)
}

/// Updates a seller's real, known name and location once B2B scraping
/// discovers them - since resolve_seller runs BEFORE the B2B fetch
/// happens (the extension never sends a name for B2B platforms at
/// all), the seller record starts genuinely empty and needs this
/// follow-up update once the real data becomes available.
pub async fn update_seller_from_b2b(
    pool: &Pool<Postgres>,
    seller_id: Uuid,
    company_name: Option<&str>,
    location: Option<&str>,
    join_date: Option<NaiveDate>,
    contact_name: Option<&str>,
    contact_phone: Option<&str>,
    profile_url: Option<&str>,
) -> Result<(), Error> {
    query(
        "UPDATE sellers SET
            name = COALESCE($1, name),
            location = COALESCE($2, location),
            join_date = COALESCE($3, join_date),
            handle = COALESCE($4, handle),
            phone = COALESCE($5, phone),
            profile_url = COALESCE($6, profile_url),
            updated_at = NOW()
         WHERE id = $7",
    )
    .bind(company_name)
    .bind(location)
    .bind(join_date)
    .bind(contact_name)
    .bind(contact_phone)
    .bind(profile_url)
    .bind(seller_id)
    .execute(pool)
    .await?;

    Ok(())
}
