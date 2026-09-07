pub mod b2brazil;

#[derive(Debug, Default)]
pub struct B2bSupplierProfile {
    pub company_name: Option<String>,
    pub logo_url: Option<String>,
    pub year_established: Option<String>,
    pub country: Option<String>,
    pub platform_verified_badge: bool,
    pub employee_count: Option<String>,
    pub sales_revenue: Option<String>,
    pub export_percentage: Option<String>,
    pub profile_url: String,
    pub source_platform: String,
    pub contact_name: Option<String>,
    pub contact_phone: Option<String>,
}

#[derive(Debug, Default)]
pub struct B2bListingProfile {
    pub title: Option<String>,
    pub description: Option<String>,
    pub image_urls: Vec<String>,
    pub unit_price: Option<String>,
    pub fob_price: Option<String>,
    pub minimum_order_quantity: Option<String>,
    pub payment_type: Option<String>,
    pub preferred_port: Option<String>,
    pub reference: Option<String>,
    pub production_capacity: Option<String>,
    pub delivery_timeframe: Option<String>,
    pub incoterms: Option<String>,
    pub packaging_details: Option<String>,
    pub listing_url: String,
    pub source_platform: String,
}

pub trait B2bScraper: Send + Sync {
    fn matches_platform(&self, platform: &str) -> bool;
    fn parse_supplier(&self, html: &str, profile_url: &str) -> B2bSupplierProfile;
    fn parse_listing(&self, html: &str, listing_url: &str) -> B2bListingProfile;
}

pub fn get_scraper_for_platform(platform: &str) -> Option<Box<dyn B2bScraper>> {
    let scrapers: Vec<Box<dyn B2bScraper>> = vec![Box::new(b2brazil::B2brazilScraper)];
    scrapers.into_iter().find(|s| s.matches_platform(platform))
}

pub async fn check_b2b_page(
    platform: &str,
    page_url: &str,
) -> Option<(B2bSupplierProfile, B2bListingProfile)> {
    let scraper = get_scraper_for_platform(platform)?;
    let client = reqwest::Client::new();
    let response = client.get(page_url).send().await.ok()?;

    if !response.status().is_success() {
        eprintln!(
            "Safely: B2B page fetch failed for {} - status {}",
            page_url,
            response.status()
        );
        return None;
    }

    let html = response.text().await.ok()?;
    let supplier = scraper.parse_supplier(&html, page_url);
    let listing = scraper.parse_listing(&html, page_url);
    Some((supplier, listing))
}
