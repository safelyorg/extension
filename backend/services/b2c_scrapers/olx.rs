use crate::services::b2c_scrapers::{
    B2cProfileResult, B2cScraper, ListingPageData, ListingScraper,
};
use scraper::{Html, Selector};

// ─────────────────────────────────────────────────────────
// JOB 1: OLX's store/profile page scraper (Tier 2) - visits the
// seller's SEPARATE store page to confirm their claimed identity
// and check for a self-referenced website.
// ─────────────────────────────────────────────────────────

pub struct OlxScraper;

impl B2cScraper for OlxScraper {
    fn matches_platform(&self, platform: &str) -> bool {
        platform == "olx"
    }

    fn parse(&self, html: &str, expected_seller_name: &str) -> B2cProfileResult {
        let document = scraper::Html::parse_document(html);
        let body_selector = scraper::Selector::parse("body").unwrap();
        let full_text: String = document
            .select(&body_selector)
            .next()
            .map(|body| body.text().collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        let lower_text = full_text.to_lowercase();
        let lower_name = expected_seller_name.to_lowercase();
        let seller_name_confirmed =
            !lower_name.trim().is_empty() && lower_text.contains(&lower_name);
        let website = extract_self_referenced_website(&full_text);
        B2cProfileResult {
            website,
            seller_name_confirmed,
        }
    }
}

fn extract_self_referenced_website(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let self_reference_phrases = [
        "our website",
        "our shop",
        "our store",
        "visit us at",
        "contact us at",
    ];
    for phrase in self_reference_phrases {
        if let Some(pos) = lower.find(phrase) {
            let window_start = pos;
            let window_end = (pos + phrase.len() + 60).min(text.len());
            let window = &text[window_start..window_end];
            if let Some(url) = find_url_in_text(window) {
                if !url.contains("olx.com") {
                    return Some(url);
                }
            }
        }
    }
    None
}

fn find_url_in_text(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|word| {
            let cleaned = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.');
            cleaned.contains('.') && cleaned.len() > 4 && !cleaned.starts_with('.')
        })
        .map(|word| {
            word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.')
                .to_string()
        })
}

// ─────────────────────────────────────────────────────────
// JOB 2: OLX's main listing page scraper
// ─────────────────────────────────────────────────────────

pub struct OlxListingScraper;

impl ListingScraper for OlxListingScraper {
    fn matches_platform(&self, platform: &str) -> bool {
        platform == "olx"
    }

    fn parse(&self, html: &str) -> ListingPageData {
        let document = Html::parse_document(html);

        let title = select_page_text(&document, "h1._75bce902")
            .or_else(|| select_page_text(&document, "h1.heading_h1__0cOM_"));

        let price = select_page_text(&document, "span._24469da7")
            .or_else(|| {
                select_page_text(
                    &document,
                    "[class*=\"product-price_productPrice\"] span:first-child",
                )
            })
            .and_then(|raw| parse_olx_price(&raw));

        let description = select_page_text(&document, "div._7a99ad24 span")
            .or_else(|| select_page_text(&document, "#description .overview_collapsed__mve6Q"));

        let location = select_page_text(&document, "span[aria-label=\"Location\"]");

        // "Posted by" - regular sellers
        let posted_by_name = document
            .select(&Selector::parse("span._9083bec6").unwrap())
            .find(|el| el.text().collect::<String>().trim() == "Posted by")
            .and_then(|label_el| {
                label_el.parent().and_then(|p| {
                    scraper::ElementRef::wrap(p).map(|el| {
                        el.text()
                            .collect::<String>()
                            .replace("Posted by", "")
                            .trim()
                            .to_string()
                    })
                })
            })
            .filter(|s| !s.is_empty());

        // "Sold by" - verified sellers
        let sold_by_name = select_page_text(&document, "#soldBy h4");
        let seller_name = sold_by_name.or(posted_by_name);

        let mut platform_id = None;
        let mut seller_profile_url = None;
        if let Ok(sel) = Selector::parse("a.da952dfc") {
            if let Some(link) = document.select(&sel).next() {
                if let Some(href) = link.value().attr("href") {
                    seller_profile_url = Some(format!("https://www.olx.com.pk{}", href));
                    if let Some(id_part) = href
                        .split("/profile/")
                        .nth(1)
                        .or_else(|| href.split("/seller/").nth(1))
                    {
                        platform_id = Some(id_part.trim_end_matches('/').to_string());
                    }
                }
            }
        }

        let last_active = select_page_text(&document, "span[aria-label=\"Creation date\"]");

        // Verified sellers ("Sold by") have a completely different
        // card structure than regular sellers ("Posted by"), with
        // genuinely richer, real trust data (rating, product count,
        // verification badge) sitting directly on the listing page.
        let mut sold_by_verified = false;
        let mut sold_by_rating = None;
        let mut sold_by_total_products = None;
        let mut sold_by_join_date = None;
        let mut sold_by_name = None;
        let mut sold_by_profile_url = None;

        if let Ok(link_sel) = Selector::parse("#soldBy a") {
            if let Some(link) = document.select(&link_sel).next() {
                if let Some(href) = link.value().attr("href") {
                    sold_by_profile_url = Some(format!("https://www.olx.com.pk{}", href));
                }
                if let Ok(name_sel) = Selector::parse("h4") {
                    sold_by_name = link
                        .select(&name_sel)
                        .next()
                        .map(|el| el.text().collect::<String>().trim().to_string());
                }
                let link_html = link.html();
                sold_by_verified = link_html.contains("verified");

                if let Ok(block_sel) = Selector::parse("[class*=\"group_grid\"]") {
                    for block in link.select(&block_sel) {
                        let block_fragment = Html::parse_fragment(&block.html());
                        let label = select_page_text(&block_fragment, "[class*=\"text-light\"]")
                            .unwrap_or_default()
                            .to_lowercase();
                        let value = select_page_text(&block_fragment, "strong");

                        if label.contains("total products") {
                            sold_by_total_products =
                                value.as_deref().and_then(|v| v.parse::<i32>().ok());
                        } else if label.contains("rating") {
                            sold_by_rating = value.as_deref().and_then(|v| {
                                v.split_whitespace()
                                    .next()
                                    .and_then(|first| first.parse::<f64>().ok())
                            });
                        } else if label.contains("member since") {
                            if let Some(v) = value {
                                sold_by_join_date = Some(format!("Member since {}", v));
                            }
                        }
                    }
                }
            }
        }

        // "Sold by" data takes priority; a regular "Posted by" seller
        // simply won't have any of these fields, correctly leaving
        // them as their honest, existing default values.
        let seller_name = sold_by_name.or(seller_name);
        let seller_profile_url = sold_by_profile_url.or(seller_profile_url);

        // Fallback for regular ("Posted by") sellers - their "Member
        // Since" year sits as a plain label/value pair, genuinely
        // different from verified sellers' richer "Sold by" card.
        let member_since_fallback = document
            .select(&Selector::parse("span").unwrap())
            .find(|el| el.text().collect::<String>().trim() == "Member Since")
            .and_then(|label_el| label_el.parent())
            .and_then(scraper::ElementRef::wrap)
            .and_then(|parent| {
                let sel = Selector::parse("span").ok()?;
                parent
                    .select(&sel)
                    .nth(1)
                    .map(|el| el.text().collect::<String>().trim().to_string())
            })
            .filter(|s| !s.is_empty())
            .map(|year| format!("Member since {}", year));

        let seller_join_date = sold_by_join_date.or(member_since_fallback);

        // Image URLs - take the first 3 real, genuine OLX-hosted
        // images, matching the same real filtering logic the original
        // client-side scraper used.
        let mut image_urls = Vec::new();
        if let Ok(img_sel) = Selector::parse("div.image-gallery-slide img._66938426") {
            for img in document.select(&img_sel).take(3) {
                if let Some(src) = img.value().attr("src") {
                    if src.contains("olx") {
                        image_urls.push(src.to_string());
                    }
                }
            }
        }

        // Tier 1 - checks the description itself for a self-mentioned
        // website, the same real logic as the original client-side
        // extractWebsiteFromDescription.
        let seller_website = description
            .as_deref()
            .and_then(extract_website_from_description);

        ListingPageData {
            title,
            price,
            description,
            seller_name,
            location,
            platform_id,
            seller_profile_url,
            last_active,
            seller_verified: sold_by_verified,
            seller_rating: sold_by_rating,
            seller_total_products: sold_by_total_products,
            seller_join_date,
            image_urls,
            seller_website,
        }
    }
}

/// Tier 1 - scans a listing's description for a mentioned website,
/// the same real logic as the original client-side scraper.
fn extract_website_from_description(description: &str) -> Option<String> {
    let url_pattern =
        regex::Regex::new(r"(https?://)?(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?")
            .ok()?;
    url_pattern
        .find_iter(description)
        .map(|m| m.as_str().to_string())
        .find(|url| !url.contains("olx.com"))
}

fn parse_olx_price(raw: &str) -> Option<i64> {
    let cleaned = raw.replace("Rs", "").replace(",", "").trim().to_string();
    let lower = cleaned.to_lowercase();
    if lower.contains("crore") {
        lower
            .replace("crore", "")
            .trim()
            .parse::<f64>()
            .ok()
            .map(|n| (n * 10_000_000.0).round() as i64)
    } else if lower.contains("lac") {
        lower
            .replace("lac", "")
            .replace("lacs", "")
            .trim()
            .parse::<f64>()
            .ok()
            .map(|n| (n * 100_000.0).round() as i64)
    } else {
        cleaned.parse::<f64>().ok().map(|n| n as i64)
    }
}

fn select_page_text(document: &Html, selector: &str) -> Option<String> {
    let sel = Selector::parse(selector).ok()?;
    let text = document.select(&sel).next()?.text().collect::<String>();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn olx_listing_scraper_matches_only_olx() {
        let scraper = OlxListingScraper;
        assert!(scraper.matches_platform("olx"));
        assert!(!scraper.matches_platform("b2brazil"));
    }

    #[test]
    fn olx_store_scraper_matches_only_olx() {
        let scraper = OlxScraper;
        assert!(scraper.matches_platform("olx"));
        assert!(!scraper.matches_platform("b2brazil"));
    }

    const POSTED_BY_SAMPLE_HTML: &str = r#"
        <h1 class="_75bce902">Test Scooter Listing</h1>
        <span class="_24469da7">Rs 419,000</span>
        <div class="_7a99ad24"><span>A genuinely real description here.</span></div>
        <span aria-label="Location">Gulberg, Lahore</span>
        <span aria-label="Creation date">2 days ago</span>
        <div><span class="_9083bec6">Posted by</span><span>Ahmed Khan</span></div>
        <a class="da952dfc" href="/profile/44107486-9495-4901-81b2-82a61a934028">Profile</a>
    "#;

    #[test]
    fn parse_extracts_correct_title_price_and_description_for_posted_by() {
        let scraper = OlxListingScraper;
        let result = scraper.parse(POSTED_BY_SAMPLE_HTML);
        assert_eq!(result.title, Some("Test Scooter Listing".to_string()));
        assert_eq!(result.price, Some(419_000));
        assert_eq!(
            result.description,
            Some("A genuinely real description here.".to_string())
        );
    }

    #[test]
    fn parse_extracts_correct_location_and_last_active() {
        let scraper = OlxListingScraper;
        let result = scraper.parse(POSTED_BY_SAMPLE_HTML);
        assert_eq!(result.location, Some("Gulberg, Lahore".to_string()));
        assert_eq!(result.last_active, Some("2 days ago".to_string()));
    }

    #[test]
    fn parse_extracts_platform_id_from_profile_url_pattern() {
        let scraper = OlxListingScraper;
        let result = scraper.parse(POSTED_BY_SAMPLE_HTML);
        assert_eq!(
            result.platform_id,
            Some("44107486-9495-4901-81b2-82a61a934028".to_string())
        );
        assert_eq!(
            result.seller_profile_url,
            Some("https://www.olx.com.pk/profile/44107486-9495-4901-81b2-82a61a934028".to_string())
        );
    }

    #[test]
    fn parse_extracts_platform_id_from_seller_url_pattern_too() {
        let html = r#"<a class="da952dfc" href="/seller/pocket-friendly-bazaar-A7795769597555">Profile</a>"#;
        let scraper = OlxListingScraper;
        let result = scraper.parse(html);
        assert_eq!(
            result.platform_id,
            Some("pocket-friendly-bazaar-A7795769597555".to_string())
        );
    }

    #[test]
    fn parse_regular_posted_by_seller_has_no_verified_seller_data() {
        let scraper = OlxListingScraper;
        let result = scraper.parse(POSTED_BY_SAMPLE_HTML);
        assert_eq!(result.seller_verified, false);
        assert_eq!(result.seller_rating, None);
        assert_eq!(result.seller_total_products, None);
        assert_eq!(result.seller_join_date, None);
    }

    const SOLD_BY_SAMPLE_HTML: &str = r#"
        <h1 class="_75bce902">Verified Seller Listing</h1>
        <div id="soldBy">
            <a href="/seller/real-shop-A1234567890123">
                <h4>Real Verified Shop</h4>
                <div class="sellerCard_verified__MB760">Verified</div>
                <div class="group_grid___9nY5">
                    <div class="text-light">Member since</div>
                    <strong>Jul 2026</strong>
                </div>
                <div class="group_grid___9nY5">
                    <div class="text-light">Total Products</div>
                    <strong>197</strong>
                </div>
            </a>
        </div>
    "#;

    #[test]
    fn parse_verified_seller_correctly_extracts_all_sold_by_data() {
        let scraper = OlxListingScraper;
        let result = scraper.parse(SOLD_BY_SAMPLE_HTML);
        assert_eq!(result.seller_name, Some("Real Verified Shop".to_string()));
        assert_eq!(result.seller_verified, true);
        assert_eq!(result.seller_total_products, Some(197));
        assert_eq!(
            result.seller_join_date,
            Some("Member since Jul 2026".to_string())
        );
        assert_eq!(
            result.seller_profile_url,
            Some("https://www.olx.com.pk/seller/real-shop-A1234567890123".to_string())
        );
    }

    #[test]
    fn parse_verified_seller_extracts_rating_when_present() {
        let html = r#"
            <div id="soldBy">
                <a href="/seller/test">
                    <h4>Test Shop</h4>
                    <div class="group_grid___9nY5">
                        <div class="text-light">Rating</div>
                        <strong>4.7 out of 5</strong>
                    </div>
                </a>
            </div>
        "#;
        let scraper = OlxListingScraper;
        let result = scraper.parse(html);
        assert_eq!(result.seller_rating, Some(4.7));
    }

    #[test]
    fn parse_sold_by_name_takes_priority_over_posted_by_name() {
        let html = format!("{}{}", POSTED_BY_SAMPLE_HTML, SOLD_BY_SAMPLE_HTML);
        let scraper = OlxListingScraper;
        let result = scraper.parse(&html);
        assert_eq!(result.seller_name, Some("Real Verified Shop".to_string()));
    }

    #[test]
    fn parse_price_handles_plain_rupees() {
        let html = r#"<span class="_24469da7">Rs 45,000</span>"#;
        assert_eq!(OlxListingScraper.parse(html).price, Some(45_000));
    }

    #[test]
    fn parse_price_handles_lac_notation() {
        let html = r#"<span class="_24469da7">Rs 4.19 Lac</span>"#;
        assert_eq!(OlxListingScraper.parse(html).price, Some(419_000));
    }

    #[test]
    fn parse_price_handles_crore_notation() {
        let html = r#"<span class="_24469da7">Rs 1.5 Crore</span>"#;
        assert_eq!(OlxListingScraper.parse(html).price, Some(15_000_000));
    }

    #[test]
    fn parse_extracts_only_genuine_olx_hosted_images_up_to_three() {
        let html = r#"
            <div class="image-gallery-slide"><img class="_66938426" src="https://images.olx.com.pk/1.jpeg"></div>
            <div class="image-gallery-slide"><img class="_66938426" src="https://images.olx.com.pk/2.jpeg"></div>
            <div class="image-gallery-slide"><img class="_66938426" src="https://images.olx.com.pk/3.jpeg"></div>
            <div class="image-gallery-slide"><img class="_66938426" src="https://images.olx.com.pk/4.jpeg"></div>
            <div class="image-gallery-slide"><img class="_66938426" src="https://some-other-cdn.com/fake.jpeg"></div>
        "#;
        let result = OlxListingScraper.parse(html);
        assert_eq!(result.image_urls.len(), 3);
        assert!(result.image_urls.iter().all(|url| url.contains("olx")));
    }

    #[test]
    fn parse_returns_empty_image_list_when_none_present() {
        let result = OlxListingScraper.parse(POSTED_BY_SAMPLE_HTML);
        assert_eq!(result.image_urls, Vec::<String>::new());
    }

    #[test]
    fn parse_finds_a_real_website_mentioned_in_the_description() {
        let html = r#"
            <div class="_7a99ad24"><span>Great phone for sale. Visit our website at myshop.com for more.</span></div>
        "#;
        let result = OlxListingScraper.parse(html);
        assert!(result.seller_website.is_some());
        assert!(!result.seller_website.unwrap().contains("olx.com"));
    }

    #[test]
    fn parse_finds_no_website_when_description_has_none() {
        let result = OlxListingScraper.parse(POSTED_BY_SAMPLE_HTML);
        assert_eq!(result.seller_website, None);
    }

    #[test]
    fn store_page_confirms_seller_name_when_genuinely_present() {
        let html = "<body>Welcome to Ahmed Khan's official store page.</body>";
        let result = OlxScraper.parse(html, "Ahmed Khan");
        assert!(result.seller_name_confirmed);
    }

    #[test]
    fn store_page_does_not_confirm_a_name_that_is_genuinely_absent() {
        let html = "<body>Welcome to our store page.</body>";
        let result = OlxScraper.parse(html, "Ahmed Khan");
        assert!(!result.seller_name_confirmed);
    }

    #[test]
    fn store_page_finds_a_real_self_referenced_website() {
        let html = "<body>Visit us at realstore.com for more deals.</body>";
        let result = OlxScraper.parse(html, "");
        assert_eq!(result.website, Some("realstore.com".to_string()));
    }

    #[test]
    fn store_page_never_treats_olx_itself_as_a_self_referenced_website() {
        let html = "<body>Visit us at olx.com.pk for more deals.</body>";
        let result = OlxScraper.parse(html, "");
        assert_eq!(result.website, None);
    }

    #[test]
    fn parse_does_not_panic_on_genuinely_empty_html() {
        let result = OlxListingScraper.parse("");
        assert_eq!(result.title, None);
        assert_eq!(result.price, None);
        assert_eq!(result.image_urls, Vec::<String>::new());
    }
}
