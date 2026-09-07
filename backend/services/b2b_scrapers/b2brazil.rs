use crate::services::b2b_scrapers::{B2bListingProfile, B2bScraper, B2bSupplierProfile};
use scraper::{Html, Selector};

pub struct B2brazilScraper;

impl B2bScraper for B2brazilScraper {
    fn matches_platform(&self, platform: &str) -> bool {
        platform == "b2brazil"
    }

    fn parse_supplier(&self, html: &str, profile_url: &str) -> B2bSupplierProfile {
        let document = Html::parse_document(html);

        let logo_url = select_attr(&document, "#header-info-thumb img", "src");
        let company_name = select_text(&document, "#header-info-company h1");

        let platform_verified_badge = Selector::parse("#header-info-company-verify")
            .ok()
            .and_then(|sel| document.select(&sel).next())
            .map(|el| {
                let class = el.value().attr("class").unwrap_or("");
                !class.contains("not-verify")
            })
            .unwrap_or(false);

        let mut year_established = None;
        let mut country = None;
        if let Ok(sel) = Selector::parse(".actions-item h4") {
            for el in document.select(&sel) {
                let text = el.text().collect::<String>();
                let trimmed = text.trim();
                if let Some(year) = trimmed.strip_prefix("Since ") {
                    year_established = Some(year.trim().to_string());
                } else if !trimmed.is_empty() && year_established.is_some() && country.is_none() {
                    country = Some(trimmed.to_string());
                }
            }
        }

        let (contact_name, contact_phone, contact_location) =
            extract_contact_and_location(&document);
        let country = contact_location.or(country);

        let mut employee_count = None;
        let mut sales_revenue = None;
        let mut export_percentage = None;
        if let Ok(sel) = Selector::parse(".section-content-more-info-item") {
            for item in document.select(&sel) {
                let label =
                    select_text(&Html::parse_fragment(&item.html()), "p").unwrap_or_default();
                let value = select_text(&Html::parse_fragment(&item.html()), "h4");
                match label.as_str() {
                    "Employees" => employee_count = value,
                    "Sales volume (USD)" => sales_revenue = value,
                    "% Export sales" => export_percentage = value,
                    _ => {}
                }
            }
        }

        B2bSupplierProfile {
            company_name,
            logo_url,
            year_established,
            country,
            platform_verified_badge,
            employee_count,
            sales_revenue,
            export_percentage,
            profile_url: profile_url.to_string(),
            source_platform: "b2brazil".to_string(),
            contact_name,
            contact_phone,
        }
    }

    fn parse_listing(&self, html: &str, listing_url: &str) -> B2bListingProfile {
        let document = Html::parse_document(html);

        let title = select_text(&document, ".section-product-title");
        let description = select_text(&document, ".section-content-about.product-description p");

        let mut fields = std::collections::HashMap::new();
        if let Ok(sel) = Selector::parse(".section-product-item") {
            for item in document.select(&sel) {
                let fragment = Html::parse_fragment(&item.html());
                let label = select_text(&fragment, "h3").unwrap_or_default();
                let label = label.trim_end_matches(':').to_string();
                // Most fields wrap their value in <p>; Incoterms in the
                // real page has no <p> at all, just plain trailing text.
                let value = select_text(&fragment, "p")
                    .or_else(|| {
                        let full_text = fragment.root_element().text().collect::<String>();
                        let after_label = full_text.splitn(2, &label).nth(1)?;
                        let cleaned = after_label.trim_start_matches(':').trim();
                        if cleaned.is_empty() {
                            None
                        } else {
                            Some(cleaned.to_string())
                        }
                    })
                    .filter(|v| v != "Not informed");
                fields.insert(label, value);
            }
        }

        let mut image_urls = Vec::new();
        if let Ok(img_sel) = Selector::parse("ul.section-product-slider-items li img") {
            for img in document.select(&img_sel).take(3) {
                let value = img.value();
                let real_src = value
                    .attr("data-src")
                    .or_else(|| value.attr("src"))
                    .filter(|src| !src.contains("loading-"));
                if let Some(src) = real_src {
                    image_urls.push(src.to_string());
                }
            }
        }

        B2bListingProfile {
            title,
            description,
            image_urls,
            unit_price: fields.remove("Unit Price").flatten(),
            fob_price: fields.remove("FOB Price").flatten(),
            minimum_order_quantity: fields.remove("Minimum Order Quantity").flatten(),
            payment_type: fields.remove("Type of Payment").flatten(),
            preferred_port: fields.remove("Preferred Port").flatten(),
            reference: fields.remove("Reference").flatten(),
            production_capacity: fields.remove("Production Capacity").flatten(),
            delivery_timeframe: fields.remove("Delivery Timeframe").flatten(),
            incoterms: fields.remove("Incoterms").flatten(),
            packaging_details: fields.remove("Packaging Details").flatten(),
            listing_url: listing_url.to_string(),
            source_platform: "b2brazil".to_string(),
        }
    }
}

fn select_text(document: &Html, selector: &str) -> Option<String> {
    let sel = Selector::parse(selector).ok()?;
    let text = document.select(&sel).next()?.text().collect::<String>();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn select_attr(document: &Html, selector: &str, attr: &str) -> Option<String> {
    let sel = Selector::parse(selector).ok()?;
    document
        .select(&sel)
        .next()?
        .value()
        .attr(attr)
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_SAMPLE_HTML: &str = r#"
        <div id="header-info-thumb"><img src="https://cdn.b2brazil.com/logo.png"></div>
        <div id="header-info-company">
            <h1>Akurat Consultoria Empresarial</h1>
            <div id="header-info-company-verify" class="not-verify">Unverified company</div>
        </div>
        <div class="actions-item"><h4>Since 2013</h4></div>
        <div class="actions-item"><h4>Brazil</h4></div>
        <div class="section-content-more-info-item"><h4>0-10</h4><p>Employees</p></div>
        <div class="section-content-more-info-item"><h4>200K - 500K</h4><p>Sales volume (USD)</p></div>
        <div class="section-content-more-info-item"><h4>10%</h4><p>% Export sales</p></div>
        <h2 class="section-product-title">Precision Microcast Parts - Precision Casting</h2>
        <div class="section-content-about product-description"><p>Real audit description here.</p></div>
        <div class="section-product-item"><h3>Unit Price:</h3><p>Not informed</p></div>
        <div class="section-product-item"><h3>Minimum Order Quantity:</h3><p>500 units</p></div>
    "#;

    #[test]
    fn parse_listing_returns_empty_image_list_when_none_present() {
        let scraper = B2brazilScraper;
        let result = scraper.parse_listing(REAL_SAMPLE_HTML, "https://b2brazil.com/test");
        assert_eq!(result.image_urls, Vec::<String>::new());
    }

    const SAMPLE_WITH_IMAGES: &str = r#"
        <h2 class="section-product-title">Test Product</h2>
        <ul class="section-product-slider-items">
            <li><img class="uk-cover" src="https://cdn.b2brazil.com/real-image-1.jpg" alt="product"></li>
            <li><img class="lazyload uk-cover" data-src="https://cdn.b2brazil.com/real-image-2.jpg" src="//cdn.b2brazil.com/assets/images/loading-aH4uwG80c9b336.svg" alt="product"></li>
        </ul>
    "#;

    #[test]
    fn parse_listing_extracts_real_images_preferring_data_src_over_placeholder() {
        let scraper = B2brazilScraper;
        let result = scraper.parse_listing(SAMPLE_WITH_IMAGES, "https://b2brazil.com/test");
        assert_eq!(
            result.image_urls,
            vec![
                "https://cdn.b2brazil.com/real-image-1.jpg".to_string(),
                "https://cdn.b2brazil.com/real-image-2.jpg".to_string(),
            ]
        );
    }

    #[test]
    fn parse_supplier_extracts_real_company_data() {
        let scraper = B2brazilScraper;
        let result = scraper.parse_supplier(REAL_SAMPLE_HTML, "https://b2brazil.com/test");

        assert_eq!(
            result.company_name,
            Some("Akurat Consultoria Empresarial".to_string())
        );
        assert_eq!(result.year_established, Some("2013".to_string()));
        assert_eq!(result.country, Some("Brazil".to_string()));
        assert_eq!(result.platform_verified_badge, false);
        assert_eq!(result.employee_count, Some("0-10".to_string()));
        assert_eq!(result.sales_revenue, Some("200K - 500K".to_string()));
        assert_eq!(result.export_percentage, Some("10%".to_string()));
    }

    #[test]
    fn parse_listing_filters_out_not_informed_but_keeps_real_values() {
        let scraper = B2brazilScraper;
        let result = scraper.parse_listing(REAL_SAMPLE_HTML, "https://b2brazil.com/test");

        assert_eq!(
            result.title,
            Some("Precision Microcast Parts - Precision Casting".to_string())
        );
        assert_eq!(result.unit_price, None); // "Not informed" correctly filtered out
        assert_eq!(result.minimum_order_quantity, Some("500 units".to_string()));
    }

    #[test]
    fn matches_platform_correctly_identifies_b2brazil_only() {
        let scraper = B2brazilScraper;
        assert!(scraper.matches_platform("b2brazil"));
        assert!(!scraper.matches_platform("olx"));
        assert!(!scraper.matches_platform("alibaba"));
    }

    const VERIFIED_SAMPLE_HTML: &str = r#"
        <div id="header-info-company">
            <h1>Real Verified Company</h1>
            <div id="header-info-company-verify" class="verified">Verified company</div>
        </div>
    "#;

    #[test]
    fn parse_supplier_correctly_detects_a_genuinely_verified_badge() {
        let scraper = B2brazilScraper;
        let result = scraper.parse_supplier(VERIFIED_SAMPLE_HTML, "https://b2brazil.com/test");
        assert_eq!(result.platform_verified_badge, true);
    }

    const INCOTERMS_NO_P_TAG_HTML: &str = r#"
        <div class="section-product-item">
            <h3>Incoterms:</h3>
            FOB
        </div>
    "#;

    #[test]
    fn parse_listing_handles_incoterms_with_no_p_tag_wrapper() {
        let scraper = B2brazilScraper;
        let result = scraper.parse_listing(INCOTERMS_NO_P_TAG_HTML, "https://b2brazil.com/test");
        assert_eq!(result.incoterms, Some("FOB".to_string()));
    }

    const FIVE_IMAGES_HTML: &str = r#"
        <ul class="section-product-slider-items">
            <li><img src="https://cdn.b2brazil.com/img1.jpg"></li>
            <li><img src="https://cdn.b2brazil.com/img2.jpg"></li>
            <li><img src="https://cdn.b2brazil.com/img3.jpg"></li>
            <li><img src="https://cdn.b2brazil.com/img4.jpg"></li>
            <li><img src="https://cdn.b2brazil.com/img5.jpg"></li>
        </ul>
    "#;

    #[test]
    fn parse_listing_caps_image_urls_at_three_even_when_more_are_present() {
        let scraper = B2brazilScraper;
        let result = scraper.parse_listing(FIVE_IMAGES_HTML, "https://b2brazil.com/test");
        assert_eq!(result.image_urls.len(), 3);
    }

    #[test]
    fn parse_supplier_and_listing_do_not_panic_on_genuinely_empty_html() {
        let scraper = B2brazilScraper;
        let supplier = scraper.parse_supplier("", "https://b2brazil.com/test");
        let listing = scraper.parse_listing("", "https://b2brazil.com/test");
        assert_eq!(supplier.company_name, None);
        assert_eq!(listing.title, None);
    }

    #[test]
    fn parse_supplier_and_listing_correctly_record_the_real_url_and_platform() {
        let scraper = B2brazilScraper;
        let supplier =
            scraper.parse_supplier(REAL_SAMPLE_HTML, "https://b2brazil.com/real-profile");
        let listing = scraper.parse_listing(REAL_SAMPLE_HTML, "https://b2brazil.com/real-listing");
        assert_eq!(supplier.profile_url, "https://b2brazil.com/real-profile");
        assert_eq!(supplier.source_platform, "b2brazil");
        assert_eq!(listing.listing_url, "https://b2brazil.com/real-listing");
        assert_eq!(listing.source_platform, "b2brazil");
    }
}

/// Extracts the real, direct contact details from B2Brazil's "Contact
/// and location" block. Genuinely more specific than the founding-year
/// section's location (which only ever gives a country, e.g. "Brazil")
/// - this block gives a real city and state, e.g. "MACAE / RJ".
///
/// The phone number here is often deliberately masked by B2Brazil
/// itself (e.g. "+55 22********") until a paid tier unlocks it - a
/// masked, partial number has no real value for identity matching, so
/// it's deliberately treated the same as "not present" here, rather
/// than capturing a useless fragment.
fn extract_contact_and_location(
    document: &Html,
) -> (Option<String>, Option<String>, Option<String>) {
    let mut contact_name = None;
    let mut contact_phone = None;
    let mut location = None;

    if let Ok(li_sel) = Selector::parse("ul.section-content-more-info-list li") {
        for li in document.select(&li_sel) {
            let fragment = Html::parse_fragment(&li.html());
            let text = fragment
                .root_element()
                .text()
                .collect::<String>()
                .trim()
                .to_string();
            if text.is_empty() {
                continue;
            }
            let html_lower = li.html().to_lowercase();
            if html_lower.contains("user-icon") {
                contact_name = Some(text);
            } else if html_lower.contains("phone-") {
                if !text.contains('*') {
                    contact_phone = Some(text);
                }
            } else if html_lower.contains("map-marker") {
                location = Some(text);
            }
        }
    }
    (contact_name, contact_phone, location)
}
