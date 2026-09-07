use crate::errors::claude::ClaudeError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::env::var;

// 1. Packaging the question for Claude's API
#[derive(Serialize)]
pub struct ClaudeRequest {
    pub model: String,
    pub max_tokens: u32,
    pub messages: Vec<Message>,
}

#[derive(Serialize)]
pub struct Message {
    pub role: String,
    pub content: Vec<ContentItem>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentItem {
    Text { text: String },
    Image { source: ImageSource },
}

#[derive(Serialize)]
pub struct ImageSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub url: String,
}

// 2. Gives you the text(that contains the actual fraud analysis) from the content block
#[derive(Debug, Deserialize)]
struct ClaudeEnvelope {
    content: Vec<ContentBlock>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    text: String,
}

// 3. The raw data of analysis is inserted in this struct for better structure.
#[derive(Debug, Deserialize)]
pub struct ClaudeAnalysis {
    pub urgency_language: Finding,
    pub advance_payment_request: Finding,
    pub duplicate_listing: Finding,
    pub image_authenticity: ImageAssessment,
    pub fraud_pattern_match: Finding,
    pub contact_info_in_listing: Finding,
    pub price_assessment: PriceAssessment,
    pub extracted_phone_number: Option<String>,
    pub overall_risk_notes: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Finding {
    pub found: bool,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ImageAssessment {
    pub verdict: String,
    pub reasoning: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PriceAssessment {
    pub verdict: String,
    pub reasoning: String,
}

#[derive(Debug)]
pub struct CallClaudeArguments<'a> {
    pub platform: &'a str,
    pub seller_name: &'a str,
    pub seller_account_age: &'a str,
    pub title: &'a str,
    pub price: i64,
    pub description: &'a str,
    pub image_urls: &'a [String],
}

// B2B analysis structs
#[derive(Debug, Deserialize)]
pub struct B2bClaudeAnalysis {
    pub business_legitimacy: Finding,
    pub registration_consistency: Finding,
    pub listing_specificity: Finding,
    pub pricing_transparency: PriceAssessment,
    pub contact_verifiability: Finding,
    pub urgency_language: Finding,
    pub advance_payment_request: Finding,
    pub image_authenticity: ImageAssessment,
    pub overall_risk_notes: String,
}

#[derive(Debug)]
pub struct CallB2bClaudeArguments<'a> {
    pub platform: &'a str,
    pub company_name: &'a str,
    pub year_established: &'a str,
    pub platform_verified: bool,
    pub employee_count: &'a str,
    pub product_title: &'a str,
    pub product_description: &'a str,
    pub image_urls: &'a [String],
}

/// The ONE, shared place that builds the real content blocks sent to
/// Claude - genuinely unified for both B2C and B2B, so a future
/// decision to re-enable image analysis only ever needs to happen in
/// one spot, not two separate, duplicated copies.
fn build_content_blocks(prompt: String, _image_urls: &[String]) -> Vec<ContentItem> {
    let content_blocks: Vec<ContentItem> = vec![ContentItem::Text { text: prompt }];

    // Image sending disabled for cost reasons, for both B2C and B2B -
    // commented out here.
    // for url in _image_urls.iter().take(3) {
    //     content_blocks.push(ContentItem::Image {
    //         source: ImageSource {
    //             source_type: "url".to_string(),
    //             url: url.clone(),
    //         },
    //     });
    // }

    content_blocks
}

pub async fn call_b2c_claude(args: CallClaudeArguments<'_>) -> Result<ClaudeAnalysis, ClaudeError> {
    let client = Client::new();
    let api_key = var("ANTHROPIC_API_KEY").map_err(|_| ClaudeError::MissingApiKey)?;
    let prompt = b2c_content(&args);
    let content_blocks = build_content_blocks(prompt, args.image_urls);

    let payload = ClaudeRequest {
        model: String::from("claude-sonnet-4-6"),
        max_tokens: 2048,
        messages: vec![Message {
            role: "user".to_string(),
            content: content_blocks,
        }],
    };

    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&payload)
        .send()
        .await
        .map_err(|e| ClaudeError::RequestFailed(e.to_string()))?;

    let body_text = response
        .text()
        .await
        .map_err(|e| ClaudeError::RequestFailed(e.to_string()))?;

    let envelope: ClaudeEnvelope =
        from_str(&body_text).map_err(|e| ClaudeError::ParseFailed(e.to_string()))?;

    let inner_json = &envelope.content[0].text;
    let cleaned = inner_json
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    from_str(cleaned).map_err(|e| ClaudeError::ParseFailed(e.to_string()))
}

pub async fn call_b2b_claude(
    args: CallB2bClaudeArguments<'_>,
) -> Result<B2bClaudeAnalysis, ClaudeError> {
    let client = Client::new();
    let api_key = var("ANTHROPIC_API_KEY").map_err(|_| ClaudeError::MissingApiKey)?;
    let prompt = b2b_content(&args);
    let content_blocks = build_content_blocks(prompt, args.image_urls);

    let payload = ClaudeRequest {
        model: String::from("claude-sonnet-4-6"),
        max_tokens: 2048,
        messages: vec![Message {
            role: "user".to_string(),
            content: content_blocks,
        }],
    };

    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&payload)
        .send()
        .await
        .map_err(|e| ClaudeError::RequestFailed(e.to_string()))?;

    let body_text = response
        .text()
        .await
        .map_err(|e| ClaudeError::RequestFailed(e.to_string()))?;

    let envelope: ClaudeEnvelope =
        from_str(&body_text).map_err(|e| ClaudeError::ParseFailed(e.to_string()))?;
    let inner_json = &envelope.content[0].text;
    let cleaned = inner_json
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    from_str(cleaned).map_err(|e| ClaudeError::ParseFailed(e.to_string()))
}

pub fn b2c_content(arg: &CallClaudeArguments) -> String {
    format!(
        r#"
        You are a fraud detection assistant for an online marketplace.
        Analyze this listing and seller, then return ONLY a raw JSON object with no markdown, no code fences, no backticks, no explanation. Start your response with {{ and end with }}.

        Platform: {platform}
        Seller name: {seller_name}
        Seller account age: {seller_account_age}
        Listing title: {title}
        Listing price: PKR {price}
        Listing description: {description}

        For the duplicate_listing field: check if the description appears generic, templated, or copy-pasted. Look for mismatched details between title and description, no item-specific information like serial numbers or condition details, language that could apply to any listing of this type rather than this specific item. Set found to true if the listing appears to be a template or copy rather than an original genuine listing.
        For image_authenticity: verdict must be exactly "original" or
        "not verified" - no other words. Use "not verified" whenever no
        images were provided or authenticity cannot genuinely be assessed.
        For extracted_phone_number: sellers often write their real phone
        number in the description using odd separators to dodge
        automated scraping - things like "0+3+4+2+..." or "0:3:4:2..."
        or "0/3/4/2..." Look for any sequence of digits, however
        separated, that forms a plausible Pakistani phone number
        (typically starting with 0, 10-11 digits total). If found,
        return it as a single, clean digit string with all
        placeholder characters removed (e.g. "03001234567"). If no
        phone number is genuinely present in the text, return null.
        Return JSON in exactly this shape:

        {{
        "urgency_language": {{
            "found": false,
            "evidence": ""
        }},
        "advance_payment_request": {{
            "found": false,
            "evidence": ""
        }},
        "contact_info_in_listing": {{
            "found": false,
            "evidence": ""
        }},
        "price_assessment": {{
            "verdict": "normal",
            "reasoning": ""
        }},
        "fraud_pattern_match": {{
            "found": false,
            "evidence": ""
        }},
        "duplicate_listing": {{
            "found": false,
            "evidence": ""
        }},
        "image_authenticity": {{
            "verdict": "original",
            "reasoning": ""
        }},
        "extracted_phone_number": null,
        "overall_risk_notes": ""
        }}
        "#,
        platform = arg.platform,
        seller_name = arg.seller_name,
        seller_account_age = arg.seller_account_age,
        title = arg.title,
        price = arg.price,
        description = arg.description,
    )
}

pub fn b2b_content(arg: &CallB2bClaudeArguments) -> String {
    format!(
        r#"
        You are a B2B supplier due-diligence assistant helping a procurement
        team evaluate a potential vendor. This is NOT a consumer marketplace -
        do not apply consumer fraud patterns like "urgency language" or
        "advance payment scams." B2B listings routinely omit pricing, MOQ,
        and shipping terms (these are typically negotiated privately after
        an inquiry) - this is completely normal and must NOT be treated as
        suspicious on its own.

        Analyze this supplier and product listing, then return ONLY a raw
        JSON object with no markdown, no code fences, no backticks, no
        explanation. Start your response with {{ and end with }}.

        Platform: {platform}
        Company name: {company_name}
        Year established: {year_established}
        Platform-verified badge: {platform_verified}
        Employee count: {employee_count}
        Product title: {product_title}
        Product description: {product_description}

        For business_legitimacy: does this look like a genuine, established
        business with real operational details, or does it show signs of
        being a shell, front, or fabricated entity (e.g. no real company
        details, generic or nonsensical company name, inconsistent
        information)?

        For registration_consistency: does the company's stated information
        (name, founding year, scale) hang together coherently, or are there
        real, concrete inconsistencies?

        For listing_specificity: does the product listing describe a real,
        specific product with genuine, plausible details, or is it
        template-like, vague, or nonsensical for the stated industry?

        For pricing_transparency: assess ONLY whether provided pricing
        information (if any) seems plausible for this product type -
        missing pricing/MOQ/Incoterms is NORMAL in B2B and should verdict
        as "normal" unless something provided is actually implausible.

        For contact_verifiability: does the company provide genuine,
        checkable contact information?

        For urgency_language: does the listing or company description use
        artificial pressure tactics inconsistent with normal B2B
        relationship-building - e.g. "deal expires today," "must decide
        now," discouraging normal due diligence or sample requests? Note
        that reasonable business urgency (limited stock, seasonal demand)
        is normal and should NOT be flagged.

        For advance_payment_request: does the listing demand full,
        100% upfront payment before any samples, verification, or
        standard partial-deposit terms - genuinely unusual for
        legitimate B2B trade, where partial deposits and post-inspection
        payment terms are standard?

        For image_authenticity: no actual product images are provided
        in this analysis (image sending is disabled for cost reasons,
        matching the same limitation applied to consumer listings).
        Verdict must be exactly "original" or "not verified" - no other
        words. Use "not verified" whenever no images were provided or
        authenticity cannot genuinely be assessed.

        Return JSON in exactly this shape:
        {{
        "business_legitimacy": {{ "found": false, "evidence": "" }},
        "registration_consistency": {{ "found": false, "evidence": "" }},
        "listing_specificity": {{ "found": false, "evidence": "" }},
        "pricing_transparency": {{ "verdict": "normal", "reasoning": "" }},
        "contact_verifiability": {{ "found": false, "evidence": "" }},
        "urgency_language": {{ "found": false, "evidence": "" }},
        "advance_payment_request": {{ "found": false, "evidence": "" }},
        "image_authenticity": {{ "verdict": "not verified", "reasoning": "" }},
        "overall_risk_notes": ""
        }}
        "#,
        platform = arg.platform,
        company_name = arg.company_name,
        year_established = arg.year_established,
        platform_verified = arg.platform_verified,
        employee_count = arg.employee_count,
        product_title = arg.product_title,
        product_description = arg.product_description,
    )
}
