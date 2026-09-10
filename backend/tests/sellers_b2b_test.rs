mod common;
use crate::common::{admin_pool, cleanup_test_seller_chain};
use backend::{
    models::sellers::{SellerVerification, SellersRequest},
    services::sellers::{create_seller, find_seller, update_seller_from_b2b},
};

#[tokio::test]
async fn update_seller_from_b2b_writes_the_real_name_and_location() {
    let pool = admin_pool().await;
    let platform_id = "update_seller_b2b_test_001";
    cleanup_test_seller_chain(&pool, "b2brazil", platform_id).await;

    let seller_request = SellersRequest {
        platform: "b2brazil".to_string(),
        platform_id: Some(platform_id.to_string()),
        name: None,
        handle: None,
        phone: None,
        profile_url: None,
        join_date: None,
        location: None,
        last_active: None,
    };
    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");

    assert_eq!(
        seller.name, None,
        "expected the seller to genuinely start with no name"
    );

    update_seller_from_b2b(
        &pool,
        seller.id,
        Some("Real Company Name"),
        Some("Brazil"),
        None,
        None,
        None,
        None,
    )
    .await
    .expect("expected the update to succeed");

    let updated = find_seller(&pool, "b2brazil", platform_id)
        .await
        .expect("expected the query itself to succeed")
        .expect("expected to find the seller");

    assert_eq!(updated.name, Some("Real Company Name".to_string()));
    assert_eq!(updated.location, Some("Brazil".to_string()));

    cleanup_test_seller_chain(&pool, "b2brazil", platform_id).await;
}

#[tokio::test]
async fn update_seller_from_b2b_preserves_existing_data_when_new_values_are_none() {
    let pool = admin_pool().await;
    let platform_id = "update_seller_b2b_coalesce_test_001";
    cleanup_test_seller_chain(&pool, "b2brazil", platform_id).await;

    let seller_request = SellersRequest {
        platform: "b2brazil".to_string(),
        platform_id: Some(platform_id.to_string()),
        name: Some("Original Name".to_string()),
        handle: Some("Original Handle".to_string()),
        phone: Some("Original Phone".to_string()),
        profile_url: None,
        join_date: Some("2020".to_string()),
        location: Some("Original Location".to_string()),
        last_active: None,
    };

    let seller = create_seller(&pool, &seller_request, SellerVerification::Unknown)
        .await
        .expect("expected to create the seller");
    update_seller_from_b2b(&pool, seller.id, None, None, None, None, None, None)
        .await
        .expect("expected the update to succeed");
    let updated = find_seller(&pool, "b2brazil", platform_id)
        .await
        .expect("expected the query itself to succeed")
        .expect("expected to find the seller");

    assert_eq!(updated.name, Some("Original Name".to_string()));
    assert_eq!(updated.location, Some("Original Location".to_string()));
    assert_eq!(updated.handle, Some("Original Handle".to_string()));
    assert_eq!(updated.phone, Some("Original Phone".to_string()));
    cleanup_test_seller_chain(&pool, "b2brazil", platform_id).await;
}
