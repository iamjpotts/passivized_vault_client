#![cfg(not(windows))]
#![cfg(not(target_os = "macos"))]

#[path = "../examples/example_utils/lib.rs"]
mod example_utils;

#[path = "test_utils/lib.rs"]
mod test_utils;

use std::collections::HashMap;
use http::StatusCode;
use log::*;
use passivized_vault_client::client::{VaultApi, VaultApiUrl};
use passivized_vault_client::errors::VaultClientError;
use passivized_vault_client::models::{VaultInitRequest, VaultUnsealRequest, VaultUnsealProgress, VaultAuthTokenCreateRequest};
use passivized_vault_client_versions::test_supported_images;

#[test_supported_images]
fn test_create_and_read_tokens(image_name: &str, image_tag: &str) {
    test_utils::run_async(run_test(image_name, image_tag))
}

async fn run_test(image_name: &str, image_tag: &str) {
    use example_utils::container::VaultContainer;

    const FN: &str = "test_create_and_read_tokens";

    passivized_test_support::logging::enable_idempotent();

    let vc = VaultContainer::with_image(image_name, image_tag, FN)
        .await
        .unwrap();

    let root_token = init_and_unseal(vc.url.clone())
        .await
        .unwrap();

    create_and_read_tokens(vc.url.clone(), &root_token)
        .await
        .unwrap();

    vc.teardown()
        .await
        .unwrap();
}

async fn init_and_unseal(url: VaultApiUrl) -> Result<String, VaultClientError> {
    let vault = VaultApi::new(url);

    let status = vault.get_status().await?;

    assert!(!status.initialized, "Vault not initialized");
    assert!(status.sealed, "Vault is sealed");

    info!("Initializing Vault unseal keys");

    let unseal_init_request = VaultInitRequest {
        pgp_keys: None,
        root_token_pgp_key: None,
        secret_shares: 1,
        secret_threshold: 1,
        stored_shares: None,
        recovery_shares: None,
        recovery_threshold: None,
        recovery_pgp_keys: None
    };

    let unseal_init_response = vault.initialize(&unseal_init_request).await?;
    info!("Unseal init response:\n{:?}", unseal_init_response);

    let post_unseal_init_status = vault.get_status().await?;
    info!("Status after unseal initialization:\n{:?}", post_unseal_init_status);

    info!("Unsealing");

    for i in 0..unseal_init_request.secret_threshold {
        let unseal_key = (&unseal_init_response
            .keys_base64)
            .get(i).unwrap();

        let unseal_request = VaultUnsealRequest {
            key: Some(unseal_key.into()),
            reset: false,
            migrate: false
        };

        let unseal_response = vault.unseal(&unseal_request).await?;

        info!("Unsealed {}", unseal_response.unseal_progress_string())
    }

    let post_unseal_status = vault.get_status().await?;
    info!("Status after unseal requests:\n{:?}", post_unseal_status);

    assert!(!post_unseal_status.sealed, "Not sealed");

    info!("Root token: {}", unseal_init_response.root_token);

    Ok(unseal_init_response.root_token)
}

async fn create_and_read_tokens(url: VaultApiUrl, root_token: &str) -> Result<(), VaultClientError> {
    let vault = VaultApi::new(url);

    let create_request = VaultAuthTokenCreateRequest {
        meta: HashMap::from([("foo".into(), "bar".into())]),
        display_name: Some("qux".into()),
        num_uses: Some(7),
        ttl: Some("3h".into()),
        ..Default::default()
    };

    let created = vault.auth().tokens().create(root_token, &create_request)
        .await?
        .auth;

    assert_eq!(vec!["root".to_string()], created.policies);
    assert_eq!(vec!["root".to_string()], created.token_policies);
    assert_eq!(HashMap::from([("foo".into(), "bar".into())]), created.metadata);
    assert_eq!(60 * 60 * 3, created.lease_duration);
    assert_eq!(7, created.num_uses);

    let lookup = vault.auth().tokens().lookup_self(&created.client_token)
        .await?
        .data;

    assert_eq!("token-qux", lookup.display_name);
    assert_eq!(vec!["root".to_string()], lookup.policies);
    assert_eq!(HashMap::from([("foo".into(), "bar".into())]), lookup.meta);
    assert_eq!(60 * 60 * 3, lookup.creation_ttl);
    assert_eq!(7 - 1, lookup.num_uses);
    assert!(lookup.creation_ttl <= 60 * 60 * 3);
    assert!(lookup.creation_ttl >= 60 * 60 * 3 - 60);

    let response = vault.auth().tokens().lookup_self("garbledygook")
        .await
        .unwrap_err();

    if let VaultClientError::FailureResponse(status, _) = response {
        assert_eq!(StatusCode::FORBIDDEN, status);
    }
    else {
        panic!("Unexpected response: {:?}", response);
    }

    Ok(())
}