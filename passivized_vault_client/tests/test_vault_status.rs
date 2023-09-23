#![cfg(not(windows))]
#![cfg(not(target_os = "macos"))]

#[path = "../examples/example_utils/lib.rs"]
mod example_utils;

use log::*;
use passivized_vault_client::client::{VaultApi, VaultApiUrl};
use passivized_vault_client::errors::VaultClientError;
use passivized_vault_client::models::{VaultInitRequest, VaultUnsealRequest, VaultUnsealProgress};
use passivized_vault_client_versions::test_supported_images;

#[test_supported_images]
#[tokio::test]
async fn test_start_and_get_status(image_name: &str, image_tag: &str) {
    use example_utils::container::VaultContainer;

    const FN: &str = "test_start_and_get_status";

    passivized_test_support::logging::enable_idempotent();

    let vc = VaultContainer::with_image(image_name, image_tag, FN)
        .await
        .unwrap();

    run_with_vault(&vc.url)
        .await
        .unwrap();

    vc.teardown()
        .await
        .unwrap();
}

async fn run_with_vault(url: &VaultApiUrl) -> Result<(), VaultClientError> {
    info!("Running with Vault at {}", url);

    let vault = VaultApi::new(url.clone());

    let status = vault.get_status().await?;

    assert!(!status.initialized, "Vault not initialized");
    assert!(status.sealed, "Vault is sealed");

    info!("Initializing Vault unseal keys");

    let unseal_init_request = VaultInitRequest {
        pgp_keys: None,
        root_token_pgp_key: None,
        secret_shares: 5,
        secret_threshold: 3,
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

    info!("Getting plugins");

    let plugins = vault.plugins().catalog().get(&unseal_init_response.root_token).await?;

    info!("Auth plugins:");

    for p in &plugins.data.auth {
        info!("  {}", p);
    }

    assert!(plugins.data.auth.contains(&"ldap".to_string()));

    Ok(())
}
