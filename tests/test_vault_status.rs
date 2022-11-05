#![cfg(not(windows))]
#![cfg(not(target_os = "macos"))]

#[path = "../examples/example_utils/lib.rs"]
mod example_utils;

use log::*;
use passivized_docker_engine_client::DockerEngineClient;
use passivized_docker_engine_client::model::MountMode::ReadOnly;
use passivized_docker_engine_client::requests::{CreateContainerRequest, HostConfig};
use passivized_test_support::http_status_tests::is_success;
use passivized_test_support::waiter::wait_for_http_server;
use passivized_vault_client::client::{VaultApi, VaultApiUrl};
use passivized_vault_client::errors::VaultClientError;
use passivized_vault_client::models::{VaultInitRequest, VaultUnsealRequest, VaultUnsealProgress};
use tempfile::NamedTempFile;

use example_utils::hcl::{VAULT_CONFIG_PATH, create_vault_config_file};
use example_utils::timestamps;
use example_utils::images;

#[tokio::test]
async fn test_start_and_get_status() {
    passivized_test_support::logging::enable();

    let config_hcl: NamedTempFile = create_vault_config_file()
        .unwrap();

    let hcl_file = config_hcl.path()
        .to_str()
        .unwrap();

    let docker = DockerEngineClient::new()
        .unwrap();

    docker.images().pull_if_not_present(images::vault::NAME, images::vault::TAG)
        .await
        .unwrap();

    let create = CreateContainerRequest::default()
        .image(images::vault::IMAGE)
        .cmd(vec!["server"])
        .host_config(HostConfig::default()
            .auto_remove()
            .cap_add("IPC_LOCK")
            .mount(hcl_file, VAULT_CONFIG_PATH, ReadOnly)
        );

    info!("Creating container");

    let container = docker.containers().create(create)
        .await
        .unwrap();

    info!("Created container with id {}", container.id);
    for w in &container.warnings {
        warn!("Container warning: {}", w)
    }

    info!("Renaming container");

    docker.container(&container.id).rename(&timestamps::named("vault"))
        .await
        .unwrap();

    info!("Starting container");

    docker.container(&container.id).start()
        .await
        .unwrap();

    let inspected = docker.container(&container.id).inspect()
        .await
        .unwrap();

    let ip = inspected.first_ip_address()
        .unwrap();

    let api_url = VaultApiUrl::new(format!("http://{}:8200", ip));

    wait_for_http_server(api_url.status(), is_success())
        .await
        .unwrap();

    run_with_vault(api_url)
        .await
        .unwrap();

    info!("Stopping container {}", container.id);

    docker.container(&container.id).stop()
        .await
        .unwrap();
}

async fn run_with_vault(url: VaultApiUrl) -> Result<(), VaultClientError> {
    info!("Running with Vault at {}", url);

    let vault = VaultApi::new(url);

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
