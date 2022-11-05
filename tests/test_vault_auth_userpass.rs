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
use passivized_vault_client::models::{VaultInitRequest, VaultUnsealRequest, VaultUnsealProgress, VaultEnableAuthRequest, VaultAuthUserpassCreateRequest};
use tempfile::NamedTempFile;

use example_utils::hcl::{VAULT_CONFIG_PATH, create_vault_config_file};
use example_utils::images;
use example_utils::timestamps;

#[tokio::test]
async fn test_create_and_read_users() {
    const FN: &str = "test_create_and_read_users";

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
        .name(timestamps::named(FN))
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

    let root_token = init_and_unseal(api_url.clone())
        .await
        .unwrap();

    create_and_read_users(api_url, &root_token)
        .await
        .unwrap();

    info!("Stopping container {}", container.id);

    docker.container(&container.id).stop()
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

    Ok(unseal_init_response.root_token)
}

async fn create_and_read_users(url: VaultApiUrl, root_token: &str) -> Result<(), VaultClientError> {
    let vault = VaultApi::new(url);

    const MOUNT_PATH: &str = "foo";

    let enable_request = VaultEnableAuthRequest {
        type_: "userpass".into(),
        description: Some("Foo Users".into()),
        ..Default::default()
    };

    vault.auth().enable(root_token, MOUNT_PATH, &enable_request)
        .await?;

    const USERNAME1: &str = "john";
    const PASSWORD1: &str = "crack-me";
    const PASSWORD1B: &str = "crack-me-again";

    const USERNAME2: &str = "mary";
    const PASSWORD2: &str = "super-secure";

    // Arbitrary value used to test setting and receiving properties of the user
    const TOKEN_MAX_TTL: u64 = 12345678;

    let userpass = vault.auth().userpass(MOUNT_PATH);

    let mut user1_request = VaultAuthUserpassCreateRequest::with_password(PASSWORD1);
    user1_request.token_max_ttl = Some(TOKEN_MAX_TTL);

    userpass.create(root_token, USERNAME1, &user1_request)
        .await?;

    let user1_detail = userpass.read(root_token, USERNAME1)
        .await?;

    // Get the value we set and validate its the same.
    assert_eq!(TOKEN_MAX_TTL, user1_detail.data.token_max_ttl);

    // Validate password
    info!("Validating password for {}", USERNAME1);
    assert_ne!(
        None,
        userpass.login(USERNAME1, PASSWORD1)
            .await?
    );

    // Try an intentionally wrong password
    info!("Validating invalid password rejection for {}", USERNAME1);
    assert_eq!(
        None,
        userpass.login(USERNAME1, PASSWORD1B)
            .await?
    );

    // Change password (on Vault, users cannot change their own passwords by default, so we use the root token)
    info!("Changing password for {}", USERNAME1);
    userpass.update_password(root_token, USERNAME1, PASSWORD1B)
        .await?;

    // Validate new password
    info!("Validating new password for {}", USERNAME1);
    assert_ne!(
        None,
        userpass.login(USERNAME1, PASSWORD1B)
            .await?
    );

    // Add another user
    info!("Adding user {}", USERNAME2);
    userpass.create(root_token, USERNAME2, &VaultAuthUserpassCreateRequest::with_password(PASSWORD2))
        .await?;

    // Get list of users
    let users = userpass.list(root_token)
        .await?
        .data
        .keys;

    assert_eq!(2, users.len());
    assert!(users.contains(&USERNAME1.to_string()));
    assert!(users.contains(&USERNAME2.to_string()));

    // Delete first user and verify user is gone
    info!("Deleting user {}", USERNAME1);
    userpass.delete(root_token, USERNAME1)
        .await?;

    info!("Verifying {} was deleted", USERNAME1);
    let users = userpass.list(root_token)
        .await?
        .data
        .keys;

    assert_eq!(vec![USERNAME2.to_string()], users);

    Ok(())
}