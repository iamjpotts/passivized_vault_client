#![cfg(not(windows))]
#![cfg(not(target_os = "macos"))]

#[path = "../examples/example_utils/lib.rs"]
mod example_utils;

use std::fs::File;
use std::io;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

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

use example_utils::timestamps;

const VAULT_CONFIG_PATH: &str = "/vault/config/config.hcl";

const VAULT_CONFIG_HCL: &str = "storage \"file\" {
    path    = \"/vault/file\"
}

listener \"tcp\" {
   address = \"0.0.0.0:8200\"
   tls_disable = true
}

ui = false";

#[tokio::test]
async fn test_start_and_get_status() {
    passivized_test_support::logging::enable();

    let config_hcl: NamedTempFile = create_vault_config_file()
        .unwrap();

    let hcl_file = config_hcl.path()
        .to_str()
        .unwrap();

    info!("HCL config file: {}", hcl_file);

    let docker = DockerEngineClient::new()
        .unwrap();

    docker.images().pull_if_not_present("vault", "1.11.0")
        .await
        .unwrap();

    let create = CreateContainerRequest::default()
        .image("vault:1.11.0")
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

    info!("Selected IP address: {}", ip);

    let vault_wait = Duration::from_secs(3);

    info!("Waiting {} seconds for Vault to start", vault_wait.as_secs());
    tokio::time::sleep(vault_wait).await;

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

fn create_vault_config_file() -> Result<NamedTempFile, io::Error> {
    let mut ntf = NamedTempFile::new()?;
    write!(ntf, "{}", VAULT_CONFIG_HCL)?;

    let f = File::open(ntf.path())?;
    f.set_permissions(PermissionsExt::from_mode(0o644))?;

    Ok(ntf)
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

    Ok(())
}
