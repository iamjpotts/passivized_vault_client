//!
//! Demonstrates creating one Vault cluster, and enabling the "userpass" auth method.
//!
//! At the end of the run of this example, it stops and deletes the containers. If
//! you would like to leave them running, look for calls to stop() and comment them out.
//!
//! The containers will auto-delete themselves when stopped.

#[path = "example_utils/lib.rs"]
mod example_utils;

use std::io;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use log::*;
use passivized_docker_engine_client::DockerEngineClient;
use passivized_docker_engine_client::model::MountMode::ReadOnly;
use passivized_docker_engine_client::requests::{CreateContainerRequest, HostConfig};
use passivized_docker_engine_client::responses::CreateContainerResponse;
use passivized_test_support::http_status_tests::is_success;
use passivized_test_support::waiter::wait_for_http_server;
use passivized_vault_client::client::{VaultApi, VaultApiUrl};
use passivized_vault_client::errors::VaultClientError;
use passivized_vault_client::models::{VaultAuthUserpassCreateRequest, VaultEnableAuthRequest, VaultInitRequest, VaultUnsealRequest};
use tempfile::NamedTempFile;

use example_utils::errors::ExampleError;
use example_utils::images;
use example_utils::timestamps;

#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;
use http::StatusCode;

#[cfg(not(windows))]
use passivized_test_support::cli;

// Name of a Vault plugin
const USERPASS_MOUNT_TYPE: &str = "userpass";

// Arbitrary name
const USERPASS_MOUNT_PATH: &str = "guests";

const VAULT_CONFIG_PATH: &str = "/vault/config/config.hcl";

const VAULT_CONFIG_HCL: &str = "storage \"file\" {
    path    = \"/vault/file\"
}

listener \"tcp\" {
   address = \"0.0.0.0:8200\"
   tls_disable = true
}

ui = false";

#[cfg(windows)]
#[tokio::main]
async fn main() {
    // Due to cargo's requirement that every example have a main(), we cannot simply
    // conditional compile away this entire file.

    eprintln!("Running the Vault server on Windows is not supported by Hashicorp.");
}

#[cfg(not(windows))]
#[tokio::main]
async fn main() -> ExitCode {
    cli::run(run).await
}

fn create_vault_config_file() -> Result<NamedTempFile, io::Error> {
    let mut ntf = NamedTempFile::new()?;
    write!(ntf, "{}", VAULT_CONFIG_HCL)?;

    #[cfg(not(windows))]
    set_vault_config_permissions(ntf.path())?;

    Ok(ntf)
}

#[cfg(not(windows))]
fn set_vault_config_permissions(path: &Path) -> Result<(), io::Error> {
    let f = File::open(path)?;
    f.set_permissions(PermissionsExt::from_mode(0o644))
}

async fn create_and_start_vault(docker: &DockerEngineClient) -> Result<CreateContainerResponse, ExampleError> {
    let config_hcl: NamedTempFile = create_vault_config_file()?;

    let hcl_file = config_hcl.path()
        .to_str()
        .ok_or(ExampleError::Message("Could not get config temp file path".into()))?;

    let create = CreateContainerRequest::default()
        .name(timestamps::named("auth-userpass"))
        .image(images::vault::IMAGE)
        .cmd(vec!["server"])
        .host_config(HostConfig::default()
            .auto_remove()
            .cap_add("IPC_LOCK")
            .mount(hcl_file, VAULT_CONFIG_PATH, ReadOnly)
        );

    info!("Creating container");

    let container = docker.containers().create(create)
        .await?;

    info!("Created container with id {}", &container.id);

    info!("Starting Vault");

    docker.container(&container.id).start()
        .await?;

    Ok(container)
}

async fn wait_for_vault(docker: &DockerEngineClient, what: &str, vault: &CreateContainerResponse) -> Result<VaultApiUrl, ExampleError> {
    let inspected = docker.container(&vault.id).inspect()
        .await?;

    let ip = inspected.first_ip_address()
        .ok_or(ExampleError::Message(format!("Missing IP address for {}", what)))?;

    let api_url = VaultApiUrl::new(format!("http://{}:8200", ip));

    wait_for_http_server(api_url.status(), is_success())
        .await?;

    Ok(api_url)
}

async fn run() -> Result<(), ExampleError> {
    let docker = DockerEngineClient::new()?;

    let vault = create_and_start_vault(&docker)
        .await?;

    let vault_url = wait_for_vault(&docker, "Vault", &vault)
        .await?;

    let root_token = init_vault(&vault_url)
        .await?;

    demo_userpass(&VaultApi::new(vault_url), &root_token)
        .await?;

    info!("Stopping container {}", &vault.id);

    docker.container(&vault.id).stop()
        .await?;

    Ok(())
}

async fn init_vault(url: &VaultApiUrl) -> Result<String, VaultClientError> {
    info!("Running with Vault at {}", url);

    let vault = VaultApi::new(url.clone());

    info!("Initializing Vault unseal keys");

    let unseal_init_request = VaultInitRequest {
        secret_shares: 1,
        secret_threshold: 1,
        ..VaultInitRequest::default()
    };

    let unseal_init_response = vault.initialize(&unseal_init_request).await?;
    info!("Unseal init response:\n{:?}", unseal_init_response);

    info!("Unsealing");

    for i in 0..unseal_init_request.secret_shares {
        let unseal_key = (&unseal_init_response
            .keys_base64)
            .get(i).unwrap();

        let unseal_request = VaultUnsealRequest {
            key: Some(unseal_key.into()),
            reset: false,
            migrate: false
        };

        let unseal_response = vault.unseal(&unseal_request).await?;

        let unseal_progress =
            if unseal_response.sealed { unseal_response.unseal_progress }
            else { unseal_response.unseal_threshold }
        ;

        info!(
            "Unsealed {}/{}",
            unseal_progress,
            unseal_response.unseal_threshold
        )
    }

    Ok(unseal_init_response.root_token)
}

async fn demo_userpass(vault: &VaultApi, auth_token: &str) -> Result<(), VaultClientError> {
    const USERNAME: &str = "bob";
    const PASSWORD: &str = "guess-me";

    info!("Enabling Vault auth engine");

    let enable_request = VaultEnableAuthRequest {
        type_: USERPASS_MOUNT_TYPE.into(),
        ..Default::default()
    };

    vault
        .auth()
        .enable(auth_token, USERPASS_MOUNT_PATH, &enable_request)
        .await?;

    info!("Enabled Vault auth engine");

    let userpass = vault.auth().userpass(USERPASS_MOUNT_PATH);

    userpass.create(auth_token, USERNAME, &VaultAuthUserpassCreateRequest::with_password(PASSWORD))
        .await?;

    info!("Logging in as {}", USERNAME);
    let user_auth_token = userpass.login(USERNAME, PASSWORD)
        .await?
        .unwrap()
        .auth.client_token;

    // Get user details using their own auth token. Fails because we have not configured an access policy
    info!("Getting details of {} using himself", USERNAME);
    let response = userpass.read(&user_auth_token, USERNAME)
        .await;

    if let Err(VaultClientError::FailureResponse(StatusCode::FORBIDDEN, msg)) = &response {
        info!("Expected and received an error: {}", msg);
    }
    else {
        panic!("Unexpected response: {:?}", response);
    }

    info!("Getting details of {} using root", USERNAME);
    let user_info = userpass.read(&user_auth_token, USERNAME)
        .await?;

    info!("User token type is {}", user_info.data.token_type);

    Ok(())
}