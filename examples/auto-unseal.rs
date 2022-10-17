//!
//! Demonstrates creating two Vault clusters, where the second cluster is configured to
//! automatically unseal itself using transit keys it stores in the first cluster.
//!
//! By default, a single clear text recovery key is generated.
//!
//! At the end of the run of this example, it stops and deletes the containers. If
//! you would like to leave them running, look for calls to stop() and comment them out.
//!
//! The containers will auto-delete themselves when stopped.
//!
//! To demonstrate encrypted recovery keys, set at least two environment variables:
//!
//! * RECOVERY_PUBLIC_KEY_FILE_0
//! * RECOVERY_KEY_FOLDER
//!
//! The first is a binary (not text!) PGP public key. The second is the output folder
//! where encrypted recovery keys will be written. You can generate multiple encrypted
//! recovery keys by creating more public keys and designating them with additional
//! environment variables: RECOVERY_PUBLIC_KEY_FILE_1, RECOVERY_PUBLIC_KEY_FILE_2, etc.
//!

#[path = "example_utils/lib.rs"]
mod example_utils;

use std::cmp::min;
use std::{fs, io};
use std::fs::File;
use std::iter::zip;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use log::*;
use passivized_docker_engine_client::DockerEngineClient;
use passivized_docker_engine_client::model::MountMode::ReadOnly;
use passivized_docker_engine_client::requests::{CreateContainerRequest, HostConfig};
use passivized_docker_engine_client::responses::CreateContainerResponse;
use passivized_test_support::env;
use passivized_vault_client::client::{VaultApi, VaultApiUrl};
use passivized_vault_client::errors::VaultClientError;
use passivized_vault_client::models::{VaultEnableSecretsEngineRequest, VaultInitRequest, VaultUnsealRequest};
use tempfile::NamedTempFile;

use example_utils::errors::ExampleError;
use example_utils::timestamps;
use example_utils::retrying::wait_for_http_server;

#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;

#[cfg(not(windows))]
use passivized_test_support::cli;

const TRANSIT_MOUNT_TYPE: &str = "transit";
const TRANSIT_ENGINE_MOUNT_PATH: &str = "transit";
const TRANSIT_SEAL_KEY: &str = "unseal";

const VAULT_CONFIG_PATH: &str = "/vault/config/config.hcl";

const VAULT_CONFIG_HCL: &str = "storage \"file\" {
    path    = \"/vault/file\"
}

listener \"tcp\" {
   address = \"0.0.0.0:8200\"
   tls_disable = true
}

ui = false";

fn build_vault2_config_hcl(vault1_url: &VaultApiUrl) -> String {
    format!("storage \"file\" {{
    path    = \"/vault/file\"
}}

listener \"tcp\" {{
   address = \"0.0.0.0:8200\"
   tls_disable = true
}}

seal \"transit\" {{
    address            = \"{}\"
    disable_renewal    = \"false\"
    # token is read from VAULT_TOKEN environment variable

    // Key configuration
    key_name           = \"{}\"
    mount_path         = \"{}/\"
}}

ui = false",
    vault1_url,
    TRANSIT_SEAL_KEY,
    TRANSIT_ENGINE_MOUNT_PATH)
}

struct RecoveryKeyConfig {
    public_key_file_names: Vec<String>,
    recovery_key_folder: String,
}

fn get_recovery_key_config() -> Result<Option<RecoveryKeyConfig>, String> {
    let mut public_key_file_names: Vec<String> = Vec::new();

    for result in (0..).map(|i| env::var(format!("RECOVERY_PUBLIC_KEY_FILE_{}", i))) {
        if let Some(value) = result? {
            public_key_file_names.push(value);
        }
        else {
            break;
        }
    }

    if public_key_file_names.len() > 0 {
        let recovery_key_folder = env::require_var("RECOVERY_KEY_FOLDER")?;

        Ok(Some(RecoveryKeyConfig {
            public_key_file_names,
            recovery_key_folder
        }))
    }
    else {
        Ok(None)
    }
}

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

fn create_vault1_config_file() -> Result<NamedTempFile, io::Error> {
    let mut ntf = NamedTempFile::new()?;
    write!(ntf, "{}", VAULT_CONFIG_HCL)?;

    #[cfg(not(windows))]
    set_vault_config_permissions(ntf.path())?;

    Ok(ntf)
}

fn create_vault2_config_file(vault1_url: &VaultApiUrl) -> Result<NamedTempFile, io::Error> {
    let vault2_config = build_vault2_config_hcl(&vault1_url);

    let mut ntf = NamedTempFile::new()?;
    write!(ntf, "{}", vault2_config)?;

    #[cfg(not(windows))]
    set_vault_config_permissions(ntf.path())?;

    Ok(ntf)
}

#[cfg(not(windows))]
fn set_vault_config_permissions(path: &Path) -> Result<(), io::Error> {
    let f = File::open(path)?;
    f.set_permissions(PermissionsExt::from_mode(0o644))
}

async fn create_and_start_vault1(docker: &DockerEngineClient) -> Result<CreateContainerResponse, ExampleError> {
    let config_hcl: NamedTempFile = create_vault1_config_file()?;

    let hcl_file = config_hcl.path()
        .to_str()
        .ok_or(ExampleError::Message("Could not get config temp file path".into()))?;

    info!("HCL config file: {}", hcl_file);

    let create = CreateContainerRequest::default()
        .name(timestamps::named("auto-unseal-vault1"))
        .image("vault:1.11.0")
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
    for w in &container.warnings {
        warn!("Container warning: {}", w)
    }

    info!("Starting Vault 1");

    docker.container(&container.id).start()
        .await?;

    Ok(container)
}

async fn create_and_start_vault2(docker: &DockerEngineClient, vault1_url: &VaultApiUrl, vault1_root_token: &str) -> Result<CreateContainerResponse, ExampleError> {
    let config_hcl: NamedTempFile = create_vault2_config_file(vault1_url)?;

    let hcl_file = config_hcl.path()
        .to_str()
        .ok_or(ExampleError::Message("Could not get config temp file path".into()))?;

    info!("HCL config file 2: {}", hcl_file);

    let create = CreateContainerRequest::default()
        .name(timestamps::named("auto-unseal-vault2"))
        .image("vault:1.11.0")
        .cmd(vec!["server"])
        .env(format!("VAULT_TOKEN={}", vault1_root_token))
        .host_config(HostConfig::default()
            .auto_remove()
            .cap_add("IPC_LOCK")
            .mount(hcl_file, VAULT_CONFIG_PATH, ReadOnly)
        );

    info!("Creating container");

    let container = docker.containers().create(create)
        .await?;

    info!("Created container with id {}", container.id);
    for w in &container.warnings {
        warn!("Container warning: {}", w)
    }

    info!("Starting Vault 2");

    docker.container(&container.id).start()
        .await?;

    Ok(container)
}

async fn wait_for_vault(docker: &DockerEngineClient, what: &str, vault: &CreateContainerResponse) -> Result<VaultApiUrl, ExampleError> {
    let inspected = docker.container(&vault.id).inspect()
        .await?;

    let ip = example_utils::docker::extract_ip_address(&inspected)?;

    let wait = Duration::from_secs(2);

    info!("Waiting {} seconds for {} to start", wait.as_secs(), what);
    tokio::time::sleep(wait)
        .await;

    let api_url = VaultApiUrl::new(format!("http://{}:8200", ip));

    wait_for_http_server(&api_url.status())
        .await?;

    Ok(api_url)
}

async fn run() -> Result<(), ExampleError> {
    let recovery_key_config = get_recovery_key_config()
        .map_err(ExampleError::Message)?;

    let docker = DockerEngineClient::new()?;

    let vault1 = create_and_start_vault1(&docker)
        .await?;

    let vault1_url = wait_for_vault(&docker, "Vault 1", &vault1)
        .await?;

    let vault1_root_token = init_vault1(&vault1_url)
        .await?;

    let vault2 = create_and_start_vault2(&docker, &vault1_url, &vault1_root_token)
        .await?;

    let vault2_url = wait_for_vault(&docker, "Vault 2", &vault2)
        .await?;

    init_vault2(&vault2_url, &recovery_key_config)
        .await?;

    info!("Stopping container {} then {}", &vault2.id, &vault1.id);

    docker.container(&vault2.id).stop()
        .await?;

    docker.container(&vault1.id).stop()
        .await?;

    Ok(())
}

async fn init_vault1(url: &VaultApiUrl) -> Result<String, VaultClientError> {
    info!("Running with Vault 1 at {}", url);

    let vault = VaultApi::new(url.clone());

    info!("Initializing Vault 1 unseal keys");

    let unseal_init_request = VaultInitRequest {
        secret_shares: 5,
        secret_threshold: 3,
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

    info!("Enabling Vault 1 transit secrets engine");

    let enable_request = VaultEnableSecretsEngineRequest {
        type_: TRANSIT_MOUNT_TYPE.into(),
        ..VaultEnableSecretsEngineRequest::default()
    };

    vault
        .mounts()
        .enable_secrets_engine(&unseal_init_response.root_token, TRANSIT_ENGINE_MOUNT_PATH, &enable_request)
        .await?;

    info!("Enabled Vault 1 transit secrets engine");

    Ok(unseal_init_response.root_token)
}

async fn init_vault2(url: &VaultApiUrl, recovery_key_config: &Option<RecoveryKeyConfig>) -> Result<String, ExampleError> {
    let vault = VaultApi::new(url.clone());

    let request = match recovery_key_config {
        None => {
            VaultInitRequest {
                recovery_shares: Some(1),
                recovery_threshold: Some(1),
                ..VaultInitRequest::default()
            }
        }
        Some(rkc) => {
            let mut public_keys: Vec<String> = Vec::with_capacity(rkc.public_key_file_names.len());

            for public_key_file in &rkc.public_key_file_names {
                info!("Reading {}", public_key_file);

                let content = fs::read(public_key_file)?;

                public_keys.push(base64::encode(content));
            }

            VaultInitRequest {
                recovery_shares: Some(rkc.public_key_file_names.len()),
                recovery_threshold: Some(min(2, public_keys.len())),
                recovery_pgp_keys: Some(public_keys),
                ..VaultInitRequest::default()
            }
        }
    };

    info!("Initializing Vault 2 with recovery keys");

    let response = vault.initialize(&request)
        .await?;

    match recovery_key_config {
        None => {
            info!("Throwing away recovery keys because they are not used by this example app.");
        }
        Some(rkc) => {
            let encrypted_then_encoded = match response.recovery_keys_base64 {
                None => {
                    return Err(ExampleError::Message("Expected to receive base64-encoded encrypted recovery keys, but found none".into()))
                }
                Some(value) => {
                    value
                }
            };

            info!("Saving encrypted recovery keys");

            for (encoded, public_key_file_name) in zip(encrypted_then_encoded.iter(), rkc.public_key_file_names.clone().iter()) {
                let output_file_name = format!(
                    "{}-encrypted-recovery-key.bin",
                    Path::new(public_key_file_name)
                        .file_stem()
                        .unwrap()
                        .to_str()
                        .unwrap()
                );

                let output_file = Path::new(&rkc.recovery_key_folder)
                    .join(output_file_name);

                let decoded = base64::decode(encoded)
                    .map_err(|e| ExampleError::Message(format!("Failed to decode recovery key: {:?}", e)))?;

                info!("Writing {}", output_file.to_str().unwrap());

                fs::write(output_file, decoded)?;
            }
        }
    }

    info!("Getting Vault 2 status");

    let status = vault.get_status()
        .await?;

    assert!(status.initialized);
    assert!(!status.sealed);

    info!("Vault 2 is initialized and unsealed.");

    Ok(response.root_token)
}
