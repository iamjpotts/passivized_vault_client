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

use std::process::ExitCode;

#[cfg(not(windows))]
use log::*;

#[cfg(not(windows))]
use passivized_vault_client::client::{VaultApi, VaultApiUrl};

#[cfg(not(windows))]
use passivized_vault_client::errors::VaultClientError;

#[cfg(not(windows))]
use passivized_vault_client::models::{VaultEnableSecretsEngineRequest, VaultInitRequest, VaultUnsealRequest};

#[cfg(not(windows))]
use example_utils::container::VaultContainer;

#[cfg(not(windows))]
use example_utils::errors::ExampleError;

#[cfg(not(windows))]
use example_utils::other::{base64_decode, base64_encode};

#[cfg(not(windows))]
const TRANSIT_MOUNT_TYPE: &str = "transit";

#[cfg(not(windows))]
const TRANSIT_ENGINE_MOUNT_PATH: &str = "transit";

#[cfg(not(windows))]
const TRANSIT_SEAL_KEY: &str = "unseal";

#[cfg(not(windows))]
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

#[cfg(not(windows))]
struct RecoveryKeyConfig {
    public_key_file_names: Vec<String>,
    recovery_key_folder: String,
}

#[cfg(not(windows))]
fn get_recovery_key_config() -> Result<Option<RecoveryKeyConfig>, String> {
    use passivized_test_support::env;

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
async fn main() -> Result<(), ExitCode> {
    // Due to cargo's requirement that every example have a main(), we cannot simply
    // conditional compile away this entire file.

    eprintln!("Running the Vault server on Windows is not supported by Hashicorp.");
    Err(ExitCode::FAILURE)
}

#[cfg(not(windows))]
#[tokio::main]
async fn main() -> ExitCode {
    passivized_test_support::cli::run(run).await
}

#[cfg(not(windows))]
async fn create_and_start_vault1() -> Result<VaultContainer, ExampleError> {
    use passivized_test_support::timestamps;

    VaultContainer::new(&timestamps::named("auto-unseal-vault1"))
        .await
}

#[cfg(not(windows))]
async fn create_and_start_vault2(vault1_url: &VaultApiUrl, vault1_root_token: &str) -> Result<VaultContainer, ExampleError> {
    use passivized_test_support::timestamps;

    let hcl = build_vault2_config_hcl(&vault1_url);

    VaultContainer::with_config(
        &timestamps::named("auto-unseal-vault2"),
        &hcl,
        Some(vault1_root_token.to_string())
    )
        .await
}

#[cfg(not(windows))]
async fn run() -> Result<(), ExampleError> {
    let recovery_key_config = get_recovery_key_config()
        .map_err(ExampleError::Message)?;

    let vault1 = create_and_start_vault1()
        .await?;

    let vault1_root_token = init_vault1(&vault1.url)
        .await?;

    let vault2 = create_and_start_vault2(&vault1.url, &vault1_root_token)
        .await?;

    init_vault2(&vault2.url, &recovery_key_config)
        .await?;

    vault2.teardown()
        .await?;

    vault1.teardown()
        .await?;

    Ok(())
}

#[cfg(not(windows))]
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

#[cfg(not(windows))]
async fn init_vault2(url: &VaultApiUrl, recovery_key_config: &Option<RecoveryKeyConfig>) -> Result<String, ExampleError> {
    use std::cmp::min;
    use std::fs;
    use std::iter::zip;
    use std::path::Path;

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

                public_keys.push(base64_encode(content));
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

                let decoded = base64_decode(encoded)
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
