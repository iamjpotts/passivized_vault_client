//!
//! Demonstrates creating one Vault cluster, and enabling the "userpass" auth method.
//!
//! At the end of the run of this example, it stops and deletes the containers. If
//! you would like to leave them running, look for calls to stop() and comment them out.
//!
//! The containers will auto-delete themselves when stopped.

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
use passivized_vault_client::models::{VaultAuthUserpassCreateRequest, VaultEnableAuthRequest, VaultInitRequest, VaultUnsealRequest};

#[cfg(not(windows))]
use example_utils::errors::ExampleError;

// Name of a Vault plugin
#[cfg(not(windows))]
const USERPASS_MOUNT_TYPE: &str = "userpass";

// Arbitrary name
#[cfg(not(windows))]
const USERPASS_MOUNT_PATH: &str = "guests";

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
async fn run() -> Result<(), ExampleError> {
    use example_utils::container::VaultContainer;

    let vc = VaultContainer::new("auth-userpass")
        .await?;

    let root_token = init_vault(&vc.url)
        .await?;

    demo_userpass(&VaultApi::new(vc.url.clone()), &root_token)
        .await?;

    vc.teardown()
        .await?;

    Ok(())
}

#[cfg(not(windows))]
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

#[cfg(not(windows))]
async fn demo_userpass(vault: &VaultApi, auth_token: &str) -> Result<(), VaultClientError> {
    use http::StatusCode;

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
    let user_info = userpass.read(&auth_token, USERNAME)
        .await?;

    info!("User token type is {}", user_info.data.token_type);

    Ok(())
}