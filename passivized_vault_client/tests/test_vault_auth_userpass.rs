#![cfg(not(windows))]
#![cfg(not(target_os = "macos"))]

#[path = "../examples/example_utils/lib.rs"]
mod example_utils;

#[path = "test_utils/lib.rs"]
mod test_utils;

use std::path::{Path, PathBuf};
use http::StatusCode;
use log::*;
use passivized_vault_client::client::{VaultApi, VaultApiUrl};
use passivized_vault_client::errors::VaultClientError;
use passivized_vault_client::models::{VaultInitRequest, VaultUnsealRequest, VaultUnsealProgress, VaultEnableAuthRequest, VaultAuthUserpassCreateRequest};
use passivized_vault_client_versions::test_supported_images;

fn this_file() -> PathBuf {
    let relative = Path::new(file!());

    if relative.is_file() {
        relative.to_path_buf()
    }
    else {
        let current = std::env::current_dir()
            .unwrap();

        let result = current
            .parent()
            .unwrap()
            .join(relative);

        if result.is_file() {
            // rust reported wrong file path, but we fixed it by stripping leaf off of cwd
            result
        }
        else {
            relative.to_path_buf()
        }
    }
}

fn resources_path() -> PathBuf {
    this_file()
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .join("resources")
}

async fn read_change_own_password_hcl() -> String {
    let file_name = resources_path()
        .join("change_own_password.hcl");

    tokio::fs::read_to_string(file_name)
        .await
        .unwrap()
}

#[test_supported_images]
fn test_create_and_read_users(image_name: &str, image_tag: &str) {
    test_utils::run_async(run_test(image_name, image_tag))
}

async fn run_test(image_name: &str, image_tag: &str) {
    use example_utils::container::VaultContainer;

    const FN: &str = "test_create_and_read_users";

    passivized_test_support::logging::enable_idempotent();

    let vc = VaultContainer::with_image(image_name, image_tag, FN)
        .await
        .unwrap();

    let root_token = init_and_unseal(vc.url.clone())
        .await
        .unwrap();

    create_and_read_users(vc.url.clone(), &root_token)
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

    let auth_detail = vault.auth().read(root_token, MOUNT_PATH)
        .await?;

    assert_eq!("userpass", auth_detail.type_);

    info!("Userpass {} accessor: {}", MOUNT_PATH, auth_detail.accessor);

    const USERNAME1: &str = "john";
    const PASSWORD1: &str = "crack-me";
    const PASSWORD1B: &str = "crack-me-again";

    const USERNAME2: &str = "mary";
    const PASSWORD2: &str = "super-secure";
    const PASSWORD2B: &str = "nsa-was-here";

    const PASSWORD_POLICY_NAME: &str = "change-own-password";
    const PASSWORD_POLICY_ACCESSOR_PLACEHOLDER: &str = "${userpass_accessor}";

    const USERNAME3: &str = "hank";
    const PASSWORD3: &str = "apples";
    const PASSWORD3B: &str = "oranges";

    // Arbitrary value used to test setting and receiving properties of the user
    const TOKEN_MAX_TTL: u64 = 12345678;

    let userpass = vault.auth().userpass(MOUNT_PATH);

    // When there are zero users, validate that we get an empty list back rather than an error.
    let empty = userpass.list(root_token)
        .await
        .unwrap();

    assert_eq!(0, empty.data.keys.len());

    let mut user1_request = VaultAuthUserpassCreateRequest::with_password(PASSWORD1);
    user1_request.token_max_ttl = Some(TOKEN_MAX_TTL);

    userpass.create(root_token, USERNAME1, &user1_request)
        .await?;

    let user1_detail = userpass.read(root_token, USERNAME1)
        .await?;

    // Get the value we set and validate its the same.
    assert_eq!(TOKEN_MAX_TTL, user1_detail.data.token_max_ttl);

    // Try an empty username
    info!("Validating that an error is returned for an empty username");
    let failure = userpass.login("", PASSWORD1)
        .await
        .unwrap_err();

    if let VaultClientError::InvalidInput(field, reason) = failure {
        assert_eq!("username", field);
        assert_eq!("Missing", reason);
    }
    else {
        panic!("Unexpected failure: {:?}", failure);
    }

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

    let mut policy = read_change_own_password_hcl()
        .await;

    policy = policy
        .replace(PASSWORD_POLICY_ACCESSOR_PLACEHOLDER, &auth_detail.accessor);

    // Add a policy allowing users to change their own passwords but not each other's.
    vault.policies().acl().put(root_token, PASSWORD_POLICY_NAME, &policy)
        .await
        .unwrap();

    let policies = vault.policies().acl().list(root_token)
        .await
        .unwrap()
        .data
        .keys;

    info!("Have {} policies:", policies.len());

    for p in policies {
        info!("  {}", p);
    }

    let applied_policy = vault.policies().acl().get(root_token, PASSWORD_POLICY_NAME)
        .await?
        .data
        .policy;

    info!("Policy content:\n{}", applied_policy);
    assert_eq!(policy, applied_policy);

    info!("Logging in as {}", USERNAME2);
    let user2_token = userpass.login(USERNAME2, PASSWORD2)
        .await
        .unwrap()
        .unwrap()
        .auth
        .client_token;

    info!("Changing own password for {} should still fail (policy not attached to user)", USERNAME2);
    let update_failure = userpass.update_password(&user2_token, USERNAME2, PASSWORD2B)
        .await
        .unwrap_err();

    if let VaultClientError::FailureResponse(status, _) = update_failure {
        assert_eq!(StatusCode::FORBIDDEN, status);
    }
    else {
        panic!("Unexpected failure: {:?}", update_failure);
    }

    // Add a third user, with a policy attached
    info!("Adding user {}", USERNAME3);

    let user3_request = VaultAuthUserpassCreateRequest {
        password: PASSWORD3.into(),
        token_policies: Some(vec![PASSWORD_POLICY_NAME.to_string()]),
        ..Default::default()
    };

    userpass.create(root_token, USERNAME3, &user3_request)
        .await?;

    info!("Logging in as {}", USERNAME3);
    let user3_token = userpass.login(USERNAME3, PASSWORD3)
        .await
        .unwrap()
        .unwrap()
        .auth
        .client_token;

    let user3_detail = userpass.read(root_token, USERNAME3)
        .await
        .unwrap();

    info!("user3: {:?}", user3_detail.data);

    info!("Changing own password for {}", USERNAME3);
    userpass.update_password(&user3_token, USERNAME3, PASSWORD3B)
        .await?;

    info!("Logging in as {} with new password", USERNAME3);
    assert_ne!(
        None,
        userpass.login(USERNAME3, PASSWORD3B)
            .await
            .unwrap()
    );

    info!("User {} changing user {}'s password should fail", USERNAME3, USERNAME2);
    let update_failure = userpass.update_password(&user3_token, USERNAME2, PASSWORD2B)
        .await
        .unwrap_err();

    if let VaultClientError::FailureResponse(status, _) = update_failure {
        assert_eq!(StatusCode::FORBIDDEN, status);
    }
    else {
        panic!("Unexpected failure: {:?}", update_failure);
    }

    Ok(())
}