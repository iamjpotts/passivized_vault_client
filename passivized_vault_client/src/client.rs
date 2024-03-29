use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use http::{Method, StatusCode};
use log::info;
use serde_json::Value;

use crate::errors::{VaultClientError, VaultClientErrorContent, VaultErrorsResponse};
use crate::imp::{header_value};
use crate::models::*;

pub use crate::url::VaultApiUrl;

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

/// A typed, stateless interface over the Vault HTTP api
pub struct VaultApi {
    url: VaultApiUrl
}

impl Display for VaultApi {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault api at {}", self.url)
    }
}

impl VaultApi {

    /// Create a new instance of the Vault api client.
    ///
    /// Does not connect until you call a method that acts on the api.
    pub fn new(url: VaultApiUrl) -> Self {
        Self { url }
    }

    pub fn auth(&self) -> VaultAuthApi {
        VaultAuthApi::new(self.url.clone())
    }

    pub async fn get_status(&self) -> Result<VaultSealStatus, VaultClientError> {
        let url = self.url.status();

        info!("Connecting to {}", url);

        let response = reqwest::get(url).await?
            .error_for_status()?;

        response
            .json::<VaultSealStatus>().await
            .map_err(VaultClientError::RequestFailed)
    }

    pub async fn initialize(&self, request: &VaultInitRequest) -> Result<VaultInitResponse, VaultClientError> {
        let url = self.url.init();

        info!("Connecting to {}", url);

        match request.recovery_shares {
            None => {
                info!("Initializing normally");
            }
            Some(_) => {
                info!("Initializing for recovery");
            }
        }

        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json::<VaultInitResponse>().await
                .map_err(VaultClientError::RequestFailed)
        }
    }

    pub fn mounts(&self) -> VaultMountsApi {
        VaultMountsApi::new(self.url.clone())
    }

    pub fn plugins(&self) -> VaultPluginsApi {
        VaultPluginsApi::new(self.url.clone())
    }

    pub fn policies(&self) -> VaultPoliciesApi {
        VaultPoliciesApi::new(self.url.clone())
    }

    pub fn transit(&self) -> VaultTransitApi {
        VaultTransitApi::new(self.url.clone())
    }

    pub async fn unseal(&self, request: &VaultUnsealRequest) -> Result<VaultUnsealResponse, VaultClientError> {
        let url = self.url.unseal();

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json::<VaultUnsealResponse>().await
                .map_err(VaultClientError::RequestFailed)
        }
    }
}

pub struct VaultAuthApi {
    url: VaultApiUrl
}

impl VaultAuthApi {

    fn new(url: VaultApiUrl) -> Self {
        Self {
            url
        }
    }

    pub async fn enable(&self, auth_token: &str, path: &str, request: &VaultEnableAuthRequest) -> Result<(), VaultClientError> {
        let url = self.url.auth(path);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .post(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .json(request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            Ok(())
        }
    }

    pub async fn read(&self, auth_token: &str, path: &str) -> Result<VaultAuthReadResponse, VaultClientError> {
        let url = self.url.auth(path);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .get(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

    pub fn tokens(&self) -> VaultAuthTokensApi {
        VaultAuthTokensApi::new(self.url.clone(), "token")
    }

    pub fn userpass(&self, path: &str) -> VaultAuthUserpassApi {
        VaultAuthUserpassApi::new(self.url.clone(), path)
    }
}

pub struct VaultAuthTokensApi {
    url: VaultApiUrl,
    path: String
}

impl VaultAuthTokensApi {

    fn new(url: VaultApiUrl, path: &str) -> Self {
        Self {
            url,
            path: path.into()
        }
    }

    pub async fn create(&self, auth_token: &str, request: &VaultAuthTokenCreateRequest) -> Result<VaultAuthTokenCreateResponse, VaultClientError> {
        let url = self.url.token(&self.path).create();

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .post(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .json(request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

    pub async fn lookup_self(&self, auth_token: &str) -> Result<VaultAuthTokenLookupSelfResponse, VaultClientError> {
        let url = self.url.token(&self.path).lookup_self();

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .get(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

}

pub struct VaultAuthUserpassApi {
    url: VaultApiUrl,
    path: String
}

impl VaultAuthUserpassApi {

    fn new(url: VaultApiUrl, path: &str) -> Self {
        Self {
            url,
            path: path.into()
        }
    }

    pub async fn create<U>(&self, auth_token: &str, username: U, request: &VaultAuthUserpassCreateRequest) -> Result<(), VaultClientError>
    where
        U: Borrow<str>
    {
        let url = self.url.userpass(&self.path).user(username);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .post(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .json(request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            Ok(())
        }
    }

    pub async fn delete<U>(&self, auth_token: &str, username: U) -> Result<(), VaultClientError>
    where
        U: Borrow<str>
    {
        let url = self.url.userpass(&self.path).user(username);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .delete(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            Ok(())
        }
    }

    pub async fn list(&self, auth_token: &str) -> Result<VaultAuthUserpassListResponse, VaultClientError> {
        let url = self.url.userpass(&self.path).list();

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .request(http_list()?, url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            let failure = read_failure_response_into_error(response).await;

            if let VaultClientError::FailureResponse(StatusCode::NOT_FOUND, VaultClientErrorContent::Errors(messages)) = &failure {
                if messages.is_empty() {
                    return Ok(VaultAuthUserpassListResponse::empty());
                }
            }

            Err(failure)
        }
        else {
            response
                .json()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

    /// Validate a username/password pair against a userpass mount. If successful, the response
    /// will include a client token to use as the auth token for further requests into Vault.
    /// If the username or password is invalid, a successful but empty response is returned.
    pub async fn login<U, P>(&self, username: U, password: P) -> Result<Option<VaultAuthUserpassLoginResponse>, VaultClientError>
    where
        U: Borrow<str>,
        P: Borrow<str>
    {
        let u = username.borrow();

        if u.is_empty() {
            return Err(VaultClientError::InvalidInput("username".into(), "Missing".into()));
        }

        let request = VaultAuthUserpassLoginRequest {
            password: password.borrow().to_string()
        };

        let url = self.url.userpass(&self.path).login(u);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            let parsed_error = read_failure_response_into_error(response).await;

            if Self::is_login_failure(&parsed_error) {
                Ok(None)
            }
            else {
                Err(parsed_error)
            }
        }
        else {
            response
                .json()
                .await
                .map(Some)
                .map_err(VaultClientError::RequestFailed)
        }
    }

    fn is_login_failure(err: &VaultClientError) -> bool {
        if let VaultClientError::FailureResponse(fr_status, VaultClientErrorContent::Errors(messages)) = err {
            match *fr_status {
                // Vault version 13 returns 500 Internal Server Error
                StatusCode::BAD_REQUEST | StatusCode::INTERNAL_SERVER_ERROR =>
                    messages
                        .iter()
                        .any(|e| e.contains("invalid username or password")),
                _ => false
            }
        }
        else {
            false
        }
    }

    pub async fn read<U>(&self, auth_token: &str, username: U) -> Result<VaultAuthUserpassReadResponse, VaultClientError>
    where
        U: Borrow<str>
    {
        let url = self.url.userpass(&self.path).user(username);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .get(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

    // See also https://github.com/hashicorp/vault/issues/6590
    pub async fn update_password<U, P>(&self, auth_token: &str, username: U, password: P) -> Result<(), VaultClientError>
    where
        U: Borrow<str>,
        P: Borrow<str>
    {
        let request = VaultAuthUserpassUpdateRequest {
            password: password.borrow().to_string()
        };

        let url = self.url.userpass(&self.path).update(username);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .post(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .json(&request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            // No response body on success responses
            Ok(())
        }
    }
}

pub struct VaultMountsApi {
    url: VaultApiUrl
}

// https://www.vaultproject.io/api-docs/system/mounts
impl VaultMountsApi {

    pub fn new(url: VaultApiUrl) -> Self {
        Self { url }
    }

    pub async fn enable_secrets_engine(&self, auth_token: &str, path: &str, request: &VaultEnableSecretsEngineRequest) -> Result<(), VaultClientError> {
        let url = self.url.mount(path);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .post(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .json(request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            Ok(())
        }
    }

    pub async fn get(&self, auth_token: &str, path: &str) -> Result<VaultMountResponse, VaultClientError> {
        let url = self.url.mount(path);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .get(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        // Because the API returns 400 Bad Request instead of 404 Not Found when nothing is at the mount point,
        // we cannot reliably differentiate between a missing mount, and some other failure.

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json::<VaultMountResponse>()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

    pub async fn list(&self, auth_token: &str) -> Result<VaultMountsResponse, VaultClientError> {
        let url = self.url.mounts();

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .get(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json::<VaultMountsResponse>()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }
}

pub struct VaultPluginsApi {
    url: VaultApiUrl
}

impl VaultPluginsApi {

    pub(super) fn new(url: VaultApiUrl) -> Self {
        Self {
            url
        }
    }

    pub fn catalog(&self) -> VaultCatalogApi {
        VaultCatalogApi {
            url: self.url.clone()
        }
    }
}

pub struct VaultPoliciesApi {
    url: VaultApiUrl
}

impl VaultPoliciesApi {

    pub(super) fn new(url: VaultApiUrl) -> Self {
        Self {
            url
        }
    }

    pub fn acl(&self) -> VaultPoliciesAclApi {
        VaultPoliciesAclApi {
            url: self.url.clone()
        }
    }
}

pub struct VaultPoliciesAclApi {
    url: VaultApiUrl
}

impl VaultPoliciesAclApi {

    /// https://developer.hashicorp.com/vault/api-docs/v1.11.x/system/policies#list-acl-policies
    pub async fn list(&self, auth_token: &str) -> Result<VaultPoliciesAclListResponse, VaultClientError> {
        let url = self.url.policies().acl().list();

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .request(http_list()?, url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

    /// Read a policy.
    /// https://developer.hashicorp.com/vault/api-docs/v1.11.x/system/policies#read-acl-policy
    pub async fn get(&self, auth_token: &str, name: &str) -> Result<VaultPoliciesAclReadResponse, VaultClientError> {
        let url = self.url.policies().acl().item(name);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .get(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

    /// Create or update a policy.
    /// https://developer.hashicorp.com/vault/api-docs/v1.11.x/system/policies#create-update-acl-policy
    pub async fn put<P: Into<String>>(&self, auth_token: &str, name: &str, policy: P) -> Result<(), VaultClientError> {
        let url = self.url.policies().acl().item(name);

        info!("Connecting to {}", url);

        let request = VaultPoliciesAclUpsertRequest {
            policy: policy.into()
        };

        let response = reqwest::Client::new()
            .post(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .json(&request)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            Ok(())
        }
    }
}

pub struct VaultCatalogApi {
    url: VaultApiUrl
}

impl VaultCatalogApi {

    pub async fn get(&self, auth_token: &str) -> Result<VaultPluginCatalog, VaultClientError> {
        let url = self.url.plugins_catalog();

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .get(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json()
                .await
                .map_err(VaultClientError::RequestFailed)
        }
    }

}

pub struct VaultTransitApi {
    url: VaultApiUrl
}

// https://www.vaultproject.io/api-docs/secret/transit
impl VaultTransitApi {

    pub fn new(url: VaultApiUrl) -> Self {
        Self { url }
    }

    // The documentation says the values cannot be changed after creation, and the REST
    // api returns a success code when there's already a key, so we will assume the api
    // is idempotent.
    pub async fn create(&self, auth_token: &str, mount_path: &str, name: &str) -> Result<(), VaultClientError> {
        let url = self.url.transit(mount_path, name);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .post(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            Ok(())
        }
    }

    pub async fn read(&self, auth_token: &str, mount_path: &str, key_name: &str) -> Result<Option<VaultTransitKeyReadResponse>, VaultClientError> {
        let url = self.url.transit(mount_path, key_name);

        info!("Connecting to {}", url);

        let response = reqwest::Client::new()
            .get(url)
            .header(VAULT_TOKEN_HEADER, auth_token)
            .send()
            .await?;

        let status = response.status();

        if status == StatusCode::NOT_FOUND {
            return Ok(None)
        }

        if status.is_server_error() || status.is_client_error() {
            Err(read_failure_response_into_error(response).await)
        }
        else {
            response
                .json::<VaultTransitKeyReadResponse>()
                .await
                .map_err(VaultClientError::RequestFailed)
                .map(Some)
        }
    }
}

async fn read_failure_response_into_error(response: reqwest::Response) -> VaultClientError {
    let status = response.status();
    let content_type = header_value(&response, "Content-Type");

    if Some("application/json".to_string()) == content_type {
        let parsed: Result<Value, reqwest::Error> = response.json().await;

        match parsed {
            Ok(value) => {
                let errors: Result<VaultErrorsResponse, serde_json::Error> = serde_json::from_value(value.clone());

                let vcec = match errors {
                    Ok(parsed_errors) => {
                        VaultClientErrorContent::Errors(parsed_errors.errors)
                    }
                    Err(_) => {
                        VaultClientErrorContent::Json(value)
                    }
                };

                VaultClientError::FailureResponse(status, vcec)
            }
            Err(e) => {
                VaultClientError::RequestFailed(e)
            }
        }
    }
    else {
        match response.text().await {
            Ok(text) => {
                VaultClientError::FailureResponse(
                    status,
                    VaultClientErrorContent::Text(text)
                )
            }
            Err(e) => {
                VaultClientError::RequestFailed(e)
            }
        }
    }
}

fn http_list() -> Result<Method, VaultClientError> {
    Method::from_str("LIST")
        .map_err(|e| VaultClientError::Other(Box::new(e)))
}

#[cfg(test)]
mod test_vault_api {
    use super::{VaultApi, VaultApiUrl};

    #[test]
    fn display() {
        let url = VaultApiUrl::new("https://localhost:8200");
        let api = VaultApi::new(url);

        assert_eq!("Vault api at https://localhost:8200", format!("{}", api));
    }
}

#[cfg(test)]
mod test_vault_userpass_api {

    mod test_is_login_failure {
        use std::array::TryFromSliceError;
        use http::StatusCode;
        use crate::client::VaultAuthUserpassApi;
        use crate::errors::{VaultClientError, VaultClientErrorContent};

        const MATCHING_STATUS: StatusCode = StatusCode::BAD_REQUEST;
        const MATCHING_MESSAGE: &str = "invalid username or password";

        fn matching() -> VaultClientErrorContent {
            VaultClientErrorContent::Errors(vec![MATCHING_MESSAGE.to_string()])
        }

        #[test]
        fn false_when_network() {
            let failed: Result<[u8; 4], TryFromSliceError> = <[u8; 4]>::try_from(Vec::new().as_slice());
            let other_err = failed.unwrap_err();
            let err = VaultClientError::Other(Box::new(other_err));

            assert!(!VaultAuthUserpassApi::is_login_failure(&err));
        }

        #[test]
        fn false_when_wrong_message() {
            let err = VaultClientError::FailureResponse(
                MATCHING_STATUS,
                VaultClientErrorContent::Text("abc".into())
            );

            assert!(!VaultAuthUserpassApi::is_login_failure(&err));
        }

        #[test]
        fn false_when_wrong_status() {
            let err = VaultClientError::FailureResponse(
                StatusCode::UNAUTHORIZED,
                matching()
            );

            assert!(!VaultAuthUserpassApi::is_login_failure(&err));
        }

        #[test]
        fn true_when_message_match() {
            let err = VaultClientError::FailureResponse(
                MATCHING_STATUS,
                matching()
            );

            assert!(VaultAuthUserpassApi::is_login_failure(&err));
        }

        #[test]
        fn true_when_match_for_vault_version_13() {
            let err = VaultClientError::FailureResponse(
                StatusCode::INTERNAL_SERVER_ERROR,
                VaultClientErrorContent::Errors(
                    vec![
                        "invalid username or password".into()
                    ]
                )
            );

            assert!(VaultAuthUserpassApi::is_login_failure(&err));
        }
    }

}