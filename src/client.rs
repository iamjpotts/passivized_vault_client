use std::borrow::Borrow;
use std::fmt::{Display, Formatter};

use http::StatusCode;
use log::info;

use crate::errors::VaultClientError;
use crate::models::*;

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

#[derive(Clone)]
pub struct VaultApiUrl {
    base: String
}

impl Display for VaultApiUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Because the type name of this struct contains Url, return a plain url.
        write!(f, "{}", self.base)
    }
}

impl VaultApiUrl {

    /// Create a URL reference to a Vault API, which can be used
    /// to create a Vault API client.
    ///
    /// # Example
    ///
    /// ```rust
    /// use passivized_vault_client::client::VaultApiUrl;
    ///
    /// let api_url = VaultApiUrl::new("http://server:8200");
    /// ```
    pub fn new<A>(base: A) -> Self where A: Into<String> {
        VaultApiUrl {
            base: base.into()
        }
    }

    fn at<A: Borrow<str>>(&self, path: A) -> String {
        self.base.clone() + path.borrow()
    }

    // https://www.vaultproject.io/api-docs/system/init
    fn init(&self) -> String {
        self.at("/v1/sys/init")
    }

    fn mount(&self, path: &str) -> String {
        format!("{}/{}", self.mounts(), urlencoding::encode(path))
    }

    fn mounts(&self) -> String {
        self.at("/v1/sys/mounts")
    }

    pub fn status(&self) -> String {
        self.at("/v1/sys/seal-status")
    }

    // https://www.vaultproject.io/api-docs/secret/transit
    fn transit(&self, mount_path: &str, name: &str) -> String {
        self.at(format!("/v1/{}/keys/{}", mount_path, urlencoding::encode(name)))
    }

    // https://www.vaultproject.io/api-docs/system/unseal
    fn unseal(&self) -> String {
        self.at("/v1/sys/unseal")
    }
}

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
            let failure_body = response
                .text()
                .await?;

            Err(VaultClientError::FailureResponse(status, failure_body))
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

    match response.text().await {
        Ok(text) => {
            VaultClientError::FailureResponse(status, text)
        }
        Err(e) => {
            VaultClientError::RequestFailed(e)
        }
    }
}

#[cfg(test)]
mod test_vault_api_url {
    use super::VaultApiUrl;

    #[test]
    fn display() {
        let url = VaultApiUrl::new("https://testuri.org");

        assert_eq!("https://testuri.org", format!("{}", url));
    }

    #[test]
    fn mounts() {
        let url = VaultApiUrl::new("http://foo");

        assert_eq!("http://foo/v1/sys/seal-status", url.status());
    }

    #[test]
    fn status() {
        let url = VaultApiUrl::new("https://bar:123");

        assert_eq!("https://bar:123/v1/sys/mounts", url.mounts());
    }

    #[test]
    fn transit() {
        let url = VaultApiUrl::new("");

        assert_eq!("/v1/a/keys/b", url.transit("a", "b"));
    }
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