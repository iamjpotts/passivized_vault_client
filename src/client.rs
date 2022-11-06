use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use http::{Method, StatusCode};
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

    fn auth(&self, path: &str) -> String {
        self.at(format!("/v1/sys/auth/{}", path))
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

    fn plugins_catalog(&self) -> String {
        self.at("/v1/sys/plugins/catalog")
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

    fn userpass(&self, path: &str) -> VaultAuthUserpassApiUrl {
        VaultAuthUserpassApiUrl {
            url: self.clone(),
            path: path.to_string()
        }
    }
}

struct VaultAuthUserpassApiUrl {
    url: VaultApiUrl,
    path: String
}

impl VaultAuthUserpassApiUrl {

    fn list(&self) -> String {
        self.url.at(format!("/v1/auth/{}/users", self.path))
    }

    fn login<U: Borrow<str>>(&self, username: U) -> String {
        self.url.at(format!("/v1/auth/{}/login/{}", self.path, username.borrow()))
    }

    fn user<U: Borrow<str>>(&self, username: U) -> String {
        self.url.at(format!("/v1/auth/{}/users/{}", self.path, username.borrow()))
    }

    fn update<U: Borrow<str>>(&self, username: U) -> String {
        self.user(username) + "/password"
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

    pub fn plugins(&self) -> VaultPluginsApi {
        VaultPluginsApi::new(self.url.clone())
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

    pub fn userpass(&self, path: &str) -> VaultAuthUserpassApi {
        VaultAuthUserpassApi::new(self.url.clone(), path)
    }
}

pub struct VaultAuthUserpassApi {
    url: VaultApiUrl,
    path: String
}

impl VaultAuthUserpassApi {

    pub fn new(url: VaultApiUrl, path: &str) -> Self {
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

        let list = Method::from_str("LIST")
            .map_err(|e| VaultClientError::Other(Box::new(e)))?;

        let response = reqwest::Client::new()
            .request(list, url)
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
        if let VaultClientError::FailureResponse(fr_status, fr_message) = err {
            if *fr_status == StatusCode::BAD_REQUEST && fr_message.contains("invalid username or password") {
                return true;
            }
        }

        false
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
    fn plugins_catalog() {
        let url = VaultApiUrl::new("http://z");

        assert_eq!("http://z/v1/sys/plugins/catalog", url.plugins_catalog());
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

    #[test]
    fn userpass_login() {
        let url = VaultApiUrl::new("");

        assert_eq!("/v1/auth/x/login/mary", url.userpass("x").login("mary"));
    }

    #[test]
    fn userpass_user() {
        let url = VaultApiUrl::new("");

        assert_eq!("/v1/auth/a/b/users/john", url.userpass("a/b").user("john"));
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

#[cfg(test)]
mod test_vault_userpass_api {

    mod test_is_login_failure {
        use std::array::TryFromSliceError;
        use http::StatusCode;
        use crate::client::VaultAuthUserpassApi;
        use crate::errors::VaultClientError;

        const MATCHING_STATUS: StatusCode = StatusCode::BAD_REQUEST;
        const MATCHING_MESSAGE: &str = "invalid username or password";

        #[test]
        fn false_when_network() {
            let failed: Result<[u8; 4], TryFromSliceError> = <[u8; 4]>::try_from(Vec::new().as_slice());
            let other_err = failed.unwrap_err();
            let err = VaultClientError::Other(Box::new(other_err));

            assert!(!VaultAuthUserpassApi::is_login_failure(&err));
        }

        #[test]
        fn false_when_wrong_message() {
            let err = VaultClientError::FailureResponse(MATCHING_STATUS, "abc".into());

            assert!(!VaultAuthUserpassApi::is_login_failure(&err));
        }

        #[test]
        fn false_when_wrong_status() {
            let err = VaultClientError::FailureResponse(StatusCode::UNAUTHORIZED, MATCHING_MESSAGE.into());

            assert!(!VaultAuthUserpassApi::is_login_failure(&err));
        }

        #[test]
        fn true_when_message_match() {
            let err = VaultClientError::FailureResponse(MATCHING_STATUS, MATCHING_MESSAGE.into());

            assert!(VaultAuthUserpassApi::is_login_failure(&err));
        }
    }

}