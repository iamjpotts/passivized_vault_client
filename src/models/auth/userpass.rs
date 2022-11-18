use std::borrow::Borrow;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

/// See https://developer.hashicorp.com/vault/api-docs/v1.11.x/auth/userpass
#[derive(Clone, Debug, Default, Serialize)]
pub struct VaultAuthUserpassCreateRequest {

    pub password: String,

    // API also accepts strings, but that is not modeled for now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<u64>,

    // API also accepts strings, but that is not modeled for now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<u64>,

    // API also supports a single string with a comma-delimited list, but that is not modeled for now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,

    // API also supports a single string with a comma-delimited list, but that is not modeled for now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_bound_cidrs: Option<Vec<String>>,

    // API also accepts strings, but that is not modeled for now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_explicit_max_ttl: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_no_default_policy: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,

    // API also accepts strings, but that is not modeled for now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_period: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

impl VaultAuthUserpassCreateRequest {

    pub fn with_password<P>(password: P) -> Self
    where
        P: Borrow<str>
    {
        Self {
            password: password.borrow().into(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VaultAuthUserpassLoginRequest {
    pub password: String
}

/// See https://developer.hashicorp.com/vault/api-docs/v1.11.x/auth/userpass#login
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthUserpassLoginResponse {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: Value,
    pub wrap_info: Value,
    pub warnings: Value,
    pub auth: VaultAuthUserpassLoginResponseAuth,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthUserpassLoginResponseAuth {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub token_policies: Vec<String>,
    pub metadata: VaultAuthUserpassLoginResponseAuthMetadata,
    pub lease_duration: u64,
    pub renewable: bool,
    pub entity_id: String,
    pub token_type: String,
    pub orphan: bool,
    pub mfa_requirement: Value,
    pub num_uses: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthUserpassLoginResponseAuthMetadata {
    pub username: String,
}

/// https://developer.hashicorp.com/vault/api-docs/v1.11.x/auth/userpass#list-users
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthUserpassListResponse {
    pub data: VaultAuthUserpassListResponseData,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthUserpassListResponseData {
    /// Usernames
    pub keys: Vec<String>
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthUserpassReadResponse {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: VaultAuthUserpassReadResponseData,
    pub wrap_info: Value,
    pub warnings: Value,
    pub auth: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthUserpassReadResponseData {
    pub token_bound_cidrs: Vec<String>,
    pub token_explicit_max_ttl: u64,
    pub token_max_ttl: u64,
    pub token_no_default_policy: bool,
    pub token_num_uses: u64,
    pub token_period: u64,
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_type: String
}

#[derive(Clone, Debug, Serialize)]
pub struct VaultAuthUserpassUpdateRequest {
    pub password: String
}
