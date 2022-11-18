use std::collections::HashMap;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

/// https://developer.hashicorp.com/vault/api-docs/v1.11.x/auth/token
#[derive(Clone, Debug, Default, Serialize)]
pub struct VaultAuthTokenCreateRequest {
    pub id: Option<String>,
    pub role_name: Option<String>,
    pub policies: Vec<String>,
    pub meta: HashMap<String, String>,
    pub no_parent: Option<bool>,
    pub no_default_policy: Option<bool>,
    pub renewable: Option<bool>,
    // lease field omitted due to deprecation comment in docs
    pub ttl: Option<String>,
    pub type_: Option<String>,
    pub explicit_max_ttl: Option<String>,
    pub display_name: Option<String>,
    pub num_uses: Option<u64>,
    pub period: Option<String>,
    pub entity_alias: Option<String>
}

/// https://developer.hashicorp.com/vault/api-docs/v1.11.x/auth/token
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthTokenCreateResponse {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: Value,
    pub wrap_info: Value,
    pub warnings: Vec<String>,
    pub auth: VaultAuthTokenCreateResponseAuth,
}

/// https://developer.hashicorp.com/vault/api-docs/v1.11.x/auth/token
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthTokenCreateResponseAuth {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub token_policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub lease_duration: u64,
    pub renewable: bool,
    pub entity_id: String,
    pub token_type: String,
    pub orphan: bool,
    pub num_uses: u64,
}

/// https://developer.hashicorp.com/vault/api-docs/v1.11.x/auth/token
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthTokenLookupSelfResponse {
    pub data: VaultAuthTokenLookupSelfResponseData,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultAuthTokenLookupSelfResponseData {
    pub accessor: String,
    pub creation_time: u64,
    pub creation_ttl: u64,
    pub display_name: String,
    pub entity_id: String,
    pub expire_time: String,
    pub explicit_max_ttl: u64,
    pub id: String,
    // Included in documentation but not in response
    //pub identity_policies: Vec<String>,
    pub issue_time: String,
    pub meta: HashMap<String, String>,
    pub num_uses: u64,
    pub orphan: bool,
    pub path: String,
    pub policies: Vec<String>,
    pub renewable: bool,
    pub ttl: u64,
}
