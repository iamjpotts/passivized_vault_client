
/*
    Vault API models for service typically at port 8200
 */

mod auth;

pub use auth::*;

use std::collections::{BTreeMap, HashMap};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

/// See https://developer.hashicorp.com/vault/api-docs/v1.11.x/system/auth#read-auth-method-configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VaultAuthReadResponse {

    pub uuid: String,

    #[serde(rename="type")]
    pub type_: String,

    pub accessor: String,
    pub local: bool,
    pub seal_wrap: bool,
    pub external_entropy_access: bool,
    pub options: Value,
    pub config: Value,
    pub description: String,
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: VaultAuthReadResponseData,
    pub wrap_info: Value,
    pub warnings: Value,
    pub auth: Value
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct VaultAuthReadResponseData {
    pub accessor: String,
    pub config: VaultAuthReadResponseDataConfig,
    pub description: String,
    pub external_entropy_access: bool,
    pub local: bool,
    pub options: Value,
    pub seal_wrap: bool,

    #[serde(rename="type")]
    pub type_: String,

    pub uuid: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct VaultAuthReadResponseDataConfig {
    pub default_lease_ttl: u64,
    pub force_no_cache: bool,
    pub max_lease_ttl: u64,
    pub token_type: String
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VaultEnableAuthRequest {

    pub description: Option<String>,

    #[serde(rename="type")]
    pub type_: String,

    pub config: Option<BTreeMap<String, String>>,

    pub local: Option<bool>,

    pub seal_wrap: Option<bool>,

}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VaultEnableSecretsEngineRequest {

    #[serde(rename="type")]
    pub type_: String,

    pub description: Option<String>,

    pub config: Option<BTreeMap<String, String>>,

    pub options: Option<BTreeMap<String, String>>,

    pub local: Option<bool>,

    pub seal_wrap: Option<bool>,

    pub external_entropy_access: Option<bool>

}

#[derive(Clone, Debug, Serialize)]
pub struct VaultInitRequest {
    // Each must be base-64 encoded. The originals must be binary, not ASCII-armored
    pub pgp_keys: Option<Vec<String>>,

    // Must be base-64 encoded
    pub root_token_pgp_key: Option<String>,

    // Required; must be greater than zero
    pub secret_shares: usize,

    // Required; must be greater than zero and less than or equal to secret_shares
    pub secret_threshold: usize,

    pub stored_shares: Option<u32>,

    pub recovery_shares: Option<usize>,

    pub recovery_threshold: Option<usize>,

    // Each must be base-64 encoded. The originals must be binary, not ASCII-armored
    pub recovery_pgp_keys: Option<Vec<String>>
}

#[allow(clippy::derivable_impls)]  // Due to comments below
impl Default for VaultInitRequest {

    fn default() -> Self {
        Self {
            pgp_keys: None,
            root_token_pgp_key: None,
            secret_shares: 0,  // Invalid; server will reject
            secret_threshold: 0,  // Invalid; server will reject
            stored_shares: None,
            recovery_shares: None,
            recovery_threshold: None,
            recovery_pgp_keys: None
        }
    }

}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultInitResponse {
    pub keys: Vec<String>,
    pub keys_base64: Vec<String>,
    pub root_token: String,
    pub recovery_keys: Option<Vec<String>>,
    pub recovery_keys_base64: Option<Vec<String>>
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultPluginCatalog {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: VaultPluginCatalogData,
    pub wrap_info: Value,
    pub warnings: Value,
    pub auth: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultPluginCatalogData {
    pub auth: Vec<String>,
    pub database: Vec<String>,
    pub secret: Vec<String>,
}

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VaultSealStatus {
    #[serde(rename="type")]
    pub type_: String,

    pub initialized: bool,

    pub sealed: bool,

    #[serde(rename="n")]
    pub total_shares: i32,

    #[serde(rename="t")]
    pub unseal_threshold: i32,

    #[serde(rename="progress")]
    pub unseal_progress: i32,

    pub nonce: String,

    pub version: String,

    pub build_date: String,

    pub migration: bool,

    pub cluster_name: Option<String>,

    pub cluster_id: Option<String>,

    pub recovery_seal: bool,

    pub storage_type: String,
}

// https://www.vaultproject.io/api-docs/system/mounts
#[derive(Clone, Debug, Deserialize)]
pub struct VaultMountResponse {

    // Quite a few fields are omitted for now

    pub description: Option<String>,

    pub accessor: String,

    pub uuid: String,

    #[serde(rename="type")]
    pub type_: String,

}

// https://www.vaultproject.io/api-docs/system/mounts
#[derive(Clone, Debug, Deserialize)]
pub struct VaultMountsResponse {

    // Quite a few fields are omitted for now

    pub data: BTreeMap<String, VaultMountsResponseItem>

}

#[derive(Clone, Debug, Deserialize)]
pub struct VaultMountsResponseItem {

    pub accessor: String,

    pub description: Option<String>,

    #[serde(rename="type")]
    pub type_: String,

    pub uuid: String

}

/// https://developer.hashicorp.com/vault/api-docs/v1.11.x/system/policies
#[derive(Clone, Debug, Deserialize)]
pub struct VaultPoliciesAclListResponse {

    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: VaultPoliciesAclListResponseData,
    pub wrap_info: Value,
    pub warnings: Value,
    pub auth: Value

}

#[derive(Clone, Debug, Deserialize)]
pub struct VaultPoliciesAclListResponseData {

    pub keys: Vec<String>

}

/// https://developer.hashicorp.com/vault/api-docs/v1.11.x/system/policies
#[derive(Clone, Debug, Deserialize)]
pub struct VaultPoliciesAclReadResponse {

    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: VaultPoliciesAclReadResponseData,
    pub wrap_info: Value,
    pub warnings: Value,
    pub auth: Value

}

#[derive(Clone, Debug, Deserialize)]
pub struct VaultPoliciesAclReadResponseData {

    pub name: String,
    pub policy: String

}

/// https://developer.hashicorp.com/vault/api-docs/v1.11.x/system/policies
#[derive(Clone, Debug, Serialize)]
pub(crate) struct VaultPoliciesAclUpsertRequest {

    pub policy: String

}

/// https://www.vaultproject.io/api-docs/secret/transit
#[derive(Clone, Debug, Deserialize)]
pub struct VaultTransitKeyReadResponse {

    pub data: VaultTransitKeyReadResponseData

}

#[derive(Clone, Debug, Deserialize)]
pub struct VaultTransitKeyReadResponseData {

    #[serde(rename="type")]
    pub type_: String,

    pub deletion_allowed: bool,

    pub derived: bool,

    pub exportable: bool,

    pub allow_plaintext_backup: bool,

    // Key: version; value: seconds since Unix epoch
    pub keys: BTreeMap<String, u64>,

    pub min_decryption_version: u32,

    pub min_encryption_version: u32,

    pub name: String,

    pub supports_encryption: bool,

    pub supports_decryption: bool,

    pub supports_derivation: bool,

    pub supports_signing: bool,

    pub imported: Option<bool>

}

// https://www.vaultproject.io/api-docs/system/unseal
#[derive(Clone, Debug, Serialize)]
pub struct VaultUnsealRequest {

    pub key: Option<String>,

    pub reset: bool,

    pub migrate: bool
}

#[derive(Clone, Debug, Deserialize)]
pub struct VaultUnsealResponse {

    pub sealed: bool,

    #[serde(rename="t")]
    pub unseal_threshold: i32,

    #[serde(rename="n")]
    pub total_shares: i32,

    #[serde(rename="progress")]
    pub unseal_progress: i32,

    pub version: String,

    // Populated when unsealed
    pub cluster_name: Option<String>,

    // Populated when unsealed
    pub cluster_id: Option<String>
}

pub trait VaultUnsealProgress {

    fn sealed(&self) -> bool;
    fn unseal_threshold(&self) -> i32;
    fn unseal_progress(&self) -> i32;

    fn unseal_progress_string(&self) -> String {
        let threshold = self.unseal_threshold();

        let progress = if self.sealed() {
            self.unseal_progress()
        }
        else {
            self.unseal_threshold()
        };

        format!("{}/{}", progress, threshold)
    }

}

impl VaultUnsealProgress for VaultSealStatus {
    fn sealed(&self) -> bool {
        self.sealed
    }

    fn unseal_threshold(&self) -> i32 {
        self.unseal_threshold
    }

    fn unseal_progress(&self) -> i32 {
        self.unseal_progress
    }
}

impl VaultUnsealProgress for VaultUnsealResponse {
    fn sealed(&self) -> bool {
        self.sealed
    }

    fn unseal_threshold(&self) -> i32 {
        self.unseal_threshold
    }

    fn unseal_progress(&self) -> i32 {
        self.unseal_progress
    }
}

#[cfg(test)]
mod test_vault_unseal_progress_string {
    use super::{VaultUnsealProgress, VaultUnsealResponse};

    #[test]
    pub fn when_sealed() {
        let response: Box<dyn VaultUnsealProgress> = Box::new(VaultUnsealResponse {
            sealed: true,
            unseal_threshold: 3,
            total_shares: 0,
            unseal_progress: 1,
            version: "".to_string(),
            cluster_name: None,
            cluster_id: None
        });

        assert_eq!("1/3".to_string(), response.unseal_progress_string());
    }

    #[test]
    pub fn when_unsealed() {
        let response: Box<dyn VaultUnsealProgress> = Box::new(VaultUnsealResponse {
            sealed: false,
            unseal_threshold: 2,
            total_shares: 0,
            unseal_progress: 0,
            version: "".to_string(),
            cluster_name: None,
            cluster_id: None
        });

        assert_eq!("2/2".to_string(), response.unseal_progress_string());
    }

}
