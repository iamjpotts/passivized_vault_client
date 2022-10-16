use passivized_docker_engine_client::errors::{DecCreateError, DecUseError};
use passivized_vault_client::errors::VaultClientError;

#[derive(Debug, thiserror::Error)]
pub enum ExampleError {
    #[error("Docker engine client creation error: {0}")]
    DockerEngineClientCreate(DecCreateError),

    #[error("Docker engine client error: {0}")]
    DockerEngineClientUse(DecUseError),

    #[error("IO error: {0}")]
    Io(std::io::Error),

    #[error("{0}")]
    Message(String),

    #[error("Retries exceeded")]
    RetriesExceeded(),

    #[error("Reqwest error: {0}")]
    Reqwest(reqwest::Error),

    #[error("Vault client error: {0}")]
    VaultClient(VaultClientError),
}

impl From<DecCreateError> for ExampleError {
    fn from(other: DecCreateError) -> Self {
        Self::DockerEngineClientCreate(other)
    }
}

impl From<DecUseError> for ExampleError {
    fn from(other: DecUseError) -> Self {
        Self::DockerEngineClientUse(other)
    }
}

impl From<std::io::Error> for ExampleError {
    fn from(other: std::io::Error) -> Self {
        Self::Io(other)
    }
}

impl From<VaultClientError> for ExampleError {
    fn from(other: VaultClientError) -> Self {
        Self::VaultClient(other)
    }
}
