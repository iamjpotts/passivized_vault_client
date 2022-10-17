use core::marker::Send;
use http::status::StatusCode;
use std::error::Error;

#[derive(Debug, thiserror::Error)]
pub enum VaultClientError {
    #[error("Vault http request failed with status {0}\n{1}")]
    FailureResponse(StatusCode, String),

    #[error("Vault http request failed: {0}")]
    RequestFailed(reqwest::Error),

    #[error("Vault client error: {0}")]
    Other(Box<dyn Error + Send>)
}

impl From<reqwest::Error> for VaultClientError {
    fn from(other: reqwest::Error) -> Self {
        VaultClientError::RequestFailed(other)
    }
}

#[cfg(test)]
mod test_vault_client_error {
    use super::VaultClientError;

    const BAD_URL: &str = "this:is:wrong";

    fn reqwest_failed() -> Result<(), reqwest::Error> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // Call the asynchronous method using the runtime.
        let result = rt.block_on(reqwest::get(BAD_URL));

        Err(result.unwrap_err())
    }

    fn vault_client_failed() -> Result<(), VaultClientError> {
        // Compile time check that we can automatically convert a vault error into an RSC error
        reqwest_failed()?;

        Ok(())
    }

    #[test]
    fn reqwest_error_into_vault_error() {
        let actual = vault_client_failed().unwrap_err();

        if let VaultClientError::RequestFailed(error) = actual {
            assert!(error.is_builder());
            assert_eq!(Some(BAD_URL.to_string()), error.url().map(|u| u.to_string()));
        }
        else {
            panic!("Unexpected error: {:?}", actual);
        }
    }
}
