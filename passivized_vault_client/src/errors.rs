use core::marker::Send;
use http::status::StatusCode;
use serde_derive::Deserialize;
use std::error::Error;
use std::fmt::{Display, Formatter};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum VaultClientError {
    #[error("Vault http request failed with status {0}\n{1}")]
    FailureResponse(StatusCode, VaultClientErrorContent),

    // Name, message
    #[error("Invalid value for {0}: {1}")]
    InvalidInput(String, String),

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultClientErrorContent {
    Errors(Vec<String>),
    Json(Value),
    Text(String),
}

fn write_errors(f: &mut Formatter<'_>, messages: &Vec<String>) -> std::fmt::Result {
    let mut first = true;

    for m in messages {
        if first {
            first = false;
        }
        else {
            write!(f, ", ")?;
        }

        write!(f, "{}", m)?;
    }

    Ok(())
}

impl Display for VaultClientErrorContent {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Errors(values) => write_errors(f, values),
            Self::Json(value) => write!(f, "{}", value),
            Self::Text(value) => write!(f, "{}", value)
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct VaultErrorsResponse {
    pub errors: Vec<String>
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

#[cfg(test)]
mod test_vault_client_error_content {

    mod display {
        use serde_json::Value;
        use crate::errors::VaultClientErrorContent;

        #[test]
        fn from_errors_empty() {
            assert_eq!("", format!("{}", VaultClientErrorContent::Errors(vec![])))
        }

        #[test]
        fn from_errors_one() {
            assert_eq!("foo", format!("{}", VaultClientErrorContent::Errors(vec!["foo".into()])))
        }

        #[test]
        fn from_errors_multiple() {
            assert_eq!("foo, bar", format!("{}", VaultClientErrorContent::Errors(vec!["foo".into(), "bar".into()])))
        }

        #[test]
        fn from_json() {
            assert_eq!("123", format!("{}", VaultClientErrorContent::Json(Value::Number(123.into()))))
        }

        #[test]
        fn from_text() {
            assert_eq!("boom", format!("{}", VaultClientErrorContent::Text("boom".into())))
        }

    }

}