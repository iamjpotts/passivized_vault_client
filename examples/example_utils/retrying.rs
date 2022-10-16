use std::time::Duration;
use log::*;
use super::errors::ExampleError;

pub async fn wait_for_http_server(url: &str) -> Result<String, ExampleError> {
    let mut retries_remaining = 15;

    while retries_remaining > 0 {
        let result = reqwest::get(url)
            .await;

        match result {
            Err(e) => {
                warn!("GET {} failed: {}", url, e);

                if !e.is_connect() {
                    return Err(ExampleError::Reqwest(e));
                }
            }
            Ok(response) => {
                return match response.text().await {
                    Err(e) => {
                        warn!("GET text of {} failed: {}", url, e);
                        Err(ExampleError::Reqwest(e))
                    }
                    Ok(text) => {
                        info!("GET {} succeeded:\n{}", url, text);
                        Ok(text)
                    }
                }
            }
        }

        info!("Will retry; {} attempts remaining", retries_remaining);
        tokio::time::sleep(Duration::from_secs(1)).await;
        retries_remaining = retries_remaining - 1;
    }

    Err(ExampleError::RetriesExceeded())
}
