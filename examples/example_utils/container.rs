use log::{info, warn};
use passivized_docker_engine_client::DockerEngineClient;
use passivized_docker_engine_client::errors::DecUseError;
use passivized_docker_engine_client::model::MountMode::ReadOnly;
use passivized_docker_engine_client::requests::{CreateContainerRequest, HostConfig};
use passivized_test_support::http_status_tests::is_success;
use passivized_test_support::timestamps;
use passivized_test_support::waiter::wait_for_http_server;
use tempfile::NamedTempFile;
use passivized_vault_client::client::VaultApiUrl;

use super::errors::ExampleError;
use super::hcl::{create_vault_config_file_with_content, VAULT_CONFIG_HCL, VAULT_CONFIG_PATH};
use super::images;

pub struct VaultContainer {
    pub docker: DockerEngineClient,
    pub container_id: String,
    pub url: VaultApiUrl,
}

impl VaultContainer {

    pub async fn new(name: &str) -> Result<Self, ExampleError> {
        Self::with_config(name, VAULT_CONFIG_HCL, None)
            .await
    }

    pub async fn with_config(name: &str, hcl: &str, vault_token: Option<String>) -> Result<Self, ExampleError> {
        let config_hcl: NamedTempFile = create_vault_config_file_with_content(hcl)
            .unwrap();

        let hcl_file = config_hcl.path()
            .to_str()
            .ok_or(ExampleError::Message("Could not get config temp file path".into()))?;

        let docker = DockerEngineClient::new()?;

        docker.images().pull_if_not_present(images::vault::NAME, images::vault::TAG)
            .await?;

        let mut create = CreateContainerRequest::default()
            .name(timestamps::named(name))
            .image(images::vault::IMAGE)
            .cmd(vec!["server"])
            .host_config(HostConfig::default()
                .auto_remove()
                .cap_add("IPC_LOCK")
                .mount(hcl_file, VAULT_CONFIG_PATH, ReadOnly)
            );

        if let Some(vt) = vault_token {
            // Only used when once Vault instance needs to access another Vault instance.
            create = create.env(format!("VAULT_TOKEN={}", vt))
        }

        info!("Creating container");

        let container = docker.containers().create(create)
            .await?;

        info!("Created container with id {}", container.id);
        for w in &container.warnings {
            warn!("Container warning: {}", w)
        }

        docker.container(&container.id).start()
            .await?;

        let inspected = docker.container(&container.id).inspect()
            .await?;

        let ip = inspected.first_ip_address()
            .unwrap();

        let api_url = VaultApiUrl::new(format!("http://{}:8200", ip));

        wait_for_http_server(api_url.status(), is_success())
            .await
            .unwrap();

        Ok(Self {
            docker,
            container_id: container.id,
            url: api_url
        })
    }

    pub async fn teardown(self) -> Result<(), DecUseError> {
        info!("Stopping container {}", self.container_id);

        self.docker.container(&self.container_id).stop()
            .await
    }

}