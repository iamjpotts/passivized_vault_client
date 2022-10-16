use passivized_docker_engine_client::responses::InspectContainerResponse;
use log::info;
use super::errors::ExampleError;

pub fn extract_ip_address(inspected: &InspectContainerResponse) -> Result<String, ExampleError> {
    let ns = &inspected.network_settings;

    info!("Networks: {}", ns.networks.len());

    let mut ip_address: Option<String> = None;

    for (network_name, network) in &ns.networks {
        info!("Network {}: {}", network_name, network.ip_address);
        ip_address = ip_address.or(Some(network.ip_address.clone()));
    }

    match ip_address {
        None => {
            Err(ExampleError::Message("Could not find IP address".into()))
        }
        Some(ip) => {
            Ok(ip)
        }
    }
}
