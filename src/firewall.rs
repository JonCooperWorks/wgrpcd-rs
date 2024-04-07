use tokio::sync::mpsc;
use tonic::Status;

use crate::service::FirewallCommand;
use crate::service::wgrpcd::{FirewallUpdateRequest, FirewallUpdateResponse};

const ALLOW: &str = "allow";
const DENY: &str = "deny";

pub struct Firewall {
    table_name: String,
    chain_name: String,
    wireguard_device: String,
}

impl Firewall {
    pub fn new(wireguard_device: String, table_name: String, chain_name: String) -> Self {
        Firewall { table_name, chain_name, wireguard_device }
    }

    pub fn wait_for_commands_blocking(&self, fw_rx: &mut mpsc::Receiver<FirewallCommand>) {
        while let Some(command) = fw_rx.blocking_recv() {
            match command {
                FirewallCommand::UpdateFirewall(request, client) => client.send(self.update_firewall(request)).unwrap(),
            }
        }
    }

    fn update_firewall(&self, request: FirewallUpdateRequest) -> Result<FirewallUpdateResponse, Status> {
        // TODO: update connectivity via nftables
        // TODO: support granting a source access to multiple destinations
        // TODO: chain per client
        log::info!("{:?}", request);
        let response = FirewallUpdateResponse {
            updated: true
        };
        Ok(response)
    }
}