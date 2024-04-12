use std::str::FromStr;
use std::time::UNIX_EPOCH;

use defguard_wireguard_rs::{WGApi, WireguardInterfaceApi};
use defguard_wireguard_rs::host::Peer;
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use tokio::sync::mpsc;
use tonic::Status;
use wireguard_keys::{Privkey, Pubkey};

use crate::service::{wgrpcd, WireguardCommand};
use crate::service::wgrpcd::{CreatePeerRequest, CreatePeerResponse, ImportRequest, ImportResponse, ListPeersRequest, ListPeersResponse, RekeyPeerRequest, RekeyPeerResponse, RemovePeerRequest, RemovePeerResponse};

#[cfg(target_os = "linux")]
const USERSPACE: bool = false;
#[cfg(not(target_os = "linux"))]
const USERSPACE: bool = true;


pub(crate) struct VPN {
    wg: Box<WGApi>,
    public_key: Pubkey,
}

impl VPN {
    pub(crate) fn new(device: String, public_key: Pubkey) -> Self {
        let wg = Box::new(WGApi::new(device, USERSPACE).unwrap());
        Self {
            wg,
            public_key,
        }
    }

    pub fn wait_for_commands_blocking(&self, wg_rx: &mut mpsc::Receiver<WireguardCommand>) {
        while let Some(command) = wg_rx.blocking_recv() {
            match command {
                WireguardCommand::CreatePeer(request, caller) => caller.send(self.create_peer(request)).unwrap(),
                WireguardCommand::RekeyPeer(request, caller) => caller.send(self.rekey_peer(request)).unwrap(),
                WireguardCommand::ImportPeers(request, caller) => caller.send(self.import_peers(request)).unwrap(),
                WireguardCommand::ListPeers(request, caller) => caller.send(self.list_peers(request)).unwrap(),
                WireguardCommand::RemovePeer(request, caller) => caller.send(self.remove_peer(request)).unwrap(),
            }
        }
    }

    fn create_peer(&self, request: CreatePeerRequest) -> Result<CreatePeerResponse, Status> {
        // Generate private and public keys
        let private_key = Privkey::generate();
        let public_key = private_key.pubkey();

        let allowed_ips = strings_to_ipaddrmask_blocking(&request.allowed_i_ps)?;
        let public_key = Key::try_from(public_key.as_slice())
            .expect("Error generating public key");

        let peer = Peer {
            public_key,
            allowed_ips,
            ..Default::default()
        };
        return match self.wg.configure_peer(&peer) {
            Ok(_) => {
                let response = CreatePeerResponse {
                    private_key: private_key.to_base64(),
                    public_key: private_key.pubkey().to_base64(),
                    allowed_i_ps: request.allowed_i_ps,
                    server_public_key: self.public_key.to_base64(),
                };
                Ok(response)
            }
            Err(e) => {
                log::error!("Error adding peer for {}: {}", request.allowed_i_ps.join(", "), e);
                Err(Status::internal("Error adding peer".to_string()))
            }
        };
    }

    fn rekey_peer(&self, request: RekeyPeerRequest) -> Result<RekeyPeerResponse, Status> {
        let old_public_key = request.public_key;

        // Generate private and public keys
        let new_private_key = Privkey::generate();
        let new_public_key = new_private_key.pubkey();
        let allowed_ips = strings_to_ipaddrmask_blocking(&request.allowed_i_ps)?;

        let key = Key::from_str(old_public_key.as_str())
            .map_err(|_e| Status::invalid_argument(format!("Invalid public key: {}", old_public_key)))?;

        key_is_peer(&self.wg, &key)
            .map_err(|_e| Status::not_found(format!("Key {} not found", key.to_string())))?;

        self.wg.remove_peer(&key)
            .map_err(|e| {
                log::error!("Error removing peer {}: {}", old_public_key, e);
                Status::internal(format!("Error removing old public key {}", old_public_key))
            })?;

        let pubkey = Key::decode(new_public_key.to_hex()).expect("There is a bug in the Privkey generation");

        self.wg.configure_peer(&Peer {
            public_key: pubkey,
            allowed_ips,
            ..Default::default()
        })
            .map_err(|e| Status::internal(format!("Error adding updated key to interface: {}", e)))?;

        let response = RekeyPeerResponse {
            private_key: new_private_key.to_base64(),
            public_key: new_public_key.to_base64(),
            allowed_i_ps: request.allowed_i_ps,
            server_public_key: self.public_key.to_base64(),
        };

        Ok(response)
    }


    fn remove_peer(&self, request: RemovePeerRequest) -> Result<RemovePeerResponse, Status> {
        let key = Key::from_str(request.public_key.as_str())
            .map_err(|e| Status::invalid_argument(format!("Failed to convert public key {}: {}", request.public_key, e)))?;

        if !key_is_peer(&self.wg, &key)? {
            return Err(Status::not_found(format!("Key {} not found", key.to_string())));
        }

        self.wg.remove_peer(&key)
            .map_err(|_e| Status::internal("Error removing peer".to_string()))?;

        let response = RemovePeerResponse { removed: true };
        Ok(response)
    }

    fn import_peers(&self, request: ImportRequest) -> Result<ImportResponse, Status> {
        for peer in request.peers {
            let allowed_ips = strings_to_ipaddrmask_blocking(&peer.allowed_i_ps)
                .map_err(|e| Status::invalid_argument(format!("Failed to process allowed IPs: {}", e)))?;

            let public_key = Key::from_str(&peer.public_key)
                .map_err(|e| Status::invalid_argument(format!("Failed to convert public key {}: {}", peer.public_key, e)))?;

            self.wg.configure_peer(&Peer {
                public_key,
                allowed_ips,
                ..Default::default()
            })
                .map_err(|e| Status::internal(format!("Error adding peer: {}", e)))?;
        }

        Ok(ImportResponse {})
    }

    fn list_peers(&self, _: ListPeersRequest) -> Result<ListPeersResponse, Status> {
        let data = self.wg.read_interface_data()
            .map_err(|e| Status::internal(format!("Error reading peers: {}", e)))?;

        let peers: Vec<wgrpcd::Peer> = data.peers
            .into_values()
            .map(|wg_peer| wgrpcd::Peer {
                public_key: wg_peer.public_key.to_string(),
                allowed_i_ps: wg_peer.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
                received_bytes: wg_peer.rx_bytes as i64,
                transmitted_bytes: wg_peer.tx_bytes as i64,
                last_seen: wg_peer
                    .last_handshake
                    .map_or(0, |time| time.duration_since(UNIX_EPOCH)
                        .map_or(0, |duration| duration.as_secs())),
            })
            .collect();

        Ok(ListPeersResponse { peers })
    }
}

fn strings_to_ipaddrmask_blocking(allowed_ips: &Vec<String>) -> Result<Vec<IpAddrMask>, Status> {
    // Process allowed IPs, filtering out invalid entries
    // Validate all allowed IPs upfront
    allowed_ips
        .iter()
        .map(|ip| IpAddrMask::from_str(ip)
            .map_err(|_| Status::invalid_argument(format!("Invalid IP address: {}", ip))))
        .collect()
}

fn key_is_peer(wireguard: &WGApi, key: &Key) -> Result<bool, Status> {
    let peers = wireguard.read_interface_data()
        .map_err(|_e| Status::internal("Failed to read wireguard interface".to_string()))?
        .peers;

    return Ok(peers.contains_key(key));
}
