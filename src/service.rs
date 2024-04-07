use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::transport::server::Router;

use wgrpcd::{ChangeListenPortRequest, ChangeListenPortResponse, CreatePeerRequest, CreatePeerResponse, DevicesRequest, DevicesResponse, FirewallUpdateRequest, FirewallUpdateResponse, ImportRequest, ImportResponse, ListPeersRequest, ListPeersResponse, RekeyPeerRequest, RekeyPeerResponse, RemovePeerRequest, RemovePeerResponse};
use wgrpcd::wireguard_rpc_server::{WireguardRpc, WireguardRpcServer};

pub mod wgrpcd {
    tonic::include_proto!("wgrpcd");
}


pub enum WireguardCommand {
    CreatePeer(CreatePeerRequest, oneshot::Sender<Result<CreatePeerResponse, Status>>),
    RekeyPeer(RekeyPeerRequest, oneshot::Sender<Result<RekeyPeerResponse, Status>>),
    RemovePeer(RemovePeerRequest, oneshot::Sender<Result<RemovePeerResponse, Status>>),
    ListPeers(ListPeersRequest, oneshot::Sender<Result<ListPeersResponse, Status>>),
    ImportPeers(ImportRequest, oneshot::Sender<Result<ImportResponse, Status>>),
}

pub enum FirewallCommand {
    UpdateFirewall(FirewallUpdateRequest, oneshot::Sender<Result<FirewallUpdateResponse, Status>>)
}


pub struct ServerConfig {
    pub client_ca: Vec<u8>,
    pub tls_certificate: Vec<u8>,
    pub tls_key: Vec<u8>,
    pub wireguard_device: String,
    pub wg_tx: mpsc::Sender<WireguardCommand>,
    pub fw_tx: mpsc::Sender<FirewallCommand>,
}

pub struct WireguardService {
    wireguard_device: String,
    wireguard_commands: mpsc::Sender<WireguardCommand>,
    firewall_commands: mpsc::Sender<FirewallCommand>,
}


impl WireguardService {
    pub fn server(config: ServerConfig) -> Result<Router, anyhow::Error> {
        let wireguard_service = Self {
            wireguard_device: config.wireguard_device,
            wireguard_commands: config.wg_tx,
            firewall_commands: config.fw_tx,
        };

        let server_identity = Identity::from_pem(&config.tls_certificate, &config.tls_key);
        let tls_config = ServerTlsConfig::new()
            .client_ca_root(Certificate::from_pem(&config.client_ca))
            .client_auth_optional(false)
            .identity(server_identity);

        let server = Server::builder()
            .tls_config(tls_config)?
            .add_service(WireguardRpcServer::new(wireguard_service));

        Ok(server)
    }
}


#[tonic::async_trait]
impl WireguardRpc for WireguardService {
    async fn change_listen_port(&self, _: Request<ChangeListenPortRequest>) -> Result<Response<ChangeListenPortResponse>, Status> {
        Ok(Response::new(ChangeListenPortResponse {
            new_listen_port: 443,
        }))
    }

    async fn create_peer(&self, request: Request<CreatePeerRequest>) -> Result<Response<CreatePeerResponse>, Status> {
        let message = request.into_inner();
        let ips = message.allowed_i_ps.join(" ");
        let (tx, rx) = oneshot::channel();
        self.wireguard_commands.send(WireguardCommand::CreatePeer(message, tx))
            .await
            .map_err(|e| {
                log::error!("Error sending command to Wireguard thread when creating peer: {}", e);
                Status::internal("Error creating peer".to_string())
            })?;

        match rx.await {
            Ok(Ok(response)) => {
                log::info!("Created peer {} with public key allowed to connect from {}", response.public_key, response.allowed_i_ps.join(", "));
                Ok(Response::new(response))
            }
            Ok(Err(e)) => Err(e),
            Err(e) => {
                log::error!("Error spawning background thread while creating peer with allowed IPs: {}: {}", ips, e);
                Err(Status::internal(format!("Error creating peer with allowed IPs: {}", ips)))
            }
        }
    }

    async fn rekey_peer(&self, request: Request<RekeyPeerRequest>) -> Result<Response<RekeyPeerResponse>, Status> {
        let inner = request.into_inner();
        let old_public_key = inner.public_key.clone();
        let (tx, rx) = oneshot::channel();
        self.wireguard_commands
            .send(WireguardCommand::RekeyPeer(inner, tx))
            .await
            .map_err(|e| {
                log::error!("Error sending command to Wireguard thread when rekeying peer {}: {}", old_public_key, e);
                Status::internal(format!("Error rekeying peer: {}", old_public_key))
            })?;

        match rx.await {
            Ok(Ok(response)) => {
                log::info!("Rekeyed peer {} with new public key: {}", old_public_key, response.public_key);
                Ok(Response::new(response))
            }
            Ok(Err(e)) => Err(e),
            Err(e) => {
                log::error!("Error receiving response from background thread while rekeying peer {}", e);
                Err(Status::internal(format!("Error rekeying peer: {}", old_public_key)))
            }
        }
    }

    async fn remove_peer(&self, request: Request<RemovePeerRequest>) -> Result<Response<RemovePeerResponse>, Status> {
        let inner = request.into_inner();
        let (tx, rx) = oneshot::channel();

        self.wireguard_commands
            .send(WireguardCommand::RemovePeer(inner, tx))
            .await
            .map_err(|e| {
                log::error!("Error sending command to Wireguard thread when removing peer: {}", e);
                Status::internal("Error sending remove peer command")
            })?;

        match rx.await {
            Ok(Ok(response)) => {
                log::info!("Removed peer successfully");
                Ok(Response::new(response))
            }
            Ok(Err(e)) => Err(e),
            Err(e) => {
                log::error!("Error receiving response from background thread while removing peer: {}", e);
                Err(Status::internal("Error receiving remove peer response"))
            }
        }
    }


    async fn list_peers(&self, request: Request<ListPeersRequest>) -> Result<Response<ListPeersResponse>, Status> {
        let (tx, rx) = oneshot::channel();
        self.wireguard_commands
            .send(WireguardCommand::ListPeers(request.into_inner(), tx))
            .await
            .map_err(|e| {
                log::error!("Error sending comand to Wireguard thread when listing peers: {}", e);
                Status::internal("Error retrieving peers".to_string())
            })?;

        match rx.await {
            Ok(Ok(response)) => {
                log::info!("Retrieved {} peers", response.peers.len());
                let reply = response;
                Ok(Response::new(reply))
            }
            Ok(Err(e)) => Err(e),
            Err(e) => {
                log::error!("Error receiving from background thread while retrieving peers {}", e);
                Err(Status::internal("Error retrieving peers".to_string()))
            }
        }
    }

    async fn devices(&self, _: Request<DevicesRequest>) -> Result<Response<DevicesResponse>, Status> {
        let reply = DevicesResponse {
            devices: vec![self.wireguard_device.clone()],
        };
        Ok(Response::new(reply))
    }

    async fn import(&self, request: Request<ImportRequest>) -> Result<Response<ImportResponse>, Status> {
        let (tx, rx) = oneshot::channel();

        self.wireguard_commands.send(WireguardCommand::ImportPeers(request.into_inner(), tx))
            .await
            .map_err(|e| {
                log::error!("Error sending import peers command to Wireguard thread: {}", e);
                Status::internal("Error sending import peers command")
            })?;

        match rx.await {
            Ok(Ok(response)) => {
                log::info!("Successfully imported peers");
                Ok(Response::new(response))
            }
            Ok(Err(e)) => Err(e),
            Err(e) => {
                log::error!("Error receiving response from Wireguard thread while importing peers: {}", e);
                Err(Status::internal("Error receiving import peers response"))
            }
        }
    }

    async fn update_firewall(&self, request: Request<FirewallUpdateRequest>) -> Result<Response<FirewallUpdateResponse>, Status> {
        let (tx, rx) = oneshot::channel();
        let request = request.into_inner();

        self.firewall_commands.send(FirewallCommand::UpdateFirewall(request.clone(), tx))
            .await
            .map_err(|e| {
                log::error!("Error sending message to firewall thread: {}", e);
                Status::internal("Error sending command to firewall")
            })?;

        match rx.await {
            Ok(Ok(response)) => {
                log::info!("Applied change to firewall: {} {} -> {}", request.action, request.src, request.dsts.join(", "));
                Ok(Response::new(response))
            }
            Ok(Err(e)) => Err(e),
            Err(e) => {
                log::error!("Error receiving response from firewall: {}", e);
                Err(Status::internal("Error receiving response from firewall".to_string()))
            }
        }
    }
}