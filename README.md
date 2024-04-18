# wgrpcd

`wgrpcd` is a server-side daemon designed to manage a Wireguard VPN instance on a server through gRPC. 
This allows for managing and configuring Wireguard instances remotely and securely.
It is a Rust rewrite of my existing [wgrpcd](https://github.com/joncooperworks/wgrpcd) service because I wanted to
get better at Rust.
Don't use this in production, it is a hobby project that has not been audited.

## API Operations
+ Create peer and get provisioned config (one operation to minimize the time the private key is in memory)
+ Regenerate peer config and revoke old private key
+ Remove peer and revoke old private key
+ View registered peers

### Coming Soon
+ Update firewall rules
+ OAuth2 M2M Authentication

## Running without root
You can run this program on Linux without root by setting the `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` capabilities on the `wgrpcd` binary.
Set them using `sudo setcap CAP_NET_BIND_SERVICE,CAP_NET_ADMIN+eip wgrpcd`

## Configuration

`wgrpcd` can be configured using command-line arguments or environment variables:

### Command-Line Arguments

```plaintext
--listen_address      The server's listen address [default: [::]:443]
--ca_cert             Path to the CA certificate file [default: cacert.pem]
--tls_key             Path to the TLS key file [default: serverkey.pem]
--tls_cert            Path to the TLS certificate file [default: servercert.pem]
--wireguard_device    Wireguard device name [default: wg0]
--wireguard_public_key Path to the Wireguard public key file [default: wg.key]
```

## Authentication
`wgrpcd` uses mTLS to limit access to the gRPC API.
Unencrypted connections will be rejected.
Client certificates must be signed by the Certificate Authority passed with the `--ca_cert` flag.

## Building and Running
The [build.rs](build.rs) script handles compiling the protobuf definitions located at [`proto/wgrpcd.proto`](./proto/wgrpcd.proto) and generating the necessary Rust code for gRPC communication.
Simply ```cargo build``` and everything will be handled.
### Prerequisites
Before you start, make sure Rust and Cargo are installed on your system.

## Deployment
If the `CLOUD_INIT` environment variable is set, the build script will automatically generate a cloud-init script `wgrpcd-cloud-init-deploy.yml` in your working directory.
This file can be used to initialize a virtual machine in the cloud, setting up `wgrpcd` with TLS, a CA for signing client certificates and a Wireguard VPN with a fresh pair of keys.

### Environment Variables for Cloud-Init
To generate a cloud-init configuration during the build, set the following environment variables:

- `CA_CN`: Common Name for the CA certificate.
- `CA_COUNTRY`: Country for the CA certificate.
- `CA_STATE`: State for the CA certificate.
- `CA_CITY`: City for the CA certificate.
- `CA_COMPANY`: Company for the CA certificate.
- `WGRPCD_CN`: Common Name for the `wgrpcd` server TLS certificate.
- `ADMIN_SSH_KEY`: Path to the SSH key file used to administer the `wgrpcd` host.
- `DEPLOY_SSH_KEY`: Path to the SSH key file used to deploy `wgrpcd` instances to the `wgrpcd` host.

# Credit Where Credit is Due
""WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld."