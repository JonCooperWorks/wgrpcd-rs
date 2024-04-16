# wgrpcd

`wgrpcd` is a server-side daemon designed to manage a Wireguard VPN instance on a server through gRPC. 
This allows for managing and configuring Wireguard instances remotely and securely.
It is a Rust rewrite of my existing [wgrpcd](https://github.com/joncooperworks/wgrpcd) service because I wanted to
get better at Rust.
Don't use this in production, it is a hobby project that has not been audited.

## Features

- **Remote Management**: Control Wireguard configurations remotely via a gRPC interface.
- **Security**: Ensures secure communication using mTLS for connections between the client and the server.
- **Configurable**: Easy to configure through command-line arguments.

## Prerequisites
Before you start, make sure Rust and Cargo are installed on your system.

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

## Building and Running
The [build.rs](build.rs) script handles compiling the protobuf definitions located at [`proto/wgrpcd.proto`](./proto/wgrpcd.proto) and generating the necessary Rust code for gRPC communication.


## Deployment
If the `CLOUD_INIT` environment variable is set, the build script will automatically generate a wgrpcd-cloud-init-deploy.yml file. 
This file can be used to initialize a virtual machine in the cloud, setting up wgrpcd with all necessary configurations.

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

This will output the cloud-init to a file called `wgrpcd-cloud-init-deploy.yml` in your working directory.
