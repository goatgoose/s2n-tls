// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::raw::{config::Config, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, fs};
use tokio::net::TcpListener;

/// NOTE: this certificate and key are to be used for demonstration purposes only!
const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/cert.pem");
const DEFAULT_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/key.pem");

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, requires = "key", default_value_t = String::from(DEFAULT_CERT))]
    cert: String,
    #[clap(short, long, requires = "cert", default_value_t = String::from(DEFAULT_KEY))]
    key: String,
    #[clap(short, long, default_value_t = String::from("127.0.0.1:0"))]
    addr: String,
}

async fn run_server(cert_pem: &[u8], key_pem: &[u8], addr: &str) -> Result<(), Box<dyn Error>> {
    // Set up the configuration for new connections.
    // Minimally you will need a certificate and private key.
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.load_pem(cert_pem, key_pem)?;

    // Create the TlsAcceptor based on the configuration.
    let server = TlsAcceptor::new(config.build()?);

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    let listener = TcpListener::bind(&addr).await?;
    let addr = listener
        .local_addr()
        .map(|x| x.to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_owned());
    println!("Listening on {}", addr);

    loop {
        // Wait for a client to connect.
        let (stream, peer_addr) = listener.accept().await?;
        println!("Connection from {:?}", peer_addr);
        server.accept(stream).await?;

        // TODO: echo
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let cert_pem = fs::read(args.cert)?;
    let key_pem = fs::read(args.key)?;
    run_server(&cert_pem, &key_pem, &args.addr).await?;
    Ok(())
}
