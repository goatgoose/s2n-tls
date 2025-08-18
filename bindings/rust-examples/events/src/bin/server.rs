// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{config::Config, enums::Mode, event, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, fs};
use std::sync::atomic::AtomicU64;
use s2n_tls::event::api::{ApplicationProtocolInformation, ConnectionInfo, ConnectionMeta};
use s2n_tls::event::{Event, Meta};
use tokio::{io::AsyncWriteExt, net::TcpListener};

/// NOTE: this certificate and key are to be used for demonstration purposes only!
const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/kangaroo-chain.pem");
const DEFAULT_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/kangaroo-key.pem");

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, requires = "key", default_value_t = String::from(DEFAULT_CERT))]
    cert: String,
    #[clap(short, long, requires = "cert", default_value_t = String::from(DEFAULT_KEY))]
    key: String,
    #[clap(short, long, default_value_t = String::from("127.0.0.1:0"))]
    addr: String,
}

struct MyConnectionContext {
    counter: AtomicU64,
}

struct MyEventSubscriber;

impl event::Subscriber for MyEventSubscriber {
    type ConnectionContext = MyConnectionContext;

    fn create_connection_context(&self, meta: &ConnectionMeta, info: &ConnectionInfo) -> Self::ConnectionContext {
        MyConnectionContext { counter: AtomicU64::new(0) }
    }

    fn on_application_protocol_information(&self, context: &Self::ConnectionContext, meta: &ConnectionMeta, event: &ApplicationProtocolInformation) {
        println!("alpn event! {:?}", event.chosen_application_protocol);

        context.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        println!("counter: {}", context.counter.load(std::sync::atomic::Ordering::Relaxed));
    }

    fn on_event<M: Meta, E: Event>(&self, meta: &M, event: &E) {
        println!("event received! {:?}", event);
    }
}

async fn run_server(cert_pem: &[u8], key_pem: &[u8], addr: &str) -> Result<(), Box<dyn Error>> {
    // Set up the configuration for new connections.
    // Minimally you will need a certificate and private key.
    let mut builder = Config::builder();
    builder.set_security_policy(&DEFAULT_TLS13)?;
    builder.load_pem(cert_pem, key_pem)?;
    builder.set_application_protocol_preference(["h2", "http/1.0", "http/1.1"])?;

    let subscriber = MyEventSubscriber {};
    builder.set_event_subscriber(subscriber)?;

    let config = builder.build()?;

    // Create the TlsAcceptor based on the pool.
    let server = TlsAcceptor::new(config);

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

        // Spawn a new task to handle the connection.
        // We probably want to spawn the task BEFORE calling TcpAcceptor::accept,
        // because the TLS handshake can be slow.
        let server = server.clone();
        tokio::spawn(async move {
            let mut tls = server.accept(stream).await?;

            // Copy data from the client to stdout
            let mut stdout = tokio::io::stdout();
            tokio::io::copy(&mut tls, &mut stdout).await?;
            tls.shutdown().await?;
            println!("Connection from {:?} closed", peer_addr);

            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let test_str = "hello from rust!\n";
    s2n_tls::print_from_rust_in_rust(test_str.as_ptr(), test_str.len());

    let args = Args::parse();
    let cert_pem = fs::read(args.cert)?;
    let key_pem = fs::read(args.key)?;
    run_server(&cert_pem, &key_pem, &args.addr).await?;
    Ok(())
}
