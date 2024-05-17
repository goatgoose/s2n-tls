use std::collections::HashMap;
use std::error::Error;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use s2n_tls::callbacks::{SessionTicket, SessionTicketCallback};
use s2n_tls::config::Config;
use s2n_tls::connection::{Builder, Connection, ModifiedBuilder};
use s2n_tls::security::DEFAULT_TLS13;
use s2n_tls_tokio::TlsConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct ApplicationContext {
    ip_addr: IpAddr,
}

unsafe impl Send for ApplicationContext {}
unsafe impl Sync for ApplicationContext {}

#[derive(Default, Clone)]
pub struct SessionTicketHandler {
    session_tickets: Arc<Mutex<HashMap<IpAddr, Vec<u8>>>>,
}

impl SessionTicketCallback for SessionTicketHandler {
    fn on_session_ticket(&self, connection: &mut Connection, session_ticket: &SessionTicket) {
        let size = session_ticket.len().unwrap();
        let mut data = vec![0; size];
        session_ticket.data(&mut data).unwrap();

        let mut session_tickets = self.session_tickets.lock().unwrap();
        let ip_addr = connection.application_context::<ApplicationContext>().unwrap().ip_addr;
        session_tickets.insert(ip_addr, data);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cert_path = format!("{}/certs/test-cert.pem", env!("CARGO_MANIFEST_DIR"));
    let cert = std::fs::read(cert_path).unwrap();

    let session_ticket_handler = SessionTicketHandler::default();

    let mut config = s2n_tls::config::Builder::new();
    config.set_security_policy(&DEFAULT_TLS13).unwrap();
    config.trust_pem(&cert).unwrap();
    config.set_session_ticket_callback(session_ticket_handler.clone()).unwrap();
    config.enable_session_tickets(true).unwrap();
    let config = config.build()?;

    for handshake_idx in 0..5 {
        let stream = TcpStream::connect("127.0.0.1:9000").await?;
        let ip = stream.peer_addr().unwrap().ip();

        let builder = ModifiedBuilder::new(config.clone(), |conn| {
            // Associate the IP address with the new connection.
            conn.set_application_context(ApplicationContext {
                ip_addr: ip,
            });

            // If a session ticket exists that corresponds with the IP address, set it to resume the
            // connection.
            let session_tickets = session_ticket_handler.session_tickets.lock().unwrap();
            if let Some(session_ticket) = session_tickets.get(&ip) {
                conn.set_session_ticket(session_ticket)?;
            }

            Ok(conn)
        });
        let client = TlsConnector::new(builder);

        let handshake = client.connect("127.0.0.1", stream).await;
        let mut tls = match handshake {
            Ok(tls) => tls,
            Err(e) => {
                println!("error during handshake: {e}");
                return Ok(());
            }
        };

        let mut response = String::new();
        tls.read_to_string(&mut response).await?;
        println!("response: {response}");

        tls.shutdown().await?;

        let connection = tls.as_ref();
        if handshake_idx == 0 {
            assert!(!connection.resumed());
        } else {
            assert!(connection.resumed());
        }
    }

    Ok(())
}
