//! sw_listener 0.4.0
//! (proof of concept version)
//!
//! sw_listener and sw_connector is tunnel software using the QUIC protocol.
//!
//! compile and run as below
//! cargo run
//!
//! requirement
//!  - SSL server certificate and key files for sw_listener
//!  - CA certificate for sw_connector
//!  - TLS client auth
//!
//! not implimented
//! - error handling and logging
//! - manage connection

use std::net::ToSocketAddrs;
use std::{error::Error, fs, io, sync::Arc};

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

#[tokio::main]

async fn main() -> Result<(), Box<dyn Error>> {
    //
    // SSL: Server Certificate and Private Key Settings
    //

    let (certs, key) = {
        let cert =
            fs::read(get_env("SERVER_CERT_PATH", "../Certs_and_Key/server_crt.der").to_string())
                .unwrap();
        let key =
            fs::read(get_env("SERVER_KEY_PATH", "../Certs_and_Key/server_key.der").to_string())
                .unwrap();
        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        (vec![cert], key)
    };

    //
    // SSL: CA Certificate Settings
    //
    let mut client_auth_roots = rustls::RootCertStore::empty();
    match fs::read(get_env("SERVER_CA_PATH", "../Certs_and_Key/ca.der").to_string()) {
        Ok(cert) => {
            client_auth_roots.add(&rustls::Certificate(cert))?;
        }
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            println!("local server certificate not found");
        }
        Err(e) => {
            println!("failed to open local server certificate: {}", e);
        }
    }

    //
    // Server Configuration and QUIC endpoint Settings
    //
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(
            client_auth_roots,
        )))
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into())
        .max_idle_timeout(None);
    let server_addrs = (
        get_env("SERVER_ADDRS", "0.0.0.0"),
        get_env("SERVER_PORT", "11443").parse().unwrap(),
    )
        .to_socket_addrs()?
        .next()
        .unwrap();
    let endpoint = quinn::Endpoint::server(server_config, server_addrs)?;
    println!("QUIC listening on {}", endpoint.local_addr()?);

    let mut n_conn = 1;
    while let Some(conn) = endpoint.accept().await {
        println!("QUIC connection incoming {}", n_conn);
        n_conn += 1;
        let fut = swl_lib::quic::handle_quic_connection(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                println!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    Ok(())
}

fn get_env(key: &str, default: &str) -> String {
    let env = match std::env::var(key) {
        Ok(val) => val,
        Err(_) => default.to_string(),
    };
    return env;
}
