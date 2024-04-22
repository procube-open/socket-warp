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
use std::time::Duration;
use std::{error::Error, fs, io, sync::Arc};
use swl_lib::apis::create_app;
use swl_lib::quic::handle_quic_connection;
use swl_lib::utils::get_env;
use tokio::signal;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let swl_cert_path = get_env("SWL_CERT_PATH", "../Certs_and_Key/server_crt.der").to_string();
  let swl_key_path = get_env("SWL_KEY_PATH", "../Certs_and_Key/server_key.der").to_string();
  let swl_ca_path = get_env("SWL_CA_PATH", "../Certs_and_Key/ca.der").to_string();
  let swl_addrs = get_env("SWL_ADDRS", "0.0.0.0");
  let swl_port = get_env("SWL_PORT", "11443").parse().unwrap();

  //
  // SSL: Server Certificate and Private Key Settings
  //
  let (certs, key) = {
    let cert = fs::read(swl_cert_path).unwrap();
    let cert = rustls::Certificate(cert);
    let key = fs::read(swl_key_path).unwrap();
    let key = rustls::PrivateKey(key);
    (vec![cert], key)
  };

  //
  // SSL: CA Certificate Settings
  //
  let mut client_auth_roots = rustls::RootCertStore::empty();
  match fs::read(swl_ca_path) {
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
    .with_client_cert_verifier(Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(client_auth_roots)))
    .with_single_cert(certs, key)?;
  server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

  let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
  Arc::get_mut(&mut server_config.transport).unwrap().max_concurrent_uni_streams(0_u8.into()).keep_alive_interval(Some(Duration::from_secs(3)));
  let server_addrs = (swl_addrs, swl_port).to_socket_addrs()?.next().unwrap();
  let endpoint = quinn::Endpoint::server(server_config, server_addrs)?;
  println!("QUIC listening on {}", endpoint.local_addr()?);

  let mut n_conn = 1;

  let t1 = tokio::spawn(async move { create_app("127.0.0.1", 8080).await });
  let t2 = tokio::spawn(async move {
    while let Some(conn) = endpoint.accept().await {
      println!("QUIC connection incoming {}", n_conn);
      n_conn += 1;
      let fut = handle_quic_connection(conn);
      tokio::spawn(async move {
        if let Err(e) = fut.await {
          println!("connection failed: {reason}", reason = e.to_string())
        }
      });
    }
  });

  let task_handle = tokio::spawn(async move {
    tokio::select! {
      _ = signal::ctrl_c() => {
        println!("canceled");
      },
      _ = t1 => {}
      _ = t2 => {}
    }
  });
  task_handle.await.unwrap();

  Ok(())
}
