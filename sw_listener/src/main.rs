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

use log::{info, warn};
use std::env;
use std::net::ToSocketAddrs;
use std::time::Duration;
use std::{error::Error, fs, io, sync::Arc};
use swl_lib::apis::create_app;
use swl_lib::quic::handle_quic_connection;
use swl_lib::utils::{get_env, key_to_der, pem_to_der};
use tokio::signal;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  env::set_var("RUST_LOG", "info");
  env_logger::init();

  let swl_cert_path = get_env("SWL_CERT_PATH", "../Certs_and_Key/server.crt").to_string();
  let swl_key_path = get_env("SWL_KEY_PATH", "../Certs_and_Key/server.key").to_string();
  let swl_ca_path = get_env("SWL_CA_PATH", "../Certs_and_Key/ca.crt").to_string();
  let swl_addrs = get_env("SWL_ADDRS", "0.0.0.0");
  let swl_port: u16 = get_env("SWL_PORT", "11443").parse().unwrap();
  let apis_addrs = get_env("APIS_ADDRS", "0.0.0.0");
  let apis_port: u16 = get_env("APIS_PORT", "8080").parse().unwrap();

  //
  // SSL: Server Certificate and Private Key Settings
  //
  let (certs, key) = {
    let cert = fs::read(swl_cert_path).unwrap();
    let cert = pem_to_der(&cert).unwrap();
    let cert = rustls::Certificate(cert);
    let key = fs::read(swl_key_path).unwrap();
    let key = key_to_der(&key).unwrap();
    let key = rustls::PrivateKey(key);
    (vec![cert], key)
  };

  //
  // SSL: CA Certificate Settings
  //
  let mut client_auth_roots = rustls::RootCertStore::empty();
  match fs::read(swl_ca_path) {
    Ok(cert) => {
      let cert = pem_to_der(&cert).unwrap();
      client_auth_roots.add(&rustls::Certificate(cert))?;
    }
    Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
      warn!("local server certificate not found");
    }
    Err(e) => {
      warn!("failed to open local server certificate: {}", e);
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
    .keep_alive_interval(Some(Duration::from_secs(50)))
    .max_idle_timeout(Some(Duration::from_secs(55).try_into()?));
  let server_addrs = (swl_addrs, swl_port).to_socket_addrs()?.next().unwrap();
  let endpoint = quinn::Endpoint::server(server_config, server_addrs)?;
  info!("QUIC listening on {}", endpoint.local_addr()?);

  let mut n_conn = 1;
  let t1 = tokio::spawn(async move { create_app(&apis_addrs, apis_port).await });
  let t2 = tokio::spawn(async move {
    while let Some(conn) = endpoint.accept().await {
      info!("QUIC connection incoming {}", n_conn);
      n_conn += 1;
      let fut = handle_quic_connection(conn);
      tokio::spawn(async move {
        if let Err(e) = fut.await {
          warn!("connection failed: {reason}", reason = e.to_string())
        }
      });
    }
  });

  let task_handle = tokio::spawn(async move {
    tokio::select! {
      _ = signal::ctrl_c() => { warn!("canceled"); }
      _ = t1 => {}
      _ = t2 => {}
    }
  });
  task_handle.await.unwrap();

  Ok(())
}
