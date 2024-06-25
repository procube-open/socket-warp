use log::{error, info, warn};
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

  let swl_cert_path = get_env("SWL_CERT_PATH", "../Certs_and_Key/test/server.crt").to_string();
  let swl_key_path = get_env("SWL_KEY_PATH", "../Certs_and_Key/test/server.key").to_string();
  let swl_ca_path = get_env("SWL_CA_PATH", "../Certs_and_Key/test/ca.crt").to_string();
  let swl_addrs = get_env("SWL_ADDRS", "0.0.0.0");
  let swl_port: u16 = get_env("SWL_PORT", "11443").parse()?;
  let swl_scep_url = get_env("SWL_SCEP_URL", "http://127.0.0.1:3000/api/cert/verify");

  let apis_addrs = get_env("APIS_ADDRS", "0.0.0.0");
  let apis_port: u16 = get_env("APIS_PORT", "8080").parse()?;

  //
  // SSL: Server Certificate and Private Key Settings
  //
  let (certs, key) = {
    let cert = fs::read(swl_cert_path)?;
    let cert = pem_to_der(&cert)?;
    let cert = rustls::Certificate(cert);
    let key = fs::read(swl_key_path)?;
    let key = key_to_der(&key)?;
    let key = rustls::PrivateKey(key);
    (vec![cert], key)
  };

  //
  // SSL: CA Certificate Settings
  //
  let mut client_auth_roots = rustls::RootCertStore::empty();
  if let Ok(cert) = fs::read(&swl_ca_path) {
    let cert = pem_to_der(&cert)?;
    client_auth_roots.add(&rustls::Certificate(cert))?;
  } else if let Err(e) = fs::read(&swl_ca_path) {
    if e.kind() == io::ErrorKind::NotFound {
      error!("local server certificate not found");
    } else {
      error!("failed to open local server certificate: {}", e);
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
  let server_addrs = (swl_addrs, swl_port)
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to resolve address"))?;
  let endpoint = quinn::Endpoint::server(server_config, server_addrs)?;
  info!("QUIC listening on {}", endpoint.local_addr()?);

  let apis_task = tokio::spawn(async move { create_app(&apis_addrs, apis_port).await });
  let quic_task = tokio::spawn(async move {
    while let Some(conn) = endpoint.accept().await {
      let fut = handle_quic_connection(conn, swl_scep_url.clone());
      tokio::spawn(async move {
        if let Err(e) = fut.await {
          error!("connection failed: {reason}", reason = e.to_string())
        }
      });
    }
  });

  let task_handle = tokio::spawn(async move {
    tokio::select! {
      _ = signal::ctrl_c() => { warn!("canceled"); }
      result = apis_task => {
        if let Err(e) = result {
          error!("Actix task failed: {:?}", e);
        }
      }
      result = quic_task => {
        if let Err(e) = result {
          error!("Quinn task failed: {:?}", e);
        }
      }
    }
  });
  task_handle.await?;

  Ok(())
}
