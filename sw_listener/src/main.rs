use log::{error, info, warn};
use std::env;
use std::net::ToSocketAddrs;
use std::time::Duration;
use std::{error::Error, io, sync::Arc};
use swl_lib::apis::create_app;
use swl_lib::quic::handle_quic_connection;
use swl_lib::utils::{get_env, key_to_der, pem_to_der, read_file};
use tokio::signal;

const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const MAX_CONCURRENT_UNI_STREAMS: u8 = 0;
const KEEP_ALIVE_INTERVAL_SECS: u64 = 50;
const MAX_IDLE_TIMEOUT_SECS: u64 = 60;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  env::set_var("RUST_LOG", "info");
  env_logger::init();

  let swl_cert_path = get_env("SWL_CERT_PATH", "../Certs_and_Key/swl-1/cert.pem").to_string();
  let swl_key_path = get_env("SWL_KEY_PATH", "../Certs_and_Key/swl-1/key.pem").to_string();
  let swl_ca_path = get_env("SWL_CA_PATH", "../Certs_and_Key/swl-1/ca.crt").to_string();
  let swl_addrs = get_env("SWL_ADDRS", "0.0.0.0");
  let swl_port: u16 = get_env("SWL_PORT", "11443").parse()?;
  let swl_scep_url = get_env("SWL_SCEP_URL", "http://127.0.0.1:3000/api/cert/verify");

  let apis_addrs = get_env("APIS_ADDRS", "0.0.0.0");
  let apis_port: u16 = get_env("APIS_PORT", "8081").parse()?;

  let (certs, key) = load_certificates(&swl_cert_path, &swl_key_path)?;
  let server_auth_roots = load_ca_certificate(&swl_ca_path)?;

  let server_config = create_server_config(certs, key, server_auth_roots)?;

  let server_addrs = (swl_addrs.clone(), swl_port).to_socket_addrs()?.next().ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::Other,
      format!("Failed to resolve address: {}:{}", swl_addrs, swl_port),
    )
  })?;
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

fn load_certificates(
  cert_path: &str,
  key_path: &str,
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), Box<dyn Error>> {
  let pem_cert = read_file(cert_path, "Server certificate file not found or failed to open")?;
  let der_cert = pem_to_der(&pem_cert).map_err(|e| {
    error!("{}: {}", "Failed to convert server certificate to DER", e);
    e
  })?;
  let cert = rustls::Certificate(der_cert);
  let pem_key = read_file(key_path, "Server key file not found or failed to open")?;
  let der_key = key_to_der(&pem_key).map_err(|e| {
    error!("{}: {}", "Failed to convert server key to DER", e);
    e
  })?;
  let key = rustls::PrivateKey(der_key);
  Ok((vec![cert], key))
}

fn load_ca_certificate(ca_path: &str) -> Result<rustls::RootCertStore, Box<dyn Error>> {
  let mut server_auth_roots = rustls::RootCertStore::empty();
  let pem_ca = read_file(ca_path, "Root certificate file not found or failed to open")?;
  let der_ca = pem_to_der(&pem_ca).map_err(|e| {
    error!("{}: {}", "Failed to convert root certificate to DER", e);
    e
  })?;
  server_auth_roots.add(&rustls::Certificate(der_ca))?;
  Ok(server_auth_roots)
}

fn create_server_config(
  certs: Vec<rustls::Certificate>,
  key: rustls::PrivateKey,
  server_auth_roots: rustls::RootCertStore,
) -> Result<quinn::ServerConfig, Box<dyn Error>> {
  let mut server_crypto = rustls::ServerConfig::builder()
    .with_safe_defaults()
    .with_client_cert_verifier(Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(
      server_auth_roots,
    )))
    .with_single_cert(certs, key)?;
  server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

  let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
  Arc::get_mut(&mut server_config.transport)
    .unwrap()
    .max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into())
    .keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL_SECS)))
    .max_idle_timeout(Some(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS).try_into()?));
  Ok(server_config)
}
