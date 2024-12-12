use log::{debug, error, info, warn};
use quinn_proto::crypto::rustls::QuicServerConfig;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::env;
use std::net::ToSocketAddrs;
use std::time::Duration;
use std::{error::Error, io, sync::Arc};
use swl_lib::apis::create_app;
use swl_lib::quic::handle_quic_connection;
use swl_lib::utils::get_env;
use tokio::signal;

const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const MAX_CONCURRENT_UNI_STREAMS: u8 = 0;
const KEEP_ALIVE_INTERVAL_SECS: u64 = 50;
const MAX_IDLE_TIMEOUT_SECS: u64 = 60;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let swl_cert_path = get_env("SWL_CERT_PATH", "../Certs_and_Key/swl-1/cert.pem").to_string();
  let swl_key_path = get_env("SWL_KEY_PATH", "../Certs_and_Key/swl-1/key.pem").to_string();
  let swl_ca_path = get_env("SWL_CA_PATH", "../Certs_and_Key/swl-1/ca.crt").to_string();
  let swl_addrs = get_env("SWL_ADDRS", "0.0.0.0");
  let swl_port: u16 = get_env("SWL_PORT", "11443").parse()?;
  let swl_scep_url = get_env("SWL_SCEP_URL", "http://127.0.0.1:3000/api/cert/verify");

  let apis_addrs = get_env("APIS_ADDRS", "0.0.0.0");
  let apis_port: u16 = get_env("APIS_PORT", "8081").parse()?;

  let swl_log_level = get_env("SWL_LOG_LEVEL", "info").to_string();
  env::set_var("RUST_LOG", &swl_log_level);
  env_logger::init();

  debug!("SWL_LOG_LEVEL: {}", swl_log_level);
  debug!("SWL_CERT_PATH: {}", swl_cert_path);
  debug!("SWL_KEY_PATH: {}", swl_key_path);
  debug!("SWL_CA_PATH: {}", swl_ca_path);
  debug!("SWL_ADDRS: {}", swl_addrs);
  debug!("SWL_PORT: {}", swl_port);
  debug!("SWL_SCEP_URL: {}", swl_scep_url);
  debug!("APIS_ADDRS: {}", apis_addrs);
  debug!("APIS_PORT: {}", apis_port);

  let (certs, key) = load_certificates(&swl_cert_path, &swl_key_path)?;
  debug!("Loaded certificates and key");

  let server_auth_roots = load_ca_certificate(&swl_ca_path)?;
  debug!("Loaded CA certificate");

  let server_config = create_server_config(certs, key, server_auth_roots)?;
  debug!("Created server config");

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
  };

  Ok(())
}

fn load_certificates(
  cert_path: &str,
  key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error>> {
  let cert: CertificateDer<'static> = CertificateDer::from_pem_file(cert_path).unwrap();
  let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(key_path).unwrap();
  Ok((vec![cert], key))
}

fn load_ca_certificate(ca_path: &str) -> Result<quinn::rustls::RootCertStore, Box<dyn Error>> {
  let mut server_auth_roots = quinn::rustls::RootCertStore::empty();
  let root: CertificateDer<'static> = CertificateDer::from_pem_file(ca_path)?;
  server_auth_roots.add(root)?;
  Ok(server_auth_roots)
}

fn create_server_config(
  certs: Vec<CertificateDer<'static>>,
  key: PrivateKeyDer<'static>,
  roots: quinn::rustls::RootCertStore,
) -> Result<quinn::ServerConfig, Box<dyn Error>> {
  let cert_verifier = quinn::rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
  let mut server_crypto =
    quinn::rustls::ServerConfig::builder().with_client_cert_verifier(cert_verifier).with_single_cert(certs, key)?;
  server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
  let mut server_config =
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(Arc::new(server_crypto))?));
  Arc::get_mut(&mut server_config.transport)
    .unwrap()
    .max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into())
    .keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL_SECS)))
    .max_idle_timeout(Some(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS).try_into()?));
  Ok(server_config)
}
