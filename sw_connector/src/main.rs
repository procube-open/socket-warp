use log::{error, info};
use quinn::rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use quinn_proto::crypto::rustls::QuicClientConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{
  env,
  error::Error,
  fs::File,
  io::{self, Read},
  net::ToSocketAddrs,
  sync::Arc,
};
use swc_lib::quic::{handle_stream, ALPN_QUIC_HTTP};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Config {
  client_cert_path: String,
  client_key_path: String,
  ca_cert_path: String,
  server_name: String,
  service_port: u16,
}

const KEEP_ALIVE_INTERVAL_SECS: u64 = 50;
const MAX_IDLE_TIMEOUT_SECS: u64 = 60;
const MAX_VECTOR_SIZE: usize = 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  env::set_var("RUST_LOG", "info");
  env_logger::init();

  let config = load_config("settings.json")?;
  let (certs, key) = load_client_cert_and_key(&config)?;
  let client_auth_roots = load_ca_cert(&config)?;

  let client_config = configure_client(certs, key, client_auth_roots)?;
  let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
  endpoint.set_default_client_config(client_config);

  let server_addrs = resolve_server_address(&config)?;
  let host = config.server_name.clone();

  info!("QUIC connecting to {} at {}", server_addrs, host);
  let connection = endpoint.connect(server_addrs, &host)?.await?;
  info!("QUIC connected");

  info!("Starting to wait for QUIC streams");
  wait_for_quic_stream(connection).await?;
  info!("Finished waiting for QUIC streams");

  Ok(())
}

fn load_config(file_path: &str) -> Result<Config, Box<dyn Error>> {
  let mut file = File::open(file_path)?;
  let mut contents = String::new();
  file.read_to_string(&mut contents)?;
  let config: Config = serde_json::from_str(&contents)?;
  Ok(config)
}

fn load_client_cert_and_key(
  config: &Config,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error>> {
  let cert: CertificateDer<'static> = CertificateDer::from_pem_file(&config.client_cert_path)?;
  let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(&config.client_key_path)?;
  Ok((vec![cert], key))
}

fn load_ca_cert(config: &Config) -> Result<quinn::rustls::RootCertStore, Box<dyn Error>> {
  let mut client_auth_roots = quinn::rustls::RootCertStore::empty();
  let root: CertificateDer<'static> = CertificateDer::from_pem_file(&config.ca_cert_path)?;
  client_auth_roots.add(root)?;
  Ok(client_auth_roots)
}

fn configure_client(
  certs: Vec<CertificateDer<'static>>,
  key: PrivateKeyDer<'static>,
  client_auth_roots: quinn::rustls::RootCertStore,
) -> Result<quinn::ClientConfig, Box<dyn Error>> {
  let mut client_crypto = quinn::rustls::ClientConfig::builder()
    .with_root_certificates(client_auth_roots)
    .with_client_auth_cert(certs, key)
    .expect("invalid client auth certs/key");
  client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

  let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
  let mut transport_config = quinn::TransportConfig::default();
  transport_config
    .keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL_SECS)))
    .max_idle_timeout(Some(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS).try_into()?));
  client_config.transport_config(Arc::new(transport_config));

  Ok(client_config)
}

fn resolve_server_address(config: &Config) -> Result<std::net::SocketAddr, Box<dyn Error>> {
  let server_addrs = (config.server_name.clone(), config.service_port)
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to resolve address"))?;
  Ok(server_addrs)
}

async fn wait_for_quic_stream(connection: quinn::Connection) -> Result<(), Box<dyn Error>> {
  loop {
    let stream = match connection.accept_bi().await {
      Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
        info!("connection closed by application");
        return Ok(());
      }
      Err(e) => {
        error!("connection error: {:?}", e);
        return Err(e.into());
      }
      Ok(s) => s,
    };
    tokio::spawn(async move {
      if let Err(e) = handle_stream(stream, MAX_VECTOR_SIZE).await {
        error!("failed: {reason}", reason = e.to_string());
      }
    });
  }
}
