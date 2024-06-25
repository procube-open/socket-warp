use std::{
  env,
  error::Error,
  fs::{self, File},
  io::{self, Read},
  sync::Arc,
  net::ToSocketAddrs
};

use log::{error, info};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use swc_lib::quic::{handle_request, ALPN_QUIC_HTTP};
use swc_lib::utils::{key_to_der, pem_to_der};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Config {
  client_cert_path: String,
  client_key_path: String,
  ca_cert_path: String,
  server_name: String,
  service_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  env::set_var("RUST_LOG", "info");
  env_logger::init();

  //
  // Property Settings
  //
  let file_path = "settings.json";
  let mut file = File::open(file_path)?;
  let mut contents = String::new();
  file.read_to_string(&mut contents)?;

  let config: Config = serde_json::from_str(&contents)?;

  //
  // SSL: CA Certificate Settings
  //
  let mut roots = rustls::RootCertStore::empty();
  if let Ok(cert) = fs::read(&config.ca_cert_path) {
    let cert = pem_to_der(&cert)?;
    roots.add(&rustls::Certificate(cert))?;
  } else {
    info!("Local server certificate not found or failed to open");
  }

  //
  // SSL: Client Certificate and Private Key Settings
  //
  let (certs, key) = {
    let cert = fs::read(&config.client_cert_path)?;
    let cert = pem_to_der(&cert)?;
    let cert = rustls::Certificate(cert);
    let key = fs::read(&config.client_key_path)?;
    let key = key_to_der(&key)?;
    let key = rustls::PrivateKey(key);
    (vec![cert], key)
  };

  //
  // Client Configuration and QUIC endpoint Settings
  //
  let mut client_crypto = rustls::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(roots)
    .with_client_auth_cert(certs, key)
    .expect("invalid client auth certs/key");
  client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

  let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
  let mut transport_config = quinn::TransportConfig::default();
  transport_config
    .keep_alive_interval(Some(Duration::from_secs(50)))
    .max_idle_timeout(Some(Duration::from_secs(55).try_into()?));
  client_config.transport_config(Arc::new(transport_config));

  let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
  endpoint.set_default_client_config(client_config);

  let server_addrs = (config.server_name.clone(), config.service_port)
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to resolve address"))?;
  let host = config.server_name;

  //
  // connect QUIC connection to sw_listener
  //
  info!("QUIC connecting to {} at {}", server_addrs, host);
  let connection = endpoint.connect(server_addrs, &host)?.await?;
  info!("QUIC connected");

  //
  // wait QUIC stream from sw_listener for each tunnel
  //
  async {
    loop {
      let stream = match connection.accept_bi().await {
        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
          info!("connection closed");
          return Ok(());
        }
        Err(e) => {
          info!("connection errored");
          return Err(e);
        }
        Ok(s) => s,
      };
      tokio::spawn(async move {
        if let Err(e) = handle_request(stream).await {
          error!("failed: {reason}", reason = e.to_string());
        }
      });
    }
  }
  .await?;

  Ok(())
}
