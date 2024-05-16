use std::net::ToSocketAddrs;
use std::{
  env,
  error::Error,
  fs,
  io::{self},
  sync::Arc,
};

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use swc_lib::utils::{key_to_der, pem_to_der};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Settings {
  settings: HashMap<String, HashMap<String, String>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  env::set_var("RUST_LOG", "info");
  env_logger::init();
  //
  // Property Settings
  //
  let json_file = "./settings.json";
  let json_reader = io::BufReader::new(fs::File::open(json_file)?);
  let _json_object: Settings = serde_json::from_reader(json_reader)?;

  //
  // SSL: CA Certificate Settings
  //
  let mut roots = rustls::RootCertStore::empty();
  if let Ok(cert) = fs::read(_json_object.settings["path_to_ca_cert"]["value"].to_string()) {
    let cert = pem_to_der(&cert)?;
    roots.add(&rustls::Certificate(cert))?;
  } else if let Err(e) = fs::read(_json_object.settings["path_to_ca_cert"]["value"].to_string()) {
    if e.kind() == io::ErrorKind::NotFound {
      info!("local server certificate not found");
    } else {
      info!("failed to open local server certificate: {}", e);
    }
  }

  //
  // SSL: Client Certificate and Private Key Settings
  //

  let (certs, key) = {
    let cert = fs::read(_json_object.settings["path_to_client_cert"]["value"].to_string())?;
    let cert = pem_to_der(&cert)?;
    let cert = rustls::Certificate(cert);
    let key = fs::read(_json_object.settings["path_to_client_key"]["value"].to_string())?;
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

  let server_addrs = (
    _json_object.settings["server_name"]["value"].to_string(),
    _json_object.settings["service_port"]["value"].parse().unwrap(),
  )
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to resolve address"))?;
  let host = _json_object.settings["server_name"]["value"].to_string();

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
      let stream = connection.accept_bi().await;
      let stream = match stream {
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
      let _json_object_clone = _json_object.clone();
      let fut = handle_request(stream);
      tokio::spawn(async move {
        if let Err(e) = fut.await {
          info!("failed: {reason}", reason = e.to_string());
        }
      });
    }
  }
  .await?;
  Ok(())
}

async fn handle_request((mut send, mut recv): (quinn::SendStream, quinn::RecvStream)) -> Result<(), Box<dyn Error>> {
  loop {
    //
    // QUIC stream
    //
    info!("new stream opened from agent");
    let max_vector_size = "1024".to_string();
    let max_vector_size = max_vector_size.clone().parse().unwrap();

    //
    //Receive address
    //
    let mut buf0 = vec![0; max_vector_size];
    recv.read_exact(&mut buf0).await?;
    let hellostr: String = String::from_utf8(buf0.to_vec())?.chars().filter(|&c| c != '\0').collect();
    let helloarray: Vec<&str> = hellostr.split("|").collect();
    let id = helloarray[0];
    let edge_server_addr = helloarray[1];
    info!(
      "{} |Received edge server address from sw_listener: {}",
      id, edge_server_addr
    );

    //
    // stream to stream copy
    //
    let mut buf1 = vec![0; max_vector_size];
    let mut buf2 = vec![0; max_vector_size];

    //
    // edge server connect
    //
    info!("{} |connecting to edge server: {}", id, edge_server_addr);
    let mut local_stream = TcpStream::connect(edge_server_addr).await?;
    info!("{} |connected to edge server", id);
    loop {
      tokio::select! {
          n = recv.read(&mut buf1) => {
              debug!("{} |local server read ...",id);
              match n {
                  Ok(None) => {
                      debug!("{} |local server read None ... break", id);
                      break;
                  },
                  Ok(n) => {
                      let n1 = n.expect("invalid buffer");
                      debug!("{} |llocal server read {} >>> manager client", id, n1);
                      local_stream.write_all(&buf1[0..n1]).await?;
                  },
                  Err(e) => {
                      warn!("{} |manager stream failed to read from socket; err = {:?}",id, e);
                      return Err(e.into());
                  },
              };
              debug!("{} |  ... local server read done",id);
          }
          n = local_stream.read(&mut buf2) => {
              debug!("manager client read ...");
              match n {
                  Ok(0) => {
                      debug!("{} |manager server read 0 ... break",id);
                      break;
                  },
                  Ok(n) => {
                      debug!("{} |manager stream read {} >>> local server",id, n);
                      send.write_all(&buf2[0..n]).await?;
                  },
                  Err(e) => {
                      warn!("{} |local server stream failed to read from socket; err = {:?}",id, e);
                      return Err(e.into());
                  }
              };
              debug!("{} |  ... manager read done",id);
          }
      };
    }
    info!("complete");
  }
}
