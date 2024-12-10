use crate::hashmap::QUICMAP;
use crate::utils::der_to_pem;
use log::{error, info, warn};
use serde::Deserialize;
use std::error::Error;
use tokio::net::TcpStream;

#[derive(Deserialize, Debug)]
struct User {
  uid: String,
}

pub async fn handle_quic_connection(conn: quinn::Connecting, scep_url: String) -> Result<(), Box<dyn Error>> {
  let connection = conn.await.map_err(|e| {
    error!("Failed to establish QUIC connection: {}", e);
    e
  })?;

  let quic_id = connection.stable_id();
  info!("{} | New QUIC connection established", quic_id);

  let certs = connection.peer_identity().unwrap().downcast::<Vec<rustls::Certificate>>().unwrap().pop().unwrap();
  let pem_data = der_to_pem(certs.as_ref())?;
  let pem_str = String::from_utf8(pem_data)?;

  //
  // Send client certificate to SCEP server for verification
  //
  let encoded = percent_encoding::utf8_percent_encode(&pem_str, percent_encoding::NON_ALPHANUMERIC).to_string();
  let client = reqwest::Client::new();
  let response = client.get(&scep_url).header("X-Mtls-Clientcert", &encoded).send().await.map_err(|e| {
    error!("Failed to send request to SCEP server: {}", e);
    e
  })?;
  let status = response.status();
  if !status.is_success() {
    let body = response.text().await.unwrap_or_else(|_| "Failed to read response body".to_string());
    error!(
      "Failed to verify client certificate. Status: {}, Body: {}",
      status, body
    );
    return Err("Failed to verify client certificate".into());
  }
  info!("{} | Successfully verified client certificate", quic_id);
  let body = response.text().await?;
  let u: User = serde_json::from_str(&body)?;
  let mut map = QUICMAP.write().await;
  if map.contains_key(&u.uid) && map.get(&u.uid).unwrap().close_reason().is_none() {
    error!("{} | Connection already exists for UID: {}", quic_id, u.uid);
    return Err("Connection already exists".into());
  }
  map.insert(u.uid, connection);

  Ok(())
}

pub async fn handle_stream(mut manager_stream: TcpStream, max_vector_size: usize, uid: &String, connect_addrs: String) {
  let map = QUICMAP.read().await;
  let connection = if let Some(conn) = map.get(uid) {
    conn
  } else {
    error!("No QUIC connection found for UID: {}", uid);
    return;
  };

  let (mut send, mut recv) = match connection.open_bi().await {
    Ok(streams) => streams,
    Err(e) => {
      error!("Failed to open bi stream: {}", e);
      return;
    }
  };
  let index = send.id().index();
  let quic_id = connection.stable_id();
  let id = format!("{}-{}", quic_id, index);
  info!("{} | Opened bi stream", id);

  if let Err(e) = send_edge_server_address(&mut send, &id, &connect_addrs, max_vector_size).await {
    error!("{} | Failed to send edge server address: {}", id, e);
    return;
  }

  tokio::spawn(async move {
    if let Err(e) = stream_to_stream_copy(&mut send, &mut recv, &mut manager_stream, &id).await {
      error!("{} | Stream to stream copy failed: {}", id, e);
    }
  });
}

async fn send_edge_server_address(
  send: &mut quinn::SendStream,
  id: &str,
  connect_addrs: &str,
  max_vector_size: usize,
) -> Result<(), Box<dyn Error>> {
  let concatenated = format!("{}|{}", id, connect_addrs);
  let mut bytes = concatenated.as_bytes().to_vec();
  bytes.resize(max_vector_size, 0);
  send.write_all(&bytes).await.map_err(|e| {
    error!("{} | Failed to write connection id: {}", id, e);
    e.into()
  })
}

async fn stream_to_stream_copy(
  send: &mut quinn::SendStream,
  recv: &mut quinn::RecvStream,
  manager_stream: &mut TcpStream,
  id: &str,
) -> Result<(), Box<dyn Error>> {
  let (mut manager_read, mut manager_write) = manager_stream.split();

  tokio::select! {
    recv_result = tokio::io::copy(recv, &mut manager_write) => {
      match recv_result {
        Ok(bytes_copied) => {
          info!("{} | Copied {} bytes from recv to manager stream", id, bytes_copied);
        }
        Err(e) => {
          warn!("{} | Failed to copy from recv to manager stream: {}", id, e);
          return Err(e.into());
        }
      }
    }
    send_result = tokio::io::copy(&mut manager_read, send) => {
      match send_result {
        Ok(bytes_copied) => {
          info!("{} | Copied {} bytes from manager stream to send", id, bytes_copied);
        }
        Err(e) => {
          warn!("{} | Failed to copy from manager stream to send: {}", id, e);
          return Err(e.into());
        }
      }
    }
  };

  Ok(())
}
