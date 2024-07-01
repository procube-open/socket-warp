use crate::hashmap::QUICMAP;
use crate::utils::der_to_pem;
use log::{error, info, warn};
use serde::Deserialize;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Deserialize, Debug)]
struct User {
  uid: String,
}
#[derive(Deserialize, Debug)]
struct UError {
  message: String,
}

pub async fn handle_quic_connection(conn: quinn::Connecting, scep_url: String) -> Result<(), Box<dyn Error>> {
  let connection = conn.await?;

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
  let response = client.get(&scep_url).header("X-Mtls-Clientcert", &encoded).send().await?;
  let status = response.status();

  if status.is_success() {
    info!("{} | Successfully verified client certificate", quic_id);
    let body = response.text().await?;
    let u: User = serde_json::from_str(&body)?;
    let mut map = QUICMAP.lock().await;
    if map.contains_key(&u.uid) && map.get(&u.uid).unwrap().close_reason().is_none() {
      error!("{} | Connection already exists for UID: {}", quic_id, u.uid);
      return Err("Connection already exists".into());
    }
    map.insert(u.uid, connection);
  } else {
    error!("{} | Failed to verify client certificate", quic_id);
    let body = response.text().await?;
    let e: UError = serde_json::from_str(&body)?;
    return Err(e.message.into());
  }

  Ok(())
}

pub async fn handle_stream(mut manager_stream: TcpStream, max_vector_size: usize, uid: &String, connect_addrs: String) {
  let map = QUICMAP.lock().await;
  let connection = if let Some(conn) = map.get(uid) {
    conn
  } else {
    error!("No QUIC connection found for UID: {}", uid);
    return;
  };

  //
  // got SendStream and RecvStream
  //
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
  info!("{} |Opened bi stream", id);

  tokio::spawn(async move {
    loop {
      let mut buf1 = vec![0; max_vector_size];
      let mut buf2 = vec![0; max_vector_size];

      //
      // Send edge server address
      //
      let concatenated = format!("{}|{}", id, connect_addrs);
      let mut bytes = concatenated.as_bytes().to_vec();
      bytes.resize(max_vector_size, 0);
      if let Err(e) = send.write_all(&bytes).await {
        error!("{} |Failed to write connection id: {}", id, e);
        return;
      };

      //
      // stream to stream copy loop
      //
      loop {
        tokio::select! {
          n = recv.read(&mut buf1) => match n {
            Ok(Some(n)) => {
              if let Err(e) = manager_stream.write_all(&buf1[0..n]).await {
                warn!("{} |Failed to write to manager stream: {}", id, e);
                  return;
                }
            },
            Ok(None) => break,
            Err(e) => {
                warn!("{} |manager stream failed to read from socket; err = {:?}", id, e);
                return;
            },
          },
          n = manager_stream.read(&mut buf2) => match n {
            Ok(0) => break,
            Ok(n) => {
              if let Err(e) = send.write_all(&buf2[0..n]).await {
                warn!("{} |Failed to write to QUIC send stream: {}", id, e);
                return;
              }
            },
            Err(e) => {
              warn!("{} |local server stream failed to read from socket; err = {:?}", id, e);
              return;
            },
          },
        }
      }
    }
  });
}
