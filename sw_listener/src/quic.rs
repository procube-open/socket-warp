use crate::hashmap::QUICMAP;
use crate::utils::{der_to_pem, get_env};
use http::StatusCode;
use log::{debug, info, warn};
use reqwest::Client;
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

pub async fn handle_quic_connection(conn: quinn::Connecting) -> Result<(), Box<dyn Error>> {
  //
  // handle QUIC connction (thread for each sw_connector)
  //
  let connection = conn.await?;

  info!("QUIC established");

  let c = &connection.peer_identity().unwrap().downcast::<Vec<rustls::Certificate>>().unwrap()[0];
  let pem_data = der_to_pem(c.as_ref())?;
  let s = String::from_utf8(pem_data)?;
  let mut encoded = String::from("");
  url_escape::encode_path_to_string(s.to_string(), &mut encoded);
  let client = Client::new();
  let url = get_env("SCEP_SERVER_URL", "http://127.0.0.1:3001/userObject");
  let response = match client.get(url).header("X-Mtls-Clientcert", encoded).send().await {
    Ok(res) => res,
    Err(error) => return Err(Box::new(error)),
  };
  let status = response.status();

  if StatusCode::is_success(&status) {
    info!("Client certificate verified");
    let body = response.text().await?;
    let u: User = serde_json::from_str(&body)?;
    let mut map = QUICMAP.lock().await;
    map.insert(u.uid, connection);
  } else {
    warn!("{}", status);
    let body = response.text().await?;
    let e: UError = serde_json::from_str(&body)?;
    warn!("{}", e.message);
  }
  Ok(())
}

pub async fn handle_stream(mut manager_stream: TcpStream, max_vector_size: usize, uid: &String, connect_addrs: String) {
  let map = QUICMAP.lock().await;
  let connection = match map.get(uid) {
    Some(conn) => conn,
    None => {
      warn!("No QUIC connection found for UID: {}", uid);
      return;
    }
  };
  let id = format!("{}|", connection.stable_id().to_string());

  // got SendStream and RecvStream
  let (mut send, mut recv) = match connection.open_bi().await {
    Ok(streams) => streams,
    Err(e) => {
      warn!("{} |Failed to open bi stream: {}", id, e);
      return;
    }
  };

  tokio::spawn(async move {
    loop {
      let mut buf1 = vec![0; max_vector_size];
      let mut buf2 = vec![0; max_vector_size];

      //
      // Send edge server address
      //
      if let Err(e) = send.write_all(id.as_bytes()).await {
        warn!("{} |Failed to write connection id: {}", id, e);
        return;
      }
      if let Err(e) = send.write_all(connect_addrs.as_bytes()).await {
        warn!("{} |Failed to write address: {}", id, e);
        return;
      }
      if let Err(e) =
        send.write_all(&buf1[0..max_vector_size - id.as_bytes().len() - connect_addrs.as_bytes().len()]).await
      {
        warn!("{} |Failed to write escape chars: {}", id, e);
        return;
      }

      //
      // stream to stream copy loop
      //
      loop {
        tokio::select! {
            n = recv.read(&mut buf1) => {
                match n {
                    Ok(None) => {
                        debug!("{} |local server read None ... break",id);
                        break;
                    },
                    Ok(n) => {
                        let n1 = match n {
                            Some(n) => n,
                            None => {
                                warn!("{} |Failed to get read length",id);
                                return;
                            },
                        };
                        debug!("{} |local server {} bytes >>> manager_stream",id, n1);
                        if let Err(e) = manager_stream.write_all(&buf1[0..n1]).await {
                            warn!("{} |Failed to write to manager stream: {}",id, e);
                            return;
                        }
                    },
                    Err(e) => {
                        warn!("{} |manager stream failed to read from socket; err = {:?}",id, e);
                        return;
                    },
                };
                debug!("{} |  ... local server read done",id);
            }
            n = manager_stream.read(&mut buf2) => {
                debug!("{} |manager client read ...",id);
                match n {
                    Ok(0) => {
                        debug!("{} |manager server read 0 ... break",id);
                        break;
                    },
                    Ok(n) => {
                        debug!("{} |manager client {} bytes >>> local server",id,n);
                        if let Err(e) = send.write_all(&buf2[0..n]).await {
                            warn!("{} |Failed to write to QUIC send stream: {}",id, e);
                            return;
                        }
                    },
                    Err(e) => {
                        warn!("{} |local server stream failed to read from socket; err = {:?}",id, e);
                        return;
                    }
                };
                debug!("{} |  ... manager read done",id);
            }
        };
      }
    }
  });
}
