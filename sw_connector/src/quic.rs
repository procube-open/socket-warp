use log::{error, info, warn};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub async fn handle_stream(
  (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
  max_vector_size: usize,
) -> Result<(), Box<dyn Error>> {
  loop {
    info!("new stream opened from agent");

    // receive address
    let (id, edge_server_addr) = receive_address(&mut recv, max_vector_size).await?;
    info!(
      "{} |Received edge server address from sw_listener: {}",
      id, edge_server_addr
    );

    // edge server connect
    let mut local_stream = TcpStream::connect(edge_server_addr).await?;
    info!("{} |connected to edge server", id);

    // stream to stream copy
    if let Err(e) = stream_to_stream_copy_loop(&mut send, &mut recv, &mut local_stream, &id, max_vector_size).await {
      error!("{} | Stream to stream copy loop failed: {}", id, e);
      return Err(e);
    }
  }
}

async fn receive_address(
  recv: &mut quinn::RecvStream,
  max_vector_size: usize,
) -> Result<(String, String), Box<dyn Error>> {
  let mut buf0 = vec![0; max_vector_size];
  recv.read_exact(&mut buf0).await?;
  let hellostr: String = String::from_utf8(buf0.to_vec())?.chars().filter(|&c| c != '\0').collect();
  let helloarray: Vec<&str> = hellostr.split('|').collect();
  if helloarray.len() != 2 {
    return Err("Invalid address format".into());
  }
  Ok((helloarray[0].to_string(), helloarray[1].to_string()))
}

async fn stream_to_stream_copy_loop(
  send: &mut quinn::SendStream,
  recv: &mut quinn::RecvStream,
  local_stream: &mut TcpStream,
  id: &str,
  max_vector_size: usize,
) -> Result<(), Box<dyn Error>> {
  let mut buf1 = vec![0; max_vector_size];
  let mut buf2 = vec![0; max_vector_size];

  loop {
    tokio::select! {
      n = recv.read(&mut buf1) => match n {
        Ok(None) => break,
        Ok(Some(n1)) => {
          if let Err(e) = local_stream.write_all(&buf1[0..n1]).await {
            warn!("{} | Failed to write to manager stream: {:?}", id, e);
            return Err(e.into());
          }
        },
        Err(e) => {
          warn!("{} | Manager stream failed to read from socket; err = {:?}", id, e);
          return Err(e.into());
        },
      },
      n = local_stream.read(&mut buf2) => match n {
        Ok(0) => break,
        Ok(n) => {
          if let Err(e) = send.write_all(&buf2[0..n]).await {
            warn!("{} | Failed to write to QUIC send stream: {:?}", id, e);
            return Err(e.into());
          }
        },
        Err(e) => {
          warn!("{} | Local server stream failed to read from socket; err = {:?}", id, e);
          return Err(e.into());
        }
      }
    }
  }
  Ok(())
}
