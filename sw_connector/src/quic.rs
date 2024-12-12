use log::{error, info, warn};
use std::error::Error;
use tokio::net::TcpStream;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub async fn handle_stream(
  (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
  max_vector_size: usize,
) -> Result<(), Box<dyn Error>> {
  info!("new stream opened from agent");

  // receive address
  let (id, edge_server_addr) = receive_address(&mut recv, max_vector_size).await?;
  info!(
    "{} |Received edge server address from sw_listener: {}",
    id, edge_server_addr
  );

  // edge server connect
  let mut local_stream = match TcpStream::connect(edge_server_addr).await {
    Ok(stream) => stream,
    Err(e) => {
      error!("{} | Failed to connect to edge server: {}", id, e);
      return Err(e.into());
    }
  };
  info!("{} |connected to edge server", id);

  // stream to stream copy
  if let Err(e) = stream_to_stream_copy(&mut send, &mut recv, &mut local_stream, &id).await {
    error!("{} | Stream to stream copy failed: {}", id, e);
    return Err(e);
  }

  Ok(())
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

async fn stream_to_stream_copy(
  send: &mut quinn::SendStream,
  recv: &mut quinn::RecvStream,
  local_stream: &mut TcpStream,
  id: &str,
) -> Result<(), Box<dyn Error>> {
  let (mut local_read, mut local_write) = local_stream.split();
  info!("{} | Stream to stream copy started", id);
  tokio::select! {
    recv_result = tokio::io::copy(recv, &mut local_write) => {
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
    send_result = tokio::io::copy(&mut local_read, send) => {
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
  info!("{} | Stream to stream copy finished", id);
  Ok(())
}
