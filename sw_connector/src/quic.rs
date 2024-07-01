use log::{info, warn};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub async fn handle_request(
  (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<(), Box<dyn Error>> {
  loop {
    //
    // QUIC stream
    //
    info!("new stream opened from agent");
    let max_vector_size = "1024".to_string();
    let max_vector_size = max_vector_size.clone().parse().unwrap();

    //
    // receive address
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
    // edge server connect
    //
    let mut local_stream = TcpStream::connect(edge_server_addr).await?;
    info!("{} |connected to edge server", id);

    //
    // stream to stream copy
    //
    let mut buf1 = vec![0; max_vector_size];
    let mut buf2 = vec![0; max_vector_size];
    loop {
      tokio::select! {
        n = recv.read(&mut buf1) => match n {
          Ok(Some(n1)) => {
            if let Err(e) = local_stream.write_all(&buf1[0..n1]).await {
              warn!("{} | Failed to write to manager stream: {:?}", id, e);
              return Err(e.into());
            }
          },
          Ok(None) => break,
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
  }
}
