use quinn::rustls::server::Acceptor;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};

const MAX_PREFIX: usize = 64 * 1024;
const HOST_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn normalize_host(raw_host: &str) -> String {
  let host = raw_host.trim().to_ascii_lowercase();
  if let Some(bracketed) = host.strip_prefix('[') {
    if let Some((address, _)) = bracketed.split_once(']') {
      return address.to_string();
    }
    return host;
  }
  host.split_once(':').map_or(host.as_str(), |(name, _)| name).to_string()
}

fn http_host(prefix: &[u8]) -> Option<String> {
  let request = std::str::from_utf8(prefix).ok()?;
  let mut lines = request.split("\r\n");
  let mut request_line = lines.next()?.split_whitespace();
  request_line.next()?;
  request_line.next()?;
  if !request_line.next()?.starts_with("HTTP/1.") || request_line.next().is_some() {
    return None;
  }
  let mut host = None;
  for line in lines {
    if line.is_empty() {
      break;
    }
    let (name, value) = line.split_once(':')?;
    if name.eq_ignore_ascii_case("host") {
      if host.is_some() || value.trim().is_empty() {
        return None;
      }
      host = Some(normalize_host(value));
    }
  }
  host
}

pub(crate) async fn read_host(stream: &mut TcpStream) -> (Option<String>, Vec<u8>) {
  let deadline = Instant::now() + HOST_TIMEOUT;
  let mut prefix = Vec::new();
  let mut acceptor = Acceptor::default();
  loop {
    if prefix.len() == MAX_PREFIX {
      return (None, prefix);
    }
    let mut buffer = vec![0; (MAX_PREFIX - prefix.len()).min(4096)];
    let count = match timeout_at(deadline, stream.read(&mut buffer)).await {
      Ok(Ok(count)) if count > 0 => count,
      _ => return (None, prefix),
    };
    buffer.truncate(count);
    prefix.extend_from_slice(&buffer);

    if prefix[0] == 0x16 {
      let mut input = buffer.as_slice();
      while !input.is_empty() {
        match acceptor.read_tls(&mut input) {
          Ok(0) | Err(_) => return (None, prefix),
          Ok(_) => {}
        }
        match acceptor.accept() {
          Ok(Some(accepted)) => {
            return (accepted.client_hello().server_name().map(normalize_host), prefix);
          }
          Ok(None) => {}
          Err(_) => return (None, prefix),
        }
      }
    } else if !prefix[0].is_ascii_graphic() {
      return (None, prefix);
    } else if let Some(end) = prefix.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
      return (http_host(&prefix[..end + 4]), prefix);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use quinn::rustls::{ClientConfig, ClientConnection, RootCertStore};
  use std::sync::Arc;
  use tokio::io::AsyncWriteExt;
  use tokio::net::TcpListener;

  async fn fragmented_host(data: &[u8], split: usize) -> (Option<String>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    client.write_all(&data[..split]).await.unwrap();
    let handle = tokio::spawn(async move { read_host(&mut server).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    client.write_all(&data[split..]).await.unwrap();
    handle.await.unwrap()
  }

  #[tokio::test]
  async fn reads_fragmented_http_without_losing_bytes() {
    let request = b"GET / HTTP/1.1\r\nHoSt: Example.COM:8080\r\n\r\nbody";
    let (host, prefix) = fragmented_host(request, 20).await;
    assert_eq!(host.as_deref(), Some("example.com"));
    assert!(request.starts_with(&prefix));
    assert!(prefix.windows(4).any(|bytes| bytes == b"\r\n\r\n"));
  }

  #[tokio::test]
  async fn reads_fragmented_tls_client_hello_sni() {
    let config = ClientConfig::builder_with_provider(Arc::new(quinn::rustls::crypto::ring::default_provider()))
      .with_safe_default_protocol_versions().unwrap()
      .with_root_certificates(RootCertStore::empty())
      .with_no_client_auth();
    let mut client = ClientConnection::new(Arc::new(config), "Example.COM".try_into().unwrap()).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let (host, prefix) = fragmented_host(&hello, 8).await;
    assert_eq!(host.as_deref(), Some("example.com"));
    assert_eq!(prefix, hello);
  }

  #[tokio::test]
  async fn preserves_partial_request_on_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nHo").await.unwrap();
    let (host, prefix) = read_host(&mut server).await;
    assert_eq!(host, None);
    assert_eq!(prefix, b"GET / HTTP/1.1\r\nHo");
  }

  #[test]
  fn rejects_missing_or_ambiguous_http_host() {
    assert_eq!(http_host(b"GET / HTTP/1.1\r\n\r\n"), None);
    assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), None);
    assert_eq!(normalize_host("[::1]:8080"), "::1");
  }
}
