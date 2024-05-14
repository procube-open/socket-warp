use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

lazy_static! {
  pub static ref QUICMAP: Arc<Mutex<HashMap<String, quinn::Connection>>> = Arc::new(Mutex::new(HashMap::new()));
  pub static ref TCPMAP: Arc<Mutex<HashMap<u16, tokio::net::TcpListener>>> = Arc::new(Mutex::new(HashMap::new()));
}
