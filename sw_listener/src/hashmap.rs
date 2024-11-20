use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

lazy_static! {
  pub static ref QUICMAP: Arc<RwLock<HashMap<String, quinn::Connection>>> = Arc::new(RwLock::new(HashMap::new()));
}
