use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

lazy_static! {
  pub static ref HASHMAP: Arc<Mutex<HashMap<String, quinn::Connection>>> = Arc::new(Mutex::new(HashMap::new()));
}
