use crate::hashmap::QUICMAP;
use crate::quic::handle_stream;
use crate::virtual_host::{normalize_host, read_host};
use actix_web::{delete, get, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task;

type TaskMap = Arc<RwLock<HashMap<u16, TaskInfo>>>;

#[derive(Debug, Serialize, Deserialize)]
struct OpenObj {
  uid: String,
  port: u16,
  connect_address: String,
  connect_port: u16,
  virtual_host: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CloseObj {
  port: u16,
}

#[derive(Debug)]
struct TaskInfo {
  routes: Vec<RouteInfo>,
  handle: task::JoinHandle<()>,
}

#[derive(Debug, Clone)]
struct RouteInfo {
  uid: String,
  connect_address: String,
  connect_port: u16,
  virtual_host: Option<String>,
}

impl RouteInfo {
  fn key(&self) -> Option<String> {
    self.virtual_host.as_deref().map(normalize_host)
  }
}

fn select_route(routes: &[RouteInfo], host: Option<&str>) -> Option<RouteInfo> {
  host.and_then(|host| routes.iter().find(|route| route.key().as_deref() == Some(host)))
    .or_else(|| routes.iter().find(|route| route.virtual_host.is_none()))
    .cloned()
}

fn upsert_route(routes: &mut Vec<RouteInfo>, route: RouteInfo) {
  let key = route.key();
  if let Some(existing) = routes.iter_mut().find(|existing| existing.key() == key) {
    *existing = route;
  } else {
    routes.push(route);
  }
}

#[post("/open")]
async fn open(json: web::Json<OpenObj>, task_map: web::Data<TaskMap>) -> impl Responder {
  let open_obj = json.into_inner();
  info!("OpenObj: {:?}", open_obj);
  if !QUICMAP.read().await.contains_key(&open_obj.uid) {
    return HttpResponse::InternalServerError().body("No QUIC connection exists for the specified UID.");
  }
  let port = open_obj.port;
  let route = RouteInfo {
    uid: open_obj.uid,
    connect_address: open_obj.connect_address,
    connect_port: open_obj.connect_port,
    virtual_host: open_obj.virtual_host,
  };
  let mut map = task_map.write().await;
  if let Some(task_info) = map.get_mut(&port) {
    upsert_route(&mut task_info.routes, route);
    return HttpResponse::Ok().body("Route updated on existing TcpListener");
  }

  match TcpListener::bind(("0.0.0.0", port)).await {
    Ok(listener) => {
      let task_map_for_loop = task_map.get_ref().clone();
      let handle = task::spawn(async move {
        info!("TcpListener created successfully on port {}", port);
        loop {
          match listener.accept().await {
            Ok((mut stream, peer_address)) => {
              info!("Accepted connection from: {:?}", peer_address);
              let task_map = task_map_for_loop.clone();
              tokio::spawn(async move {
                let routes = match task_map.read().await.get(&port) {
                  Some(info) => info.routes.clone(),
                  None => return,
                };
                let (host, prefix) = if routes.iter().all(|route| route.virtual_host.is_none()) {
                  (None, Vec::new())
                } else {
                  read_host(&mut stream).await
                };
                if let Some(route) = select_route(&routes, host.as_deref()) {
                  let addr = format!("{}:{}", route.connect_address, route.connect_port);
                  handle_stream(stream, 1024, &route.uid, addr, prefix).await;
                } else {
                  warn!("No socket-warp route matched on port {}. Closing accepted connection.", port);
                }
              });
            }
            Err(e) => {
              info!("Failed to accept connection: {}", e);
              break;
            }
          }
        }
      });
      map.insert(
        port,
        TaskInfo {
          routes: vec![route],
          handle,
        },
      );
      return HttpResponse::Ok().body("TcpListener created successfully!");
    }
    Err(e) => {
      let body = format!("Failed to create TcpListener: {}", e);
      return HttpResponse::InternalServerError().body(body);
    }
  }
}

#[delete("/close")]
async fn close(json: web::Json<CloseObj>, task_map: web::Data<TaskMap>) -> impl Responder {
  if let Some(task_info) = task_map.write().await.remove(&json.port) {
    task_info.handle.abort();
    return HttpResponse::Ok().body(format!("Task {} canceled", &json.port));
  } else {
    return HttpResponse::NotFound().body(format!("Task {} not found", &json.port));
  }
}

#[get("/list")]
async fn list(task_map: web::Data<TaskMap>) -> impl Responder {
  let task_map = task_map.read().await;
  let list: Vec<_> = task_map
    .iter()
    .flat_map(|(&port, task_info)| {
      task_info.routes.iter().map(move |route| {
        json!({
          "port": port,
          "uid": route.uid,
          "connect_address": route.connect_address,
          "connect_port": route.connect_port,
          "virtual_host": route.virtual_host
        })
      })
    })
    .collect();
  HttpResponse::Ok().json(list)
}

pub async fn create_app(addr: &str, port: u16) {
  info!("API listening on {}:{}", addr, port);
  let task_map: TaskMap = Arc::new(RwLock::new(HashMap::new()));
  let app = move || {
    App::new()
      .app_data(web::Data::new(task_map.clone()))
      .wrap(Logger::default())
      .service(open)
      .service(close)
      .service(list)
  };
  HttpServer::new(app).bind((addr, port)).expect("Cannot bind to address").run().await.expect("Server failed");
}

#[cfg(test)]
mod tests {
  use super::*;

  fn route(host: Option<&str>, uid: &str) -> RouteInfo {
    RouteInfo {
      uid: uid.to_string(),
      connect_address: "localhost".to_string(),
      connect_port: 80,
      virtual_host: host.map(str::to_string),
    }
  }

  #[test]
  fn selects_matching_host_or_default() {
    let routes = vec![route(Some("Example.COM:80"), "host"), route(None, "default")];
    assert_eq!(select_route(&routes, Some("example.com")).unwrap().uid, "host");
    assert_eq!(select_route(&routes, Some("other.com")).unwrap().uid, "default");
    assert_eq!(select_route(&routes, None).unwrap().uid, "default");
    assert!(select_route(&routes[..1], Some("other.com")).is_none());
    assert!(select_route(&routes[..1], None).is_none());
  }

  #[test]
  fn replaces_same_host_without_replacing_other_routes() {
    let mut routes = vec![route(Some("example.com"), "old"), route(None, "default")];
    upsert_route(&mut routes, route(Some("EXAMPLE.COM:80"), "new"));
    upsert_route(&mut routes, route(Some("other.com"), "other"));
    assert_eq!(routes.len(), 3);
    assert_eq!(select_route(&routes, Some("example.com")).unwrap().uid, "new");
    assert_eq!(select_route(&routes, None).unwrap().uid, "default");
  }
}
