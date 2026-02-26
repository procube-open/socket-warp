use crate::hashmap::QUICMAP;
use crate::quic::handle_stream;
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

#[post("/open")]
async fn open(json: web::Json<OpenObj>, task_map: web::Data<TaskMap>) -> impl Responder {
  let open_obj = json.into_inner();
  info!("OpenObj: {:?}", open_obj);

  {
    let quicmap = QUICMAP.read().await;
    if !quicmap.contains_key(&open_obj.uid) {
      return HttpResponse::InternalServerError().body("No QUIC connection exists for the specified UID.");
    }
  }

  let route = RouteInfo {
    uid: open_obj.uid,
    connect_address: open_obj.connect_address,
    connect_port: open_obj.connect_port,
    virtual_host: open_obj.virtual_host,
  };

  if upsert_route_on_existing_port(open_obj.port, route.clone(), task_map.get_ref()).await {
    return HttpResponse::Ok().body("Route updated on existing TcpListener");
  }

  let max_vector_size: usize = 1024;
  match TcpListener::bind(("0.0.0.0", open_obj.port)).await {
    Ok(listener) => {
      let listen_port = open_obj.port;
      let task_map_for_loop = task_map.get_ref().clone();
      let handle = task::spawn(async move {
        info!("TcpListener created successfully on port {}", listen_port);
        loop {
          match listener.accept().await {
            Ok((stream, peer_address)) => {
              let task_map_for_route = task_map_for_loop.clone();
              info!("Accepted connection from: {:?}", peer_address);
              tokio::spawn(async move {
                if let Some(selected_route) = select_route_for_stream(listen_port, &stream, &task_map_for_route).await {
                  let addr = format!("{}:{}", selected_route.connect_address, selected_route.connect_port);
                  handle_stream(stream, max_vector_size, &selected_route.uid, addr).await;
                } else {
                  warn!(
                    "No socket-warp route matched on port {}. Closing accepted connection.",
                    listen_port
                  );
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

      task_map.write().await.insert(
        open_obj.port,
        TaskInfo {
          routes: vec![route],
          handle,
        },
      );
      HttpResponse::Ok().body("TcpListener created successfully!")
    }
    Err(e) => {
      let body = format!("Failed to create TcpListener: {}", e);
      HttpResponse::InternalServerError().body(body)
    }
  }
}

async fn upsert_route_on_existing_port(port: u16, route: RouteInfo, task_map: &TaskMap) -> bool {
  let mut map = task_map.write().await;
  let Some(task_info) = map.get_mut(&port) else {
    return false;
  };

  let route_key = route.key();
  if let Some(existing_index) = task_info.routes.iter().position(|existing| existing.key() == route_key) {
    task_info.routes[existing_index] = route;
  } else {
    task_info.routes.push(route);
  }
  true
}

async fn select_route_for_stream(port: u16, stream: &tokio::net::TcpStream, task_map: &TaskMap) -> Option<RouteInfo> {
  let (routes, peeked_host) = {
    let map = task_map.read().await;
    let task_info = map.get(&port)?;
    if task_info.routes.len() == 1 {
      return task_info.routes.first().cloned();
    }

    let routes = task_info.routes.clone();
    drop(map);
    let host = extract_http_host(stream).await;
    (routes, host)
  };

  if let Some(host) = peeked_host {
    if let Some(route) = routes.iter().find(|route| route.key().as_deref() == Some(host.as_str())) {
      return Some(route.clone());
    }
  }

  routes.iter().find(|route| route.virtual_host.is_none()).cloned()
}

async fn extract_http_host(stream: &tokio::net::TcpStream) -> Option<String> {
  let mut buffer = vec![0; 4096];
  let bytes = stream.peek(&mut buffer).await.ok()?;
  if bytes == 0 {
    return None;
  }

  let request = String::from_utf8_lossy(&buffer[..bytes]);
  for line in request.lines() {
    if let Some((key, value)) = line.split_once(':') {
      if key.trim().eq_ignore_ascii_case("host") {
        return Some(normalize_host(value));
      }
    }
  }
  None
}

fn normalize_host(raw_host: &str) -> String {
  let host = raw_host.trim().to_lowercase();

  if host.starts_with('[') {
    if let Some(end) = host.find(']') {
      return host[1..end].to_string();
    }
    return host;
  }

  match host.split_once(':') {
    Some((hostname, _port)) => hostname.to_string(),
    None => host,
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
