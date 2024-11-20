use crate::hashmap::QUICMAP;
use crate::quic::handle_stream;
use actix_web::{delete, get, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder};
use log::info;
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
}

#[derive(Debug, Serialize, Deserialize)]
struct CloseObj {
  port: u16,
}

#[derive(Debug)]
struct TaskInfo {
  uid: String,
  connect_address: String,
  connect_port: u16,
  handle: task::JoinHandle<()>,
}

#[post("/open")]
async fn open(json: web::Json<OpenObj>, task_map: web::Data<TaskMap>) -> impl Responder {
  let quicmap = QUICMAP.read().await;
  let max_vector_size: usize = 1024;
  info!("OpenObj: {:?}", json);
  let port = json.port.clone();
  let uid = json.uid.clone();
  let connect_address = json.connect_address.clone();
  let connect_port = json.connect_port.clone();
  if !quicmap.contains_key(&json.uid) {
    return HttpResponse::InternalServerError().body("No QUIC connection exists for the specified UID.");
  }
  match TcpListener::bind(("0.0.0.0", json.port)).await {
    Ok(listener) => {
      let task = task::spawn({
        let uid = json.uid.clone();
        let connect_address = json.connect_address.clone();
        let connect_port = json.connect_port.clone();
        async move {
          info!("TcpListener created successfully on port {}", json.port);
          loop {
            match listener.accept().await {
              Ok((stream, peer_address)) => {
                info!("Accepted connection from: {:?}", peer_address);
                let addr = format!("{}:{}", connect_address, connect_port);
                handle_stream(stream, max_vector_size, &uid, addr).await;
              }
              Err(e) => {
                info!("Failed to accept connection: {}", e);
                break;
              }
            }
          }
        }
      });
      task_map.write().await.insert(
        port,
        TaskInfo {
          uid,
          connect_address,
          connect_port,
          handle: task,
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
    .map(|(&port, task_info)| {
      json!({
        "port": port,
        "uid": task_info.uid,
        "connect_address": task_info.connect_address,
        "connect_port": task_info.connect_port
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
