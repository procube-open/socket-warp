use crate::hashmap::QUICMAP;
use crate::quic::handle_stream;
use actix_web::{delete, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::task;

type TaskMap = Arc<Mutex<HashMap<u16, task::JoinHandle<()>>>>;

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

#[post("/open")]
async fn open(json: web::Json<OpenObj>, task_map: web::Data<TaskMap>) -> impl Responder {
  let quicmap = QUICMAP.lock().await;
  let max_vector_size: usize = 1024;
  info!("opening port {}", json.port);
  let port = json.port.clone();
  if quicmap.contains_key(&json.uid) {
    match TcpListener::bind(("0.0.0.0", json.port)).await {
      Ok(listener) => {
        let task = task::spawn(async move {
          info!("TcpListener created successfully!");
          loop {
            let (stream, _) = listener.accept().await.unwrap();
            info!("Accepted connection from: {:?}", stream.peer_addr());
            let addr = format!("{}:{}", &json.connect_address, &json.connect_port.to_string());
            handle_stream(stream, max_vector_size, &json.uid, addr).await;
          }
        });
        task_map.lock().unwrap().insert(port, task);
        HttpResponse::Ok().body("TcpListener created successfully!")
      }
      Err(e) => {
        let body = format!("Failed to create TcpListener: {}", e);
        HttpResponse::InternalServerError().body(body)
      }
    }
  } else {
    HttpResponse::InternalServerError().body("No QUIC connection exists for the specified UID.")
  }
}

#[delete("/close")]
async fn close(json: web::Json<CloseObj>, task_map: web::Data<TaskMap>) -> impl Responder {
  if let Some(handle) = task_map.lock().unwrap().remove(&json.port) {
    handle.abort(); // タスクの中断
    HttpResponse::Ok().body(format!("Task {} canceled", &json.port))
  } else {
    HttpResponse::NotFound().body(format!("Task {} not found", &json.port))
  }
}

pub async fn create_app(addr: &str, port: u16) -> () {
  info!("API listening on {}:{}", addr, port.to_string());
  let task_map: TaskMap = Arc::new(Mutex::new(HashMap::new()));
  let app =
    move || App::new().app_data(web::Data::new(task_map.clone())).wrap(Logger::default()).service(open).service(close);
  HttpServer::new(app).bind((addr, port)).expect("Can not bind").run().await.expect("Server failed");
}
