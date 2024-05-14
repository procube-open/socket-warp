use crate::hashmap::{QUICMAP, TCPMAP};
use crate::quic::handle_stream;
use actix_web::{delete, post, web, App, HttpResponse, HttpServer, Responder};
use log::info;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

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
async fn open(json: web::Json<OpenObj>) -> impl Responder {
  let quicmap = QUICMAP.lock().await;
  let max_vector_size: usize = 1024;
  info!("opening port {}", json.port);
  if quicmap.contains_key(&json.uid) {
    match TcpListener::bind(("0.0.0.0", json.port)).await {
      Ok(listener) => {
        let mut tcpmap = TCPMAP.lock().await;
        tcpmap.insert(json.port, listener);
        info!("TcpListener created successfully!");
        tokio::spawn(async move {
          loop {
            let (stream, _) = tcpmap.get(&json.port).unwrap().accept().await.unwrap();
            info!("Accepted connection from: {:?}", stream.peer_addr());
            let addr = format!("{}:{}", &json.connect_address, &json.connect_port.to_string());
            handle_stream(stream, max_vector_size, &json.uid, addr).await;
          }
        });
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
async fn close(json: web::Json<CloseObj>) -> impl Responder {
  let mut tcpmap = TCPMAP.lock().await;
  if let Some(listener) = tcpmap.remove(&json.port) {
    let _ = listener; //listenerの所有権を解放
    HttpResponse::Ok().body("TcpListener closed successfully!")
  } else {
    HttpResponse::InternalServerError().body("No TcpListener exists for the specified Port.")
  }
}

pub async fn create_app(addr: &str, port: u16) -> () {
  info!("API listening on {}:{}", addr, port.to_string());
  let app = || App::new().service(open);
  HttpServer::new(app).bind((addr, port)).expect("Can not bind").run().await.expect("Server failed");
}
