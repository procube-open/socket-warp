use crate::hashmap::HASHMAP;
use crate::quic::handle_stream;
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Debug, Serialize, Deserialize)]
struct PostObj {
  uid: String,
  port: u16,
  connect_address: String,
  connect_port: u16,
}

#[post("/open")]
async fn open(json: web::Json<PostObj>) -> impl Responder {
  let map = HASHMAP.lock().await;
  if map.contains_key(&json.uid) {
    match TcpListener::bind(("127.0.0.1", json.port)).await {
      Ok(listener) => {
        println!("TcpListener created successfully!");
        tokio::spawn(async move {
          loop {
            let (stream, _) = listener.accept().await.unwrap();
            println!("Accepted connection from: {:?}", stream.peer_addr());
            let addr = format!("{}:{}", &json.connect_address, &json.connect_port.to_string());
            handle_stream(stream, 1024, &json.uid, addr).await;
          }
        });
        HttpResponse::Ok().body("TcpListener created successfully!")
      }
      Err(e) => {
        println!("Failed to create TcpListener: {}", e);
        HttpResponse::InternalServerError().body("Failed to create TcpListener")
      }
    }
  } else {
    HttpResponse::InternalServerError().body("No QUIC connection exists for the specified UID.")
  }
}

pub async fn create_app(addr: &str, port: u16) -> () {
  println!("API listening on {}:{}", addr,port.to_string());
  let app = || App::new().service(open);
  HttpServer::new(app).bind((addr, port)).expect("Can not bind").run().await.expect("Server failed");
}
