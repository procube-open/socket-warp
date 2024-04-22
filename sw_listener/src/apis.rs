use crate::hashmap::HASHMAP;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Serialize, Deserialize)]
struct PostObj {
    uid: String,
    port: u16,
    connect_address: String,
    connect_port: u16,
}

#[get("/hello")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
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
                        handle_stream(
                            stream,
                            1024,
                            &"test".to_string(),
                            "192.168.202.234:2222".to_string(),
                        )
                        .await;
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

async fn handle_stream(
    mut manager_stream: TcpStream,
    max_vector_size: usize,
    uid: &String,
    connect_addrs: String,
) {
    let map = HASHMAP.lock().await;
    let connection = map.get(uid).unwrap();

    // got SendStream and RecvStream
    let (mut send, mut recv) = connection.open_bi().await.unwrap();

    tokio::spawn(async move {
        loop {
            let mut buf1 = vec![0; max_vector_size];
            let mut buf2 = vec![0; max_vector_size];

            //
            // FC HELLO (share edge configuration)
            //
            send.write_all(connect_addrs.as_bytes()).await.unwrap();
            send.write_all(&buf1[0..max_vector_size - connect_addrs.as_bytes().len()])
                .await
                .unwrap();
            println!("FC HELLO to sw_connector with edge conf: {}", connect_addrs);

            //
            // stream to stream copy loop
            //
            loop {
                tokio::select! {
                  n = recv.read(&mut buf1) => {
                    match n {
                      Ok(None) => {
                        println!("local server read None ... break");
                        break;
                      },
                      Ok(n) => {
                        let n1 = n.unwrap();
                        println!("local server {} bytes >>> manager_stream", n1);
                        manager_stream.write_all(&buf1[0..n1]).await.unwrap();
                      },
                      Err(e) => {
                        eprintln!("manager stream failed to read from socket; err = {:?}", e);
                        break;
                      },
                    };
                    println!("  ... local server read done");
                  }
                  n = manager_stream.read(&mut buf2) => {
                    println!("manager client read ...");
                    match n {
                      Ok(0) => {
                        println!("manager server read 0 ... break");
                        break;
                      },
                      Ok(n) => {
                        println!("manager client {} bytes >>> local server",n);
                        send.write_all(&buf2[0..n]).await.unwrap();
                      },
                      Err(e) => {
                        eprintln!("local server stream failed to read from socket; err = {:?}", e);
                        break;
                      }
                    };
                    println!("  ... manager read done");
                  }
                };
            }
        }
    });
}

pub async fn create_app(addr: &str, port: u16) -> () {
    let app = || App::new().service(hello).service(open);
    HttpServer::new(app)
        .bind((addr, port))
        .expect("Can not bind to port 8080")
        .run()
        .await
        .expect("Server failed");
}
