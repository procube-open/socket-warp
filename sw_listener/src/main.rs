//! sw_listener 0.4.0
//! (proof of concept version)
//!
//! sw_listener and sw_connector is tunnel software using the QUIC protocol.
//!
//! compile and run as below
//! cargo run
//!
//! requirement
//!  - SSL server certificate and key files for sw_listener
//!  - CA certificate for sw_connector
//!  - TLS client auth
//!
//! not implimented
//! - error handling and logging
//! - manage connection

// use futures::{future::FutureExt, pin_mut, select};
use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use lazy_static::lazy_static;
use openssl::error::ErrorStack;
use openssl::x509::X509;
use http::StatusCode;
use reqwest::Client;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::time::Duration;
use std::{error::Error, fs, io, sync::Arc};
// use tokio::io::{AsyncReadExt, AsyncWriteExt};
// use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Mutex;

lazy_static! {
    static ref HASHMAP: Arc<Mutex<HashMap<String, (quinn::SendStream, quinn::RecvStream)>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
#[tokio::main]

async fn main() -> Result<(), Box<dyn Error>> {
    //
    // SSL: Server Certificate and Private Key Settings
    //
    let (certs, key) = {
        let cert =
            fs::read(get_env("SERVER_CERT_PATH", "../Certs_and_Key/server_crt.der").to_string())
                .unwrap();
        let key =
            fs::read(get_env("SERVER_KEY_PATH", "../Certs_and_Key/server_key.der").to_string())
                .unwrap();
        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        (vec![cert], key)
    };

    //
    // SSL: CA Certificate Settings
    //
    let mut client_auth_roots = rustls::RootCertStore::empty();
    match fs::read(get_env("SERVER_CA_PATH", "../Certs_and_Key/ca.der").to_string()) {
        Ok(cert) => {
            client_auth_roots.add(&rustls::Certificate(cert))?;
        }
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            println!("local server certificate not found");
        }
        Err(e) => {
            println!("failed to open local server certificate: {}", e);
        }
    }

    //
    // Server Configuration and QUIC endpoint Settings
    //
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(
            client_auth_roots,
        )))
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into())
        .keep_alive_interval(Some(Duration::from_secs(3)));
    let server_addrs = (
        get_env("SERVER_ADDRS", "0.0.0.0"),
        get_env("SERVER_PORT", "11443").parse().unwrap(),
    )
        .to_socket_addrs()?
        .next()
        .unwrap();
    let endpoint = quinn::Endpoint::server(server_config, server_addrs)?;
    println!("QUIC listening on {}", endpoint.local_addr()?);

    let mut n_conn = 1;

    let app = || App::new().service(hello);
    let t1 = tokio::spawn(async move {
        HttpServer::new(app)
            .bind(("0.0.0.0", 8080))
            .expect("Can not bind to port 8080")
            .run()
            .await
            .expect("Server failed");
    });
    let t2 = tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            println!("QUIC connection incoming {}", n_conn);
            n_conn += 1;
            let fut = handle_quic_connection(conn);
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    println!("connection failed: {reason}", reason = e.to_string())
                }
            });
        }
    });

    let task_handle = tokio::spawn(async move {
        tokio::select! {
            _ = signal::ctrl_c() => {
              println!("canceled");
            },
            _ = t1 => {}
            _ = t2 => {}
        }
    });
    task_handle.await.unwrap();

    Ok(())
}

async fn handle_quic_connection(conn: quinn::Connecting) -> Result<(), Box<dyn Error>> {
    //
    // handle QUIC connction (thread for each sw_connector)
    //
    let connection = conn.await?;

    println!("QUIC established");

    // read poperty files dummy
    // !!!!!! DUMMY !!!!!
    // let tun_props = vec!["0A 127.0.0.1:8122 192.168.202.171:2222".to_string()];
    // let max_vector_size = "1024";

    let c = &connection
        .peer_identity()
        .unwrap()
        .downcast::<Vec<rustls::Certificate>>()
        .unwrap()[0];
    let pem_data = der_to_pem(c.as_ref()).unwrap();
    let s = String::from_utf8(pem_data).unwrap();
    let mut encoded = String::from("");
    println!(
        "{}",
        url_escape::encode_path_to_string(s.to_string(), &mut encoded)
    );

    // TODO
    // SCEPサーバにURLエンコードしたPEMを/userObject APIで検証する
    // 返ってきたUIDの値でmapに入れ込む

    let client = Client::new();
    let url = get_env("SCEP_SERVER_URL", "http://127.0.0.1:3000/userObject");
    let response = client
        .get(url)
        .header("X-Mtls-Clientcert", encoded)
        .send()
        .await?;
    let status = response.status();
    if StatusCode::is_success(&status) {
      let body = response.text().await?;
      println!("{}", body);
    } else {
      println!("http request failed")
    }
    // //
    // // Listen local ports for manager client
    // //
    // for prop in tun_props {
    //     println!("tunnel preparing, prop string[{}]", prop);

    //     let h_tmp: Vec<&str> = prop.split(' ').collect();
    //     let _t = h_tmp[0];
    //     let _server_accept_addr = h_tmp[1];
    //     let _edge_server_addr = h_tmp[2];
    //     let listener = TcpListener::bind(_server_accept_addr).await?;
    //     println!(
    //         "   manager listening on:{}, tun:{}, edge:{}",
    //         _server_accept_addr, _t, _edge_server_addr
    //     );
    //     loop {
    //         // got manager stream
    //         let (mut manager_stream, addr) = listener.accept().await.unwrap();
    //         println!("accepted manager client {}", addr);

    //         // got SendStream and RecvStream
    //         let (mut send, mut recv) = connection.open_bi().await.unwrap();
    //         println!("   connect QUIC stream {}", _t);

    //         let hellostr = String::from(prop.clone()) + " ";

    //         let max_vector_size = max_vector_size.parse().unwrap();

    //         tokio::spawn(async move {
    //             loop {
    //                 let mut buf1 = vec![0; max_vector_size];
    //                 let mut buf2 = vec![0; max_vector_size];

    //                 //
    //                 // FC HELLO (share edge configuration)
    //                 //
    //                 send.write_all(hellostr.as_bytes()).await.unwrap();
    //                 send.write_all(&buf1[0..max_vector_size - hellostr.as_bytes().len()])
    //                     .await
    //                     .unwrap();
    //                 println!("FC HELLO to sw_connector with edge conf: {}", hellostr);

    //                 //
    //                 // stream to stream copy loop
    //                 //
    //                 let mut buf0 = vec![0; max_vector_size];
    //                 recv.read_exact(&mut buf0).await.unwrap();
    //                 let hellostr2 = String::from_utf8(buf0.to_vec()).unwrap();
    //                 println!("{}", hellostr2.to_string());
    //                 // let mut map = HASHMAP.lock().await;
    //                 // map.insert(hellostr2, (send, recv));
    //                 loop {
    //                     tokio::select! {
    //                       n = recv.read(&mut buf1) => {
    //                         match n {
    //                           Ok(None) => {
    //                             println!("local server read None ... break");
    //                             break;
    //                           },
    //                           Ok(n) => {
    //                             let n1 = n.unwrap();
    //                             println!("local server {} bytes >>> manager_stream", n1);
    //                             manager_stream.write_all(&buf1[0..n1]).await.unwrap();
    //                           },
    //                           Err(e) => {
    //                             eprintln!("manager stream failed to read from socket; err = {:?}", e);
    //                             break;
    //                           },
    //                         };
    //                         println!("  ... local server read done");
    //                       }
    //                       n = manager_stream.read(&mut buf2) => {
    //                         println!("manager client read ...");
    //                         match n {
    //                           Ok(0) => {
    //                             println!("manager server read 0 ... break");
    //                             break;
    //                           },
    //                           Ok(n) => {
    //                             println!("manager client {} bytes >>> local server",n);
    //                             send.write_all(&buf2[0..n]).await.unwrap();
    //                           },
    //                           Err(e) => {
    //                             eprintln!("local server stream failed to read from socket; err = {:?}", e);
    //                             break;
    //                           }
    //                         };
    //                         println!("  ... manager read done");
    //                       }
    //                     };
    //                 }
    //             }
    //         });
    //     }
    // }

    Ok(())
}

fn get_env(key: &str, default: &str) -> String {
    let env = match std::env::var(key) {
        Ok(val) => val,
        Err(_) => default.to_string(),
    };
    return env;
}

fn der_to_pem(der_data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let x509 = X509::from_der(der_data)?;
    let pem = x509.to_pem()?;
    Ok(pem)
}

#[get("/hello")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}
