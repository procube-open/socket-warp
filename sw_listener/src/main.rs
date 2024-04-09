//! fc_server 0.4.0
//! (proof of concept version)
//!
//! fc_server and fc_agent is tunnel software using the QUIC protocol.
//!
//! compile and run as below
//! cargo run
//!
//! requirement
//!  - SSL server certificate and key files for fc_server
//!  - CA certificate for fc_agent
//!  - TLS client auth
//!
//! not implimented
//! - error handling and logging
//! - manage connection
//! - accept multi connection on a listen port

use std::net::ToSocketAddrs;
use std::{error::Error, fs, io, sync::Arc};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Settings {
    settings: HashMap<String, HashMap<String, String>>,
}

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
        .max_idle_timeout(None);
    let server_addrs = (
        get_env("SERVER_NAME", "sw-listener.nsag-dev.procube-demo.jp"),
        get_env("SERVER_PORT", "11443").parse().unwrap(),
    )
        .to_socket_addrs()?
        .next()
        .unwrap();
    // let server_addrs = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4433);
    let endpoint = quinn::Endpoint::server(server_config, server_addrs)?;
    println!("QUIC listening on {}", endpoint.local_addr()?);

    let mut n_conn = 1;
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

    Ok(())
}

async fn handle_quic_connection(conn: quinn::Connecting) -> Result<(), Box<dyn Error>> {
    //
    // handle QUIC connction (thread for each fc_agent)
    //
    let connection = conn.await?;

    println!("QUIC established");

    // read poperty files dummy
    // !!!!!! DUMMY !!!!!
    let tun_props = vec!["0A 127.0.0.1:8122 192.168.202.93:2222".to_string()];
    let max_vector_size = "1024";

    //
    // Listen local ports for manager client
    //
    for prop in tun_props {
        println!("tunnel preparing, prop string[{}]", prop);

        let h_tmp: Vec<&str> = prop.split(' ').collect();
        let _t = h_tmp[0];
        let _server_accept_addr = h_tmp[1];
        let _edge_server_addr = h_tmp[2];
        let listener = TcpListener::bind(_server_accept_addr).await?;
        println!(
            "   manager listening on:{}, tun:{}, edge:{}",
            _server_accept_addr, _t, _edge_server_addr
        );
        loop {
            // got manager stream
            let (mut manager_stream, addr) = listener.accept().await.unwrap();
            println!("accepted manager client {}", addr);

            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            println!("   connect QUIC stream {}", _t);

            let hellostr = String::from(prop.clone()) + " ";

            let max_vector_size = max_vector_size.parse().unwrap();

            tokio::spawn(async move {
                loop {
                    let mut buf1 = vec![0; max_vector_size];
                    let mut buf2 = vec![0; max_vector_size];

                    //
                    // FC HELLO (share edge configuration)
                    //
                    send.write_all(hellostr.as_bytes()).await.unwrap();
                    send.write_all(&buf1[0..max_vector_size - hellostr.as_bytes().len()])
                        .await
                        .unwrap();
                    println!("FC HELLO to fc_agent with edge conf: {}", hellostr);

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
    }

    Ok(())
}

fn get_env(key: &str, default: &str) -> String {
    let env = match std::env::var(key) {
        Ok(val) => val,
        Err(_) => {
            println!("\"{}\" is not defined in environment variables.", key);
            default.to_string()
        }
    };
    return env;
}
