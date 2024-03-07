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
    // Property Settings
    //
    let json_file = "./settings_server.json";
    let json_reader = io::BufReader::new(fs::File::open(json_file).unwrap());
    let _json_object: Settings = serde_json::from_reader(json_reader).unwrap();

    //
    // SSL: Server Certificate and Private Key Settings
    //
    let (certs, key) = {
        let cert =
            fs::read(_json_object.settings["path_to_server_cert"]["value"].to_string()).unwrap();
        let key =
            fs::read(_json_object.settings["path_to_server_key"]["value"].to_string()).unwrap();
        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        (vec![cert], key)
    };

    //
    // SSL: CA Certificate Settings
    //
    let mut client_auth_roots = rustls::RootCertStore::empty();
    match fs::read(_json_object.settings["path_to_ca_cert"]["value"].to_string()) {
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
        .max_concurrent_uni_streams(0_u8.into());
    let server_addrs = (
        _json_object.settings["server_name"]["value"].to_string(),
        _json_object.settings["service_port"]["value"]
            .parse()
            .unwrap(),
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
        let _json_object_clone = _json_object.clone();
        let fut = handle_quic_connection(conn, _json_object_clone);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                println!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    Ok(())
}

async fn handle_quic_connection(
    conn: quinn::Connecting,
    _json_object: Settings,
) -> Result<(), Box<dyn Error>> {
    //
    // handle QUIC connction (thread for each fc_agent)
    //
    let connection = conn.await?;

    println!("QUIC established");
    // read poperty files dummy
    // !!!!!! DUMMY !!!!!
    let tun_props = [
        _json_object.settings["tunnel_property_1"]["value"].to_string(),
        _json_object.settings["tunnel_property_2"]["value"].to_string(),
        _json_object.settings["tunnel_property_3"]["value"].to_string(),
    ];
    println!("test: {}", tun_props.len());

    let t = tun_props[0].clone();
    let server_accept_addr = tun_props[1].clone();
    let edge_server_addr = tun_props[2].clone();
    let max_vector_size = _json_object.settings["max_vector_size"]["value"].to_string();

    //
    // Listen local ports for manager client
    //
    for i in 0..tun_props.len() {
        println!("tunnel No.{} preparing, prop string[{}]", i, tun_props[i]);

        let listener = TcpListener::bind(server_accept_addr.clone()).await?;
        println!(
            "   manager listening on:{}, tun:{}, edge{}",
            server_accept_addr, t, edge_server_addr
        );

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        println!("   connect QUIC stream {}", t);

        let hellostr = String::from(tun_props[i].clone()) + " ";

        let t = t.clone();
        let max_vector_size = max_vector_size.clone().parse().unwrap();
        tokio::spawn(async move {
            let (mut manager_stream, addr) = listener.accept().await.unwrap();
            println!("t{}|  accepted manager client {}", t, addr);
            // got manager stream

            let mut buf1 = vec![0; max_vector_size];
            let mut buf2 = vec![0; max_vector_size];

            //
            // FC HELLO (share edge configuration)
            //
            send.write_all(hellostr.as_bytes()).await.unwrap();
            send.write_all(&buf1[0..max_vector_size - hellostr.as_bytes().len()])
                .await
                .unwrap();
            println!("t{}|FC HELLO to fc_agent with edge conf: {}", t, hellostr);

            //
            // stream to stream copy loop
            //
            loop {
                tokio::select! {
                  n = recv.read(&mut buf1) => {
                    println!("t{}|local server read ...", t);
                    match n {
                      Ok(None) => {
                          // Noneはcloseのはず。
                          println!("t{}|  local server read None ... break", t);
                          break;
                      },
                      Ok(n) => {
                          let n1 = n.unwrap();
                          println!("t{}|  local server {} bytes >>> manager_stream", t, n1);
                          manager_stream.write_all(&buf1[0..n1]).await.unwrap();
                      },
                      //Err(e) => {
                      //    eprintln!("t{}|  manager stream failed to read from socket; err = {:?}", i, e);
                      //    return Err(e.into());
                      //},
                      Err(_) => {
                          break;
                      },
                     };
                    //println!("  ... local server read done");
                   }
                 n = manager_stream.read(&mut buf2) => {
                    println!("t{}|manager client read ...", t);
                    match n {
                      Ok(0) => {
                          // 0はcloseのはず。
                          println!("t{}|  manager server read 0 ... break", t);
                          break;
                      },
                      Ok(n) => {
                          println!("t{}|  manager client {} bytes >>> local server",t ,n);
                          send.write_all(&buf2[0..n]).await.unwrap();
                      },
                      Err(e) => {
                          eprintln!("t{}|  local server stream failed to read from socket; err = {:?}", i,  e);
                          //return Err(e.into());
                          break;
                      }
                     };
                     //println!("  ... manager read done");
                   }
                };
            }
        });
    }

    Ok(())
}
