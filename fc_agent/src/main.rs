//! fc_agent 0.4.0
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
use std::{
    error::Error,
    fs,
    io::{self},
    sync::Arc,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    let json_file = "./settings_agent.json";
    let json_reader = io::BufReader::new(fs::File::open(json_file).unwrap());
    let _json_object: Settings = serde_json::from_reader(json_reader).unwrap();

    //
    // SSL: : CA Certificate Settings
    //
    let mut roots = rustls::RootCertStore::empty();
    match fs::read(_json_object.settings["path_to_ca_cert"]["value"].to_string()) {
        Ok(cert) => {
            roots.add(&rustls::Certificate(cert))?;
        }
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            println!("local server certificate not found");
        }
        Err(e) => {
            println!("failed to open local server certificate: {}", e);
        }
    }

    //
    // SSL: Client Certificate and Private Key Settings
    //

    let (certs, key) = {
        let cert =
            fs::read(_json_object.settings["path_to_client_cert"]["value"].to_string()).unwrap();
        let key =
            fs::read(_json_object.settings["path_to_client_key"]["value"].to_string()).unwrap();

        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        (vec![cert], key)
    };

    //
    // Client Configuration and QUIC endpoint Settings
    //
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .expect("invalid client auth certs/key");

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

    let server_addrs = (
        _json_object.settings["server_name"]["value"].to_string(),
        _json_object.settings["service_port"]["value"]
            .parse()
            .unwrap(),
    )
        .to_socket_addrs()?
        .next()
        .unwrap();
    let host = _json_object.settings["server_name"]["value"].to_string();
    // let server_addrs = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433);
    // let host = "localhost";

    //
    // connect QUIC connection to fc_server
    //
    println!("QUIC connecting to {} at {}", server_addrs, host);
    let connection = endpoint.connect(server_addrs, &host)?.await?;
    println!("QUIC connected");

    //
    // wait QUIC stream from fc_server for each tunnel
    //
    async {
        println!("QUIC established");
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    println!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    println!("connection errored");
                    return Err(e);
                }
                Ok(s) => s,
            };
            let _json_object_clone = _json_object.clone();
            let fut = handle_request(stream, _json_object_clone);
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    println!("failed: {reason}", reason = e.to_string());
                }
            });
        }
    }
    .await?;
    Ok(())
}

async fn handle_request(
    //(mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    _json_object: Settings,
) -> Result<(), Box<dyn Error>> {
    //
    // QUIC stream
    //
    println!("new stream opened from agent");

    let max_vector_size = _json_object.settings["max_vector_size"]["value"].to_string();
    let max_vector_size = max_vector_size.clone().parse().unwrap();
    //
    // FC HELLO receive
    //
    let mut buf0 = vec![0; max_vector_size];
    recv.read_exact(&mut buf0).await?;
    let hellostr: String = String::from_utf8(buf0.to_vec()).unwrap();
    let h_tmp: Vec<&str> = hellostr.split(' ').collect();
    let t = h_tmp[0];
    //let server_accept_addr = h_tmp[1];
    let edge_server_addr = h_tmp[2];
    println!(
        "t{}|FC HELLO was received from fc_server with edge conf: {}",
        t, edge_server_addr
    );

    //
    // edge server conect
    //

    println!("t{}|connecting to edge server: {}", t, edge_server_addr);
    let mut local_stream = TcpStream::connect(edge_server_addr).await?;
    //let mut local_stream = TcpStream::connect(_json_object.settings["tunnel_property_1"]["value"].to_string()).await?; // for ncat server
    //let mut local_stream = TcpStream::connect(_json_object.settings["tunnel_property_2"]["value"].to_string()).await?;     // for ssh server
    //let mut local_stream = TcpStream::connect(_json_object.settings["tunnel_property_3"]["value"].to_string()).await?; // for http server
    println!("t{}|connected to edge server", t);

    //
    // stream to stream copy
    //
    let mut buf1 = vec![0; max_vector_size];
    let mut buf2 = vec![0; max_vector_size];

    loop {
        tokio::select! {
          n = recv.read(&mut buf1) => {
            println!("t{}|local server read ...", t);
            match n {
              Ok(None) => {
                  println!("t{}|  local server read None ... break", t);
                  break;
              },
              Ok(n) => {
                  let n1 = n.unwrap();
                  println!("t{}|  local server read {} >>> manager client", t, n1);
                  local_stream.write_all(&buf1[0..n1]).await.unwrap();
              },
              Err(e) => {
                  eprintln!("t{}|  manager stream failed to read from socket; err = {:?}", t, e);
                  return Err(e.into());
              },
              //Err(_) => {
              //    continue;
              //},
             };
            //println!("  ... local server read done");
           }
           n = local_stream.read(&mut buf2) => {
            println!("t{}|manager client read ...", t);
            match n {
              Ok(0) => {
                  println!("t{}|  manager server read 0 ... break", t);
                  break;
              },
              Ok(n) => {
                  println!("t{}|  manager stream read {} >>> local server", t, n);
                  send.write_all(&buf2[0..n]).await.unwrap();
              },
              Err(e) => {
                  eprintln!("t{}|  local server stream failed to read from socket; err = {:?}", t, e);
                  return Err(e.into());
              }
             };
            //println!("  ... manager read done");
           }
        };
    }

    println!("complete");
    Ok(())
}
