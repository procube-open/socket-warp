use crate::hashmap::HASHMAP;
use crate::utils::{der_to_pem, get_env};
use http::StatusCode;
use reqwest::Client;
use serde::Deserialize;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Deserialize, Debug)]
struct User {
  uid: String,
}
#[derive(Deserialize, Debug)]
struct UError {
  message: String,
}

pub async fn handle_quic_connection(conn: quinn::Connecting) -> Result<(), Box<dyn Error>> {
  //
  // handle QUIC connction (thread for each sw_connector)
  //
  let connection = conn.await?;

  println!("QUIC established");

  let c = &connection.peer_identity().unwrap().downcast::<Vec<rustls::Certificate>>().unwrap()[0];
  let pem_data = der_to_pem(c.as_ref()).unwrap();
  let s = String::from_utf8(pem_data).unwrap();
  let mut encoded = String::from("");
  url_escape::encode_path_to_string(s.to_string(), &mut encoded);
  let client = Client::new();
  let url = get_env("SCEP_SERVER_URL", "http://127.0.0.1:3001/userObject");
  let response = match client.get(url).header("X-Mtls-Clientcert", encoded).send().await {
    Ok(res) => res,
    Err(error) => {
      let e = error.source().unwrap().to_string();
      panic!("Error occured while sending REST API: {:?}", e)
    },
  };
  let status = response.status();

  if StatusCode::is_success(&status) {
    println!("Verified");
    let body = response.text().await?;
    let u: User = serde_json::from_str(&body).unwrap();
    let mut map = HASHMAP.lock().await;
    map.insert(u.uid, connection);
  } else {
    println!("{}", status);
    let body = response.text().await?;
    let e: UError = serde_json::from_str(&body).unwrap();
    println!("{}", e.message);
  }
  Ok(())
}

pub async fn handle_stream(mut manager_stream: TcpStream, max_vector_size: usize, uid: &String, connect_addrs: String) {
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
      send.write_all(&buf1[0..max_vector_size - connect_addrs.as_bytes().len()]).await.unwrap();
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
