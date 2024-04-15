use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn handle_quic_connection(conn: quinn::Connecting) -> Result<(), Box<dyn Error>> {
    //
    // handle QUIC connction (thread for each sw_connector)
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

            // got SendStream and RecvStream
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
                    println!("FC HELLO to sw_connector with edge conf: {}", hellostr);

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
