use crate::hashmap::HASHMAP;
use crate::utils::{der_to_pem, get_env};
use http::StatusCode;
use reqwest::Client;
use std::error::Error;

pub async fn handle_quic_connection(conn: quinn::Connecting) -> Result<(), Box<dyn Error>> {
    //
    // handle QUIC connction (thread for each sw_connector)
    //
    let connection = conn.await?;

    println!("QUIC established");

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
    // 返ってきたUIDの値でmapに入れ込む

    let client = Client::new();
    let url = get_env("SCEP_SERVER_URL", "http://127.0.0.1:3001/userObject");
    let response = client
        .get(url)
        .header("X-Mtls-Clientcert", encoded)
        .send()
        .await?;
    let status = response.status();
    if StatusCode::is_success(&status) {
        let body = response.text().await?;
        println!("{}", body);
        // let mut map = HASHMAP.lock().await;
        // map.insert("test".to_string(), connection);
    } else {
        println!("{}", status);
        let body = response.text().await?;
        println!("{}", body);
    }
    let mut map = HASHMAP.lock().await;
    map.insert("test".to_string(), connection);
    Ok(())
}
