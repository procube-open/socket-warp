use actix_web::{get, HttpResponse, Responder};

#[get("/hello")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

use actix_web::{App, HttpServer};

pub async fn create_app(addr: &str, port: u16) -> std::io::Result<()>  {
    HttpServer::new(|| App::new().service(hello))
        .bind((addr, port))?
        .run()
        .await
}
