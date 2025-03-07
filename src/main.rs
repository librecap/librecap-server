use actix_web::middleware::Logger;
use actix_web::{App, HttpServer};
use dotenvy::dotenv;
use std::env;

use librecap_server::{add_librecap, initialize_app_state};

const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 8080;
const DEFAULT_WORKERS: usize = 16;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let host = env::var("HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let workers = env::var("WORKERS")
        .ok()
        .and_then(|w| w.parse().ok())
        .unwrap_or(DEFAULT_WORKERS);

    let app_state = initialize_app_state().await;

    let server = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_state.clone())
            .configure(add_librecap)
    });

    let server = if workers > 1 {
        server.workers(workers)
    } else {
        server
    };

    log::info!(
        "Starting server at http://{}:{} with {} workers",
        host,
        port,
        workers
    );
    server.bind((host, port))?.run().await
}
