use actix_cors::Cors;
use actix_web::http::header::USER_AGENT;
use actix_web::middleware::Logger;
use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use dotenvy::dotenv;
use redis::{AsyncCommands, Client as RedisClient};
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod image_captcha;
mod pow;
mod redis_config;
mod utils;

use image_captcha::ImageCaptchaManager;
use pow::{generate_pow_challenge_buffer, parse_pow_solution_buffer, PowChallenge, PowManager};
use redis_config::RedisConfig;
use utils::combine_byte_arrays;

const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 8080;
const DEFAULT_WORKERS: usize = 16;
const DEFAULT_DATASET_NAME: &str = "ai_dogs.pkl";

const POW_SECRET_KEY: &str = "pow_secret";
const IMAGE_CAPTCHA_SECRET_KEY: &str = "image_captcha_secret";
const SOLVED_NONCES_KEY_PREFIX: &str = "solved_nonce:";
const SAFETY_MARGIN_SECONDS: u64 = 5;

const INITIAL_HARDNESS: u8 = 20;
const SECOND_HARDNESS: u8 = 22;
const IMAGE_HARDNESS: u8 = 2;
const INITIAL_CHALLENGE_EXPIRY_SECONDS: u64 = 10;
// const SECOND_CHALLENGE_EXPIRY_SECONDS: u64 = 20;

struct AppState {
    redis_client: RedisClient,
    pow_manager: PowManager,
    image_captcha_manager: ImageCaptchaManager,
}

fn get_client_ip(req: &HttpRequest) -> String {
    if let Some(forwarded_for) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            let ips: Vec<&str> = forwarded_str.split(',').collect();
            if !ips.is_empty() {
                return ips[0].trim().to_string();
            }
        }
    }

    req.connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string()
}

fn get_user_agent(req: &HttpRequest) -> &str {
    req.headers()
        .get(USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
}

fn generate_pow_challenge_bad_response(
    ip: &IpAddr,
    user_agent: &str,
    pow_manager: &PowManager,
) -> HttpResponse {
    HttpResponse::BadRequest()
        .append_header(("Content-Type", "application/octet-stream"))
        .body(generate_pow_challenge_buffer(
            ip,
            user_agent,
            pow_manager,
            INITIAL_HARDNESS,
            SECOND_HARDNESS,
        ))
}

#[get("/librecap/v1/initial")]
async fn get_initial_challenges(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let ip_str = get_client_ip(&req);
    let user_agent = get_user_agent(&req);

    let ip = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest().body("Invalid IP address");
        }
    };

    HttpResponse::Ok()
        .append_header(("Content-Type", "application/octet-stream"))
        .body(generate_pow_challenge_buffer(
            &ip,
            user_agent,
            &data.pow_manager,
            INITIAL_HARDNESS,
            SECOND_HARDNESS,
        ))
}

#[post("/librecap/v1/challenge")]
async fn challenge_endpoint(
    req: HttpRequest,
    challenge_data: web::Bytes,
    data: web::Data<AppState>,
) -> impl Responder {
    let ip_str = get_client_ip(&req);
    let user_agent = get_user_agent(&req);

    let ip = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            log::error!("Invalid IP address: {}", ip_str);
            return HttpResponse::BadRequest().finish();
        }
    };

    let parsed = match parse_pow_solution_buffer(&challenge_data) {
        Ok(parsed) => parsed,
        Err(_) => {
            log::error!("Invalid challenge data");
            return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
        }
    };

    if parsed.hardness != INITIAL_HARDNESS {
        log::error!("Invalid hardness: {}", parsed.hardness);
        return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
    }

    let challenge = PowChallenge {
        nonce: parsed.nonce,
        timestamp: parsed.timestamp,
        signature: parsed.signature,
        hardness: parsed.hardness,
    };

    if !data.pow_manager.verify_challenge_validity(
        &challenge,
        &ip,
        user_agent,
        INITIAL_CHALLENGE_EXPIRY_SECONDS,
    ) {
        log::error!("Invalid challenge validity");
        return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
    }

    if !data
        .pow_manager
        .verify_solution(&challenge, &parsed.solution)
    {
        log::error!("Invalid solution");
        return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
    }

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry_time = challenge.timestamp + INITIAL_CHALLENGE_EXPIRY_SECONDS;

    if current_time >= expiry_time {
        log::error!("Challenge expired");
        return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
    }

    let nonce_key = format!("{}{:x?}", SOLVED_NONCES_KEY_PREFIX, challenge.nonce);

    let mut redis_conn = match data.redis_client.get_async_connection().await {
        Ok(conn) => conn,
        Err(_) => {
            log::error!("Failed to connect to Redis");
            return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
        }
    };

    let set_result: bool = redis_conn
        .set_nx::<&str, String, bool>(&nonce_key, current_time.to_string())
        .await
        .unwrap_or(false);

    if !set_result {
        log::error!("Failed to set nonce in Redis");
        return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
    }

    let ttl = expiry_time
        .saturating_add(SAFETY_MARGIN_SECONDS)
        .saturating_sub(current_time);
    if let Err(_) = redis_conn
        .expire::<&str, bool>(&nonce_key, ttl as usize)
        .await
    {
        log::error!("Failed to expire nonce in Redis");
        return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
    }

    let challenge = match data.image_captcha_manager.generate_captcha_challenge(
        &ip_str,
        user_agent,
        IMAGE_HARDNESS,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to generate challenge: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(&challenge.nonce); // 16 bytes
    buffer.extend_from_slice(&challenge.timestamp.to_be_bytes()); // 8 bytes
    buffer.extend_from_slice(&challenge.signature); // 32 bytes
    buffer.extend_from_slice(&challenge.indices_hash); // 32 bytes
    buffer.extend(combine_byte_arrays(&challenge.images)); // variable length

    HttpResponse::Ok()
        .append_header(("Content-Type", "application/octet-stream"))
        .body(buffer)
}

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

    let dataset_path =
        env::var("DATASET_PATH").unwrap_or_else(|_| DEFAULT_DATASET_NAME.to_string());

    let redis_config = RedisConfig::from_env();
    let redis_url = redis_config.get_url().await;

    log::info!("Connecting to Redis at {}", redis_url);

    let redis_client = redis::Client::open(redis_url).expect("Failed to create Redis client");

    let pow_manager = {
        let mut con = redis_client
            .get_async_connection()
            .await
            .expect("Failed to connect to Redis");
        let secret: Option<Vec<u8>> = con.get(POW_SECRET_KEY).await.unwrap_or(None);

        match secret {
            Some(secret_bytes) if secret_bytes.len() == 32 => {
                let mut secret_array = [0u8; 32];
                secret_array.copy_from_slice(&secret_bytes);
                PowManager::with_secret(secret_array)
            }
            _ => {
                let pow_manager = PowManager::new();
                let secret = pow_manager.get_secret();
                con.set::<&str, &[u8], ()>(POW_SECRET_KEY, secret.as_slice())
                    .await
                    .expect("Failed to store PoW secret");
                pow_manager
            }
        }
    };

    let image_captcha_manager = {
        let mut con = redis_client
            .get_async_connection()
            .await
            .expect("Failed to connect to Redis");
        let secret: Option<Vec<u8>> = con.get(IMAGE_CAPTCHA_SECRET_KEY).await.unwrap_or(None);

        match secret {
            Some(secret_bytes) if secret_bytes.len() == 32 => {
                let mut secret_array = [0u8; 32];
                secret_array.copy_from_slice(&secret_bytes);
                ImageCaptchaManager::with_secret(&PathBuf::from(&dataset_path), secret_array)
                    .expect("Failed to load image captcha with secret")
            }
            _ => {
                let image_captcha_manager = ImageCaptchaManager::new(&PathBuf::from(&dataset_path))
                    .expect("Failed to load image captcha dataset");
                let secret = image_captcha_manager.get_secret();
                con.set::<&str, &[u8], ()>(IMAGE_CAPTCHA_SECRET_KEY, secret.as_slice())
                    .await
                    .expect("Failed to store image captcha secret");
                image_captcha_manager
            }
        }
    };

    let app_state = web::Data::new(AppState {
        redis_client,
        pow_manager,
        image_captcha_manager,
    });

    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(app_state.clone())
            .service(get_initial_challenges)
            .service(challenge_endpoint)
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
