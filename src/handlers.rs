use actix_web::http::header::USER_AGENT;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use redis::AsyncCommands;
use redis::Client as RedisClient;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::image_captcha::{ImageCaptchaManager, combine_byte_arrays};
use crate::pow::{
    generate_pow_challenge_buffer, parse_pow_solution_buffer, PowChallenge, PowManager,
};

const SOLVED_NONCES_KEY_PREFIX: &str = "solved_nonce:";
const SAFETY_MARGIN_SECONDS: u64 = 5;

const INITIAL_HARDNESS: u8 = 20;
const SECOND_HARDNESS: u8 = 22;
const IMAGE_HARDNESS: u8 = 2;
const INITIAL_CHALLENGE_EXPIRY_SECONDS: u64 = 10;

pub struct AppState {
    pub redis_client: RedisClient,
    pub pow_manager: PowManager,
    pub image_captcha_manager: ImageCaptchaManager,
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

#[get("/initial")]
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

#[post("/challenge")]
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
