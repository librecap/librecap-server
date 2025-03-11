use actix_web::http::header::USER_AGENT;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use redis::AsyncCommands;
use redis::Client as RedisClient;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::audio_captcha::AudioCaptchaManager;
use crate::image_captcha::{combine_byte_arrays, ImageCaptchaManager};
use crate::pow::{
    generate_pow_challenge_buffer, parse_pow_solution_buffer, PowChallenge, PowManager,
};

const SOLVED_NONCES_KEY_PREFIX: &str = "solved_nonce:";
const SAFETY_MARGIN_SECONDS: u64 = 5;

const INITIAL_HARDNESS: u8 = 20;
const SECOND_HARDNESS: u8 = 22;
const IMAGE_HARDNESS: u8 = 2;
const AUDIO_HARDNESS: u8 = 8;
const INITIAL_CHALLENGE_EXPIRY_SECONDS: u64 = 10;

pub struct AppState {
    pub redis_client: RedisClient,
    pub pow_manager: PowManager,
    pub image_captcha_manager: ImageCaptchaManager,
    pub audio_captcha_manager: AudioCaptchaManager,
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

async fn validate_initial_pow_challenge(
    challenge_data: &[u8],
    ip: &IpAddr,
    user_agent: &str,
    pow_manager: &PowManager,
    redis_client: &RedisClient,
) -> bool {
    let parsed = match parse_pow_solution_buffer(challenge_data) {
        Ok(parsed) => parsed,
        Err(_) => {
            log::error!("Invalid challenge data");
            return false;
        }
    };

    if parsed.hardness != INITIAL_HARDNESS {
        log::error!("Invalid hardness: {}", parsed.hardness);
        return false;
    }

    let challenge = PowChallenge {
        nonce: parsed.nonce,
        timestamp: parsed.timestamp,
        signature: parsed.signature,
        hardness: parsed.hardness,
    };

    if !pow_manager.verify_challenge_validity(
        &challenge,
        ip,
        user_agent,
        INITIAL_CHALLENGE_EXPIRY_SECONDS,
    ) {
        log::error!("Invalid challenge validity");
        return false;
    }

    if !pow_manager.verify_solution(&challenge, &parsed.solution) {
        log::error!("Invalid solution");
        return false;
    }

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry_time = challenge.timestamp + INITIAL_CHALLENGE_EXPIRY_SECONDS;

    if current_time >= expiry_time {
        log::error!("Challenge expired");
        return false;
    }

    let nonce_key = format!("{}{:x?}", SOLVED_NONCES_KEY_PREFIX, challenge.nonce);

    let mut redis_conn = match redis_client.get_async_connection().await {
        Ok(conn) => conn,
        Err(_) => {
            log::error!("Failed to connect to Redis");
            return false;
        }
    };

    let set_result: bool = redis_conn
        .set_nx::<&str, String, bool>(&nonce_key, current_time.to_string())
        .await
        .unwrap_or(false);

    if !set_result {
        log::error!("Failed to set nonce in Redis");
        return false;
    }

    let ttl = expiry_time
        .saturating_add(SAFETY_MARGIN_SECONDS)
        .saturating_sub(current_time);
    if let Err(_) = redis_conn
        .expire::<&str, bool>(&nonce_key, ttl as usize)
        .await
    {
        log::error!("Failed to expire nonce in Redis");
        return false;
    }

    true
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

    if !validate_initial_pow_challenge(
        &challenge_data,
        &ip,
        user_agent,
        &data.pow_manager,
        &data.redis_client,
    )
    .await
    {
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
    let combined_images = combine_byte_arrays(&challenge.images);
    buffer.extend(combined_images); // variable length

    HttpResponse::Ok()
        .append_header(("Content-Type", "application/octet-stream"))
        .body(buffer)
}

fn normalize_language(lang_code: &str) -> &'static str {
    match lang_code.to_lowercase().as_str() {
        "en" | "eng" | "en-us" | "en-gb" | "en-au" | "en-ca" | "en-nz" | "en-ie" | "en-za"
        | "en-in" | "english" => "en",
        "es" | "spa" | "es-es" | "es-mx" | "es-ar" | "es-co" | "es-cl" | "es-pe" | "es-ve"
        | "es-419" | "spanish" | "castellano" => "es",
        "fr" | "fra" | "fr-fr" | "fr-ca" | "fr-be" | "fr-ch" | "fr-lu" | "fr-mc" | "french"
        | "français" => "fr",
        "de" | "deu" | "de-de" | "de-at" | "de-ch" | "de-lu" | "de-li" | "german" | "deutsch" => {
            "de"
        }
        "it" | "ita" | "it-it" | "it-ch" | "it-sm" | "it-va" | "italian" | "italiano" => "it",
        "pt" | "por" | "pt-pt" | "pt-br" | "pt-ao" | "pt-mz" | "pt-cv" | "portuguese"
        | "português" => "pt",
        "ru" | "rus" | "ru-ru" | "ru-by" | "ru-kz" | "russian" | "русский" => "ru",
        "ar" | "ara" | "ar-sa" | "ar-eg" | "ar-dz" | "ar-ma" | "ar-tn" | "ar-om" | "ar-ye"
        | "ar-sy" | "ar-jo" | "ar-lb" | "ar-kw" | "ar-ae" | "ar-bh" | "ar-qa" | "arabic"
        | "عربي" => "ar",
        "hi" | "hin" | "hi-in" | "hindi" | "हिन्दी" => "hi",
        "ja" | "jpn" | "ja-jp" | "japanese" | "日本語" => "ja",
        "ko" | "kor" | "ko-kr" | "ko-kp" | "korean" | "한국어" => "ko",
        "zh" | "zho" | "zh-cn" | "zh-hans" | "cmn" | "chi" | "chinese" | "中文" | "yue" | "wuu"
        | "hsn" | "hak" | "nan" | "gan" | "中国" => "zh-CN",
        "zh-tw" | "zh-hk" | "zh-mo" | "zh-sg" | "zh-hant" => "zh-CN",
        "bn" | "ben" | "bengali" | "ur" | "urd" | "urdu" | "pa" | "pan" | "punjabi" | "gu"
        | "guj" | "gujarati" | "mr" | "mar" | "marathi" | "ne" | "nep" | "nepali" => "hi",
        "uk" | "ukr" | "ukrainian" | "be" | "bel" | "belarusian" | "bg" | "bul" | "bulgarian"
        | "sr" | "srp" | "serbian" | "hr" | "hrv" | "croatian" | "bs" | "bos" | "bosnian" => "ru",
        "ca" | "cat" | "catalan" | "gl" | "glg" | "galician" | "ast" | "asturian" => "es",
        "ro" | "ron" | "romanian" | "mo" | "mol" | "moldavian" => "fr",
        "nl" | "nld" | "dutch" | "af" | "afr" | "afrikaans" | "fy" | "fry" | "frisian" | "lb"
        | "ltz" | "luxembourgish" => "de",

        _ => "en",
    }
}

fn detect_language(req: &HttpRequest) -> &'static str {
    if let Some(lang_header) = req.headers().get("Librecap-Language") {
        if let Ok(lang) = lang_header.to_str() {
            return normalize_language(lang);
        }
    }

    if let Some(accept_lang) = req.headers().get("Accept-Language") {
        if let Ok(lang_str) = accept_lang.to_str() {
            if let Some(primary_lang) = lang_str.split(',').next() {
                let lang_code = primary_lang.split(';').next().unwrap_or(primary_lang);
                return normalize_language(lang_code);
            }
        }
    }

    "en"
}

#[post("/audio_challenge")]
async fn audio_challenge_endpoint(
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

    if !validate_initial_pow_challenge(
        &challenge_data,
        &ip,
        user_agent,
        &data.pow_manager,
        &data.redis_client,
    )
    .await
    {
        return generate_pow_challenge_bad_response(&ip, user_agent, &data.pow_manager);
    }

    let mut rng = rand::thread_rng();
    let char_count = AUDIO_HARDNESS as i32 + rand::Rng::gen_range(&mut rng, -1..=1);
    let char_count = char_count.max(2) as usize;

    let language = detect_language(&req);

    let challenge = match data.audio_captcha_manager.generate_character_challenge(
        &ip_str, user_agent, "mixed", language, char_count, "mp3", true,
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
    buffer.extend(&challenge.audio_data);

    if let Ok(mut file) = std::fs::File::create("test.mp3") {
        if let Err(e) = std::io::Write::write_all(&mut file, &challenge.audio_data) {
            log::error!("Failed to write debug audio file: {}", e);
        }
        println!("e");
    }

    HttpResponse::Ok()
        .append_header(("Content-Type", "application/octet-stream"))
        .body(buffer)
}
