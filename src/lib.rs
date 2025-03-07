use actix_cors::Cors;
use actix_web::web;
use redis::AsyncCommands;

use dotenvy::dotenv;
use std::env;
use std::path::PathBuf;

pub mod handlers;
pub mod image_captcha;
pub mod pow;
pub mod redis_config;

pub use handlers::AppState;

const DEFAULT_DATASET_NAME: &str = "ai_dogs.pkl";
const POW_SECRET_KEY: &str = "pow_secret";
const IMAGE_CAPTCHA_SECRET_KEY: &str = "image_captcha_secret";

async fn get_app_state() -> AppState {
    dotenv().ok();

    let dataset_path =
        env::var("DATASET_PATH").unwrap_or_else(|_| DEFAULT_DATASET_NAME.to_string());

    let redis_config = redis_config::RedisConfig::from_env();
    let redis_url = redis_config.get_url().await;

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
                pow::PowManager::with_secret(secret_array)
            }
            _ => {
                let pow_manager = pow::PowManager::new();
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
                image_captcha::ImageCaptchaManager::with_secret(
                    &PathBuf::from(&dataset_path),
                    secret_array,
                )
                .expect("Failed to load image captcha with secret")
            }
            _ => {
                let image_captcha_manager =
                    image_captcha::ImageCaptchaManager::new(&PathBuf::from(&dataset_path))
                        .expect("Failed to load image captcha dataset");
                let secret = image_captcha_manager.get_secret();
                con.set::<&str, &[u8], ()>(IMAGE_CAPTCHA_SECRET_KEY, secret.as_slice())
                    .await
                    .expect("Failed to store image captcha secret");
                image_captcha_manager
            }
        }
    };

    AppState {
        redis_client,
        pow_manager,
        image_captcha_manager,
    }
}

pub fn add_librecap(app: &mut web::ServiceConfig) {
    let cors = Cors::default()
        .allow_any_origin()
        .allow_any_method()
        .allow_any_header();

    app.service(
        web::scope("/librecap/v1")
            .wrap(cors)
            .service(handlers::get_initial_challenges)
            .service(handlers::challenge_endpoint),
    );
}

pub async fn initialize_app_state() -> web::Data<AppState> {
    let state = get_app_state().await;
    web::Data::new(state)
}
