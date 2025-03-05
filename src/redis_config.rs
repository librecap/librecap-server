use std::env;
use url::Url;

const DEFAULT_REDIS_HOST: &str = "127.0.0.1";
const DEFAULT_REDIS_PORT: u16 = 6379;

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_REDIS_HOST.to_string(),
            port: DEFAULT_REDIS_PORT,
            password: None,
        }
    }
}

impl RedisConfig {
    pub fn from_env() -> Self {
        let mut config = RedisConfig::default();

        if let Ok(url_str) = env::var("REDIS_URL") {
            if let Ok(url) = Url::parse(&url_str) {
                config = Self::from_url(&url);
            }
        }

        if let Ok(host) = env::var("REDIS_HOST") {
            config.host = host;
        }

        if let Ok(port_str) = env::var("REDIS_PORT") {
            if let Ok(port) = port_str.parse() {
                config.port = port;
            }
        }

        if let Ok(password) = env::var("REDIS_PASSWORD") {
            config.password = Some(password);
        }

        config
    }

    fn from_url(url: &Url) -> Self {
        let mut config = RedisConfig::default();

        config.host = url.host_str().unwrap_or(DEFAULT_REDIS_HOST).to_string();

        config.port = url.port().unwrap_or(DEFAULT_REDIS_PORT);

        if let Some(password) = url.password() {
            config.password = Some(password.to_string());
        }

        config
    }

    pub async fn get_url(&self) -> String {
        match &self.password {
            Some(pass) => format!("redis://:{}@{}:{}", pass, self.host, self.port),
            None => format!("redis://{}:{}", self.host, self.port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        let config = RedisConfig::default();
        assert_eq!(config.host, DEFAULT_REDIS_HOST);
        assert_eq!(config.port, DEFAULT_REDIS_PORT);
        assert_eq!(config.password, None);
    }

    #[test]
    fn test_from_env_with_url() {
        env::set_var("REDIS_URL", "redis://:password123@localhost:6380");
        let config = RedisConfig::from_env();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 6380);
        assert_eq!(config.password, Some("password123".to_string()));
        env::remove_var("REDIS_URL");
    }

    #[test]
    fn test_individual_env_vars() {
        env::set_var("REDIS_HOST", "redis.example.com");
        env::set_var("REDIS_PORT", "6381");
        env::set_var("REDIS_PASSWORD", "secret123");

        let config = RedisConfig::from_env();
        assert_eq!(config.host, "redis.example.com");
        assert_eq!(config.port, 6381);
        assert_eq!(config.password, Some("secret123".to_string()));

        env::remove_var("REDIS_HOST");
        env::remove_var("REDIS_PORT");
        env::remove_var("REDIS_PASSWORD");
    }

    #[test]
    fn test_env_vars_override_url() {
        env::set_var("REDIS_URL", "redis://:password123@localhost:6380");
        env::set_var("REDIS_HOST", "redis.example.com");
        env::set_var("REDIS_PORT", "6381");

        let config = RedisConfig::from_env();
        assert_eq!(config.host, "redis.example.com");
        assert_eq!(config.port, 6381);
        assert_eq!(config.password, Some("password123".to_string()));

        env::remove_var("REDIS_URL");
        env::remove_var("REDIS_HOST");
        env::remove_var("REDIS_PORT");
    }
}
