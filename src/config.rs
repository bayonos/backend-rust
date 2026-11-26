use std::collections::HashMap;
use std::fs;

use crate::crypto::random_hex;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub db_driver: String,
    pub db_path: String,
    pub mysql_host: String,
    pub mysql_port: u16,
    pub mysql_user: String,
    pub mysql_password: String,
    pub mysql_database: String,
    pub jwt_secret: String,
    pub jwt_secret_is_ephemeral: bool,
    pub access_token_ttl_sec: i64,
    pub refresh_token_ttl_sec: i64,
    pub pbkdf2_iterations: u32,
    pub max_login_attempts: usize,
    pub rate_limit_window_sec: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            db_driver: "mysql".to_string(),
            db_path: "auth.db".to_string(),
            mysql_host: "127.0.0.1".to_string(),
            mysql_port: 3306,
            mysql_user: "root".to_string(),
            mysql_password: "root".to_string(),
            mysql_database: "smartfarm_db".to_string(),
            jwt_secret: String::new(),
            jwt_secret_is_ephemeral: false,
            access_token_ttl_sec: 900,
            refresh_token_ttl_sec: 604800,
            pbkdf2_iterations: 210000,
            max_login_attempts: 10,
            rate_limit_window_sec: 60,
        }
    }
}

fn load_dot_env(path: &str, env: &mut HashMap<String, String>) {
    let content = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return,
    };
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(index) = line.find('=') else {
            continue;
        };
        let key = line[..index].trim();
        let mut value = line[index + 1..].trim().to_string();
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = value[1..value.len() - 1].to_string();
        }
        if !key.is_empty() {
            env.entry(key.to_string()).or_insert(value);
        }
    }
}

fn safe_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (
                (bytes[index + 1] as char).to_digit(16),
                (bytes[index + 2] as char).to_digit(16),
            ) {
                decoded.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

pub fn apply_database_url(url: &str, cfg: &mut Config) {
    if url.is_empty() {
        return;
    }
    let Some(scheme_end) = url.find("://") else {
        return;
    };
    let scheme = url[..scheme_end].to_lowercase();
    let mut rest = &url[scheme_end + 3..];

    if scheme == "sqlite" || scheme == "sqlite3" {
        cfg.db_driver = "sqlite".to_string();
        if !rest.is_empty() {
            cfg.db_path = rest.to_string();
        }
        return;
    }
    if scheme != "mysql" && scheme != "mysql2" && scheme != "mariadb" {
        return;
    }
    cfg.db_driver = "mysql".to_string();
    if let Some(pos) = rest.find('?') {
        rest = &rest[..pos];
    }

    let mut authority = rest;
    if let Some(slash) = rest.find('/') {
        authority = &rest[..slash];
        let db_name = &rest[slash + 1..];
        if !db_name.is_empty() {
            cfg.mysql_database = safe_decode(db_name);
        }
    }

    let mut host_port = authority;
    if let Some(at) = authority.rfind('@') {
        let user_info = &authority[..at];
        host_port = &authority[at + 1..];
        if let Some(colon) = user_info.find(':') {
            cfg.mysql_user = safe_decode(&user_info[..colon]);
            cfg.mysql_password = safe_decode(&user_info[colon + 1..]);
        } else if !user_info.is_empty() {
            cfg.mysql_user = safe_decode(user_info);
        }
    }

    if !host_port.is_empty() {
        if let Some(colon) = host_port.rfind(':') {
            let host = &host_port[..colon];
            let port = &host_port[colon + 1..];
            if !host.is_empty() {
                cfg.mysql_host = host.to_string();
            }
            if let Ok(parsed) = port.parse::<u16>() {
                cfg.mysql_port = parsed;
            }
        } else {
            cfg.mysql_host = host_port.to_string();
        }
    }
}

fn get_env(env: &HashMap<String, String>, names: &[&str], fallback: &str) -> String {
    for name in names {
        if let Some(value) = env.get(*name) {
            if !value.is_empty() {
                return value.clone();
            }
        }
    }
    fallback.to_string()
}

fn get_env_i64(env: &HashMap<String, String>, names: &[&str], fallback: i64) -> i64 {
    for name in names {
        if let Some(value) = env.get(*name) {
            if !value.is_empty() {
                if let Ok(parsed) = value.parse::<f64>() {
                    if parsed.is_finite() && parsed.fract() == 0.0 {
                        return parsed as i64;
                    }
                }
            }
        }
    }
    fallback
}

pub fn load_config(env: &HashMap<String, String>, dotenv_path: &str) -> Config {
    let mut merged = env.clone();
    if !dotenv_path.is_empty() {
        load_dot_env(dotenv_path, &mut merged);
    }

    let mut cfg = Config::default();
    cfg.host = get_env(&merged, &["HOST"], &cfg.host);
    let port = get_env_i64(&merged, &["PORT"], cfg.port as i64);
    if (1..=65535).contains(&port) {
        cfg.port = port as u16;
    }

    let database_url = get_env(&merged, &["DATABASE_URL"], "");
    if !database_url.is_empty() {
        apply_database_url(&database_url, &mut cfg);
    }

    cfg.db_driver = get_env(&merged, &["DB_DRIVER", "DB_CONNECTION"], &cfg.db_driver);
    cfg.db_path = get_env(&merged, &["DB_PATH"], &cfg.db_path);
    cfg.mysql_host = get_env(&merged, &["MYSQL_HOST", "DB_HOST"], &cfg.mysql_host);
    let mysql_port = get_env_i64(&merged, &["MYSQL_PORT", "DB_PORT"], cfg.mysql_port as i64);
    if (1..=65535).contains(&mysql_port) {
        cfg.mysql_port = mysql_port as u16;
    }
    cfg.mysql_user = get_env(
        &merged,
        &["MYSQL_USER", "DB_USER", "DB_USERNAME"],
        &cfg.mysql_user,
    );
    cfg.mysql_password = get_env(
        &merged,
        &["MYSQL_PASSWORD", "DB_PASSWORD"],
        &cfg.mysql_password,
    );
    cfg.mysql_database = get_env(
        &merged,
        &["MYSQL_DB", "DB_DATABASE", "DB_NAME"],
        &cfg.mysql_database,
    );

    cfg.jwt_secret = get_env(&merged, &["JWT_SECRET"], "");
    if cfg.jwt_secret.is_empty() {
        cfg.jwt_secret = random_hex(32);
        cfg.jwt_secret_is_ephemeral = true;
    }
    let access_ttl = get_env_i64(&merged, &["ACCESS_TOKEN_TTL_SEC"], cfg.access_token_ttl_sec);
    if access_ttl > 0 {
        cfg.access_token_ttl_sec = access_ttl;
    }
    let refresh_ttl = get_env_i64(
        &merged,
        &["REFRESH_TOKEN_TTL_SEC"],
        cfg.refresh_token_ttl_sec,
    );
    if refresh_ttl > 0 {
        cfg.refresh_token_ttl_sec = refresh_ttl;
    }
    let iterations = get_env_i64(
        &merged,
        &["PBKDF2_ITERATIONS"],
        cfg.pbkdf2_iterations as i64,
    );
    if iterations >= 10000 && iterations <= u32::MAX as i64 {
        cfg.pbkdf2_iterations = iterations as u32;
    }
    let attempts = get_env_i64(
        &merged,
        &["LOGIN_MAX_ATTEMPTS"],
        cfg.max_login_attempts as i64,
    );
    if attempts > 0 {
        cfg.max_login_attempts = attempts as usize;
    }
    let window = get_env_i64(
        &merged,
        &["LOGIN_RATE_WINDOW_SEC"],
        cfg.rate_limit_window_sec,
    );
    if window > 0 {
        cfg.rate_limit_window_sec = window;
    }
    cfg
}

pub fn environ() -> HashMap<String, String> {
    std::env::vars().collect()
}
