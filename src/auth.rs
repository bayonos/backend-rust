use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::config::Config;
use crate::crypto::{
    Claims, constant_time_equals, create_jwt, hash_password, random_hex, sha256_hex, verify_jwt,
    verify_password,
};
use crate::db::{Database, User, user_json};

pub struct RateLimiter {
    attempts: Mutex<HashMap<String, Vec<i64>>>,
    max_attempts: usize,
    window_sec: i64,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, window_sec: i64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window_sec,
        }
    }

    pub fn allow(&self, key: &str, now: i64) -> bool {
        if self.max_attempts == 0 || self.window_sec <= 0 {
            return true;
        }
        let mut attempts = match self.attempts.lock() {
            Ok(value) => value,
            Err(_) => return true,
        };
        let queue = attempts.entry(key.to_string()).or_default();
        let cutoff = now - self.window_sec;
        while queue.first().is_some_and(|value| *value <= cutoff) {
            queue.remove(0);
        }
        if queue.len() >= self.max_attempts {
            return false;
        }
        queue.push(now);
        true
    }
}

#[derive(Clone)]
pub struct AuthService {
    db: Arc<dyn Database>,
    config: Arc<Config>,
    limiter: Arc<RateLimiter>,
    dummy_hash: Arc<OnceLock<String>>,
}

#[derive(Debug)]
pub struct AuthResult {
    pub ok: bool,
    pub status_code: u16,
    pub error: String,
    pub user: Option<Value>,
    pub tokens: Option<Value>,
}

fn fail(status_code: u16, message: impl Into<String>) -> AuthResult {
    AuthResult {
        ok: false,
        status_code,
        error: message.into(),
        user: None,
        tokens: None,
    }
}

fn success(status_code: u16) -> AuthResult {
    AuthResult {
        ok: true,
        status_code,
        error: String::new(),
        user: None,
        tokens: None,
    }
}

impl AuthService {
    pub fn new(db: Arc<dyn Database>, config: Config) -> Self {
        let limiter = RateLimiter::new(config.max_login_attempts, config.rate_limit_window_sec);
        Self {
            db,
            config: Arc::new(config),
            limiter: Arc::new(limiter),
            dummy_hash: Arc::new(OnceLock::new()),
        }
    }

    pub fn now_epoch_seconds() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn dummy_password_hash(&self) -> Option<&str> {
        self.dummy_hash
            .get_or_init(|| {
                hash_password(
                    "timing-mitigation-placeholder",
                    self.config.pbkdf2_iterations,
                )
                .unwrap_or_default()
            })
            .as_str()
            .into()
    }

    fn is_valid_username(username: &str) -> bool {
        username.len() >= 3
            && username.len() <= 50
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
    }

    fn is_valid_email(email: &str) -> bool {
        if email.len() < 5 || email.len() > 120 {
            return false;
        }
        let Some((local, domain)) = email.split_once('@') else {
            return false;
        };
        if local.is_empty()
            || !local
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b))
        {
            return false;
        }
        let Some((name, tld)) = domain.rsplit_once('.') else {
            return false;
        };
        !name.is_empty()
            && !tld.is_empty()
            && tld.len() >= 2
            && tld.bytes().all(|b| b.is_ascii_alphabetic())
            && domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    }

    fn validate_password(password: &str) -> Option<&'static str> {
        if password.len() < 8 {
            return Some("Password must be at least 8 characters long");
        }
        if password.len() > 128 {
            return Some("Password must be at most 128 characters long");
        }
        let has_letter = password.bytes().any(|b| b.is_ascii_alphabetic());
        let has_digit = password.bytes().any(|b| b.is_ascii_digit());
        if !has_letter || !has_digit {
            return Some("Password must include at least one letter and one number");
        }
        None
    }

    fn verify_stored_password(candidate: &str, stored: &str) -> bool {
        if stored.starts_with("pbkdf2_sha256$") {
            verify_password(candidate, stored)
        } else {
            !stored.is_empty() && constant_time_equals(candidate, stored)
        }
    }

    async fn issue_tokens(&self, user: &User, now: i64) -> Result<Value, String> {
        let claims = Claims {
            user_id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            role: user.role.clone(),
            issued_at: now,
            expires_at: now + self.config.access_token_ttl_sec,
            jti: random_hex(16),
        };
        let access_token = create_jwt(&claims, &self.config.jwt_secret);
        let refresh_token = random_hex(32);
        let stored = self
            .db
            .store_refresh_token(
                user.id,
                &sha256_hex(&refresh_token),
                now + self.config.refresh_token_ttl_sec,
                now,
            )
            .await?;
        if !stored {
            return Err("Failed to store refresh token".to_string());
        }
        Ok(json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self.config.access_token_ttl_sec,
        }))
    }

    pub async fn register_user(
        &self,
        username: &str,
        password: &str,
        full_name: &str,
        email: &str,
        phone: &str,
        role: &str,
    ) -> AuthResult {
        let clean_username = username.trim();
        let clean_full_name = full_name.trim();
        let clean_email = email.trim().to_lowercase();
        let clean_phone = phone.trim().to_string();
        let clean_role = if role.is_empty() {
            "owner".to_string()
        } else {
            role.trim().to_lowercase()
        };

        if !Self::is_valid_username(clean_username) {
            return fail(
                400,
                "Username must be 3-50 characters (letters, digits, _, ., -)",
            );
        }
        if clean_full_name.is_empty() || clean_full_name.len() > 100 {
            return fail(400, "full_name is required (max 100 characters)");
        }
        if !clean_email.is_empty() && !Self::is_valid_email(&clean_email) {
            return fail(400, "Invalid email address");
        }
        if clean_phone.len() > 30 {
            return fail(400, "phone must be at most 30 characters");
        }
        if !["owner", "manager", "staff", "admin"].contains(&clean_role.as_str()) {
            return fail(400, "role must be one of: owner, manager, staff, admin");
        }
        if let Some(message) = Self::validate_password(password) {
            return fail(400, message);
        }

        if !clean_email.is_empty() {
            match self.db.find_user_by_email(&clean_email).await {
                Ok(Some(_)) => return fail(409, "Email already exists"),
                Ok(None) => {}
                Err(error) => return fail(500, error),
            }
        }

        let now = Self::now_epoch_seconds();
        let password_hash = match hash_password(password, self.config.pbkdf2_iterations) {
            Ok(value) => value,
            Err(error) => return fail(500, error),
        };
        let user = match self
            .db
            .create_user(
                clean_username,
                &password_hash,
                clean_full_name,
                &clean_email,
                &clean_phone,
                &clean_role,
            )
            .await
        {
            Ok(value) => value,
            Err(error) => return fail(409, error),
        };
        let tokens = match self.issue_tokens(&user, now).await {
            Ok(value) => value,
            Err(error) => return fail(500, error),
        };
        let mut result = success(201);
        result.user = Some(user_json(&user));
        result.tokens = Some(tokens);
        result
    }

    pub async fn login(&self, identifier: &str, password: &str, client_ip: &str) -> AuthResult {
        let now = Self::now_epoch_seconds();
        let rate_key = if client_ip.is_empty() {
            "unknown"
        } else {
            client_ip
        };
        if !self.limiter.allow(rate_key, now) {
            return fail(429, "Too many login attempts. Please try again later.");
        }

        let clean_id = identifier.trim();
        if clean_id.is_empty() || password.is_empty() {
            return fail(400, "Identifier and password are required");
        }

        let found = if clean_id.contains('@') {
            self.db.find_user_by_email(&clean_id.to_lowercase()).await
        } else {
            self.db.find_user_by_username(clean_id).await
        };
        let user = match found {
            Ok(value) => value,
            Err(error) => return fail(500, error),
        };
        let Some(user) = user else {
            if let Some(hash) = self.dummy_password_hash() {
                verify_password(password, hash);
            }
            return fail(401, "Invalid credentials");
        };
        if !Self::verify_stored_password(password, &user.password) {
            return fail(401, "Invalid credentials");
        }
        if user.status != "active" {
            return fail(403, "User account is inactive");
        }
        let tokens = match self.issue_tokens(&user, now).await {
            Ok(value) => value,
            Err(error) => return fail(500, error),
        };
        let mut result = success(200);
        result.user = Some(user_json(&user));
        result.tokens = Some(tokens);
        result
    }

    pub async fn refresh_session(&self, refresh_token: &str) -> AuthResult {
        let clean_token = refresh_token.trim();
        if clean_token.is_empty() {
            return fail(400, "refresh_token is required");
        }
        let now = Self::now_epoch_seconds();
        let token_hash = sha256_hex(clean_token);
        let record = match self.db.find_refresh_token(&token_hash).await {
            Ok(value) => value,
            Err(error) => return fail(500, error),
        };
        let Some(record) = record else {
            return fail(401, "Invalid or expired refresh token");
        };
        if record.revoked || record.expires_at <= now {
            return fail(401, "Invalid or expired refresh token");
        }
        match self.db.revoke_refresh_token(&token_hash).await {
            Ok(true) => {}
            _ => return fail(401, "Invalid or expired refresh token"),
        }
        let user = match self.db.find_user_by_id(record.user_id).await {
            Ok(Some(value)) => value,
            Ok(None) => return fail(401, "User no longer exists"),
            Err(error) => return fail(500, error),
        };
        if user.status != "active" {
            return fail(403, "User account is inactive");
        }
        let tokens = match self.issue_tokens(&user, now).await {
            Ok(value) => value,
            Err(error) => return fail(500, error),
        };
        let mut result = success(200);
        result.user = Some(user_json(&user));
        result.tokens = Some(tokens);
        result
    }

    pub async fn logout(&self, refresh_token: &str) -> AuthResult {
        let clean_token = refresh_token.trim();
        if clean_token.is_empty() {
            return fail(400, "refresh_token is required");
        }
        let _ = self.db.revoke_refresh_token(&sha256_hex(clean_token)).await;
        success(200)
    }

    pub async fn logout_all(&self, user_id: i64) -> AuthResult {
        let _ = self.db.revoke_all_user_refresh_tokens(user_id).await;
        success(200)
    }

    pub fn authenticate_access_token(&self, bearer_token: &str) -> Option<Claims> {
        if bearer_token.is_empty() {
            return None;
        }
        verify_jwt(
            bearer_token,
            &self.config.jwt_secret,
            Self::now_epoch_seconds(),
        )
        .ok()
    }

    pub async fn get_profile(&self, user_id: i64) -> AuthResult {
        let user = match self.db.find_user_by_id(user_id).await {
            Ok(Some(value)) => value,
            Ok(None) => return fail(404, "User not found"),
            Err(error) => return fail(500, error),
        };
        let mut result = success(200);
        result.user = Some(user_json(&user));
        result
    }

    pub async fn change_password(
        &self,
        user_id: i64,
        current_password: &str,
        new_password: &str,
    ) -> AuthResult {
        if current_password.is_empty() || new_password.is_empty() {
            return fail(400, "current_password and new_password are required");
        }
        if let Some(message) = Self::validate_password(new_password) {
            return fail(400, message);
        }
        let user = match self.db.find_user_by_id(user_id).await {
            Ok(Some(value)) => value,
            Ok(None) => return fail(404, "User not found"),
            Err(error) => return fail(500, error),
        };
        if !Self::verify_stored_password(current_password, &user.password) {
            return fail(401, "Current password is incorrect");
        }
        let new_hash = match hash_password(new_password, self.config.pbkdf2_iterations) {
            Ok(value) => value,
            Err(error) => return fail(500, error),
        };
        match self.db.update_password(user_id, &new_hash).await {
            Ok(true) => {}
            _ => return fail(500, "Failed to update password"),
        }
        let _ = self.db.revoke_all_user_refresh_tokens(user_id).await;
        success(200)
    }
}
