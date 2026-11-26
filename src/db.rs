use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use sqlx::FromRow;
use sqlx::mysql::{MySqlConnectOptions, MySqlPool};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool};

use crate::config::Config;

#[derive(Clone, Debug)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub full_name: String,
    pub email: String,
    pub phone: String,
    pub role: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct RefreshToken {
    pub id: i64,
    pub user_id: i64,
    pub token_hash: String,
    pub expires_at: i64,
    pub revoked: bool,
    pub created_at: i64,
}

#[derive(FromRow)]
struct SqliteUserRow {
    id: i64,
    username: String,
    password: String,
    full_name: String,
    email: Option<String>,
    phone: Option<String>,
    role: String,
    status: String,
    created_at: String,
}

#[derive(FromRow)]
struct MySqlUserRow {
    id: i32,
    username: String,
    password: String,
    full_name: String,
    email: Option<String>,
    phone: Option<String>,
    role: String,
    status: String,
    created_at: Option<String>,
}

#[derive(FromRow)]
struct SqliteRefreshRow {
    id: i64,
    user_id: i64,
    token_hash: String,
    expires_at: i64,
    revoked: i64,
    created_at: i64,
}

#[derive(FromRow)]
struct MySqlRefreshRow {
    id: i64,
    user_id: i32,
    token_hash: String,
    expires_at: i64,
    revoked: i8,
    created_at: i64,
}

impl From<SqliteUserRow> for User {
    fn from(row: SqliteUserRow) -> Self {
        Self {
            id: row.id,
            username: row.username,
            password: row.password,
            full_name: row.full_name,
            email: row.email.unwrap_or_default(),
            phone: row.phone.unwrap_or_default(),
            role: row.role,
            status: row.status,
            created_at: row.created_at,
        }
    }
}

impl From<MySqlUserRow> for User {
    fn from(row: MySqlUserRow) -> Self {
        Self {
            id: row.id as i64,
            username: row.username,
            password: row.password,
            full_name: row.full_name,
            email: row.email.unwrap_or_default(),
            phone: row.phone.unwrap_or_default(),
            role: row.role,
            status: row.status,
            created_at: row.created_at.unwrap_or_default(),
        }
    }
}

impl From<SqliteRefreshRow> for RefreshToken {
    fn from(row: SqliteRefreshRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            expires_at: row.expires_at,
            revoked: row.revoked != 0,
            created_at: row.created_at,
        }
    }
}

impl From<MySqlRefreshRow> for RefreshToken {
    fn from(row: MySqlRefreshRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id as i64,
            token_hash: row.token_hash,
            expires_at: row.expires_at,
            revoked: row.revoked != 0,
            created_at: row.created_at,
        }
    }
}

const SQLITE_USER_SELECT: &str =
    "SELECT id, username, password, full_name, email, phone, role, status, created_at FROM users";
const MYSQL_USER_SELECT: &str = "SELECT id, username, password, full_name, email, phone, role, status, \
     COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') AS created_at FROM users";

pub enum Db {
    Sqlite(SqlitePool),
    MySql(MySqlPool),
}

pub async fn connect(cfg: &Config) -> Result<Db, String> {
    match cfg.db_driver.as_str() {
        "sqlite" => {
            let options = if cfg.db_path == ":memory:" {
                SqliteConnectOptions::new()
                    .in_memory(true)
                    .busy_timeout(Duration::from_secs(5))
                    .foreign_keys(true)
            } else {
                SqliteConnectOptions::from_str(&format!("sqlite:{}", cfg.db_path))
                    .map_err(|err| err.to_string())?
                    .create_if_missing(true)
                    .busy_timeout(Duration::from_secs(5))
                    .foreign_keys(true)
                    .journal_mode(SqliteJournalMode::Wal)
            };
            let max_connections = if cfg.db_path == ":memory:" { 1 } else { 10 };
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(max_connections)
                .connect_with(options)
                .await
                .map_err(|err| err.to_string())?;
            Ok(Db::Sqlite(pool))
        }
        "mysql" => {
            let options = MySqlConnectOptions::new()
                .host(cfg.mysql_host.as_str())
                .port(cfg.mysql_port)
                .username(cfg.mysql_user.as_str())
                .password(cfg.mysql_password.as_str())
                .database(cfg.mysql_database.as_str());
            let pool = MySqlPool::connect_with(options)
                .await
                .map_err(|err| err.to_string())?;
            Ok(Db::MySql(pool))
        }
        other => Err(format!(
            "Unsupported DB_DRIVER: {other} (expected mysql or sqlite)"
        )),
    }
}

fn is_duplicate_entry(error: &sqlx::Error) -> bool {
    let message = error.to_string();
    message.contains("UNIQUE constraint failed")
        || message.contains("Duplicate entry")
        || message.contains("1062")
}

fn utc_timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86400);
    let seconds_of_day = seconds.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year,
        month,
        day,
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let day_of_era = z - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + if month <= 2 { 1 } else { 0 }, month, day)
}

#[async_trait]
pub trait Database: Send + Sync {
    async fn init_schema(&self) -> Result<(), String>;
    async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        full_name: &str,
        email: &str,
        phone: &str,
        role: &str,
    ) -> Result<User, String>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, String>;
    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, String>;
    async fn find_user_by_id(&self, user_id: i64) -> Result<Option<User>, String>;
    async fn update_password(&self, user_id: i64, new_hash: &str) -> Result<bool, String>;
    async fn store_refresh_token(
        &self,
        user_id: i64,
        token_hash: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, String>;
    async fn find_refresh_token(&self, token_hash: &str) -> Result<Option<RefreshToken>, String>;
    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<bool, String>;
    async fn revoke_all_user_refresh_tokens(&self, user_id: i64) -> Result<bool, String>;
}

#[async_trait]
impl Database for Db {
    async fn init_schema(&self) -> Result<(), String> {
        let statements: &[&str] = match self {
            Db::Sqlite(_) => &[
                "CREATE TABLE IF NOT EXISTS users (\
                 id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 username TEXT NOT NULL UNIQUE COLLATE NOCASE, \
                 password TEXT NOT NULL, full_name TEXT NOT NULL, \
                 email TEXT COLLATE NOCASE, phone TEXT, \
                 role TEXT NOT NULL DEFAULT 'owner', \
                 status TEXT NOT NULL DEFAULT 'active', \
                 created_at TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS refresh_tokens (\
                 id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 user_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE, \
                 expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, \
                 created_at INTEGER NOT NULL, \
                 FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)",
                "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)",
            ],
            Db::MySql(_) => &[
                "CREATE TABLE IF NOT EXISTS users (\
                 id INT NOT NULL AUTO_INCREMENT, username VARCHAR(50) NOT NULL, \
                 password VARCHAR(255) NOT NULL, full_name VARCHAR(100) NOT NULL, \
                 email VARCHAR(120) DEFAULT NULL, phone VARCHAR(30) DEFAULT NULL, \
                 role ENUM('owner','manager','staff','admin') NOT NULL DEFAULT 'owner', \
                 status ENUM('active','inactive') NOT NULL DEFAULT 'active', \
                 created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP, \
                 PRIMARY KEY (id), UNIQUE KEY username (username) \
                 ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
                "CREATE TABLE IF NOT EXISTS refresh_tokens (\
                 id BIGINT NOT NULL AUTO_INCREMENT, user_id INT NOT NULL, \
                 token_hash CHAR(64) NOT NULL, expires_at BIGINT NOT NULL, \
                 revoked TINYINT(1) NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, \
                 PRIMARY KEY (id), UNIQUE KEY uk_refresh_tokens_hash (token_hash), \
                 KEY idx_refresh_tokens_user_id (user_id), \
                 CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) \
                 REFERENCES users(id) ON DELETE CASCADE \
                 ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            ],
        };
        for statement in statements {
            match self {
                Db::Sqlite(pool) => {
                    sqlx::query(statement)
                        .execute(pool)
                        .await
                        .map_err(|err| err.to_string())?;
                }
                Db::MySql(pool) => {
                    sqlx::query(statement)
                        .execute(pool)
                        .await
                        .map_err(|err| err.to_string())?;
                }
            }
        }
        Ok(())
    }

    async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        full_name: &str,
        email: &str,
        phone: &str,
        role: &str,
    ) -> Result<User, String> {
        let sql = "INSERT INTO users (username, password, full_name, email, phone, role, status, created_at) \
                   VALUES (?, ?, ?, ?, ?, ?, 'active', ?)";
        let email_value = if email.is_empty() { None } else { Some(email) };
        let phone_value = if phone.is_empty() { None } else { Some(phone) };
        let created_at = utc_timestamp();
        let result = match self {
            Db::Sqlite(pool) => sqlx::query(sql)
                .bind(username)
                .bind(password_hash)
                .bind(full_name)
                .bind(email_value)
                .bind(phone_value)
                .bind(role)
                .bind(&created_at)
                .execute(pool)
                .await
                .map(|_| ()),
            Db::MySql(pool) => sqlx::query(sql)
                .bind(username)
                .bind(password_hash)
                .bind(full_name)
                .bind(email_value)
                .bind(phone_value)
                .bind(role)
                .bind(&created_at)
                .execute(pool)
                .await
                .map(|_| ()),
        };
        if let Err(error) = result {
            return if is_duplicate_entry(&error) {
                Err("Username already exists".to_string())
            } else {
                Err(error.to_string())
            };
        }
        self.find_user_by_username(username)
            .await?
            .ok_or_else(|| "Failed to load newly created user".to_string())
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, String> {
        match self {
            Db::Sqlite(pool) => {
                let sql = format!("{SQLITE_USER_SELECT} WHERE LOWER(email) = LOWER(?) LIMIT 1");
                let row: Option<SqliteUserRow> = sqlx::query_as(&sql)
                    .bind(email)
                    .fetch_optional(pool)
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(row.map(Into::into))
            }
            Db::MySql(pool) => {
                let sql = format!("{MYSQL_USER_SELECT} WHERE LOWER(email) = LOWER(?) LIMIT 1");
                let row: Option<MySqlUserRow> = sqlx::query_as(&sql)
                    .bind(email)
                    .fetch_optional(pool)
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(row.map(Into::into))
            }
        }
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, String> {
        match self {
            Db::Sqlite(pool) => {
                let sql = format!("{SQLITE_USER_SELECT} WHERE LOWER(username) = LOWER(?) LIMIT 1");
                let row: Option<SqliteUserRow> = sqlx::query_as(&sql)
                    .bind(username)
                    .fetch_optional(pool)
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(row.map(Into::into))
            }
            Db::MySql(pool) => {
                let sql = format!("{MYSQL_USER_SELECT} WHERE LOWER(username) = LOWER(?) LIMIT 1");
                let row: Option<MySqlUserRow> = sqlx::query_as(&sql)
                    .bind(username)
                    .fetch_optional(pool)
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(row.map(Into::into))
            }
        }
    }

    async fn find_user_by_id(&self, user_id: i64) -> Result<Option<User>, String> {
        match self {
            Db::Sqlite(pool) => {
                let sql = format!("{SQLITE_USER_SELECT} WHERE id = ? LIMIT 1");
                let row: Option<SqliteUserRow> = sqlx::query_as(&sql)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(row.map(Into::into))
            }
            Db::MySql(pool) => {
                let sql = format!("{MYSQL_USER_SELECT} WHERE id = ? LIMIT 1");
                let row: Option<MySqlUserRow> = sqlx::query_as(&sql)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(row.map(Into::into))
            }
        }
    }

    async fn update_password(&self, user_id: i64, new_hash: &str) -> Result<bool, String> {
        let sql = "UPDATE users SET password = ? WHERE id = ?";
        let affected = match self {
            Db::Sqlite(pool) => sqlx::query(sql)
                .bind(new_hash)
                .bind(user_id)
                .execute(pool)
                .await
                .map_err(|err| err.to_string())?
                .rows_affected(),
            Db::MySql(pool) => sqlx::query(sql)
                .bind(new_hash)
                .bind(user_id)
                .execute(pool)
                .await
                .map_err(|err| err.to_string())?
                .rows_affected(),
        };
        Ok(affected > 0)
    }

    async fn store_refresh_token(
        &self,
        user_id: i64,
        token_hash: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        let sql = "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at) \
                   VALUES (?, ?, ?, 0, ?)";
        let affected = match self {
            Db::Sqlite(pool) => sqlx::query(sql)
                .bind(user_id)
                .bind(token_hash)
                .bind(expires_at)
                .bind(now)
                .execute(pool)
                .await
                .map_err(|err| err.to_string())?
                .rows_affected(),
            Db::MySql(pool) => sqlx::query(sql)
                .bind(user_id)
                .bind(token_hash)
                .bind(expires_at)
                .bind(now)
                .execute(pool)
                .await
                .map_err(|err| err.to_string())?
                .rows_affected(),
        };
        Ok(affected > 0)
    }

    async fn find_refresh_token(&self, token_hash: &str) -> Result<Option<RefreshToken>, String> {
        match self {
            Db::Sqlite(pool) => {
                let row: Option<SqliteRefreshRow> = sqlx::query_as(
                    "SELECT id, user_id, token_hash, expires_at, revoked, created_at \
                     FROM refresh_tokens WHERE token_hash = ? LIMIT 1",
                )
                .bind(token_hash)
                .fetch_optional(pool)
                .await
                .map_err(|err| err.to_string())?;
                Ok(row.map(Into::into))
            }
            Db::MySql(pool) => {
                let row: Option<MySqlRefreshRow> = sqlx::query_as(
                    "SELECT id, user_id, token_hash, expires_at, revoked, created_at \
                     FROM refresh_tokens WHERE token_hash = ? LIMIT 1",
                )
                .bind(token_hash)
                .fetch_optional(pool)
                .await
                .map_err(|err| err.to_string())?;
                Ok(row.map(Into::into))
            }
        }
    }

    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<bool, String> {
        let sql = "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0";
        let affected = match self {
            Db::Sqlite(pool) => sqlx::query(sql)
                .bind(token_hash)
                .execute(pool)
                .await
                .map_err(|err| err.to_string())?
                .rows_affected(),
            Db::MySql(pool) => sqlx::query(sql)
                .bind(token_hash)
                .execute(pool)
                .await
                .map_err(|err| err.to_string())?
                .rows_affected(),
        };
        Ok(affected > 0)
    }

    async fn revoke_all_user_refresh_tokens(&self, user_id: i64) -> Result<bool, String> {
        let sql = "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0";
        match self {
            Db::Sqlite(pool) => {
                sqlx::query(sql)
                    .bind(user_id)
                    .execute(pool)
                    .await
                    .map_err(|err| err.to_string())?;
            }
            Db::MySql(pool) => {
                sqlx::query(sql)
                    .bind(user_id)
                    .execute(pool)
                    .await
                    .map_err(|err| err.to_string())?;
            }
        }
        Ok(true)
    }
}

pub fn user_json(user: &User) -> Value {
    serde_json::json!({
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "role": user.role,
        "status": user.status,
        "created_at": user.created_at,
    })
}
