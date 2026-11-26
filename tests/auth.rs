use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use backend_rust::auth::AuthService;
use backend_rust::config::{self, Config};
use backend_rust::crypto;
use backend_rust::db::{self, Database};
use backend_rust::http;
use serde_json::{Value, json};
use tower::ServiceExt;

fn test_config() -> Config {
    let mut cfg = Config::default();
    cfg.db_driver = "sqlite".to_string();
    cfg.db_path = ":memory:".to_string();
    cfg.jwt_secret = "test-super-secret-key-at-least-32-bytes".to_string();
    cfg.access_token_ttl_sec = 900;
    cfg.refresh_token_ttl_sec = 3600;
    cfg.pbkdf2_iterations = 10000;
    cfg.max_login_attempts = 3;
    cfg
}

async fn new_service() -> AuthService {
    let cfg = test_config();
    let db = db::connect(&cfg).await.expect("connect");
    db.init_schema().await.expect("schema");
    AuthService::new(Arc::new(db), cfg)
}

async fn dispatch(
    app: &Router,
    method: &str,
    path: &str,
    body: &str,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder.body(Body::from(body.to_string())).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[test]
fn config_env_parsing() {
    let mut cfg = Config::default();
    config::apply_database_url(
        "mysql://smartuser:pass%40word@bayonos-db-smartfarm:3307/smartfarm_db?ssl-mode=PREFERRED",
        &mut cfg,
    );
    assert_eq!(cfg.db_driver, "mysql");
    assert_eq!(cfg.mysql_user, "smartuser");
    assert_eq!(cfg.mysql_password, "pass@word");
    assert_eq!(cfg.mysql_host, "bayonos-db-smartfarm");
    assert_eq!(cfg.mysql_port, 3307);
    assert_eq!(cfg.mysql_database, "smartfarm_db");

    let env = HashMap::from([
        ("DB_CONNECTION".to_string(), "mysql".to_string()),
        ("DB_HOST".to_string(), "db.internal".to_string()),
        ("DB_PORT".to_string(), "3308".to_string()),
        ("DB_USERNAME".to_string(), "appuser".to_string()),
        ("DB_PASSWORD".to_string(), "appsecret".to_string()),
        ("DB_DATABASE".to_string(), "smartfarm_db".to_string()),
    ]);
    let cfg = config::load_config(&env, "");
    assert_eq!(cfg.db_driver, "mysql");
    assert_eq!(cfg.mysql_host, "db.internal");
    assert_eq!(cfg.mysql_port, 3308);
    assert_eq!(cfg.mysql_user, "appuser");
    assert_eq!(cfg.mysql_password, "appsecret");
}

#[test]
fn crypto_pbkdf2_and_jwt() {
    let raw = "hello+world/test=123";
    let encoded = crypto::base64_url_encode(raw.as_bytes());
    let decoded = crypto::base64_url_decode(&encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), raw);

    let hash = crypto::hash_password("SecretPass123", 10000).unwrap();
    assert!(hash.starts_with("pbkdf2_sha256$10000$"));
    assert!(crypto::verify_password("SecretPass123", &hash));
    assert!(!crypto::verify_password("WrongPass123", &hash));
    assert!(!crypto::verify_password("SecretPass123", "malformed"));

    let now = AuthService::now_epoch_seconds();
    let token = crypto::create_jwt(
        &crypto::Claims {
            user_id: 42,
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            role: "owner".to_string(),
            issued_at: now,
            expires_at: now + 300,
            jti: "jti-1".to_string(),
        },
        "secret-key",
    );
    let claims = crypto::verify_jwt(&token, "secret-key", now).unwrap();
    assert_eq!(claims.user_id, 42);
    assert_eq!(claims.username, "alice");
    assert!(crypto::verify_jwt(&token, "wrong-secret", now).is_err());
    assert!(crypto::verify_jwt(&token, "secret-key", now + 301).is_err());
}

#[tokio::test]
async fn register_login_refresh_logout() {
    let service = new_service().await;
    for (username, password, full_name, email, role) in [
        ("ab", "Password123", "Alice", "a@example.com", "owner"),
        ("alice", "Password123", "", "a@example.com", "owner"),
        ("alice", "Password123", "Alice", "bad-email", "owner"),
        ("alice", "short1", "Alice", "alice@example.com", "owner"),
        (
            "alice",
            "onlyletters",
            "Alice",
            "alice@example.com",
            "owner",
        ),
        (
            "alice",
            "Password123",
            "Alice",
            "alice@example.com",
            "invalidrole",
        ),
    ] {
        let result = service
            .register_user(username, password, full_name, email, "", role)
            .await;
        assert_eq!(result.status_code, 400, "{}", result.error);
    }

    let reg = service
        .register_user(
            "alice",
            "Password123",
            "Alice Chan",
            "Alice@Example.com",
            "010290240",
            "manager",
        )
        .await;
    assert!(reg.ok, "{}", reg.error);
    assert_eq!(reg.status_code, 201);
    assert_eq!(reg.user.unwrap()["email"], "alice@example.com");

    assert_eq!(
        service
            .register_user(
                "alice2",
                "Password123",
                "Alice Two",
                "alice@example.com",
                "",
                "owner"
            )
            .await
            .status_code,
        409
    );

    let login = service
        .login("ALICE@example.com", "Password123", "127.0.0.1")
        .await;
    assert!(login.ok);
    let old_refresh = login.tokens.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let refreshed = service.refresh_session(&old_refresh).await;
    assert!(refreshed.ok);
    let new_refresh = refreshed.tokens.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(new_refresh, old_refresh);
    assert_eq!(service.refresh_session(&old_refresh).await.status_code, 401);
    assert!(service.logout(&new_refresh).await.ok);
    assert_eq!(service.refresh_session(&new_refresh).await.status_code, 401);
}

#[tokio::test]
async fn legacy_password_rate_limit_and_change_password() {
    let cfg = test_config();
    let db = db::connect(&cfg).await.unwrap();
    db.init_schema().await.unwrap();
    let seeded = db
        .create_user(
            "admin",
            "admin123",
            "Raksmey Chann",
            "admin@efarm.local",
            "010290240",
            "owner",
        )
        .await
        .unwrap();
    let service = AuthService::new(Arc::new(db), cfg);

    let login = service.login("admin", "admin123", "10.0.0.1").await;
    assert!(login.ok);
    let refresh_token = login.tokens.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(
        service
            .login("admin", "Wrong1", "10.0.0.5")
            .await
            .status_code,
        401
    );
    assert_eq!(
        service
            .login("admin", "Wrong2", "10.0.0.5")
            .await
            .status_code,
        401
    );
    assert_eq!(
        service
            .login("admin", "Wrong3", "10.0.0.5")
            .await
            .status_code,
        401
    );
    assert_eq!(
        service
            .login("admin", "admin123", "10.0.0.5")
            .await
            .status_code,
        429
    );

    assert_eq!(
        service
            .change_password(seeded.id, "WrongCurrent1", "NewPass123")
            .await
            .status_code,
        401
    );
    assert!(
        service
            .change_password(seeded.id, "admin123", "NewPass123")
            .await
            .ok
    );
    assert_eq!(
        service.refresh_session(&refresh_token).await.status_code,
        401
    );
    assert_eq!(
        service
            .login("admin", "admin123", "10.0.0.6")
            .await
            .status_code,
        401
    );
    assert!(service.login("admin", "NewPass123", "10.0.0.6").await.ok);
}

#[tokio::test]
async fn http_routes() {
    let app = http::router(new_service().await);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/api/auth/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["access-control-allow-origin"], "*");

    let (status, body) = dispatch(&app, "GET", "/health", "", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");

    let (status, _) = dispatch(&app, "POST", "/api/auth/register", "{bad", None).await;
    assert_eq!(status, 400);

    let (status, reg) = dispatch(
        &app,
        "POST",
        "/api/auth/register",
        &json!({
            "username": "httpuser",
            "password": "Password123",
            "full_name": "HTTP User",
            "email": "http@example.com",
            "role": "staff",
        })
        .to_string(),
        None,
    )
    .await;
    assert_eq!(status, 201);
    let access = reg["access_token"].as_str().unwrap().to_string();
    let refresh = reg["refresh_token"].as_str().unwrap().to_string();

    let (status, _) = dispatch(
        &app,
        "POST",
        "/auth/login",
        &json!({"email": "http@example.com", "password": "Password123"}).to_string(),
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = dispatch(&app, "GET", "/api/auth/me", "", Some(&access)).await;
    assert_eq!(status, 200);

    let (status, refreshed) = dispatch(
        &app,
        "POST",
        "/api/auth/refresh",
        &json!({"refresh_token": refresh}).to_string(),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let new_refresh = refreshed["refresh_token"].as_str().unwrap().to_string();

    let (status, _) = dispatch(
        &app,
        "POST",
        "/api/auth/change-password",
        &json!({"current_password": "Password123", "new_password": "NewPassword456"}).to_string(),
        Some(&access),
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = dispatch(
        &app,
        "POST",
        "/api/auth/refresh",
        &json!({"refresh_token": new_refresh}).to_string(),
        None,
    )
    .await;
    assert_eq!(status, 401);

    let (status, login2) = dispatch(
        &app,
        "POST",
        "/api/auth/login",
        &json!({"username": "httpuser", "password": "NewPassword456"}).to_string(),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let access2 = login2["access_token"].as_str().unwrap().to_string();
    let refresh2 = login2["refresh_token"].as_str().unwrap().to_string();

    let (status, _) = dispatch(&app, "POST", "/api/auth/logout-all", "", Some(&access2)).await;
    assert_eq!(status, 200);
    let (status, _) = dispatch(
        &app,
        "POST",
        "/api/auth/refresh",
        &json!({"refresh_token": refresh2}).to_string(),
        None,
    )
    .await;
    assert_eq!(status, 401);

    let (status, _) = dispatch(&app, "GET", "/nope", "", None).await;
    assert_eq!(status, 404);
}
