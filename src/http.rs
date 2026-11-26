use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, FromRequest, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Map, Value, json};

use crate::auth::{AuthResult, AuthService};

pub struct AppState {
    pub auth: AuthService,
}

fn add_cors(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization"),
    );
}

fn json_response(status_code: StatusCode, body: Value) -> Response {
    let mut response = (status_code, Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn json_error(status_code: u16, message: &str) -> Response {
    json_response(
        StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        json!({ "error": message }),
    )
}

fn auth_result_response(result: AuthResult) -> Response {
    if !result.ok {
        return json_error(result.status_code, &result.error);
    }
    let mut body = Map::new();
    if let Some(user) = result.user {
        body.insert("user".to_string(), user);
    }
    if let Some(tokens) = result.tokens {
        if let Some(object) = tokens.as_object() {
            for (key, value) in object {
                body.insert(key.clone(), value.clone());
            }
        }
    }
    json_response(
        StatusCode::from_u16(result.status_code).unwrap_or(StatusCode::OK),
        Value::Object(body),
    )
}

struct JsonObject(Value);

impl<S> FromRequest<S> for JsonObject
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| json_error(400, "Invalid JSON request body"))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| json_error(400, "Invalid JSON request body"))?;
        if !value.is_object() {
            return Err(json_error(400, "Invalid JSON request body"));
        }
        Ok(JsonObject(value))
    }
}

fn string_field(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(Value::as_str).map(str::to_string)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

fn client_ip(headers: &HeaderMap, connect: Option<ConnectInfo<SocketAddr>>) -> String {
    if let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        if let Some(first) = forwarded.split(',').next() {
            let first = first.trim();
            if !first.is_empty() {
                return first.to_string();
            }
        }
    }
    if let Some(real_ip) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
    {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    connect
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

async fn cors_middleware(req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        add_cors(response.headers_mut());
        return response;
    }
    let mut response = next.run(req).await;
    add_cors(response.headers_mut());
    response
}

async fn root() -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "service": "smartfarm-auth-backend",
            "endpoints": [
                "GET /health",
                "POST /api/auth/register",
                "POST /api/auth/login",
                "POST /api/auth/refresh",
                "POST /api/auth/logout",
                "POST /api/auth/logout-all",
                "GET /api/auth/me",
                "POST /api/auth/change-password",
            ],
        }),
    )
}

async fn health() -> Response {
    json_response(StatusCode::OK, json!({ "status": "ok" }))
}

async fn register(State(state): State<Arc<AppState>>, JsonObject(body): JsonObject) -> Response {
    let Some(username) = string_field(&body, "username") else {
        return json_error(400, "username and password are required strings");
    };
    let Some(password) = string_field(&body, "password") else {
        return json_error(400, "username and password are required strings");
    };
    let full_name = string_field(&body, "full_name").unwrap_or_else(|| username.clone());
    let email = string_field(&body, "email").unwrap_or_default();
    let phone = string_field(&body, "phone").unwrap_or_default();
    let role = string_field(&body, "role").unwrap_or_default();
    auth_result_response(
        state
            .auth
            .register_user(&username, &password, &full_name, &email, &phone, &role)
            .await,
    )
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    JsonObject(body): JsonObject,
) -> Response {
    let identifier = string_field(&body, "identifier")
        .or_else(|| string_field(&body, "email"))
        .or_else(|| string_field(&body, "username"));
    let Some(identifier) = identifier else {
        return json_error(
            400,
            "username (or email/identifier) and password are required",
        );
    };
    let Some(password) = string_field(&body, "password") else {
        return json_error(
            400,
            "username (or email/identifier) and password are required",
        );
    };
    let ip = client_ip(&headers, None);
    auth_result_response(state.auth.login(&identifier, &password, &ip).await)
}

async fn refresh(State(state): State<Arc<AppState>>, JsonObject(body): JsonObject) -> Response {
    let Some(token) = string_field(&body, "refresh_token") else {
        return json_error(400, "refresh_token is required");
    };
    auth_result_response(state.auth.refresh_session(&token).await)
}

async fn logout(State(state): State<Arc<AppState>>, JsonObject(body): JsonObject) -> Response {
    let Some(token) = string_field(&body, "refresh_token") else {
        return json_error(400, "refresh_token is required");
    };
    let result = state.auth.logout(&token).await;
    if !result.ok {
        return json_error(result.status_code, &result.error);
    }
    json_response(StatusCode::OK, json!({ "message": "Logged out" }))
}

async fn logout_all(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return json_error(401, "Missing or invalid Authorization header");
    };
    let Some(claims) = state.auth.authenticate_access_token(&token) else {
        return json_error(401, "Invalid or expired access token");
    };
    state.auth.logout_all(claims.user_id).await;
    json_response(StatusCode::OK, json!({ "message": "All sessions revoked" }))
}

async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return json_error(401, "Missing or invalid Authorization header");
    };
    let Some(claims) = state.auth.authenticate_access_token(&token) else {
        return json_error(401, "Invalid or expired access token");
    };
    auth_result_response(state.auth.get_profile(claims.user_id).await)
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    JsonObject(body): JsonObject,
) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return json_error(401, "Missing or invalid Authorization header");
    };
    let Some(claims) = state.auth.authenticate_access_token(&token) else {
        return json_error(401, "Invalid or expired access token");
    };
    let Some(current_password) = string_field(&body, "current_password") else {
        return json_error(400, "current_password and new_password are required");
    };
    let Some(new_password) = string_field(&body, "new_password") else {
        return json_error(400, "current_password and new_password are required");
    };
    let result = state
        .auth
        .change_password(claims.user_id, &current_password, &new_password)
        .await;
    if !result.ok {
        return json_error(result.status_code, &result.error);
    }
    json_response(
        StatusCode::OK,
        json!({ "message": "Password updated; all refresh tokens revoked" }),
    )
}

async fn not_found() -> Response {
    json_error(404, "Not found")
}

pub fn router(auth: AuthService) -> Router {
    let state = Arc::new(AppState { auth });
    Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/api/auth/register", post(register))
        .route("/auth/register", post(register))
        .route("/api/auth/login", post(login))
        .route("/auth/login", post(login))
        .route("/api/auth/refresh", post(refresh))
        .route("/auth/refresh", post(refresh))
        .route("/api/auth/logout", post(logout))
        .route("/auth/logout", post(logout))
        .route("/api/auth/logout-all", post(logout_all))
        .route("/auth/logout-all", post(logout_all))
        .route("/api/auth/me", get(me))
        .route("/auth/me", get(me))
        .route("/api/auth/change-password", post(change_password))
        .route("/auth/change-password", post(change_password))
        .fallback(not_found)
        .layer(middleware::from_fn(cors_middleware))
        .with_state(state)
}
