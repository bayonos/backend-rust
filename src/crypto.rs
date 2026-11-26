use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Claims {
    pub user_id: i64,
    pub username: String,
    pub email: String,
    pub role: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub jti: String,
}

fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn base64_url_encode(data: &[u8]) -> String {
    b64_encode(data)
}

pub fn base64_url_decode(encoded: &str) -> Result<Vec<u8>, String> {
    b64_decode(encoded)
}

fn b64_decode(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = encoded.as_bytes();
    let mut end = bytes.len();
    let mut padding = 0;
    while end > 0 && bytes[end - 1] == b'=' {
        padding += 1;
        end -= 1;
    }
    if padding > 2 {
        return Err("invalid base64url".to_string());
    }
    let core = &encoded[..end];
    if core.is_empty()
        || !core
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid base64url".to_string());
    }
    URL_SAFE_NO_PAD.decode(core).map_err(|err| err.to_string())
}

pub fn random_hex(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn constant_time_equals(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.is_empty() {
        return true;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(key_len);
    let mut block: u32 = 1;
    while output.len() < key_len {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC accepts any key");
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut mac =
                <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC accepts any key");
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (x, y) in t.iter_mut().zip(&u) {
                *x ^= *y;
            }
        }
        output.extend_from_slice(&t);
        block += 1;
    }
    output.truncate(key_len);
    output
}

fn bytes_constant_time_equals(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn hash_password(password: &str, iterations: u32) -> Result<String, String> {
    if iterations == 0 {
        return Err("iterations must be positive".to_string());
    }
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let derived = pbkdf2_sha256(password.as_bytes(), &salt, iterations, 32);
    Ok(format!(
        "pbkdf2_sha256${}${}${}",
        iterations,
        hex::encode(salt),
        hex::encode(derived)
    ))
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let parts: Vec<&str> = stored_hash.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2_sha256" {
        return false;
    }
    let iterations = match parts[1].parse::<u32>() {
        Ok(value) if value > 0 && value.to_string() == parts[1] => value,
        _ => return false,
    };
    let salt = match hex::decode(parts[2]) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let expected = match hex::decode(parts[3]) {
        Ok(value) if !value.is_empty() => value,
        _ => return false,
    };
    let derived = pbkdf2_sha256(password.as_bytes(), &salt, iterations, expected.len());
    bytes_constant_time_equals(&derived, &expected)
}

pub fn create_jwt(claims: &Claims, secret: &str) -> String {
    let header = json!({ "alg": "HS256", "typ": "JWT" });
    let payload = json!({
        "sub": claims.user_id,
        "username": claims.username,
        "email": claims.email,
        "role": claims.role,
        "iat": claims.issued_at,
        "exp": claims.expires_at,
        "jti": claims.jti,
    });
    let header_bytes = serde_json::to_vec(&header).unwrap_or_default();
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let signing_input = format!(
        "{}.{}",
        b64_encode(&header_bytes),
        b64_encode(&payload_bytes)
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(signing_input.as_bytes());
    format!(
        "{}.{}",
        signing_input,
        b64_encode(&mac.finalize().into_bytes())
    )
}

fn json_int(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

pub fn verify_jwt(token: &str, secret: &str, now_epoch_sec: i64) -> Result<Claims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
        return Err("malformed token".to_string());
    }
    let signature = b64_decode(parts[2])?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| "invalid signature".to_string())?;

    let header_json: Value =
        serde_json::from_slice(&b64_decode(parts[0])?).map_err(|err| err.to_string())?;
    if header_json.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Err("unsupported algorithm".to_string());
    }
    let payload_json: Value =
        serde_json::from_slice(&b64_decode(parts[1])?).map_err(|err| err.to_string())?;

    let user_id = json_int(payload_json.get("sub")).ok_or("invalid sub")?;
    let expires_at = json_int(payload_json.get("exp")).ok_or("invalid exp")?;
    let username = payload_json
        .get("username")
        .and_then(Value::as_str)
        .ok_or("invalid username")?
        .to_string();
    let email = payload_json
        .get("email")
        .and_then(Value::as_str)
        .ok_or("invalid email")?
        .to_string();
    let role = payload_json
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let issued_at = json_int(payload_json.get("iat")).unwrap_or(0);
    let jti = payload_json
        .get("jti")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if user_id <= 0 || expires_at <= now_epoch_sec {
        return Err("expired or invalid token".to_string());
    }
    Ok(Claims {
        user_id,
        username,
        email,
        role,
        issued_at,
        expires_at,
        jti,
    })
}
