use actix_web::HttpRequest;
use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use base64::prelude::*;
use tracing::warn;

use crate::config::{AppConfig, UserConfig};
use crate::security::sanitize_for_log;

const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$WnJ1TFZNZEQ0QTR2ZTBJWmU1U3VRZz09$xUlVAT+VaNcyoUWHkG7kByZSepDKwJnzFScqJUmYlg8";

pub fn parse_basic_auth(req: &HttpRequest) -> Option<(String, String)> {
    let header = req.headers().get("Authorization")?;
    let header_str = header.to_str().ok()?;
    let (scheme, b64) = header_str.split_once(' ')?;

    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }

    let decoded = BASE64_STANDARD.decode(b64).ok();
    let decoded_str = String::from_utf8(decoded?).ok()?;

    let mut parts = decoded_str.splitn(2, ':');
    let user = parts.next()?.to_string();
    let pass = parts.next().unwrap_or("").to_string();

    Some((user, pass))
}

pub fn verify_user(cfg: &AppConfig, username: &str, password: &str) -> Option<UserConfig> {
    let user = cfg.find_user(username).cloned();
    let password_hash = user
        .as_ref()
        .map(|user| user.password_hash.as_str())
        .unwrap_or(DUMMY_PASSWORD_HASH);

    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(h) => h,
        Err(e) => {
            warn!(
                "Error while parsing the password for {}: {}",
                sanitize_for_log(username),
                e
            );
            return None;
        }
    };

    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        user
    } else {
        None
    }
}

pub(crate) fn validate_password_hash(password_hash: &str) -> Result<(), String> {
    PasswordHash::new(password_hash)
        .map(|_| ())
        .map_err(|e| format!("Invalid password hash: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, UserConfig};
    use actix_web::test::TestRequest;
    use argon2::PasswordHasher;
    use argon2::password_hash::phc::Salt;

    const TEST_SALT: &str = "WnJ1TFZNZEQ0QTR2ZTBJWmU1U3VRZz09";

    fn build_test_config() -> AppConfig {
        let salt = Salt::from_b64(TEST_SALT).unwrap();
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password_with_salt(b"secret", &salt)
            .unwrap()
            .to_string();

        AppConfig {
            users: vec![UserConfig {
                server: "127.0.0.1".into(),
                tsig_key_path: "/dev/null".into(),
                username: "test".into(),
                password_hash: hash,
                allowed_hosts: vec!["host.example.com.".into()],
            }],
        }
    }

    #[test]
    fn verify_correct_password() {
        let cfg = build_test_config();
        let user = verify_user(&cfg, "test", "secret");
        assert!(user.is_some());
    }

    #[test]
    fn verify_legacy_password_hash() {
        let mut cfg = build_test_config();
        // Fixed Argon2 0.5.3 test vector, independent of the current hash generator.
        cfg.users[0].password_hash =
            "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4"
                .into();

        assert!(validate_password_hash(&cfg.users[0].password_hash).is_ok());
        assert!(verify_user(&cfg, "test", "password").is_some());
        assert!(verify_user(&cfg, "test", "wrong").is_none());
    }

    #[test]
    fn reject_wrong_password() {
        let cfg = build_test_config();
        let user = verify_user(&cfg, "test", "wrong");
        assert!(user.is_none());
    }

    #[test]
    fn reject_unknown_user() {
        let cfg = build_test_config();
        let user = verify_user(&cfg, "nobody", "secret");
        assert!(user.is_none());
    }

    #[test]
    fn parse_basic_auth_header() {
        let encoded = BASE64_STANDARD.encode("test:secret");
        let header_val = format!("Basic {}", encoded);

        let req = TestRequest::get()
            .insert_header(("Authorization", header_val))
            .to_http_request();

        let res = parse_basic_auth(&req);
        assert!(res.is_some());
        let (u, p) = res.unwrap();
        assert_eq!(u, "test");
        assert_eq!(p, "secret");
    }

    #[test]
    fn parse_basic_auth_is_case_insensitive_for_scheme() {
        let encoded = BASE64_STANDARD.encode("test:secret");

        let req = TestRequest::get()
            .insert_header(("Authorization", format!("basic {}", encoded)))
            .to_http_request();

        let res = parse_basic_auth(&req);
        assert!(res.is_some());
    }
}
