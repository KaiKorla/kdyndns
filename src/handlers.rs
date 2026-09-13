use actix_web::mime;
use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::AppState;
use crate::auth::{parse_basic_auth, verify_user};
use crate::dns::{DnsError, normalize_fqdn};
use crate::security::{auth_failure_delay, auth_rate_limit_key, sanitize_for_log};

#[derive(Deserialize)]
pub struct UpdateQuery {
    pub host: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type(mime::TEXT_HTML)
        .body("KDynDns - https://github.com/KaiKorla/KDynDNS")
}

#[get("/health")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().content_type(mime::TEXT_HTML).body("OK")
}

#[get("/update")]
pub async fn update(
    req: HttpRequest,
    query: web::Query<UpdateQuery>,
    state: web::Data<AppState>,
) -> impl Responder {
    let peer = request_client_ip(&req);
    let credentials = parse_basic_auth(&req);
    let limiter_key = auth_rate_limit_key(
        peer.as_deref(),
        credentials.as_ref().map(|(username, _)| username.as_str()),
    );

    if !state.auth_limiter.allow_attempt(&limiter_key) {
        sleep(auth_failure_delay()).await;
        return HttpResponse::TooManyRequests()
            .content_type(mime::TEXT_HTML)
            .body("Too many authentication attempts");
    }

    let (username, password) = match credentials {
        Some(c) => c,
        None => {
            state.auth_limiter.record_failure(&limiter_key);
            sleep(auth_failure_delay()).await;
            return HttpResponse::Unauthorized()
                .append_header(("WWW-Authenticate", "Basic realm=\"KDynDNS\""))
                .body("Unauthorized");
        }
    };
    let safe_username = sanitize_for_log(&username);

    let cfg = match state.config.read() {
        Ok(cfg) => cfg.clone(),
        Err(_) => {
            warn!(
                "Config lock poisoned during auth for user '{}'",
                safe_username
            );
            return HttpResponse::InternalServerError()
                .content_type(mime::TEXT_HTML)
                .body("Internal server error");
        }
    };

    let auth_slot = match state.auth_slots.acquire().await {
        Ok(slot) => slot,
        Err(_) => {
            return HttpResponse::ServiceUnavailable()
                .content_type(mime::TEXT_HTML)
                .body("Authentication unavailable");
        }
    };

    let username_for_verify = username.clone();
    let password_for_verify = password;
    let user = match tokio::task::spawn_blocking(move || {
        verify_user(&cfg, &username_for_verify, &password_for_verify)
    })
    .await
    {
        Ok(user) => user,
        Err(e) => {
            warn!(
                "Password verification task failed for user '{}': {}",
                safe_username, e
            );
            return HttpResponse::InternalServerError()
                .content_type(mime::TEXT_HTML)
                .body("Internal server error");
        }
    };
    drop(auth_slot);

    let user = match user {
        Some(u) => u,
        None => {
            state.auth_limiter.record_failure(&limiter_key);
            sleep(auth_failure_delay()).await;
            warn!("Auth failed for user '{}'", safe_username);
            return HttpResponse::Unauthorized()
                .content_type(mime::TEXT_HTML)
                .body("Invalid credentials");
        }
    };
    state.auth_limiter.reset_key(&limiter_key);

    let host_norm = match normalize_fqdn(&query.host) {
        Ok(host) => host,
        Err(DnsError::InvalidHost) => {
            return HttpResponse::BadRequest()
                .content_type(mime::TEXT_HTML)
                .body("Invalid host");
        }
        Err(DnsError::UpdateFailed(_)) => {
            return HttpResponse::BadRequest()
                .content_type(mime::TEXT_HTML)
                .body("Invalid host");
        }
    };
    let safe_host = sanitize_for_log(&host_norm);

    if !user
        .allowed_hosts
        .iter()
        .any(|allowed_host| allowed_host == &host_norm)
    {
        warn!(
            "User '{}' is not allowed to update host '{}'",
            safe_username, safe_host
        );
        return HttpResponse::Forbidden()
            .content_type(mime::TEXT_HTML)
            .body("Host not allowed");
    }

    if query.ipv4.is_none() && query.ipv6.is_none() {
        return HttpResponse::BadRequest()
            .content_type(mime::TEXT_HTML)
            .body("At least one of ipv4 or ipv6 required");
    }

    let ipv4: Option<Ipv4Addr> = match &query.ipv4 {
        Some(v) if !v.trim().is_empty() => match v.trim().parse() {
            Ok(ip) => Some(ip),
            Err(_) => {
                return HttpResponse::BadRequest()
                    .content_type(mime::TEXT_HTML)
                    .body("Invalid ipv4 format");
            }
        },
        _ => None,
    };

    let ipv6: Option<Ipv6Addr> = match &query.ipv6 {
        Some(v) if !v.trim().is_empty() => match v.trim().parse() {
            Ok(ip) => Some(ip),
            Err(_) => {
                return HttpResponse::BadRequest()
                    .content_type(mime::TEXT_HTML)
                    .body("Invalid ipv6 format");
            }
        },
        _ => None,
    };

    if ipv4.is_none() && ipv6.is_none() {
        return HttpResponse::BadRequest()
            .content_type(mime::TEXT_HTML)
            .body("ipv4/ipv6 empty or invalid");
    }

    info!(
        "Update request: user={}, host={}, ipv4={:?}, ipv6={:?}",
        safe_username, safe_host, ipv4, ipv6
    );

    match state
        .updater
        .update_records(&user, &host_norm, ipv4, ipv6)
        .await
    {
        Ok(()) => HttpResponse::Ok().content_type(mime::TEXT_HTML).body("OK"),
        Err(DnsError::InvalidHost) => HttpResponse::BadRequest()
            .content_type(mime::TEXT_HTML)
            .body("Invalid host"),
        Err(DnsError::UpdateFailed(e)) => {
            warn!("DNS update failed for {}: {}", safe_host, e);
            HttpResponse::InternalServerError()
                .content_type(mime::TEXT_HTML)
                .body("DNS update failed")
        }
    }
}

fn forwarded_client_ip(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("X-Forwarded-For")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .or_else(|| {
            req.headers()
                .get("X-Real-IP")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .and_then(|value| value.parse::<IpAddr>().ok())
                .map(|ip| ip.to_string())
        })
}

fn request_client_ip(req: &HttpRequest) -> Option<String> {
    forwarded_client_ip(req).or_else(|| req.peer_addr().map(|addr| addr.ip().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test};
    use argon2::PasswordHasher;
    use argon2::password_hash::phc::Salt;
    use base64::prelude::*;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;
    use tokio::sync::Semaphore;

    use crate::AppState;
    use crate::config::{AppConfig, UserConfig};
    use crate::dns::MockDnsUpdater;
    use crate::security::{AuthRateLimiter, default_auth_concurrency_limit};

    const TEST_SALT: &str = "WnJ1TFZNZEQ0QTR2ZTBJWmU1U3VRZz09";

    fn build_test_state(should_fail: bool) -> AppState {
        build_test_state_with_limiter(should_fail, AuthRateLimiter::default())
    }

    fn build_test_state_with_limiter(should_fail: bool, auth_limiter: AuthRateLimiter) -> AppState {
        let salt = Salt::from_b64(TEST_SALT).unwrap();
        let argon2 = argon2::Argon2::default();
        let hash = argon2
            .hash_password_with_salt(b"secret", &salt)
            .unwrap()
            .to_string();

        let cfg = AppConfig {
            users: vec![UserConfig {
                server: "127.0.0.1".into(),
                tsig_key_path: "/dev/null".into(),
                username: "user".into(),
                password_hash: hash,
                allowed_hosts: vec!["test.example.com.".into()],
            }],
        };

        let updater = MockDnsUpdater {
            should_fail,
            ..Default::default()
        };

        AppState {
            config: Arc::new(RwLock::new(cfg)),
            updater: Arc::new(updater),
            auth_limiter: Arc::new(auth_limiter),
            auth_slots: Arc::new(Semaphore::new(default_auth_concurrency_limit())),
        }
    }

    #[actix_web::test]
    async fn health_works() {
        let state = build_test_state(false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(health)).await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn update_requires_auth() {
        let state = build_test_state(false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(update)).await;

        let req = test::TestRequest::get()
            .uri("/update?host=test.example.com.&ipv4=1.2.3.4")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn update_success_with_mock_dns() {
        let state = build_test_state(false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(update)).await;

        let token = BASE64_STANDARD.encode("user:secret");
        let req = test::TestRequest::get()
            .uri("/update?host=test.example.com.&ipv4=1.2.3.4")
            .append_header(("Authorization", format!("Basic {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn update_dns_failure_propagates_500() {
        let state = build_test_state(true);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(update)).await;

        let token = BASE64_STANDARD.encode("user:secret");
        let req = test::TestRequest::get()
            .uri("/update?host=test.example.com.&ipv4=1.2.3.4")
            .append_header(("Authorization", format!("Basic {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 500);
    }

    #[actix_web::test]
    async fn repeated_auth_failures_are_rate_limited() {
        let state =
            build_test_state_with_limiter(false, AuthRateLimiter::new(Duration::from_secs(60), 1));
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(update)).await;

        let token = BASE64_STANDARD.encode("user:wrong");
        let req = test::TestRequest::get()
            .uri("/update?host=test.example.com.&ipv4=1.2.3.4")
            .append_header(("Authorization", format!("Basic {}", token)))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);

        let token = BASE64_STANDARD.encode("user:wrong");
        let req = test::TestRequest::get()
            .uri("/update?host=test.example.com.&ipv4=1.2.3.4")
            .append_header(("Authorization", format!("Basic {}", token)))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 429);
    }

    #[actix_web::test]
    async fn update_accepts_case_insensitive_host_match() {
        let state = build_test_state(false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(update)).await;

        let token = BASE64_STANDARD.encode("user:secret");
        let req = test::TestRequest::get()
            .uri("/update?host=TEST.EXAMPLE.COM&ipv4=1.2.3.4")
            .append_header(("Authorization", format!("basic {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn forwarded_client_ip_prefers_x_forwarded_for() {
        let req = test::TestRequest::default()
            .insert_header(("X-Forwarded-For", "203.0.113.10, 127.0.0.1"))
            .insert_header(("X-Real-IP", "198.51.100.10"))
            .to_http_request();

        assert_eq!(request_client_ip(&req).as_deref(), Some("203.0.113.10"));
    }
}
