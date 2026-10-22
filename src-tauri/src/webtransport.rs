//! Experimental, browser-authenticated WebTransport pairing endpoint.
//! This module proves the browser TLS/pinning handshake only; file transfer is not
//! routed through this endpoint until end-to-end tests have passed.

use std::{collections::HashMap, net::IpAddr, sync::Arc, time::{Duration, Instant}};
use local_ip_address::local_ip;
use serde::{Deserialize, Serialize};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{oneshot, Mutex, Semaphore}, time::timeout};
use tokio_util::sync::CancellationToken;
use wtransport::{tls::Sha256DigestFmt, Endpoint, Identity, ServerConfig};

pub const PORT: u16 = 8443;
pub const ALLOWED_ORIGIN: &str = "https://alvarog-dev.github.io";
const MAX_HELLO_BYTES: usize = 512;
const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);
const MAX_PIN_ATTEMPTS_PER_WINDOW: u32 = 5;

#[derive(Clone, Debug, Serialize)]
pub struct WebTransportInfo {
    pub host: String,
    pub url: String,
    pub certificate_hash: String,
    pub origin: String,
}

#[derive(Deserialize)]
struct PairRequest {
    #[serde(rename = "type")]
    kind: String,
    pin: String,
}

pub async fn run(
    pin: String,
    shutdown: CancellationToken,
    ready: oneshot::Sender<Result<WebTransportInfo, String>>,
) {
    let ip = match local_ip() {
        Ok(IpAddr::V4(ip)) => ip,
        Ok(IpAddr::V6(_)) => {
            let _ = ready.send(Err("WebTransport necesita IPv4 en esta versión.".to_owned()));
            return;
        }
        Err(error) => {
            let _ = ready.send(Err(format!("No se pudo detectar la IP para WebTransport: {error}")));
            return;
        }
    };
    let host = ip.to_string();
    let identity = match Identity::self_signed(&[host.as_str(), "localhost", "127.0.0.1"]) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = ready.send(Err(format!("No se pudo crear el certificado WebTransport: {error}")));
            return;
        }
    };
    let Some(certificate) = identity.certificate_chain().as_slice().first() else {
        let _ = ready.send(Err("El certificado WebTransport no contiene una hoja.".to_owned()));
        return;
    };
    let certificate_hash = certificate.hash().fmt(Sha256DigestFmt::DottedHex).replace(':', "");
    let config = ServerConfig::builder().with_bind_default(PORT).with_identity(identity).build();
    let endpoint = match Endpoint::server(config) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let _ = ready.send(Err(format!("No se pudo abrir WebTransport en UDP/{PORT}: {error}")));
            return;
        }
    };
    let info = WebTransportInfo {
        host: host.clone(),
        url: format!("https://{host}:{PORT}/aetherdrop-wt-probe-v1"),
        certificate_hash,
        origin: ALLOWED_ORIGIN.to_owned(),
    };
    if ready.send(Ok(info)).is_err() {
        return;
    }

    let auth_failures: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
    let handshake_slots = Arc::new(Semaphore::new(16));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            incoming = endpoint.accept() => {
                let expected_pin = pin.clone();
                let auth_failures = auth_failures.clone();
                let handshake_slots = handshake_slots.clone();
                tokio::spawn(async move {
                    let request = match timeout(Duration::from_secs(5), incoming).await {
                        Ok(Ok(request)) => request,
                        _ => return,
                    };
                    if request.origin() != Some(ALLOWED_ORIGIN)
                        || request.path() != "/aetherdrop-wt-probe-v1"
                    {
                        let _ = request.forbidden().await;
                        return;
                    }
                    let permit = match handshake_slots.try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            let _ = request.too_many_requests().await;
                            return;
                        }
                    };
                    let remote_ip = request.remote_address().ip();
                    let blocked = {
                        let now = Instant::now();
                        let mut failures = auth_failures.lock().await;
                        failures.retain(|_, (_, last_failure)| now.duration_since(*last_failure) < AUTH_FAILURE_WINDOW);
                        failures.get(&remote_ip).is_some_and(|(attempts, _)| *attempts >= MAX_PIN_ATTEMPTS_PER_WINDOW)
                    };
                    if blocked {
                        let _ = request.too_many_requests().await;
                        return;
                    }
                    let connection = match timeout(Duration::from_secs(5), request.accept()).await {
                        Ok(Ok(connection)) => connection,
                        _ => return,
                    };
                    let (mut send, mut receive) = match timeout(
                        Duration::from_secs(5),
                        connection.accept_bi(),
                    ).await {
                        Ok(Ok(streams)) => streams,
                        _ => return,
                    };
                    let read_result = timeout(Duration::from_secs(5), async {
                        let mut bytes = Vec::with_capacity(128);
                        let mut byte = [0u8; 1];
                        loop {
                            let count = match receive.read(&mut byte).await {
                                Ok(count) => count,
                                Err(_) => return None,
                            };
                            if count == 0 { return None; }
                            if byte[0] == b'\n' { return Some(bytes); }
                            if bytes.len() >= MAX_HELLO_BYTES { return Some(bytes); }
                            bytes.push(byte[0]);
                        }
                    }).await;
                    let request_bytes = match read_result {
                        Ok(Some(bytes)) if bytes.len() < MAX_HELLO_BYTES => bytes,
                        _ => {
                            let _ = send.write_all(b"{\"ok\":false,\"error\":\"request_too_large_or_timeout\"}\n").await;
                            return;
                        }
                    };
                    let _permit = permit;
                    let valid = serde_json::from_slice::<PairRequest>(&request_bytes)
                        .map(|request| request.kind == "pair" && constant_time_eq(request.pin.as_bytes(), expected_pin.as_bytes()))
                        .unwrap_or(false);
                    if valid {
                        auth_failures.lock().await.remove(&remote_ip);
                    } else {
                        let now = Instant::now();
                        let mut failures = auth_failures.lock().await;
                        let entry = failures.entry(remote_ip).or_insert((0, now));
                        if now.duration_since(entry.1) >= AUTH_FAILURE_WINDOW {
                            *entry = (1, now);
                        } else {
                            entry.0 = entry.0.saturating_add(1);
                            entry.1 = now;
                        }
                    }
                    let response: &[u8] = if valid {
                        b"{\"ok\":true,\"protocol\":\"aetherdrop-webtransport-v1\"}\n"
                    } else {
                        b"{\"ok\":false,\"error\":\"pairing_rejected\"}\n"
                    };
                    let _ = send.write_all(response).await;
                    let _ = send.finish().await;
                });
            }
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() { return false; }
    left.iter().zip(right).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn pairing_secret_comparison_checks_length_and_content() {
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"123456", b"12345"));
    }
}
