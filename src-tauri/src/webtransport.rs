//! Experimental WebTransport endpoint with certificate pinning, device pairing,
//! authenticated metadata operations, and bounded protocol framing. File transfer
//! operations remain unavailable until their handlers and end-to-end tests are complete.

use std::{collections::HashMap, net::IpAddr, sync::Arc, time::{Duration, Instant}};
use super::{AppState, AuthorizedSession, ClipboardRequest, DownloadTicket, SessionRecord, UploadFinishRequest, UploadRequestPermit, UploadStartRequest, MAX_CLIPBOARD_BYTES, UPLOAD_CHUNK_BYTES};
use axum::{extract::{Extension, Path as AxumPath, State}, http::{HeaderMap, HeaderValue, StatusCode}, Json};
use bytes::Bytes;
use super::webtransport_protocol::ResponseHeader;
use local_ip_address::local_ip;
use serde::{Deserialize, Serialize};
use tokio::{io::{AsyncReadExt, AsyncSeekExt}, sync::{oneshot, Mutex, Semaphore}, time::timeout};
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
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn run(
    state: AppState,
    shutdown: CancellationToken,
    ready: oneshot::Sender<Result<WebTransportInfo, String>>,
) {
    let pin = state.pin.clone();
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
                let state = state.clone();
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
                    if !super::is_lan_peer_address(remote_ip) {
                        let _ = request.forbidden().await;
                        return;
                    }
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
                                Ok(Some(count)) => count,
                                Ok(None) | Err(_) => return None,
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
                    let pair_request = serde_json::from_slice::<PairRequest>(&request_bytes).ok();
                    let valid = pair_request.as_ref().is_some_and(|request| {
                        request.kind == "pair"
                            && constant_time_eq(request.pin.as_bytes(), expected_pin.as_bytes())
                            && request.device_id.as_deref().map_or(true, valid_device_id)
                    });
                    let mut issued_token: Option<String> = None;
                    if valid {
                        auth_failures.lock().await.remove(&remote_ip);
                        if let Some(device_id) = pair_request.and_then(|request| request.device_id) {
                            let mut devices = state.trusted_devices.write().await;
                            if !devices.contains(&device_id) && devices.len() < super::MAX_TRUSTED_DEVICES {
                                devices.push(device_id.clone());
                            }
                            if devices.contains(&device_id) {
                                let now = Instant::now();
                                let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
                                let mut sessions = state.session_tokens.write().await;
                                sessions.retain(|_, session| {
                                    if session.device_id == device_id {
                                        session.cancellation.cancel();
                                        false
                                    } else {
                                        true
                                    }
                                });
                                sessions.insert(token.clone(), SessionRecord {
                                    device_id: device_id.clone(),
                                    expires_at: now + super::SESSION_TTL,
                                    cancellation: CancellationToken::new(),
                                });
                                issued_token = Some(token);
                                drop(sessions);
                                drop(devices);
                                let stale_transfers: Vec<String> = state.pending_uploads.read().await
                                    .iter()
                                    .filter(|(_, upload)| upload.owner_device_id == device_id)
                                    .map(|(transfer_id, _)| transfer_id.clone())
                                    .collect();
                                for transfer_id in stale_transfers {
                                    super::remove_pending_upload(&state, &transfer_id).await;
                                }
                            }
                        }
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
                    let session_issued = issued_token.is_some();
                    let response = if valid && (pair_request_is_probe_only(&request_bytes) || session_issued) {
                        serde_json::json!({
                            "ok": true,
                            "protocol": "aetherdrop-webtransport-v1",
                            "token": issued_token,
                            "expires_in": if session_issued { super::SESSION_TTL.as_secs() } else { 0 }
                        })
                    } else {
                        serde_json::json!({"ok": false, "error": "pairing_rejected"})
                    };
                    let mut response_bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
                    response_bytes.push(b'\n');
                    let _ = send.write_all(&response_bytes).await;
                    let _ = send.finish().await;

                    // The pinned QUIC connection remains alive after pairing. Each
                    // application operation gets its own bounded bidirectional stream.
                    if !valid || (!pair_request_is_probe_only(&request_bytes) && !session_issued) {
                        return;
                    }
                    loop {
                        let streams = tokio::select! {
                            _ = state.server_shutdown.cancelled() => return,
                            result = timeout(Duration::from_secs(120), connection.accept_bi()) => match result {
                                Ok(Ok(streams)) => streams,
                                _ => return,
                            }
                        };
                        let (mut response_stream, mut request_stream) = streams;
                        let request_header = match timeout(Duration::from_secs(10), read_request_header(&mut request_stream)).await {
                            Ok(Ok(header)) => header,
                            _ => {
                                let _ = response_stream.finish().await;
                                continue;
                            }
                        };
                        // Acquire before reading an 8 MiB upload body so concurrent
                        // streams cannot bypass the HTTP path's memory bound.
                        let upload_request_permit = if request_header.op == "upload.chunk" {
                            state.upload_slots.clone().try_acquire_owned().ok()
                                .map(|permit| UploadRequestPermit { _permit: Arc::new(permit) })
                        } else {
                            None
                        };
                        let download_request_permit = if request_header.op == "download.read" {
                            state.download_slots.clone().try_acquire_owned().ok().map(Arc::new)
                        } else {
                            None
                        };
                        let request_body = if let Some(length) = request_header.payload_bytes {
                            let cap = if request_header.op == "clipboard.set" { super::MAX_CLIPBOARD_BYTES as u64 } else { UPLOAD_CHUNK_BYTES as u64 };
                            if length > cap || (request_header.op == "upload.chunk" && upload_request_permit.is_none()) {
                                None
                            } else {
                                match timeout(Duration::from_secs(30), read_stream_payload(&mut request_stream, length, cap)).await {
                                    Ok(Ok(body)) => Some(body),
                                    _ => {
                                        let _ = response_stream.finish().await;
                                        continue;
                                    }
                                }
                            }
                        } else {
                            None
                        };
                        let result = dispatch_request(&state, &request_header, request_body, upload_request_permit, download_request_permit.clone()).await;
                        let (response, response_body) = match result {
                            Ok((value, body)) => (ResponseHeader {
                                version: super::webtransport_protocol::PROTOCOL_VERSION,
                                request_id: request_header.request_id.clone(),
                                ok: true,
                                error: None,
                                payload_bytes: body.as_ref().map(|bytes| bytes.len() as u64),
                                result: Some(value),
                            }, body),
                            Err(code) => (ResponseHeader {
                                version: super::webtransport_protocol::PROTOCOL_VERSION,
                                request_id: request_header.request_id,
                                ok: false,
                                error: Some(code.to_owned()),
                                payload_bytes: None,
                                result: None,
                            }, None),
                        };
                        let (frame, body_to_send) = match super::webtransport_protocol::encode_header(&response) {
                            Ok(frame) => (Some(frame), response_body),
                            Err(_) => (
                                super::webtransport_protocol::encode_header(&ResponseHeader {
                                    version: super::webtransport_protocol::PROTOCOL_VERSION,
                                    request_id: request_header.request_id.clone(),
                                    ok: false,
                                    error: Some("response_too_large".to_owned()),
                                    payload_bytes: None,
                                    result: None,
                                }).ok(),
                                None,
                            ),
                        };
                        if let Some(frame) = frame {
                            let _ = response_stream.write_all(&frame).await;
                            if let Some(body) = body_to_send {
                                let _ = response_stream.write_all(&body).await;
                            }
                        }
                        let _ = response_stream.finish().await;
                    }
                });
            }
        }
    }
}

fn pair_request_is_probe_only(bytes: &[u8]) -> bool {
    serde_json::from_slice::<PairRequest>(bytes)
        .map(|request| request.kind == "pair" && request.device_id.is_none())
        .unwrap_or(false)
}


/// Read a single bounded framed JSON request header from a WebTransport stream.
async fn read_request_header(
    stream: &mut wtransport::RecvStream,
) -> Result<super::webtransport_protocol::RequestHeader, super::webtransport_protocol::FrameError> {
    use super::webtransport_protocol::{FrameError, RequestHeader, FRAME_PREFIX_BYTES, MAX_HEADER_BYTES};
    let mut prefix = [0u8; FRAME_PREFIX_BYTES];
    read_stream_exact(stream, &mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 { return Err(FrameError::Empty); }
    if length > MAX_HEADER_BYTES { return Err(FrameError::TooLarge); }
    let mut json = vec![0u8; length];
    read_stream_exact(stream, &mut json).await?;
    let text = std::str::from_utf8(&json).map_err(|_| FrameError::InvalidUtf8)?;
    let header: RequestHeader = serde_json::from_str(text).map_err(|_| FrameError::InvalidJson)?;
    super::webtransport_protocol::validate_request(&header)?;
    if header.payload_bytes.is_none() {
        let mut extra = [0u8; 1];
        match stream.read(&mut extra).await {
            Ok(None) | Ok(Some(0)) => {}
            Ok(Some(_)) => return Err(FrameError::InvalidLength),
            Err(_) => return Err(FrameError::InvalidLength),
        }
    }
    Ok(header)
}

async fn read_stream_payload(
    stream: &mut wtransport::RecvStream,
    length: u64,
    max_length: u64,
) -> Result<Vec<u8>, super::webtransport_protocol::FrameError> {
    use super::webtransport_protocol::FrameError;
    if length > max_length || length > usize::MAX as u64 {
        return Err(FrameError::InvalidLength);
    }
    let mut body = vec![0u8; length as usize];
    read_stream_exact(stream, &mut body).await?;
    let mut extra = [0u8; 1];
    match stream.read(&mut extra).await {
        Ok(None) | Ok(Some(0)) => Ok(body),
        Ok(Some(_)) | Err(_) => Err(FrameError::InvalidLength),
    }
}

async fn read_stream_exact(
    stream: &mut wtransport::RecvStream,
    output: &mut [u8],
) -> Result<(), super::webtransport_protocol::FrameError> {
    use super::webtransport_protocol::FrameError;
    let mut offset = 0;
    while offset < output.len() {
        match stream.read(&mut output[offset..]).await {
            Ok(Some(0)) | Ok(None) | Err(_) => return Err(FrameError::InvalidLength),
            Ok(Some(count)) => offset += count,
        }
    }
    Ok(())
}

fn upload_status_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "unauthorized",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::TOO_MANY_REQUESTS => "too_many_requests",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::INSUFFICIENT_STORAGE => "insufficient_storage",
        StatusCode::GONE => "expired",
        _ => "transfer_failed",
    }
}

async fn dispatch_request(
    state: &AppState,
    request: &super::webtransport_protocol::RequestHeader,
    body: Option<Vec<u8>>,
    upload_request_permit: Option<UploadRequestPermit>,
    download_request_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
) -> Result<(serde_json::Value, Option<Vec<u8>>), &'static str> {
    use super::webtransport_protocol::validate_request;
    validate_request(request).map_err(|_| "invalid_request")?;
    if state.server_shutdown.is_cancelled() {
        return Err("server_shutting_down");
    }
    let token = request.session.as_deref().ok_or("unauthorized")?;
    let now = Instant::now();
    let session = state.session_tokens.read().await.get(token).cloned().ok_or("unauthorized")?;
    if session.expires_at <= now || session.cancellation.is_cancelled()
        || !state.trusted_devices.read().await.contains(&session.device_id)
    {
        return Err("unauthorized");
    }
    let authorized = AuthorizedSession {
        token: token.to_owned(),
        device_id: session.device_id.clone(),
        expires_at: session.expires_at,
        cancellation: session.cancellation.clone(),
    };
    match request.op.as_str() {
        "clipboard.get" => {
            if request.data.is_some() { return Err("invalid_request"); }
            let text = state.clipboard_text.read().await.clone();
            if text.len() > MAX_CLIPBOARD_BYTES { return Err("clipboard_too_large"); }
            Ok((serde_json::json!({"encoding": "utf-8", "bytes": text.len()}), Some(text.into_bytes())))
        }
        "clipboard.set" => {
            if request.data.is_some() { return Err("invalid_request"); }
            let bytes = body.ok_or("invalid_request")?;
            if bytes.len() > MAX_CLIPBOARD_BYTES { return Err("payload_too_large"); }
            let text = String::from_utf8(bytes).map_err(|_| "invalid_utf8")?;
            let result = super::set_clipboard(State(state.clone()), Json(ClipboardRequest { text })).await;
            match result {
                Ok(_) => Ok((serde_json::json!({"updated": true}), None)),
                Err((status, _)) => Err(upload_status_code(status)),
            }
        }
        "upload.start" => {
            let data = request.data.as_ref().and_then(serde_json::Value::as_object).ok_or("invalid_request")?;
            if data.len() != 2 { return Err("invalid_request"); }
            let filename = data.get("filename").and_then(serde_json::Value::as_str).ok_or("invalid_request")?;
            let size_bytes = data.get("size_bytes").and_then(serde_json::Value::as_u64).ok_or("invalid_request")?;
            let result = super::start_chunked_upload(State(state.clone()), Extension(authorized.clone()),
                Json(UploadStartRequest { filename: filename.to_owned(), size_bytes })).await;
            match result {
                Ok(Json(value)) => Ok((serde_json::to_value(value).map_err(|_| "internal_error")?, None)),
                Err((status, _)) => Err(upload_status_code(status)),
            }
        }
        "upload.status" => {
            let data = request.data.as_ref().and_then(serde_json::Value::as_object).ok_or("invalid_request")?;
            if data.len() != 1 { return Err("invalid_request"); }
            let transfer_id = data.get("transfer_id").and_then(serde_json::Value::as_str).ok_or("invalid_request")?;
            let result = super::chunked_upload_status(State(state.clone()), Extension(authorized.clone()),
                AxumPath(transfer_id.to_owned())).await;
            match result {
                Ok(Json(value)) => Ok((serde_json::to_value(value).map_err(|_| "internal_error")?, None)),
                Err((status, _)) => Err(upload_status_code(status)),
            }
        }
        "upload.chunk" => {
            let data = request.data.as_ref().and_then(serde_json::Value::as_object).ok_or("invalid_request")?;
            if data.len() != 3 || request.payload_bytes.is_none() { return Err("invalid_request"); }
            let transfer_id = data.get("transfer_id").and_then(serde_json::Value::as_str).ok_or("invalid_request")?;
            let chunk_index = data.get("chunk_index").and_then(serde_json::Value::as_u64).ok_or("invalid_request")?;
            let sha256 = data.get("sha256").and_then(serde_json::Value::as_str).filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())).ok_or("invalid_request")?;
            let permit = upload_request_permit.ok_or("too_many_requests")?;
            let body = body.ok_or("invalid_request")?;
            let mut headers = HeaderMap::new();
            headers.insert("x-chunk-sha256", sha256.parse::<HeaderValue>().map_err(|_| "invalid_request")?);
            let result = super::upload_chunk(State(state.clone()), Extension(authorized.clone()),
                Extension(UploadRequestPermit { _permit: Arc::new(permit) }),
                AxumPath((transfer_id.to_owned(), chunk_index)), headers, Bytes::from(body)).await;
            match result {
                Ok(Json(value)) => Ok((serde_json::to_value(value).map_err(|_| "internal_error")?, None)),
                Err((status, _)) => Err(upload_status_code(status)),
            }
        }
        "upload.finish" => {
            let data = request.data.as_ref().and_then(serde_json::Value::as_object).ok_or("invalid_request")?;
            if data.len() != 2 { return Err("invalid_request"); }
            let transfer_id = data.get("transfer_id").and_then(serde_json::Value::as_str).ok_or("invalid_request")?;
            let sha256 = data.get("sha256").and_then(serde_json::Value::as_str).ok_or("invalid_request")?;
            let result = super::finish_chunked_upload(State(state.clone()), Extension(authorized.clone()),
                AxumPath(transfer_id.to_owned()), Json(UploadFinishRequest { sha256: sha256.to_owned() })).await;
            match result {
                Ok(Json(value)) => Ok((serde_json::to_value(value).map_err(|_| "internal_error")?, None)),
                Err((status, _)) => Err(upload_status_code(status)),
            }
        }
        "upload.cancel" => {
            let data = request.data.as_ref().and_then(serde_json::Value::as_object).ok_or("invalid_request")?;
            if data.len() != 1 { return Err("invalid_request"); }
            let transfer_id = data.get("transfer_id").and_then(serde_json::Value::as_str).ok_or("invalid_request")?;
            let status = super::cancel_chunked_upload(State(state.clone()), Extension(authorized.clone()),
                AxumPath(transfer_id.to_owned())).await;
            if status.is_success() { Ok((serde_json::json!({"cancelled": true}), None)) }
            else { Err(upload_status_code(status)) }
        }
        "session.check" => {
            if request.data.is_some() { return Err("invalid_request"); }
            Ok((serde_json::json!({
            "valid": true,
            "expires_in": session.expires_at.saturating_duration_since(now).as_secs()
        }), None))
        }
        "files.list" => {
            if request.data.is_some() { return Err("invalid_request"); }
            let files = state.pc_files.read().await;
            let items: Vec<serde_json::Value> = files.iter().map(|(id, path)| {
                serde_json::json!({
                    "id": id,
                    "name": path.file_name().unwrap_or_default().to_string_lossy().chars().take(120).collect::<String>()
                })
            }).collect();
            Ok((serde_json::Value::Array(items), None))
        }
        "download.start" => {
            let data = request.data.as_ref().and_then(serde_json::Value::as_object).ok_or("invalid_request")?;
            if data.len() != 1 { return Err("invalid_request"); }
            let file_id = data.get("file_id").and_then(serde_json::Value::as_str).ok_or("invalid_request")?;
            if file_id.is_empty() || file_id.len() > 128 { return Err("invalid_request"); }
            let path = {
                let files = state.pc_files.read().await;
                files.iter().find(|(id, _)| id == file_id).map(|(_, path)| path.clone())
            }.ok_or("file_not_found")?;
            let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|_| "file_unavailable")?;
            if !metadata.file_type().is_file() { return Err("file_unavailable"); }
            let canonical = tokio::fs::canonicalize(&path).await.map_err(|_| "file_unavailable")?;
            if canonical != path { return Err("file_unavailable"); }
            let ticket = format!("wt{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
            let now = Instant::now();
            let mut tickets = state.download_tickets.write().await;
            tickets.retain(|_, item| item.expires_at > now);
            if tickets.len() >= 512 { return Err("too_many_downloads"); }
            tickets.insert(ticket.clone(), DownloadTicket {
                file_id: file_id.to_owned(),
                session_token: token.to_owned(),
                device_id: session.device_id.clone(),
                expires_at: now + Duration::from_secs(60),
            });
            Ok((serde_json::json!({
                "ticket": ticket,
                "name": path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                "size_bytes": metadata.len(),
                "chunk_size": UPLOAD_CHUNK_BYTES,
                "expires_in": 60
            }), None))
        }
        "download.read" => {
            let _download_permit = download_request_permit.ok_or("too_many_downloads")?;
            let data = request.data.as_ref().and_then(serde_json::Value::as_object).ok_or("invalid_request")?;
            if data.len() != 3 { return Err("invalid_request"); }
            let ticket_token = data.get("ticket").and_then(serde_json::Value::as_str).ok_or("invalid_request")?;
            let offset = data.get("offset").and_then(serde_json::Value::as_u64).ok_or("invalid_request")?;
            let length = data.get("length").and_then(serde_json::Value::as_u64).ok_or("invalid_request")?;
            if !ticket_token.starts_with("wt") || ticket_token.len() > 128 || length == 0 || length > UPLOAD_CHUNK_BYTES as u64 {
                return Err("invalid_request");
            }
            let ticket = {
                let now = Instant::now();
                let mut tickets = state.download_tickets.write().await;
                let entry = tickets.get_mut(ticket_token).ok_or("download_expired")?;
                if entry.expires_at <= now
                    || entry.session_token != token
                    || entry.device_id != session.device_id
                {
                    return Err("download_expired");
                }
                // Sliding expiry allows large files on slow LANs while an active
                // download is progressing; an idle or abandoned ticket still expires.
                entry.expires_at = now + Duration::from_secs(60);
                entry.clone()
            };
            let path = {
                let files = state.pc_files.read().await;
                files.iter().find(|(id, _)| id == &ticket.file_id).map(|(_, path)| path.clone())
            }.ok_or("file_not_found")?;
            let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|_| "file_unavailable")?;
            let canonical = tokio::fs::canonicalize(&path).await.map_err(|_| "file_unavailable")?;
            if !metadata.file_type().is_file() || canonical != path {
                return Err("file_unavailable");
            }
            if offset.checked_add(length).is_none_or(|end| end > metadata.len()) {
                return Err("invalid_range");
            }
            let mut file = tokio::fs::File::open(&canonical).await.map_err(|_| "file_unavailable")?;
            let opened_metadata = file.metadata().await.map_err(|_| "file_unavailable")?;
            if !opened_metadata.is_file() || opened_metadata.len() != metadata.len() {
                return Err("file_changed");
            }
            file.seek(std::io::SeekFrom::Start(offset)).await.map_err(|_| "file_unavailable")?;
            let mut body = vec![0u8; length as usize];
            file.read_exact(&mut body).await.map_err(|_| "file_changed")?;
            Ok((serde_json::json!({"offset": offset, "bytes": length}), Some(body)))
        }
        _ => Err("operation_not_implemented"),
    }
}

fn valid_device_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() { return false; }
    left.iter().zip(right).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_secret_comparison_checks_length_and_content() {
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"123456", b"12345"));
    }

    #[test]
    fn device_identifiers_are_bounded_and_ascii_safe() {
        assert!(valid_device_id("dev_0123456789abcdef"));
        assert!(!valid_device_id(""));
        assert!(!valid_device_id("device with spaces"));
        assert!(!valid_device_id(&"x".repeat(65)));
        assert!(!valid_device_id("dev_á"));
    }

    #[test]
    fn legacy_probe_pairing_does_not_claim_to_issue_a_session() {
        assert!(pair_request_is_probe_only(br#"{"type":"pair","pin":"123456"}"#));
        assert!(!pair_request_is_probe_only(br#"{"type":"pair","pin":"123456","device_id":"dev_123"}"#));
        assert!(!pair_request_is_probe_only(br#"{"type":"nope","pin":"123456"}"#));
    }

    #[tokio::test]
    async fn webtransport_download_reads_only_the_requested_bounded_range() {
        let dir = std::env::temp_dir().join(format!("aetherdrop-wt-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("hello.txt");
        tokio::fs::write(&path, b"hello world").await.unwrap();

        let device_id = "dev_test123".to_owned();
        let token = "test_token_123".to_owned();
        let state = AppState {
            save_dir: Arc::new(tokio::sync::RwLock::new(dir.clone())),
            pc_files: Arc::new(tokio::sync::RwLock::new(vec![("file1".to_owned(), path.clone())])),
            pin: "123456".to_owned(),
            trusted_devices: Arc::new(tokio::sync::RwLock::new(vec![device_id.clone()])),
            clipboard_text: Arc::new(tokio::sync::RwLock::new(String::new())),
            session_tokens: Arc::new(tokio::sync::RwLock::new(HashMap::from([(
                token.clone(),
                SessionRecord {
                    device_id: device_id.clone(),
                    expires_at: Instant::now() + Duration::from_secs(60),
                    cancellation: CancellationToken::new(),
                },
            )]))),
            auth_failures: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            upload_slots: Arc::new(Semaphore::new(super::super::MAX_CONCURRENT_UPLOADS)),
            download_slots: Arc::new(Semaphore::new(super::super::MAX_CONCURRENT_DOWNLOADS)),
            pending_upload_slots: Arc::new(Semaphore::new(super::super::MAX_PENDING_UPLOADS)),
            pending_uploads: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            completed_uploads: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            reserved_upload_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            download_tickets: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            server_status: Arc::new(tokio::sync::RwLock::new(super::super::ServerStatus::Ready)),
            server_shutdown: CancellationToken::new(),
            mdns_daemon: Arc::new(std::sync::Mutex::new(None)),
            webtransport_info: Arc::new(tokio::sync::RwLock::new(None)),
            webtransport_error: Arc::new(tokio::sync::RwLock::new(None)),
        };

        let start = super::super::webtransport_protocol::RequestHeader {
            version: super::super::webtransport_protocol::PROTOCOL_VERSION,
            request_id: "download_start".to_owned(),
            op: "download.start".to_owned(),
            session: Some(token.clone()),
            payload_bytes: None,
            data: Some(serde_json::json!({"file_id": "file1"})),
        };
        let (metadata, _) = dispatch_request(&state, &start, None, None, None).await.unwrap();
        let ticket = metadata["ticket"].as_str().unwrap().to_owned();
        assert_eq!(metadata["size_bytes"].as_u64(), Some(11));

        let read = super::super::webtransport_protocol::RequestHeader {
            version: super::super::webtransport_protocol::PROTOCOL_VERSION,
            request_id: "download_read".to_owned(),
            op: "download.read".to_owned(),
            session: Some(token),
            payload_bytes: None,
            data: Some(serde_json::json!({"ticket": ticket, "offset": 6, "length": 5})),
        };
        let download_permit = state.download_slots.clone().try_acquire_owned().unwrap();
        let (_, body) = dispatch_request(
            &state,
            &read,
            None,
            None,
            Some(Arc::new(download_permit)),
        ).await.unwrap();
        assert_eq!(body.unwrap(), b"world");

        use sha2::{Digest, Sha256};
        let start_upload = super::super::webtransport_protocol::RequestHeader {
            version: super::super::webtransport_protocol::PROTOCOL_VERSION,
            request_id: "upload_start".to_owned(),
            op: "upload.start".to_owned(),
            session: Some("test_token_123".to_owned()),
            payload_bytes: None,
            data: Some(serde_json::json!({"filename": "uploaded.txt", "size_bytes": 5})),
        };
        let (upload_metadata, _) = dispatch_request(&state, &start_upload, None, None, None).await.unwrap();
        let transfer_id = upload_metadata["transfer_id"].as_str().unwrap().to_owned();
        let hash = format!("{:x}", Sha256::digest(b"world"));
        let upload_chunk = super::super::webtransport_protocol::RequestHeader {
            version: super::super::webtransport_protocol::PROTOCOL_VERSION,
            request_id: "upload_chunk".to_owned(),
            op: "upload.chunk".to_owned(),
            session: Some("test_token_123".to_owned()),
            payload_bytes: Some(5),
            data: Some(serde_json::json!({
                "transfer_id": transfer_id,
                "chunk_index": 0,
                "sha256": hash,
            })),
        };
        let permit = state.upload_slots.clone().try_acquire_owned().unwrap();
        dispatch_request(
            &state,
            &upload_chunk,
            Some(b"world".to_vec()),
            Some(UploadRequestPermit { _permit: Arc::new(permit) }),
            None,
        ).await.unwrap();
        let finish_upload = super::super::webtransport_protocol::RequestHeader {
            version: super::super::webtransport_protocol::PROTOCOL_VERSION,
            request_id: "upload_finish".to_owned(),
            op: "upload.finish".to_owned(),
            session: Some("test_token_123".to_owned()),
            payload_bytes: None,
            data: Some(serde_json::json!({
                "transfer_id": transfer_id,
                "sha256": hash,
            })),
        };
        let (receipt, _) = dispatch_request(&state, &finish_upload, None, None, None).await.unwrap();
        assert_eq!(receipt["files"][0]["filename"], "uploaded.txt");
        assert_eq!(tokio::fs::read(dir.join("uploaded.txt")).await.unwrap(), b"world");

        tokio::fs::remove_file(path).await.unwrap();
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
