use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Path as AxumPath, State},
    middleware::{self, Next},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use futures_util::TryStreamExt;
use local_ip_address::local_ip;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio_util::{io::ReaderStream, sync::CancellationToken};

use base64::{engine::general_purpose, Engine as _};
use std::io::Cursor;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use arboard::Clipboard;

const MAX_UPLOAD_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CONCURRENT_UPLOADS: usize = 3;
const MAX_CONCURRENT_DOWNLOADS: usize = 3;
const MAX_PENDING_UPLOADS: usize = 24;
const MAX_PENDING_UPLOADS_PER_DEVICE: usize = 4;
const UPLOAD_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const UPLOAD_CHUNK_U64: u64 = UPLOAD_CHUNK_BYTES as u64;
const PENDING_UPLOAD_TTL: Duration = Duration::from_secs(2 * 60 * 60);
const MAX_SHARED_FILES: usize = 256;
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;
const MAX_CLIPBOARD_REQUEST_BYTES: usize = 6 * 1024 * 1024;
const MAX_AUTH_REQUEST_BYTES: usize = 4 * 1024;
const DISK_SPACE_RESERVE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TRACKED_AUTH_IPS: usize = 1024;
const MAX_TRUSTED_DEVICES: usize = 64;
const MAX_AUTH_FAILURES: u32 = 10;
const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const AUTH_BLOCK_DURATION: Duration = Duration::from_secs(60);
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Clone)]
struct SessionRecord {
    device_id: String,
    expires_at: Instant,
    cancellation: CancellationToken,
}

#[derive(Clone)]
struct AuthorizedSession {
    token: String,
    device_id: String,
    expires_at: Instant,
    cancellation: CancellationToken,
}

#[derive(Clone)]
struct UploadRequestPermit(Arc<OwnedSemaphorePermit>);

#[derive(Clone)]
struct AuthFailureState {
    window_started: Instant,
    attempts: u32,
    blocked_until: Option<Instant>,
}

enum PublishError {
    Unauthorized,
    Cancelled,
    ShuttingDown,
    Io(std::io::Error),
}

#[derive(Debug, Serialize)]
struct UploadReceipt {
    filename: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct UploadResponse {
    files: Vec<UploadReceipt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadFinishRequest {
    sha256: String,
}

#[derive(Clone)]
struct DownloadTicket {
    file_id: String,
    session_token: String,
    device_id: String,
    expires_at: Instant,
}

#[derive(Serialize)]
struct DownloadTicketResponse {
    ticket: String,
    expires_in: u64,
}

#[derive(Clone)]
enum ServerStatus {
    Starting,
    Ready,
    Failed(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadStartRequest {
    filename: String,
    size_bytes: u64,
}

#[derive(Serialize)]
struct UploadStartResponse {
    transfer_id: String,
    chunk_size: usize,
    chunks_total: u64,
    next_chunk: u64,
}

#[derive(Debug, Serialize)]
struct UploadProgressResponse {
    filename: String,
    size_bytes: u64,
    received_bytes: u64,
    next_chunk: u64,
    chunks_total: u64,
    chunk_size: usize,
    chunk_hashes: Vec<String>,
}

struct PendingUpload {
    filename: String,
    temp_path: PathBuf,
    expected_size: u64,
    received_size: u64,
    next_chunk: u64,
    hasher: Sha256,
    chunk_hashes: Vec<String>,
    last_activity: Instant,
    _slot: OwnedSemaphorePermit,
}

#[derive(Clone)]
struct PendingUploadHandle {
    owner_device_id: String,
    session_token: String,
    session_cancellation: CancellationToken,
    session_expires_at: Instant,
    cancellation: CancellationToken,
    inner: Arc<AsyncMutex<PendingUpload>>,
}

#[derive(Clone)]
struct AppState {
    save_dir: Arc<RwLock<PathBuf>>,
    pc_files: Arc<RwLock<Vec<(String, PathBuf)>>>,
    pin: String,
    trusted_devices: Arc<RwLock<Vec<String>>>,
    clipboard_text: Arc<RwLock<String>>,
    session_tokens: Arc<RwLock<HashMap<String, SessionRecord>>>,
    auth_failures: Arc<RwLock<HashMap<IpAddr, AuthFailureState>>>,
    upload_slots: Arc<Semaphore>,
    download_slots: Arc<Semaphore>,
    pending_upload_slots: Arc<Semaphore>,
    pending_uploads: Arc<RwLock<HashMap<String, PendingUploadHandle>>>,
    reserved_upload_bytes: Arc<AtomicU64>,
    download_tickets: Arc<RwLock<HashMap<String, DownloadTicket>>>,
    server_status: Arc<RwLock<ServerStatus>>,
    server_shutdown: CancellationToken,
    mdns_daemon: Arc<std::sync::Mutex<Option<ServiceDaemon>>>,
}

#[derive(Serialize)]
pub struct ConnectionInfo {
    url: String,
    qr_base64: String,
    save_path: String,
    pin: String,
}

#[derive(Deserialize)]
struct PinRequest {
    pin: String,
    device_id: String,
}

#[derive(Deserialize)]
struct ClipboardRequest {
    text: String,
}

#[tauri::command]
async fn get_connection_info(state: tauri::State<'_, AppState>) -> Result<ConnectionInfo, String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match state.server_status.read().await.clone() {
                ServerStatus::Ready => return Ok(()),
                ServerStatus::Failed(message) => return Err(message),
                ServerStatus::Starting => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }).await
        .map_err(|_| "El servidor local sigue iniciándose. Vuelve a intentarlo.".to_owned())??;

    let my_ip = local_ip().map_err(|error| format!("No se pudo detectar una dirección de red: {}", error))?;
    if my_ip.is_loopback() || my_ip.is_unspecified() {
        return Err("No se ha detectado una dirección de red LAN válida. Conecta el ordenador a la red y vuelve a intentarlo.".to_owned());
    }
    let host = match my_ip {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => {
            return Err(format!(
                "La dirección local detectada es IPv6 ({}), pero el servidor de este prototipo está enlazado a IPv4. Conecta el ordenador a una red con IPv4 para vincular el móvil.",
                address
            ));
        }
    };
    let url = format!("http://{}:8080", host);

    let code = QrCode::new(url.as_bytes()).map_err(|e| e.to_string())?;
    let image = code.render::<image::Luma<u8>>().min_dimensions(200, 200).build();
    
    let mut buffer = Cursor::new(Vec::new());
    image.write_to(&mut buffer, image::ImageFormat::Png).map_err(|e| e.to_string())?;
    let base64_img = general_purpose::STANDARD.encode(buffer.get_ref());

    let dir = state.save_dir.read().await;

    Ok(ConnectionInfo {
        url,
        qr_base64: format!("data:image/png;base64,{}", base64_img),
        save_path: dir.to_string_lossy().to_string(),
        pin: state.pin.clone(),
    })
}

#[tauri::command]
async fn set_save_directory(path: String, state: tauri::State<'_, AppState>) -> Result<String, String> {
    if path.trim().is_empty() {
        return Err("La carpeta de destino está vacía.".to_owned());
    }
    let candidate = PathBuf::from(&path);
    tokio::fs::create_dir_all(&candidate).await
        .map_err(|error| format!("No se pudo preparar la carpeta: {}", error))?;
    let canonical = tokio::fs::canonicalize(&candidate).await
        .map_err(|error| format!("No se pudo resolver la carpeta: {}", error))?;
    let metadata = tokio::fs::metadata(&canonical).await
        .map_err(|error| format!("No se pudo consultar la carpeta: {}", error))?;
    if !metadata.is_dir() {
        return Err("El destino seleccionado no es una carpeta.".to_owned());
    }
    let probe_path = canonical.join(format!(".aetherdrop-write-test-{}", uuid::Uuid::new_v4()));
    let probe = tokio::fs::OpenOptions::new().write(true).create_new(true).open(&probe_path).await
        .map_err(|error| format!("No hay permiso de escritura en esa carpeta: {}", error))?;
    drop(probe);
    tokio::fs::remove_file(&probe_path).await
        .map_err(|error| format!("No se pudo limpiar la prueba de escritura: {}", error))?;
    let previous_directory = state.save_dir.read().await.clone();
    if previous_directory != canonical {
        cleanup_stale_uploads(&previous_directory).await;
    }
    cleanup_stale_uploads(&canonical).await;
    let display_path = canonical.to_string_lossy().to_string();
    *state.save_dir.write().await = canonical;
    Ok(display_path)
}

#[tauri::command]
async fn share_pc_file(path: String, state: tauri::State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let selected = PathBuf::from(&path);
    let canonical = tokio::fs::canonicalize(&selected).await
        .map_err(|error| format!("No se puede acceder al archivo seleccionado: {}", error))?;
    let metadata = tokio::fs::metadata(&canonical).await
        .map_err(|error| format!("No se puede consultar el archivo: {}", error))?;
    if !metadata.is_file() {
        return Err("Solo se pueden compartir archivos normales, no carpetas ni dispositivos especiales.".to_owned());
    }
    let mut files = state.pc_files.write().await;
    if files.iter().any(|(_, existing)| existing == &canonical) {
        drop(files);
        return get_shared_files_internal(&state).await;
    }
    if files.len() >= MAX_SHARED_FILES {
        return Err(format!("Has alcanzado el límite de {} archivos compartidos.", MAX_SHARED_FILES));
    }
    files.push((uuid::Uuid::new_v4().to_string(), canonical));
    drop(files);
    get_shared_files_internal(&state).await
}

#[tauri::command]
async fn remove_pc_file(id: String, state: tauri::State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    {
        let mut files = state.pc_files.write().await;
        files.retain(|(file_id, _)| file_id != &id);
    }
    get_shared_files_internal(&state).await
}

#[tauri::command]
async fn get_shared_files(state: tauri::State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    get_shared_files_internal(&state).await
}

#[tauri::command]
async fn get_trusted_devices(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.trusted_devices.read().await.clone())
}

#[tauri::command]
async fn revoke_trusted_device(device_id: String, state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    {
        let mut devices = state.trusted_devices.write().await;
        devices.retain(|device| device != &device_id);
    }
    {
        let mut sessions = state.session_tokens.write().await;
        sessions.retain(|_, session| {
            if session.device_id == device_id {
                session.cancellation.cancel();
                false
            } else {
                true
            }
        });
    }
    let pending_ids: Vec<String> = state.pending_uploads.read().await.iter()
        .filter(|(_, upload)| upload.owner_device_id == device_id)
        .map(|(transfer_id, _)| transfer_id.clone())
        .collect();
    for transfer_id in pending_ids {
        remove_pending_upload(&state, &transfer_id).await;
    }
    Ok(state.trusted_devices.read().await.clone())
}

async fn get_shared_files_internal(state: &AppState) -> Result<Vec<serde_json::Value>, String> {
    let files = state.pc_files.read().await;
    let list: Vec<_> = files.iter().map(|(id, path)| {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        serde_json::json!({ "id": id, "name": name })
    }).collect();
    Ok(list)
}

// PWA Móvil ultra-premium con subida múltiple, barra de progreso real y alertas de estado
async fn serve_sha256_js() -> axum::response::Response {
    axum::response::Response::builder()
        .header("Content-Type", "application/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(axum::body::Body::from(include_str!("sha256.js")))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn serve_mobile_js() -> axum::response::Response {
    axum::response::Response::builder()
        .header("Content-Type", "application/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(axum::body::Body::from(include_str!("mobile.js")))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn serve_ui() -> axum::response::Response {
    let html = r###"
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AetherDrop - Secure PWA</title>
            
            <style>
              :root{color-scheme:light;--bg:#f6f7fb;--surface:#fff;--ink:#182033;--muted:#778096;--line:#e8ebf2;--accent:#5b61e8;--accent-dark:#474dcc;--green:#17876b;--green-soft:#eaf8f2;--red:#c34b63}
              *{box-sizing:border-box}
              body.mobile-app{margin:0;min-height:100vh;padding:24px 16px;background:var(--bg);color:var(--ink);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:-.01em;display:flex;justify-content:center;align-items:center}
              button,input,textarea{font:inherit}
              button{cursor:pointer}
              button:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid #a5a7ff;outline-offset:2px}
              .mobile-shell{width:100%;max-width:480px;margin:auto}
              .mobile-brand{display:flex;align-items:center;gap:11px;margin:0 0 18px 2px}
              .mobile-mark{width:40px;height:40px;border-radius:13px;background:var(--accent);display:grid;place-items:center;color:white;box-shadow:0 7px 16px #5b61e82b}
              .mobile-mark svg{width:22px;height:22px}
              .mobile-brand-name{font-size:19px;font-weight:780;letter-spacing:-.055em}
              .mobile-brand-sub{font-size:12px;color:var(--muted);margin-top:1px}
              .mobile-card{background:var(--surface);border:1px solid var(--line);border-radius:22px;padding:22px;box-shadow:0 12px 34px rgba(25,35,66,.06)}
              .mobile-heading{font-size:20px;letter-spacing:-.045em;font-weight:760;margin:0}
              .mobile-muted{font-size:12px;color:var(--muted);margin:7px 0 0}
              .mobile-topline{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:18px}
              .online-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid #d9f0e7;background:#f0faf6;color:var(--green);border-radius:999px;padding:7px 10px;font-size:10px;font-weight:750;white-space:nowrap}
              .online-pill:before{content:"";width:6px;height:6px;border-radius:50%;background:#22a77d}
              .transfer-bridge{position:relative;min-height:154px;overflow:hidden;border:1px solid #e9ebf5;border-radius:17px;background:radial-gradient(ellipse at center,#f0f0ff 0%,#fafaff 52%,#fff 100%);margin:20px 0}
              .transfer-device{position:absolute;top:44%;width:44px;height:52px;border-radius:13px;display:grid;place-items:center;background:#fff;border:1px solid #e1e5ef;color:#70788c;z-index:2;box-shadow:0 7px 20px #2730520b}
              .transfer-device svg{width:21px;height:21px;stroke:currentColor}
              .transfer-device.phone{left:calc(50% - 102px)}.transfer-device.pc{right:calc(50% - 102px)}
              .transfer-orb{position:absolute;left:50%;top:44%;transform:translate(-50%,-50%);width:38px;height:38px;border-radius:14px;display:grid;place-items:center;color:white;background:linear-gradient(145deg,#777bf6,#5359df);box-shadow:0 7px 20px #5b61e83b;z-index:2}
              .transfer-orb svg{width:19px;height:19px}
              .transfer-line{position:absolute;left:calc(50% - 76px);right:calc(50% - 76px);top:44%;height:1px;background:linear-gradient(90deg,#d5d7ff,#8d91f4,#d5d7ff)}
              .transfer-packet{position:absolute;left:calc(50% - 70px);top:calc(44% - 3px);width:6px;height:6px;border-radius:50%;background:#6569ed;box-shadow:0 0 0 4px #6569ed1a;opacity:0}
              .transfer-bridge.transferring .transfer-packet{opacity:1;animation:transfer-flight 1.5s linear infinite}
              .transfer-bridge.transferring .transfer-packet.p2{animation-delay:.5s}.transfer-bridge.transferring .transfer-packet.p3{animation-delay:1s}
              .transfer-bridge.paired .transfer-orb,.transfer-bridge.transferring .transfer-orb{animation:transfer-glow 2.2s ease-in-out infinite}
              .transfer-caption{position:absolute;bottom:13px;left:8px;right:8px;text-align:center;font-size:11px;color:#596176}
              .mobile-section{margin-top:20px}
              .mobile-section-title{font-size:12px;font-weight:780;color:#3c4559;margin:0 0 10px;letter-spacing:-.01em}
              .upload-button{position:relative;display:flex;align-items:center;justify-content:center;gap:9px;width:100%;padding:14px 16px;border:0;border-radius:13px;background:var(--accent);color:#fff;font-weight:730;font-size:13px;box-shadow:0 7px 16px #5b61e81f;transition:background .18s,transform .18s}
              .upload-button:hover{background:var(--accent-dark);transform:translateY(-1px)}
              .upload-button svg{width:17px;height:17px}
              .upload-button input{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
              .progress-wrap{margin-top:15px;padding:13px;background:#f8f8ff;border:1px solid #e8e8ff;border-radius:12px}
              .progress-meta{display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:11px;color:#687087;margin-bottom:8px}
              #progressStatus{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
              #progressPercent{font-weight:800;color:var(--accent)}
              .progress-track{height:5px;border-radius:999px;background:#e6e7f2;overflow:hidden}
              #progressBar{height:100%;border-radius:999px;background:linear-gradient(90deg,#8588fa,#5b61e8);transition:width .15s}
              .mobile-field{width:100%;display:block;border:1px solid var(--line);background:#fafbfe;color:#394258;border-radius:11px;padding:12px;font-size:12px;resize:vertical;min-height:68px}
              .mobile-field::placeholder{color:#a0a6b5}
              .secondary-button{width:100%;border:1px solid var(--line);background:#fff;color:#535d73;border-radius:11px;padding:11px 12px;font-size:12px;font-weight:700;margin-top:8px;transition:background .18s}
              .secondary-button:hover{background:#f7f8fc}
              .mobile-divider{border:0;border-top:1px solid #edf0f5;margin:21px 0}
              .mobile-file-list{display:flex;flex-direction:column;gap:7px;max-height:200px;overflow:auto}
              .mobile-file-item{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px;background:#fafbfe;border:1px solid #eff1f6;border-radius:11px}
              .mobile-file-name{font-size:11px;color:#41495d;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
              .download-link{flex-shrink:0;text-decoration:none;color:var(--accent);background:var(--accent-soft);border-radius:8px;padding:7px 9px;font-size:10px;font-weight:750}
              .download-link:hover{background:#e7e8ff}
              .mobile-empty{padding:16px 8px;text-align:center;color:#9aa1b0;font-size:11px}
              .toast{margin-top:12px;padding:11px 12px;border-radius:11px;font-size:11px;font-weight:650;border:1px solid transparent}
              .toast.success{background:#eef9f4;color:var(--green);border-color:#d9f0e7}
              .toast.error{background:#fff2f4;color:var(--red);border-color:#f5dfe4}
              .pin-overlay{position:fixed;inset:0;z-index:50;background:rgba(246,247,251,.88);backdrop-filter:blur(12px);display:flex;align-items:center;justify-content:center;padding:20px}
              .pin-card{width:100%;max-width:370px;background:#fff;border:1px solid var(--line);border-radius:24px;padding:27px 24px;box-shadow:0 24px 70px rgba(25,35,66,.13);text-align:center}
              .pin-symbol{width:48px;height:48px;border-radius:16px;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;margin:0 auto 17px}
              .pin-symbol svg{width:23px;height:23px}
              .pin-card .mobile-heading{font-size:22px}
              .pin-input{width:100%;border:1px solid #e2e5ef;background:#fafbfe;border-radius:13px;padding:14px 10px;text-align:center;font:750 24px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.28em;color:var(--ink);margin:20px 0 12px}
              .pin-input:focus{border-color:#a5a7ff;outline:3px solid #a5a7ff33}
              .pin-submit{width:100%;border:0;background:var(--accent);color:#fff;border-radius:12px;padding:13px;font-weight:750;font-size:13px}
              .pin-submit:hover{background:var(--accent-dark)}
              .pin-error{font-size:11px;color:var(--red);margin:10px 0 0}
              .hidden{display:none!important}
              @keyframes transfer-flight{0%{transform:translateX(0) scale(.7);opacity:0}14%{opacity:1}85%{opacity:1}100%{transform:translateX(140px) scale(1.1);opacity:0}}
              @keyframes transfer-glow{0%,100%{box-shadow:0 7px 20px #5b61e83b}50%{box-shadow:0 7px 28px #5b61e86b}}
              @media(max-width:380px){body.mobile-app{padding:15px 10px}.mobile-card{padding:17px}.mobile-topline{align-items:flex-start}.mobile-heading{font-size:18px}.pin-card{padding:23px 18px}}
              @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}.transfer-packet{display:none}}
            </style>
        <body class="mobile-app">
            <!-- Vinculación por PIN -->
            <div id="pinModal" class="pin-overlay">
              <div class="pin-card">
                <div class="mobile-brand" style="justify-content:center;margin:0 0 25px">
                  <div class="mobile-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 7.5 12 4l5 3.5v9L12 20l-5-3.5z"/><path d="m7.5 8 4.5 3 4.5-3M12 11v8"/></svg></div>
                  <div style="text-align:left"><div class="mobile-brand-name">AetherDrop</div><div class="mobile-brand-sub">Transferencias en tu red local</div></div>
                </div>
                <div class="pin-symbol" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></svg></div>
                <h2 class="mobile-heading">Vincula tu dispositivo</h2>
                <p class="mobile-muted">Introduce el código de seis dígitos que aparece en AetherDrop para ordenador.</p>
                <input type="password" id="pinInput" maxlength="6" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" placeholder="••••••" class="pin-input" aria-label="PIN de seis dígitos">
                <button id="pinSubmit" class="pin-submit">Conectar dispositivo</button>
                <p id="pinError" class="pin-error hidden">PIN incorrecto.</p>
              </div>
            </div>

            <main id="mainApp" class="mobile-shell hidden">
              <header class="mobile-topline">
                <div class="mobile-brand" style="margin:0">
                  <div class="mobile-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 7.5 12 4l5 3.5v9L12 20l-5-3.5z"/><path d="m7.5 8 4.5 3 4.5-3M12 11v8"/></svg></div>
                  <div><div class="mobile-brand-name">AetherDrop</div><div class="mobile-brand-sub">Listo para compartir</div></div>
                </div>
                <span class="online-pill">Vinculado</span>
              </header>

              <section class="mobile-card">
                <div>
                  <h1 class="mobile-heading">Envía archivos fácilmente.</h1>
                  <p class="mobile-muted">Del móvil al ordenador, en unos segundos.</p>
                </div>
                <div id="mobileBridge" class="transfer-bridge" aria-label="Conexión visual entre móvil y ordenador">
                  <div class="transfer-line"></div>
                  <span class="transfer-packet"></span><span class="transfer-packet p2"></span><span class="transfer-packet p3"></span>
                  <div class="transfer-device phone" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2.5" width="12" height="19" rx="2.5"/><path d="M10 18.5h4"/></svg></div>
                  <div class="transfer-orb" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg></div>
                  <div class="transfer-device pc" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg></div>
                  <div id="bridgeCaption" class="transfer-caption">Móvil vinculado · listo para transferir</div>
                </div>

                <label class="upload-button">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4m-5 5 5-5 5 5"/><path d="M5 14v5a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-5"/></svg>
                  Elegir archivos para enviar
                  <input type="file" id="fileInput" multiple>
                </label>

                <div id="progressContainer" class="progress-wrap hidden">
                  <div class="progress-meta"><span id="progressStatus">Enviando archivos…</span><span id="progressPercent">0%</span></div>
                  <div class="progress-track"><div id="progressBar" style="width:0%"></div></div>
                </div>
                <button type="button" id="cancelUploadButton" class="secondary-button hidden" style="border-color:#f5dfe4;color:#a8324a">Cancelar transferencia</button>
                <div id="toast" class="hidden"></div>

                <hr class="mobile-divider">
                <section>
                  <div class="mobile-section-title">Portapapeles compartido</div>
                  <textarea id="clipboardText" rows="3" placeholder="Escribe o pega texto para enviarlo al ordenador…" class="mobile-field"></textarea>
                  <button id="sendClipboardButton" class="secondary-button">Enviar texto al ordenador</button>
                  <button id="refreshClipboardButton" class="secondary-button" style="margin-top:6px">Actualizar desde el ordenador</button>
                </section>

                <hr class="mobile-divider">
                <section>
                  <div class="mobile-topline" style="margin-bottom:10px">
                    <div class="mobile-section-title" style="margin:0">Archivos del ordenador</div>
                    <span style="font-size:10px;color:#9299aa">Para descargar</span>
                  </div>
                  <div id="fileList" class="mobile-file-list"><p class="mobile-empty">No hay archivos disponibles.</p></div>
                </section>
              </section>
              <p style="text-align:center;font-size:10px;color:#a0a6b5;margin:14px 0 0">Transferencia local · AetherDrop</p>
            </main>
            <script src="/sha256.js" defer></script>
            <script src="/mobile.js" defer></script>
        </body>
        </html>
    "###;
    axum::response::Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        .header("Referrer-Policy", "no-referrer")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(axum::body::Body::from(html))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}


fn auth_rate_limited(failures: &mut HashMap<IpAddr, AuthFailureState>, ip: IpAddr, now: Instant) -> bool {
    failures.retain(|_, entry| {
        entry.window_started.elapsed() < AUTH_FAILURE_WINDOW
            || entry.blocked_until.is_some_and(|until| until > now)
    });
    failures
        .get(&ip)
        .and_then(|entry| entry.blocked_until)
        .is_some_and(|until| until > now)
}

fn record_auth_failure(
    failures: &mut HashMap<IpAddr, AuthFailureState>,
    ip: IpAddr,
    now: Instant,
) -> bool {
    if !failures.contains_key(&ip) && failures.len() >= MAX_TRACKED_AUTH_IPS {
        return true;
    }
    let entry = failures.entry(ip).or_insert(AuthFailureState {
        window_started: now,
        attempts: 0,
        blocked_until: None,
    });
    if now.duration_since(entry.window_started) >= AUTH_FAILURE_WINDOW {
        entry.window_started = now;
        entry.attempts = 0;
        entry.blocked_until = None;
    }
    entry.attempts = entry.attempts.saturating_add(1);
    if entry.attempts >= MAX_AUTH_FAILURES {
        entry.blocked_until = Some(now + AUTH_BLOCK_DURATION);
    }
    entry.blocked_until.is_some_and(|until| until > now)
}

fn ticket_from_query(query: Option<&str>) -> Option<String> {
    query?.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == "ticket" && !value.is_empty() && value.len() <= 128)
            .then(|| value.to_owned())
    })
}

async fn session_from_download_ticket(
    state: &AppState,
    requested_file_id: &str,
    ticket_token: &str,
) -> Option<AuthorizedSession> {
    let ticket = {
        let mut tickets = state.download_tickets.write().await;
        let now = Instant::now();
        tickets.retain(|_, ticket| ticket.expires_at > now);
        tickets.remove(ticket_token)?
    };
    if ticket.expires_at <= Instant::now() || ticket.file_id != requested_file_id {
        return None;
    }
    let record = state.session_tokens.read().await.get(&ticket.session_token).cloned()?;
    if record.expires_at <= Instant::now()
        || record.device_id != ticket.device_id
        || record.cancellation.is_cancelled()
        || !state.trusted_devices.read().await.contains(&ticket.device_id)
    {
        return None;
    }
    Some(AuthorizedSession {
        token: ticket.session_token,
        device_id: record.device_id,
        expires_at: record.expires_at,
        cancellation: record.cancellation,
    })
}

fn is_lan_peer_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && (address.is_private()
                    || address.is_loopback()
                    || address.octets()[0] == 169 && address.octets()[1] == 254)
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
    }
}

fn is_allowed_local_authority(authority: &str) -> bool {
    let Ok(parsed) = authority.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    let host = parsed.host().trim_matches(&['[', ']'][..]).trim_end_matches('.');
    host.parse::<IpAddr>().is_ok()
        || host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("aetherdrop.local")
}

fn origin_matches_authority(origin: &str, request_authority: &str) -> bool {
    let Ok(uri) = origin.parse::<axum::http::Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("http")
        && uri.authority().is_some_and(|authority| {
            authority.as_str().eq_ignore_ascii_case(request_authority)
        })
}

async fn require_auth(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    // The TCP listener binds all interfaces for network-change tolerance, but this
    // service is LAN-only: deny requests from publicly routable peer addresses.
    let Some(peer) = request.extensions().get::<ConnectInfo<SocketAddr>>() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !is_lan_peer_address(peer.0.ip()) {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Reject arbitrary Host values to reduce DNS-rebinding access, and reject
    // browser cross-origin requests when Origin exists.
    let Some(host) = request.headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !is_allowed_local_authority(host) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(origin) = request.headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        if !origin_matches_authority(origin, host) {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    if request.uri().path() == "/" || request.uri().path() == "/auth" || request.uri().path() == "/mobile.js" || request.uri().path() == "/sha256.js" {
        return next.run(request).await;
    }
    let bearer_token = request.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned);

    if bearer_token.is_none() {
        if let Some(file_id) = request.uri().path().strip_prefix("/download/") {
            if let Some(ticket) = ticket_from_query(request.uri().query()) {
                if let Some(session) = session_from_download_ticket(&state, file_id, &ticket).await {
                    request.extensions_mut().insert(session);
                    return next.run(request).await;
                }
            }
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(token) = bearer_token else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let session = state.session_tokens.read().await.get(&token).cloned();
    let Some(session) = session else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if session.expires_at <= Instant::now() {
        session.cancellation.cancel();
        state.session_tokens.write().await.remove(&token);
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !state.trusted_devices.read().await.contains(&session.device_id) {
        session.cancellation.cancel();
        state.session_tokens.write().await.remove(&token);
        return StatusCode::UNAUTHORIZED.into_response();
    }

    request.extensions_mut().insert(AuthorizedSession {
        token,
        device_id: session.device_id,
        expires_at: session.expires_at,
        cancellation: session.cancellation,
    });
    // Acquire before passing the request to Axum's Bytes extractor. This bounds
    // the number of 8 MiB request bodies buffered in memory, not merely the number
    // of handlers that happen to be writing to disk.
    if request.uri().path().starts_with("/upload/chunk/") {
        let permit = match state.upload_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            }
        };
        request.extensions_mut().insert(UploadRequestPermit(Arc::new(permit)));
    }
    next.run(request).await
}

async fn check_session() -> StatusCode { StatusCode::OK }

async fn handle_auth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(payload): Json<PinRequest>,
) -> impl IntoResponse {
    let now = Instant::now();
    {
        let mut failures = state.auth_failures.write().await;
        if auth_rate_limited(&mut failures, peer.ip(), now) {
            return (StatusCode::TOO_MANY_REQUESTS, "Demasiados intentos de PIN; espera un minuto.").into_response();
        }
        if payload.pin != state.pin
            || payload.device_id.len() > 64
            || payload.device_id.is_empty()
            || !payload.device_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '-'
            })
        {
            let blocked = record_auth_failure(&mut failures, peer.ip(), now);
            if blocked {
                return (StatusCode::TOO_MANY_REQUESTS, "Demasiados intentos de PIN; espera un minuto.").into_response();
            }
            return (StatusCode::UNAUTHORIZED, "PIN o identificador del dispositivo no válidos.").into_response();
        }
        failures.remove(&peer.ip());
    }

    {
        let mut devices = state.trusted_devices.write().await;
        if !devices.contains(&payload.device_id) {
            if devices.len() >= MAX_TRUSTED_DEVICES {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "El ordenador ya tiene el máximo de dispositivos vinculados. Revoca uno desde el escritorio e inténtalo de nuevo.",
                ).into_response();
            }
            devices.push(payload.device_id.clone());
        }
    }

    // A device has at most one active bearer session. Re-pairing rotates the token
    // and cancels all uploads tied to the old session rather than leaving stale
    // temporary files or several valid tokens behind.
    let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let record = SessionRecord {
        device_id: payload.device_id.clone(),
        expires_at: now + SESSION_TTL,
        cancellation: CancellationToken::new(),
    };
    {
        let mut sessions = state.session_tokens.write().await;
        sessions.retain(|_, session| {
            if session.device_id == payload.device_id {
                session.cancellation.cancel();
                false
            } else {
                true
            }
        });
        sessions.insert(token.clone(), record);
    }

    let stale_transfers: Vec<String> = state.pending_uploads.read().await
        .iter()
        .filter(|(_, upload)| upload.owner_device_id == payload.device_id)
        .map(|(transfer_id, _)| transfer_id.clone())
        .collect();
    for transfer_id in stale_transfers {
        remove_pending_upload(&state, &transfer_id).await;
    }
    (StatusCode::OK, Json(serde_json::json!({
        "token": token,
        "expires_in": SESSION_TTL.as_secs()
    }))).into_response()
}

fn sanitize_upload_filename(input: &str) -> Option<String> {
    let normalized = input.replace('\\', "/");
    std::path::Path::new(&normalized)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            let windows_stem = name
                .split('.')
                .next()
                .unwrap_or_default()
                .trim_end_matches(' ')
                .to_ascii_uppercase();
            let reserved_device_name = matches!(
                windows_stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL"
            ) || (windows_stem.len() == 4
                && (windows_stem.starts_with("COM") || windows_stem.starts_with("LPT"))
                && windows_stem.as_bytes()[3].is_ascii_digit()
                && windows_stem.as_bytes()[3] != b'0');

            !name.is_empty()
                && *name != "."
                && *name != ".."
                && name.len() <= 240
                && !name.chars().any(|ch| {
                    char::is_control(ch) || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                })
                && !name.ends_with(' ')
                && !name.ends_with('.')
                && !reserved_device_name
        })
        .map(str::to_owned)
}

// Build a safe Content-Disposition header, including an RFC 5987 UTF-8 filename.
// The quoted fallback is ASCII-only, so quotes and control characters cannot
// break the header or cause Response::builder() to panic.
fn content_disposition_value(filename: &str) -> String {
    let fallback: String = filename
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ' ') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let fallback = fallback.trim_matches(|ch| ch == ' ' || ch == '.');
    let fallback = if fallback.is_empty() { "download" } else { fallback };

    let mut encoded = String::new();
    for byte in filename.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(*byte, b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'|' | b'~')
        {
            encoded.push(*byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "%{:02X}", byte);
        }
    }

    format!("attachment; filename=\"{}\"; filename*=UTF-8''{}", fallback, encoded)
}

#[cfg(test)]
mod upload_filename_tests {
    use super::{
        auth_rate_limited, cancel_chunked_upload, chunks_for_size, content_disposition_value,
        is_lan_peer_address,
        finish_chunked_upload, handle_auth, is_allowed_local_authority, origin_matches_authority,
        publish_temp_no_replace, record_auth_failure, sanitize_upload_filename,
        start_chunked_upload, upload_chunk, AppState, AuthFailureState, AuthorizedSession,
        DownloadTicket, PinRequest, SessionRecord, ServerStatus, UploadFinishRequest,
        UploadStartRequest,
        MAX_AUTH_FAILURES, MAX_CONCURRENT_DOWNLOADS, MAX_CONCURRENT_UPLOADS,
        MAX_PENDING_UPLOADS, MAX_TRUSTED_DEVICES, UPLOAD_CHUNK_U64,
    };
    use axum::{
        body::Bytes,
        extract::{ConnectInfo, Extension, Path as AxumPath, State},
        http::{HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse,
        Json,
    };
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::{atomic::AtomicU64, Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::{RwLock, Semaphore};
    use tokio_util::sync::CancellationToken;

    fn test_state(directory: PathBuf) -> (AppState, AuthorizedSession) {
        let device_id = "dev_test_device".to_owned();
        let token = "test-session-token".to_owned();
        let expires_at = Instant::now() + Duration::from_secs(600);
        let cancellation = CancellationToken::new();
        let session = AuthorizedSession {
            token: token.clone(),
            device_id: device_id.clone(),
            expires_at,
            cancellation: cancellation.clone(),
        };
        let state = AppState {
            save_dir: Arc::new(RwLock::new(directory)),
            pc_files: Arc::new(RwLock::new(Vec::new())),
            pin: "123456".to_owned(),
            trusted_devices: Arc::new(RwLock::new(vec![device_id.clone()])),
            clipboard_text: Arc::new(RwLock::new(String::new())),
            session_tokens: Arc::new(RwLock::new(HashMap::from([(
                token,
                SessionRecord {
                    device_id,
                    expires_at,
                    cancellation,
                },
            )]))),
            auth_failures: Arc::new(RwLock::new(HashMap::new())),
            upload_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOADS)),
            download_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS)),
            pending_upload_slots: Arc::new(Semaphore::new(MAX_PENDING_UPLOADS)),
            pending_uploads: Arc::new(RwLock::new(HashMap::new())),
            reserved_upload_bytes: Arc::new(AtomicU64::new(0)),
            download_tickets: Arc::new(RwLock::new(HashMap::<String, DownloadTicket>::new())),
            server_status: Arc::new(RwLock::new(ServerStatus::Ready)),
            server_shutdown: CancellationToken::new(),
            mdns_daemon: Arc::new(Mutex::new(None)),
        };
        (state, session)
    }

    async fn test_directory() -> PathBuf {
        let directory = std::env::temp_dir()
            .join(format!("aetherdrop-chunk-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        directory
    }

    #[test]
    fn strips_unix_and_windows_path_components() {
        assert_eq!(sanitize_upload_filename("../../photo.png"), Some("photo.png".to_owned()));
        assert_eq!(sanitize_upload_filename(r"C:\Users\demo\video.mp4"), Some("video.mp4".to_owned()));
    }

    #[test]
    fn rejects_empty_traversal_control_characters_and_unsafe_suffixes() {
        assert_eq!(sanitize_upload_filename(""), None);
        assert_eq!(sanitize_upload_filename(".."), None);
        assert_eq!(sanitize_upload_filename("bad\nname.txt"), None);
        assert_eq!(sanitize_upload_filename("name.txt "), None);
        assert_eq!(sanitize_upload_filename("name."), None);
        assert_eq!(sanitize_upload_filename("invalid:name.txt"), None);
        assert_eq!(sanitize_upload_filename("name?.txt"), None);
        assert_eq!(sanitize_upload_filename("CON"), None);
        assert_eq!(sanitize_upload_filename("nul.txt"), None);
        assert_eq!(sanitize_upload_filename("COM1.log"), None);
        assert_eq!(sanitize_upload_filename("LPT9"), None);
        assert_eq!(sanitize_upload_filename(&"x".repeat(241)), None);
    }

    #[test]
    fn content_disposition_preserves_unicode_filename_metadata() {
        let value = content_disposition_value("foto ñ.png");
        assert!(value.starts_with("attachment; filename=\"foto _.png\"; filename*=UTF-8''"));
        assert!(value.contains("%C3%B1"));
    }

    #[tokio::test]
    async fn atomic_publish_never_overwrites_an_existing_file() {
        let directory = std::env::temp_dir()
            .join(format!("aetherdrop-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let temp = directory.join(".aetherdrop-upload-test.part");
        let destination = directory.join("existing.bin");
        tokio::fs::write(&temp, b"new-data").await.unwrap();
        tokio::fs::write(&destination, b"old-data").await.unwrap();

        let error = publish_temp_no_replace(&temp, &destination).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"old-data");
        assert!(tokio::fs::try_exists(&temp).await.unwrap());

        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }

    #[tokio::test]
    async fn atomic_publish_exposes_complete_file_and_removes_temp_link() {
        let directory = std::env::temp_dir()
            .join(format!("aetherdrop-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let temp = directory.join(".aetherdrop-upload-test.part");
        let destination = directory.join("new.bin");
        tokio::fs::write(&temp, b"complete-payload").await.unwrap();

        publish_temp_no_replace(&temp, &destination).await.unwrap();
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"complete-payload");
        assert!(!tokio::fs::try_exists(&temp).await.unwrap());

        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }

    #[test]
    fn peer_validation_accepts_lan_addresses_and_rejects_public_peers() {
        assert!(is_lan_peer_address("192.168.1.10".parse().unwrap()));
        assert!(is_lan_peer_address("10.0.0.4".parse().unwrap()));
        assert!(is_lan_peer_address("169.254.20.1".parse().unwrap()));
        assert!(is_lan_peer_address("127.0.0.1".parse().unwrap()));
        assert!(is_lan_peer_address("fd12:3456::1".parse().unwrap()));
        assert!(!is_lan_peer_address("203.0.113.10".parse().unwrap()));
        assert!(!is_lan_peer_address("8.8.8.8".parse().unwrap()));
        assert!(!is_lan_peer_address("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn only_private_or_link_local_peers_are_allowed() {
        assert!(is_lan_peer_address(IpAddr::from_str("192.168.1.10").unwrap()));
        assert!(is_lan_peer_address(IpAddr::from_str("10.0.0.2").unwrap()));
        assert!(is_lan_peer_address(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(is_lan_peer_address(IpAddr::from_str("169.254.5.10").unwrap()));
        assert!(is_lan_peer_address(IpAddr::from_str("fd00::10").unwrap()));
        assert!(!is_lan_peer_address(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(!is_lan_peer_address(IpAddr::from_str("1.1.1.1").unwrap()));
    }

    #[test]
    fn host_validation_rejects_dns_rebinding_hostnames() {
        assert!(is_allowed_local_authority("192.168.1.25:8080"));
        assert!(is_allowed_local_authority("[::1]:8080"));
        assert!(is_allowed_local_authority("aetherdrop.local:8080"));
        assert!(!is_allowed_local_authority("attacker.example:8080"));
    }

    #[test]
    fn origin_must_match_the_local_authority() {
        assert!(origin_matches_authority(
            "http://192.168.1.25:8080",
            "192.168.1.25:8080"
        ));
        assert!(!origin_matches_authority(
            "https://192.168.1.25:8080",
            "192.168.1.25:8080"
        ));
        assert!(!origin_matches_authority(
            "http://attacker.example:8080",
            "192.168.1.25:8080"
        ));
    }

    #[test]
    fn sha256_matches_the_standard_known_vector() {
        let digest = format!("{:x}", Sha256::digest(b"abc"));
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn chunk_count_handles_empty_exact_and_partial_boundaries() {
        assert_eq!(chunks_for_size(0), 0);
        assert_eq!(chunks_for_size(1), 1);
        assert_eq!(chunks_for_size(UPLOAD_CHUNK_U64), 1);
        assert_eq!(chunks_for_size(UPLOAD_CHUNK_U64 + 1), 2);
        assert_eq!(chunks_for_size(2 * 1024 * 1024 * 1024), 256);
    }

    #[tokio::test]
    async fn chunked_upload_writes_verifies_and_atomically_publishes_file() {
        let directory = test_directory().await;
        let (state, session) = test_state(directory.clone());
        let data = b"AetherDrop chunk-integrity integration test".to_vec();
        let expected_hash = format!("{:x}", Sha256::digest(&data));
        let Json(start) = start_chunked_upload(
            State(state.clone()),
            Extension(session.clone()),
            Json(UploadStartRequest {
                filename: "roundtrip.bin".to_owned(),
                size_bytes: data.len() as u64,
            }),
        )
        .await
        .unwrap();

        assert_eq!(start.chunks_total, 1);
        let mut headers = HeaderMap::new();
        headers.insert("x-chunk-sha256", HeaderValue::from_str(&expected_hash).unwrap());
        let Json(progress) = upload_chunk(
            State(state.clone()),
            Extension(session.clone()),
            Extension(super::UploadRequestPermit(Arc::new(state.upload_slots.clone().acquire_owned().await.unwrap()))),
            AxumPath((start.transfer_id.clone(), 0)),
            headers,
            Bytes::from(data.clone()),
        )
        .await
        .unwrap();
        assert_eq!(progress.received_bytes, data.len() as u64);
        assert_eq!(progress.next_chunk, 1);
        assert_eq!(progress.chunk_hashes, vec![expected_hash.clone()]);

        let Json(response) = finish_chunked_upload(
            State(state.clone()),
            Extension(session),
            AxumPath(start.transfer_id),
            Json(UploadFinishRequest {
                sha256: expected_hash.clone(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.files.len(), 1);
        assert_eq!(response.files[0].sha256, expected_hash);
        assert_eq!(response.files[0].size_bytes, data.len() as u64);
        assert_eq!(tokio::fs::read(directory.join("roundtrip.bin")).await.unwrap(), data);
        assert_eq!(state.reserved_upload_bytes.load(Ordering::Acquire), 0);
        assert!(state.pending_uploads.read().await.is_empty());
        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }

    #[tokio::test]
    async fn multi_chunk_upload_preserves_order_and_full_file_hash() {
        let directory = test_directory().await;
        let (state, session) = test_state(directory.clone());
        let mut data = vec![0x5Au8; UPLOAD_CHUNK_U64 as usize + 137];
        for (index, byte) in data.iter_mut().enumerate().skip(UPLOAD_CHUNK_U64 as usize) {
            *byte = (index % 251) as u8;
        }
        let full_hash = format!("{:x}", Sha256::digest(&data));
        let first_chunk = &data[..UPLOAD_CHUNK_U64 as usize];
        let second_chunk = &data[UPLOAD_CHUNK_U64 as usize..];
        let Json(start) = start_chunked_upload(
            State(state.clone()),
            Extension(session.clone()),
            Json(UploadStartRequest {
                filename: "multi-chunk.bin".to_owned(),
                size_bytes: data.len() as u64,
            }),
        )
        .await
        .unwrap();
        assert_eq!(start.chunks_total, 2);

        let mut first_headers = HeaderMap::new();
        first_headers.insert(
            "x-chunk-sha256",
            HeaderValue::from_str(&format!("{:x}", Sha256::digest(first_chunk))).unwrap(),
        );
        let Json(after_first) = upload_chunk(
            State(state.clone()),
            Extension(session.clone()),
            Extension(super::UploadRequestPermit(Arc::new(
                state.upload_slots.clone().acquire_owned().await.unwrap()
            ))),
            AxumPath((start.transfer_id.clone(), 0)),
            first_headers,
            Bytes::copy_from_slice(first_chunk),
        )
        .await
        .unwrap();
        assert_eq!(after_first.next_chunk, 1);
        assert_eq!(after_first.received_bytes, UPLOAD_CHUNK_U64);
        assert_eq!(after_first.chunk_hashes.len(), 1);

        let mut second_headers = HeaderMap::new();
        second_headers.insert(
            "x-chunk-sha256",
            HeaderValue::from_str(&format!("{:x}", Sha256::digest(second_chunk))).unwrap(),
        );
        let Json(after_second) = upload_chunk(
            State(state.clone()),
            Extension(session.clone()),
            Extension(super::UploadRequestPermit(Arc::new(
                state.upload_slots.clone().acquire_owned().await.unwrap()
            ))),
            AxumPath((start.transfer_id.clone(), 1)),
            second_headers,
            Bytes::copy_from_slice(second_chunk),
        )
        .await
        .unwrap();
        assert_eq!(after_second.next_chunk, 2);
        assert_eq!(after_second.received_bytes, data.len() as u64);
        assert_eq!(after_second.chunk_hashes.len(), 2);

        let Json(finished) = finish_chunked_upload(
            State(state.clone()),
            Extension(session),
            AxumPath(start.transfer_id),
            Json(UploadFinishRequest { sha256: full_hash.clone() }),
        )
        .await
        .unwrap();
        assert_eq!(finished.files[0].sha256, full_hash);
        assert_eq!(tokio::fs::read(directory.join("multi-chunk.bin")).await.unwrap(), data);
        assert_eq!(state.reserved_upload_bytes.load(Ordering::Acquire), 0);
        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }

    #[tokio::test]
    async fn wrong_original_file_hash_never_publishes_the_destination() {
        let directory = test_directory().await;
        let (state, session) = test_state(directory.clone());
        let data = b"the correct bytes but a wrong client finish digest".to_vec();
        let actual_hash = format!("{:x}", Sha256::digest(&data));
        let Json(start) = start_chunked_upload(
            State(state.clone()),
            Extension(session.clone()),
            Json(UploadStartRequest {
                filename: "must-not-publish.bin".to_owned(),
                size_bytes: data.len() as u64,
            }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("x-chunk-sha256", HeaderValue::from_str(&actual_hash).unwrap());
        upload_chunk(
            State(state.clone()),
            Extension(session.clone()),
            Extension(super::UploadRequestPermit(Arc::new(state.upload_slots.clone().acquire_owned().await.unwrap()))),
            AxumPath((start.transfer_id.clone(), 0)),
            headers,
            Bytes::from(data),
        )
        .await
        .unwrap();

        let error = finish_chunked_upload(
            State(state.clone()),
            Extension(session),
            AxumPath(start.transfer_id),
            Json(UploadFinishRequest {
                sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!tokio::fs::try_exists(directory.join("must-not-publish.bin")).await.unwrap());
        assert_eq!(state.reserved_upload_bytes.load(Ordering::Acquire), 0);
        assert!(state.pending_uploads.read().await.is_empty());
        assert!(tokio::fs::read_dir(&directory).await.unwrap().next_entry().await.unwrap().is_none());
        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }

    #[tokio::test]
    async fn bad_chunk_hash_does_not_advance_or_write_and_cancel_cleans_temp_file() {
        let directory = test_directory().await;
        let (state, session) = test_state(directory.clone());
        let data = b"must not be written under the wrong digest".to_vec();
        let Json(start) = start_chunked_upload(
            State(state.clone()),
            Extension(session.clone()),
            Json(UploadStartRequest {
                filename: "must-not-exist.bin".to_owned(),
                size_bytes: data.len() as u64,
            }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-chunk-sha256",
            HeaderValue::from_static("0000000000000000000000000000000000000000000000000000000000000000"),
        );
        let error = upload_chunk(
            State(state.clone()),
            Extension(session.clone()),
            Extension(super::UploadRequestPermit(Arc::new(state.upload_slots.clone().acquire_owned().await.unwrap()))),
            AxumPath((start.transfer_id.clone(), 0)),
            headers,
            Bytes::from(data),
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);

        let Json(status) = super::chunked_upload_status(
            State(state.clone()),
            Extension(session.clone()),
            AxumPath(start.transfer_id.clone()),
        )
        .await
        .unwrap();
        assert_eq!(status.next_chunk, 0);
        assert_eq!(status.received_bytes, 0);
        let handle = state.pending_uploads.read().await.get(&start.transfer_id).cloned().unwrap();
        let temp_path = handle.inner.lock().await.temp_path.clone();
        drop(handle);
        let temp_metadata = tokio::fs::metadata(&temp_path).await.unwrap();
        assert_eq!(temp_metadata.len(), 0, "invalid hashes must never write bytes to the temporary file");

        assert_eq!(
            cancel_chunked_upload(
                State(state.clone()),
                Extension(session),
                AxumPath(start.transfer_id),
            )
            .await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(state.reserved_upload_bytes.load(Ordering::Acquire), 0);
        assert!(state.pending_uploads.read().await.is_empty());
        assert!(tokio::fs::read_dir(&directory).await.unwrap().next_entry().await.unwrap().is_none());
        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }

    #[tokio::test]
    async fn re_pairing_rotates_the_session_and_cancels_the_previous_token() {
        let directory = test_directory().await;
        let (state, session) = test_state(directory.clone());
        let Json(pending_transfer) = start_chunked_upload(
            State(state.clone()),
            Extension(session),
            Json(UploadStartRequest {
                filename: "resume-after-pairing.bin".to_owned(),
                size_bytes: 128,
            }),
        )
        .await
        .unwrap();
        let temp_path = {
            let handle = state.pending_uploads.read().await
                .get(&pending_transfer.transfer_id).cloned().unwrap();
            let path = handle.inner.lock().await.temp_path.clone();
            path
        };
        let old_cancellation = state.session_tokens.read().await
            .get("test-session-token")
            .unwrap()
            .cancellation
            .clone();

        let response = handle_auth(
            State(state.clone()),
            ConnectInfo("192.0.2.10:51000".parse().unwrap()),
            Json(PinRequest {
                pin: "123456".to_owned(),
                device_id: "dev_test_device".to_owned(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(old_cancellation.is_cancelled());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let new_token = json.get("token").and_then(|value| value.as_str()).unwrap();
        assert_ne!(new_token, "test-session-token");
        let sessions = state.session_tokens.read().await;
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(new_token));
        drop(sessions);
        assert!(state.pending_uploads.read().await.is_empty());
        assert_eq!(state.reserved_upload_bytes.load(Ordering::Acquire), 0);
        assert!(!tokio::fs::try_exists(&temp_path).await.unwrap());
        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }

    #[tokio::test]
    async fn pairing_rejects_new_devices_after_the_trusted_device_limit() {
        let directory = test_directory().await;
        let (state, _session) = test_state(directory.clone());
        {
            let mut devices = state.trusted_devices.write().await;
            *devices = (0..MAX_TRUSTED_DEVICES)
                .map(|index| format!("dev_trusted_{index}"))
                .collect();
        }
        state.session_tokens.write().await.clear();
        let response = handle_auth(
            State(state.clone()),
            ConnectInfo("192.0.2.11:51001".parse().unwrap()),
            Json(PinRequest {
                pin: "123456".to_owned(),
                device_id: "dev_new_device".to_owned(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(state.trusted_devices.read().await.len(), MAX_TRUSTED_DEVICES);
        assert!(state.session_tokens.read().await.is_empty());
        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }

    #[test]
    fn auth_rate_limit_is_scoped_to_each_ip() {
        let mut failures = HashMap::<IpAddr, AuthFailureState>::new();
        let first = IpAddr::from_str("192.0.2.10").unwrap();
        let second = IpAddr::from_str("192.0.2.11").unwrap();
        let now = Instant::now();

        for _ in 1..MAX_AUTH_FAILURES {
            assert!(!record_auth_failure(&mut failures, first, now));
        }
        assert!(record_auth_failure(&mut failures, first, now));
        assert!(auth_rate_limited(&mut failures, first, now));
        assert!(!auth_rate_limited(&mut failures, second, now));
    }
}

// Uploaded files are staged beside their destination, synced, read back and
// SHA-256-verified, then atomically published without overwriting an existing file.
async fn create_download_ticket(
    State(state): State<AppState>,
    Extension(session): Extension<AuthorizedSession>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<DownloadTicketResponse>, (StatusCode, &'static str)> {
    if !session_is_authorized(&state, &session).await {
        return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado o el dispositivo se ha desvinculado."));
    }
    let exists = state.pc_files.read().await.iter().any(|(file_id, _)| file_id == &id);
    if !exists {
        return Err((StatusCode::NOT_FOUND, "El archivo ya no está disponible."));
    }

    let ticket = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let now = Instant::now();
    let mut tickets = state.download_tickets.write().await;
    tickets.retain(|_, entry| entry.expires_at > now);
    if tickets.len() >= 512 {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Hay demasiadas descargas pendientes. Inténtalo de nuevo."));
    }
    tickets.insert(ticket.clone(), DownloadTicket {
        file_id: id,
        session_token: session.token,
        device_id: session.device_id,
        expires_at: now + Duration::from_secs(60),
    });
    Ok(Json(DownloadTicketResponse { ticket, expires_in: 60 }))
}

#[cfg(test)]
async fn publish_temp_no_replace(temp_path: &Path, destination: &Path) -> std::io::Result<()> {
    tokio::fs::hard_link(temp_path, destination).await?;
    // Publication already succeeded. A cleanup failure leaves only a hidden .part
    // hard link and must not turn a successfully published file into a failed upload.
    if let Err(error) = tokio::fs::remove_file(temp_path).await {
        eprintln!("AetherDrop: no se pudo retirar el temporal {:?}: {}", temp_path, error);
    }
    Ok(())
}

async fn publish_temp_for_session(
    state: &AppState,
    session: &AuthorizedSession,
    transfer_cancellation: &CancellationToken,
    temp_path: &Path,
    destination: &Path,
) -> Result<(), PublishError> {
    // Hold read locks through the atomic publication. Revocation takes write locks,
    // so either the publication linearizes first or the revoked device cannot publish.
    let trusted_devices = state.trusted_devices.read().await;
    let sessions = state.session_tokens.read().await;
    let valid = sessions.get(&session.token).is_some_and(|record| {
        record.device_id == session.device_id
            && record.expires_at > Instant::now()
            && !record.cancellation.is_cancelled()
    }) && trusted_devices.contains(&session.device_id)
        && !session.cancellation.is_cancelled()
        && !transfer_cancellation.is_cancelled()
        && session.expires_at > Instant::now();
    if !valid {
        return Err(if transfer_cancellation.is_cancelled() {
            PublishError::Cancelled
        } else {
            PublishError::Unauthorized
        });
    }

    // The hard-link creation is the commit point. Cancellation before it wins;
    // after it succeeds, the complete final file exists atomically and cleanup is
    // best-effort. Do not cancel between publication and temporary-link cleanup.
    tokio::select! {
        biased;
        _ = state.server_shutdown.cancelled() => return Err(PublishError::ShuttingDown),
        _ = transfer_cancellation.cancelled() => return Err(PublishError::Cancelled),
        _ = session.cancellation.cancelled() => return Err(PublishError::Unauthorized),
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(session.expires_at)) => {
            return Err(PublishError::Unauthorized);
        }
        result = tokio::fs::hard_link(temp_path, destination) => {
            result.map_err(PublishError::Io)?;
        }
    }

    if let Err(error) = tokio::fs::remove_file(temp_path).await {
        eprintln!("AetherDrop: no se pudo retirar el temporal {:?}: {}", temp_path, error);
    }
    Ok(())
}

async fn session_is_authorized(state: &AppState, session: &AuthorizedSession) -> bool {
    if state.server_shutdown.is_cancelled()
        || session.cancellation.is_cancelled()
        || session.expires_at <= Instant::now()
    {
        return false;
    }
    let now = Instant::now();
    let valid_session = state.session_tokens.read().await
        .get(&session.token)
        .is_some_and(|record| {
            record.device_id == session.device_id
                && record.expires_at > now
                && !record.cancellation.is_cancelled()
        });
    valid_session && state.trusted_devices.read().await.contains(&session.device_id)
}

async fn reserve_upload_space(
    state: &AppState,
    directory: &Path,
    expected_size: u64,
) -> Result<(), (StatusCode, &'static str)> {
    let path = directory.to_path_buf();
    let available = tokio::task::spawn_blocking(move || fs2::available_space(path))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo comprobar el espacio libre."))?
        .map_err(|_| (StatusCode::INSUFFICIENT_STORAGE, "No se pudo consultar el espacio disponible en el disco."))?;

    loop {
        let reserved = state.reserved_upload_bytes.load(Ordering::Acquire);
        let required = reserved
            .checked_add(expected_size)
            .and_then(|value| value.checked_add(DISK_SPACE_RESERVE_BYTES))
            .ok_or((StatusCode::INSUFFICIENT_STORAGE, "La reserva de espacio supera los límites permitidos."))?;
        if available < required {
            return Err((StatusCode::INSUFFICIENT_STORAGE, "No hay espacio libre suficiente para la transferencia y la reserva de seguridad."));
        }
        let new_reserved = reserved
            .checked_add(expected_size)
            .ok_or((StatusCode::INSUFFICIENT_STORAGE, "La reserva de espacio supera los límites permitidos."))?;
        match state.reserved_upload_bytes.compare_exchange_weak(
            reserved,
            new_reserved,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(_) => continue,
        }
    }
}

fn release_reserved_upload_bytes(state: &AppState, amount: u64) {
    let _ = state.reserved_upload_bytes.fetch_update(
        Ordering::AcqRel,
        Ordering::Acquire,
        |current| Some(current.saturating_sub(amount)),
    );
}

fn chunks_for_size(size_bytes: u64) -> u64 {
    size_bytes / UPLOAD_CHUNK_U64 + u64::from(size_bytes % UPLOAD_CHUNK_U64 != 0)
}

async fn remove_pending_upload(state: &AppState, transfer_id: &str) -> bool {
    let handle = state.pending_uploads.write().await.remove(transfer_id);
    let Some(handle) = handle else {
        return false;
    };
    handle.cancellation.cancel();

    let (temp_path, reserved_remaining) = {
        let upload = handle.inner.lock().await;
        (
            upload.temp_path.clone(),
            upload.expected_size.saturating_sub(upload.received_size),
        )
    };
    release_reserved_upload_bytes(state, reserved_remaining);

    if let Err(error) = tokio::fs::remove_file(&temp_path).await {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!("AetherDrop: no se pudo limpiar la transferencia temporal {:?}: {}", temp_path, error);
        }
    }
    true
}

fn upload_progress(upload: &PendingUpload) -> UploadProgressResponse {
    UploadProgressResponse {
        filename: upload.filename.clone(),
        size_bytes: upload.expected_size,
        received_bytes: upload.received_size,
        next_chunk: upload.next_chunk,
        chunks_total: chunks_for_size(upload.expected_size),
        chunk_size: UPLOAD_CHUNK_BYTES,
        chunk_hashes: upload.chunk_hashes.clone(),
    }
}

async fn start_chunked_upload(
    State(state): State<AppState>,
    Extension(session): Extension<AuthorizedSession>,
    Json(payload): Json<UploadStartRequest>,
) -> Result<Json<UploadStartResponse>, (StatusCode, &'static str)> {
    if !session_is_authorized(&state, &session).await {
        return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado o el dispositivo se ha desvinculado."));
    }
    let Some(filename) = sanitize_upload_filename(&payload.filename) else {
        return Err((StatusCode::BAD_REQUEST, "El nombre del archivo no es válido."));
    };
    if payload.size_bytes > MAX_UPLOAD_FILE_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "El archivo supera el límite permitido."));
    }

    let slot = state.pending_upload_slots.clone().try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "Hay demasiadas transferencias pendientes; termina o cancela una antes de empezar otra."))?;
    let directory = state.save_dir.read().await.clone();
    tokio::fs::create_dir_all(&directory).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo preparar la carpeta de destino."))?;
    reserve_upload_space(&state, &directory, payload.size_bytes).await?;

    let transfer_id = uuid::Uuid::new_v4().to_string();
    let temp_path = directory.join(format!(".aetherdrop-upload-{}.part", transfer_id));
    let temp_file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
    {
        Ok(file) => file,
        Err(_) => {
            release_reserved_upload_bytes(&state, payload.size_bytes);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "No se pudo crear el archivo temporal."));
        }
    };
    drop(temp_file);

    let cancellation = CancellationToken::new();
    let handle = PendingUploadHandle {
        owner_device_id: session.device_id.clone(),
        session_token: session.token.clone(),
        session_cancellation: session.cancellation.clone(),
        session_expires_at: session.expires_at,
        cancellation: cancellation.clone(),
        inner: Arc::new(AsyncMutex::new(PendingUpload {
            filename,
            temp_path: temp_path.clone(),
            expected_size: payload.size_bytes,
            received_size: 0,
            next_chunk: 0,
            hasher: Sha256::new(),
            chunk_hashes: Vec::new(),
            last_activity: Instant::now(),
            _slot: slot,
        })),
    };

    // Check again while serializing insertion so a just-revoked client cannot
    // leave an active transfer behind after pairing has been removed.
    let mut pending = state.pending_uploads.write().await;
    let pending_for_device = pending.values()
        .filter(|upload| upload.owner_device_id == session.device_id)
        .count();
    if pending_for_device >= MAX_PENDING_UPLOADS_PER_DEVICE {
        drop(pending);
        cancellation.cancel();
        let _ = tokio::fs::remove_file(&temp_path).await;
        release_reserved_upload_bytes(&state, payload.size_bytes);
        return Err((StatusCode::TOO_MANY_REQUESTS, "Este dispositivo ya tiene demasiadas transferencias pendientes. Finaliza o cancela una antes de iniciar otra."));
    }
    if !session_is_authorized(&state, &session).await || state.server_shutdown.is_cancelled() {
        drop(pending);
        cancellation.cancel();
        let _ = tokio::fs::remove_file(&temp_path).await;
        release_reserved_upload_bytes(&state, payload.size_bytes);
        return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado o el dispositivo se ha desvinculado."));
    }
    pending.insert(transfer_id.clone(), handle);
    Ok(Json(UploadStartResponse {
        transfer_id,
        chunk_size: UPLOAD_CHUNK_BYTES,
        chunks_total: chunks_for_size(payload.size_bytes),
        next_chunk: 0,
    }))
}

async fn chunked_upload_status(
    State(state): State<AppState>,
    Extension(session): Extension<AuthorizedSession>,
    AxumPath(transfer_id): AxumPath<String>,
) -> Result<Json<UploadProgressResponse>, (StatusCode, &'static str)> {
    let handle = state.pending_uploads.read().await.get(&transfer_id).cloned()
        .ok_or((StatusCode::NOT_FOUND, "La transferencia pendiente no existe o ha caducado."))?;
    if handle.owner_device_id != session.device_id || handle.session_token != session.token {
        return Err((StatusCode::FORBIDDEN, "La transferencia pertenece a otra sesión."));
    }
    if handle.cancellation.is_cancelled()
        || handle.session_cancellation.is_cancelled()
        || handle.session_expires_at <= Instant::now()
        || !session_is_authorized(&state, &session).await
    {
        drop(handle);
        remove_pending_upload(&state, &transfer_id).await;
        return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado o el dispositivo se ha desvinculado."));
    }

    let progress = {
        let upload = handle.inner.lock().await;
        if upload.last_activity.elapsed() >= PENDING_UPLOAD_TTL {
            None
        } else {
            Some(upload_progress(&upload))
        }
    };
    match progress {
        Some(progress) => Ok(Json(progress)),
        None => {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
            Err((StatusCode::GONE, "La transferencia ha caducado por inactividad."))
        }
    }
}

async fn upload_chunk(
    State(state): State<AppState>,
    Extension(session): Extension<AuthorizedSession>,
    Extension(_request_permit): Extension<UploadRequestPermit>,
    AxumPath((transfer_id, chunk_index)): AxumPath<(String, u64)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Json<UploadProgressResponse>, (StatusCode, &'static str)> {
    let handle = state.pending_uploads.read().await.get(&transfer_id).cloned()
        .ok_or((StatusCode::NOT_FOUND, "La transferencia pendiente no existe o ha caducado."))?;
    if handle.owner_device_id != session.device_id || handle.session_token != session.token {
        return Err((StatusCode::FORBIDDEN, "La transferencia pertenece a otra sesión."));
    }
    if !session_is_authorized(&state, &session).await
        || handle.cancellation.is_cancelled()
        || handle.session_cancellation.is_cancelled()
    {
        drop(handle);
        remove_pending_upload(&state, &transfer_id).await;
        return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado o el dispositivo se ha desvinculado."));
    }

    let shutdown_cancellation = state.server_shutdown.clone();
    let transfer_cancellation = handle.cancellation.clone();
    let session_cancellation = session.cancellation.clone();
    let upload_inner = handle.inner.clone();
    let mut upload = tokio::select! {
        biased;
        _ = shutdown_cancellation.cancelled() => {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
            return Err((StatusCode::SERVICE_UNAVAILABLE, "AetherDrop se está cerrando."));
        }
        _ = transfer_cancellation.cancelled() => {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
            return Err((StatusCode::UNAUTHORIZED, "La transferencia se ha cancelado."));
        }
        _ = session_cancellation.cancelled() => {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
            return Err((StatusCode::UNAUTHORIZED, "El dispositivo se ha desvinculado."));
        }
        guard = upload_inner.lock() => guard,
    };
    if upload.last_activity.elapsed() >= PENDING_UPLOAD_TTL {
        drop(upload);
        drop(handle);
        remove_pending_upload(&state, &transfer_id).await;
        return Err((StatusCode::GONE, "La transferencia ha caducado por inactividad."));
    }
    if chunk_index != upload.next_chunk {
        return Err((StatusCode::CONFLICT, "El índice del bloque no coincide; consulta el estado y continúa desde el siguiente bloque esperado."));
    }
    if upload.received_size >= upload.expected_size {
        return Err((StatusCode::CONFLICT, "La transferencia ya ha recibido todos los bloques; finalízala."));
    }

    let expected_chunk_len = UPLOAD_CHUNK_U64
        .min(upload.expected_size.saturating_sub(upload.received_size)) as usize;
    if body.len() != expected_chunk_len {
        return Err((StatusCode::BAD_REQUEST, "El tamaño del bloque no coincide con el tamaño esperado."));
    }
    let provided_hash = headers.get("x-chunk-sha256")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .ok_or((StatusCode::BAD_REQUEST, "Falta el hash SHA-256 válido del bloque."))?;
    let actual_hash = format!("{:x}", Sha256::digest(&body));
    if actual_hash != provided_hash {
        return Err((StatusCode::BAD_REQUEST, "El bloque no supera la verificación SHA-256; vuelve a enviarlo."));
    }

    let offset = upload.received_size;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&upload.temp_path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo abrir el archivo temporal."))?;
    file.seek(std::io::SeekFrom::Start(offset)).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo posicionar el archivo temporal."))?;

    let write_result: Result<(), (StatusCode, &'static str)> = tokio::select! {
        biased;
        _ = state.server_shutdown.cancelled() => Err((StatusCode::SERVICE_UNAVAILABLE, "AetherDrop se está cerrando.")),
        _ = handle.cancellation.cancelled() => Err((StatusCode::UNAUTHORIZED, "La transferencia se ha cancelado.")),
        _ = session.cancellation.cancelled() => Err((StatusCode::UNAUTHORIZED, "El dispositivo se ha desvinculado.")),
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(session.expires_at)) => {
            Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado."))
        }
        result = async {
            file.write_all(&body).await?;
            file.sync_data().await
        } => result.map_err(|_| (StatusCode::INSUFFICIENT_STORAGE, "No se pudo escribir el bloque; comprueba el espacio disponible.")),
    };
    if let Err(error) = write_result {
        if let Err(rollback_error) = file.set_len(offset).await {
            eprintln!("AetherDrop: no se pudo revertir el bloque parcial {:?}: {}", upload.temp_path, rollback_error);
        }
        let _ = file.sync_data().await;
        drop(file);
        drop(upload);
        if error.0 == StatusCode::UNAUTHORIZED || error.0 == StatusCode::SERVICE_UNAVAILABLE {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
        }
        return Err(error);
    }
    drop(file);

    upload.hasher.update(&body);
    upload.chunk_hashes.push(actual_hash);
    upload.received_size += body.len() as u64;
    upload.next_chunk += 1;
    upload.last_activity = Instant::now();
    release_reserved_upload_bytes(&state, body.len() as u64);
    Ok(Json(upload_progress(&upload)))
}

async fn finish_chunked_upload(
    State(state): State<AppState>,
    Extension(session): Extension<AuthorizedSession>,
    AxumPath(transfer_id): AxumPath<String>,
    Json(payload): Json<UploadFinishRequest>,
) -> Result<Json<UploadResponse>, (StatusCode, &'static str)> {
    let expected_client_hash = payload.sha256.to_ascii_lowercase();
    if expected_client_hash.len() != 64
        || !expected_client_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err((StatusCode::BAD_REQUEST, "Falta un hash SHA-256 completo válido del archivo original."));
    }
    let _permit = state.upload_slots.clone().try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "Hay demasiadas operaciones de transferencia simultáneas."))?;
    let handle = state.pending_uploads.read().await.get(&transfer_id).cloned()
        .ok_or((StatusCode::NOT_FOUND, "La transferencia pendiente no existe o ha caducado."))?;
    if handle.owner_device_id != session.device_id || handle.session_token != session.token {
        return Err((StatusCode::FORBIDDEN, "La transferencia pertenece a otra sesión."));
    }

    let shutdown_cancellation = state.server_shutdown.clone();
    let transfer_cancellation = handle.cancellation.clone();
    let session_cancellation = session.cancellation.clone();
    let upload_inner = handle.inner.clone();
    let mut upload = tokio::select! {
        biased;
        _ = shutdown_cancellation.cancelled() => {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
            return Err((StatusCode::SERVICE_UNAVAILABLE, "AetherDrop se está cerrando."));
        }
        _ = transfer_cancellation.cancelled() => {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
            return Err((StatusCode::UNAUTHORIZED, "La transferencia se ha cancelado."));
        }
        _ = session_cancellation.cancelled() => {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
            return Err((StatusCode::UNAUTHORIZED, "El dispositivo se ha desvinculado."));
        }
        guard = upload_inner.lock() => guard,
    };
    if upload.received_size != upload.expected_size {
        return Err((StatusCode::CONFLICT, "La transferencia está incompleta; continúa los bloques antes de finalizar."));
    }
    if !session_is_authorized(&state, &session).await
        || upload.last_activity.elapsed() >= PENDING_UPLOAD_TTL
    {
        drop(upload);
        drop(handle);
        remove_pending_upload(&state, &transfer_id).await;
        return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado o la transferencia ha expirado."));
    }

    let result: Result<UploadReceipt, (StatusCode, &'static str)> = async {
        let mut sync_file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&upload.temp_path)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo abrir el archivo para finalizarlo."))?;
        sync_file.sync_all().await
            .map_err(|_| (StatusCode::INSUFFICIENT_STORAGE, "No se pudo sincronizar el archivo final."))?;
        drop(sync_file);

        let mut verification_file = tokio::fs::File::open(&upload.temp_path).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo verificar el archivo guardado."))?;
        let stream_digest = format!("{:x}", upload.hasher.clone().finalize());
        let mut disk_hasher = Sha256::new();
        let mut verified_size = 0u64;
        let mut buffer = vec![0u8; 128 * 1024];
        loop {
            let count = tokio::select! {
                biased;
                _ = state.server_shutdown.cancelled() => {
                    return Err((StatusCode::SERVICE_UNAVAILABLE, "AetherDrop se está cerrando."));
                }
                _ = handle.cancellation.cancelled() => {
                    return Err((StatusCode::UNAUTHORIZED, "La transferencia se ha cancelado."));
                }
                _ = session.cancellation.cancelled() => {
                    return Err((StatusCode::UNAUTHORIZED, "El dispositivo se ha desvinculado."));
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(session.expires_at)) => {
                    return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado."));
                }
                read = verification_file.read(&mut buffer) => {
                    read.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Falló la lectura de verificación del archivo."))?
                }
            };
            if count == 0 {
                break;
            }
            verified_size += count as u64;
            disk_hasher.update(&buffer[..count]);
        }
        let disk_digest = format!("{:x}", disk_hasher.finalize());
        if verified_size != upload.expected_size
            || disk_digest != stream_digest
            || disk_digest != expected_client_hash
        {
            return Err((StatusCode::UNPROCESSABLE_ENTITY, "El hash del archivo guardado no coincide con el archivo original. No se ha publicado el destino."));
        }
        if !session_is_authorized(&state, &session).await {
            return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado o el dispositivo se ha desvinculado."));
        }

        let destination_directory = upload.temp_path.parent().unwrap_or_else(|| Path::new("."));
        let destination_path = destination_directory.join(&upload.filename);
        match publish_temp_for_session(
            &state,
            &session,
            &handle.cancellation,
            &upload.temp_path,
            &destination_path,
        ).await {
            Ok(()) => Ok(UploadReceipt {
                filename: upload.filename.clone(),
                size_bytes: upload.expected_size,
                sha256: disk_digest,
            }),
            Err(PublishError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err((StatusCode::CONFLICT, "Ya existe un archivo con ese nombre. Cambia el nombre y vuelve a intentarlo."))
            }
            Err(PublishError::Unauthorized) => Err((StatusCode::UNAUTHORIZED, "El dispositivo se ha desvinculado o la sesión ha caducado.")),
            Err(PublishError::Cancelled) => Err((StatusCode::CONFLICT, "La transferencia se ha cancelado antes de publicar el archivo.")),
            Err(PublishError::ShuttingDown) => Err((StatusCode::SERVICE_UNAVAILABLE, "AetherDrop se está cerrando.")),
            Err(PublishError::Io(_)) => Err((StatusCode::INTERNAL_SERVER_ERROR, "El sistema de archivos no permite publicar el archivo de forma atómica.")),
        }
    }.await;

    drop(upload);
    match result {
        Ok(receipt) => {
            state.pending_uploads.write().await.remove(&transfer_id);
            Ok(Json(UploadResponse { files: vec![receipt] }))
        }
        Err(error) => {
            drop(handle);
            remove_pending_upload(&state, &transfer_id).await;
            Err(error)
        }
    }
}

async fn cancel_chunked_upload(
    State(state): State<AppState>,
    Extension(session): Extension<AuthorizedSession>,
    AxumPath(transfer_id): AxumPath<String>,
) -> StatusCode {
    let handle = state.pending_uploads.read().await.get(&transfer_id).cloned();
    let Some(handle) = handle else {
        return StatusCode::NOT_FOUND;
    };
    if handle.owner_device_id != session.device_id || handle.session_token != session.token {
        return StatusCode::FORBIDDEN;
    }
    drop(handle);
    if remove_pending_upload(&state, &transfer_id).await {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn list_pc_files(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let files = state.pc_files.read().await;
    let list: Vec<_> = files.iter().map(|(id, path)| {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        serde_json::json!({ "id": id, "name": name })
    }).collect();
    Json(list)
}

async fn download_pc_file(
    State(state): State<AppState>,
    Extension(session): Extension<AuthorizedSession>,
    AxumPath(id): AxumPath<String>,
) -> axum::response::Response {
    let download_permit = match state.download_slots.clone().try_acquire_owned() {
        Ok(permit) => Arc::new(permit),
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };

    // Release the shared file-list lock before opening/streaming the file.
    let path = {
        let files = state.pc_files.read().await;
        files.iter().find(|(file_id, _)| file_id == &id).map(|(_, path)| path.clone())
    };
    let Some(path) = path else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path_metadata = match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let canonical_path = match tokio::fs::canonicalize(&path).await {
        Ok(canonical_path) => canonical_path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if canonical_path != path {
        return StatusCode::NOT_FOUND.into_response();
    }
    let file = match tokio::fs::File::open(&canonical_path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let metadata = match file.metadata().await {
        Ok(metadata) => metadata,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let disposition = content_disposition_value(&filename);
    let stream_state = state.clone();
    let stream_session = session.clone();
    let stream = ReaderStream::with_capacity(file, 256 * 1024).and_then(move |chunk| {
        let state = stream_state.clone();
        let session = stream_session.clone();
        let _permit = download_permit.clone();
        async move {
            // The Arc held by this stream retains its semaphore permit until the
            // response body is dropped, even if the client stops reading early.
            if !session_is_authorized(&state, &session).await {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Session revoked"));
            }
            let _permit = _permit;
            Ok::<Bytes, std::io::Error>(chunk)
        }
    });

    match axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Disposition", disposition)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", metadata.len().to_string())
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .body(axum::body::Body::from_stream(stream))
    {
        Ok(response) => response,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_clipboard(State(state): State<AppState>) -> Json<serde_json::Value> {
    let text = state.clipboard_text.read().await.clone();
    Json(serde_json::json!({ "text": text }))
}

async fn set_clipboard(
    State(state): State<AppState>,
    Json(payload): Json<ClipboardRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if payload.text.len() > MAX_CLIPBOARD_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "El texto supera el límite de 1 MiB.".to_owned()));
    }
    let text = payload.text;
    let system_text = text.clone();
    let apply_result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut clipboard = Clipboard::new().map_err(|error| format!("No se pudo abrir el portapapeles del sistema: {}", error))?;
        clipboard.set_text(system_text).map_err(|error| format!("No se pudo actualizar el portapapeles del sistema: {}", error))
    }).await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Falló la tarea del portapapeles: {}", error)))?;
    apply_result.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    *state.clipboard_text.write().await = text;
    Ok(StatusCode::OK)
}

async fn cleanup_stale_uploads(directory: &Path) {
    let mut entries = match tokio::fs::read_dir(directory).await {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("AetherDrop: no se pudieron revisar los temporales de {:?}: {}", directory, error);
            return;
        }
    };
    let now = SystemTime::now();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(".aetherdrop-upload-") || !name.ends_with(".part") {
            continue;
        }
        let file_type = match entry.file_type().await {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if !file_type.is_file() {
            continue;
        }
        let metadata = match entry.metadata().await {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let stale = metadata.modified().ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= Duration::from_secs(24 * 60 * 60));
        if stale {
            if let Err(error) = tokio::fs::remove_file(entry.path()).await {
                eprintln!("AetherDrop: no se pudo borrar el temporal antiguo {:?}: {}", entry.path(), error);
            }
        }
    }
}

fn start_mdns_service(state: AppState) {
    std::thread::spawn(move || {
        let daemon = match ServiceDaemon::new() {
            Ok(daemon) => daemon,
            Err(error) => {
                eprintln!("AetherDrop: mDNS no disponible: {}", error);
                return;
            }
        };
        let ip = match local_ip() {
            Ok(ip) => ip,
            Err(error) => {
                eprintln!("AetherDrop: no se pudo anunciar mDNS: {}", error);
                let _ = daemon.shutdown();
                return;
            }
        };
        let ip_string = ip.to_string();
        let service_info = match ServiceInfo::new(
            "_aetherdrop._tcp.local.",
            "AetherDropPC",
            "aetherdrop.local.",
            ip_string.as_str(),
            8080,
            None,
        ) {
            Ok(service_info) => service_info,
            Err(error) => {
                eprintln!("AetherDrop: anuncio mDNS no válido: {}", error);
                let _ = daemon.shutdown();
                return;
            }
        };
        match daemon.register(service_info) {
            Ok(()) => match state.mdns_daemon.lock() {
                Ok(mut slot) if !state.server_shutdown.is_cancelled() => {
                    *slot = Some(daemon);
                }
                Ok(_slot) => {
                    let _ = daemon.shutdown();
                }
                Err(_) => {
                    eprintln!("AetherDrop: no se pudo guardar el estado de mDNS; se detiene el anuncio.");
                    let _ = daemon.shutdown();
                }
            },
            Err(error) => {
                eprintln!("AetherDrop: no se pudo registrar mDNS: {}", error);
                let _ = daemon.shutdown();
            }
        }
    });
}

fn start_local_server(state: AppState) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("aetherdrop-http")
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let message = format!("No se pudo crear el runtime HTTP: {}", error);
                eprintln!("AetherDrop: {}", message);
                // This runs on the dedicated OS thread before a Tokio runtime exists,
                // so a blocking lock guarantees the desktop UI will observe the failure.
                *state.server_status.blocking_write() = ServerStatus::Failed(message);
                return;
            }
        };
        runtime.block_on(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => listener,
                Err(error) => {
                    let message = format!("No se pudo abrir el puerto 8080: {}", error);
                    eprintln!("AetherDrop: {}", message);
                    *state.server_status.write().await = ServerStatus::Failed(message);
                    return;
                }
            };

            // Advertise the service only after port 8080 is actually bound.
            start_mdns_service(state.clone());
            let initial_dir = state.save_dir.read().await.clone();
            cleanup_stale_uploads(&initial_dir).await;
            *state.server_status.write().await = ServerStatus::Ready;

            let maintenance_state = state.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5 * 60));
                loop {
                    tokio::select! {
                        _ = maintenance_state.server_shutdown.cancelled() => break,
                        _ = interval.tick() => {
                            let now = Instant::now();
                            let trusted: std::collections::HashSet<String> =
                                maintenance_state.trusted_devices.read().await.iter().cloned().collect();
                            {
                                let mut sessions = maintenance_state.session_tokens.write().await;
                                sessions.retain(|_, session| {
                                    let keep = session.expires_at > now
                                        && trusted.contains(&session.device_id)
                                        && !session.cancellation.is_cancelled();
                                    if !keep {
                                        session.cancellation.cancel();
                                    }
                                    keep
                                });
                            }
                            {
                                let mut tickets = maintenance_state.download_tickets.write().await;
                                tickets.retain(|_, ticket| ticket.expires_at > now);
                            }
                            {
                                let mut failures = maintenance_state.auth_failures.write().await;
                                failures.retain(|_, entry| {
                                    entry.window_started.elapsed() < AUTH_FAILURE_WINDOW
                                        || entry.blocked_until.is_some_and(|until| until > now)
                                });
                            }
                            let pending_ids: Vec<String> = maintenance_state.pending_uploads.read().await
                                .iter()
                                .filter(|(_, handle)| {
                                    handle.cancellation.is_cancelled()
                                        || handle.session_cancellation.is_cancelled()
                                        || handle.session_expires_at <= now
                                })
                                .map(|(id, _)| id.clone())
                                .collect();
                            for transfer_id in pending_ids {
                                remove_pending_upload(&maintenance_state, &transfer_id).await;
                            }
                            let pending_snapshot: Vec<(String, PendingUploadHandle)> =
                                maintenance_state.pending_uploads.read().await
                                    .iter()
                                    .map(|(id, handle)| (id.clone(), handle.clone()))
                                    .collect();
                            for (transfer_id, handle) in pending_snapshot {
                                let inactive = {
                                    let upload = handle.inner.lock().await;
                                    upload.last_activity.elapsed() >= PENDING_UPLOAD_TTL
                                };
                                if inactive {
                                    remove_pending_upload(&maintenance_state, &transfer_id).await;
                                }
                            }
                            let directory = maintenance_state.save_dir.read().await.clone();
                            cleanup_stale_uploads(&directory).await;
                        }
                    }
                }
            });

            let status = state.server_status.clone();
            let server_shutdown = state.server_shutdown.clone();
            let mdns_service = state.mdns_daemon.clone();
            let app = Router::new()
                .route("/", get(serve_ui))
                .route("/mobile.js", get(serve_mobile_js))
                .route("/sha256.js", get(serve_sha256_js))
                .route("/auth", post(handle_auth).layer(DefaultBodyLimit::max(MAX_AUTH_REQUEST_BYTES)))
                .route("/session", get(check_session))
                .route("/upload/start", post(start_chunked_upload).layer(DefaultBodyLimit::max(MAX_AUTH_REQUEST_BYTES)))
                .route("/upload/status/:transfer_id", get(chunked_upload_status))
                .route("/upload/chunk/:transfer_id/:chunk_index", post(upload_chunk).layer(DefaultBodyLimit::max(UPLOAD_CHUNK_BYTES)))
                .route("/upload/finish/:transfer_id", post(finish_chunked_upload).layer(DefaultBodyLimit::max(MAX_AUTH_REQUEST_BYTES)))
                .route("/upload/cancel/:transfer_id", delete(cancel_chunked_upload))
                .route("/files", get(list_pc_files))
                .route("/download-ticket/:id", post(create_download_ticket))
                .route("/download/:id", get(download_pc_file))
                .route("/clipboard", get(get_clipboard).post(set_clipboard).layer(DefaultBodyLimit::max(MAX_CLIPBOARD_REQUEST_BYTES)))
                .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
                .with_state(state);

            if let Err(error) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            ).with_graceful_shutdown(async move {
                server_shutdown.cancelled().await;
            }).await {
                let message = format!("El servidor local se ha detenido: {}", error);
                eprintln!("AetherDrop: {}", message);
                *status.write().await = ServerStatus::Failed(message);
                let daemon = mdns_service.lock().ok().and_then(|slot| slot.as_ref().cloned());
                if let Some(daemon) = daemon {
                    let _ = daemon.shutdown();
                }
            }
        });
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let default_dir = dirs::download_dir().unwrap_or_else(|| PathBuf::from("."));
    let pin = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));

    let state = AppState {
        save_dir: Arc::new(RwLock::new(default_dir)),
        pc_files: Arc::new(RwLock::new(Vec::new())),
        pin,
        trusted_devices: Arc::new(RwLock::new(Vec::new())),
        clipboard_text: Arc::new(RwLock::new(String::new())),
        session_tokens: Arc::new(RwLock::new(HashMap::new())),
        auth_failures: Arc::new(RwLock::new(HashMap::new())),
        upload_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOADS)),
        download_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS)),
        pending_upload_slots: Arc::new(Semaphore::new(MAX_PENDING_UPLOADS)),
        pending_uploads: Arc::new(RwLock::new(HashMap::new())),
        reserved_upload_bytes: Arc::new(AtomicU64::new(0)),
        download_tickets: Arc::new(RwLock::new(HashMap::new())),
        server_status: Arc::new(RwLock::new(ServerStatus::Starting)),
        server_shutdown: CancellationToken::new(),
        mdns_daemon: Arc::new(std::sync::Mutex::new(None)),
    };

    start_local_server(state.clone());
    let shutdown_token = state.server_shutdown.clone();
    let mdns_daemon = state.mdns_daemon.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(state)
        .on_window_event(move |_window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed) {
                shutdown_token.cancel();
                let daemon = mdns_daemon.lock().ok().and_then(|slot| slot.as_ref().cloned());
                if let Some(daemon) = daemon {
                    let _ = daemon.shutdown();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_connection_info,
            set_save_directory,
            share_pc_file,
            remove_pc_file,
            get_shared_files,
            get_trusted_devices,
            revoke_trusted_device
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
