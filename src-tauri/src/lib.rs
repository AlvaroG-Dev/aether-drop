use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Multipart, Path, State},
    middleware::{self, Next},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use futures_util::TryStreamExt;
use local_ip_address::local_ip;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::sync::Arc;
use std::collections::HashMap;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{RwLock, Semaphore};
use tokio_util::{io::ReaderStream, sync::CancellationToken};

use base64::{engine::general_purpose, Engine as _};
use std::io::Cursor;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use arboard::Clipboard;

const MAX_UPLOAD_REQUEST_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_UPLOAD_FILE_BYTES: u64 = MAX_UPLOAD_REQUEST_BYTES as u64 - 1024 * 1024;
const MAX_UPLOAD_FILES: usize = 32;
const MAX_CONCURRENT_UPLOADS: usize = 3;
const MAX_SHARED_FILES: usize = 256;
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;
const MAX_TRACKED_AUTH_IPS: usize = 1024;
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
struct AuthFailureState {
    window_started: Instant,
    attempts: u32,
    blocked_until: Option<Instant>,
}

#[derive(Serialize)]
struct UploadReceipt {
    filename: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct UploadResponse {
    files: Vec<UploadReceipt>,
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

    let my_ip = local_ip().map_err(|e| format!("No se pudo detectar una dirección de red: {}", e))?;
    let host = match my_ip {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{}]", address),
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

fn is_allowed_local_authority(authority: &str) -> bool {
    let Ok(parsed) = authority.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    let host = parsed.host().trim_matches(['[', ']']).trim_end_matches('.');
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
    // The listener is exposed to the LAN. Reject arbitrary Host values to reduce
    // DNS-rebinding access, and reject browser cross-origin requests when Origin exists.
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
    if request.uri().path() == "/" || request.uri().path() == "/auth" || request.uri().path() == "/mobile.js" {
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
            devices.push(payload.device_id.clone());
        }
    }
    let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let record = SessionRecord {
        device_id: payload.device_id,
        expires_at: now + SESSION_TTL,
        cancellation: CancellationToken::new(),
    };
    state.session_tokens.write().await.insert(token.clone(), record);
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
            !name.is_empty()
                && *name != "."
                && *name != ".."
                && name.len() <= 240
                && !name.chars().any(char::is_control)
                && !name.ends_with(' ')
                && !name.ends_with('.')
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
        auth_rate_limited, content_disposition_value, is_allowed_local_authority,
        origin_matches_authority, record_auth_failure, sanitize_upload_filename,
        AuthFailureState, MAX_AUTH_FAILURES,
    };
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Instant;

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
        assert_eq!(sanitize_upload_filename(&"x".repeat(241)), None);
    }

    #[test]
    fn content_disposition_preserves_unicode_filename_metadata() {
        let value = content_disposition_value("foto ñ.png");
        assert!(value.starts_with("attachment; filename=\"foto _.png\"; filename*=UTF-8''"));
        assert!(value.contains("%C3%B1"));
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
    Path(id): Path<String>,
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

async fn handle_upload(
    State(state): State<AppState>,
    Extension(session): Extension<AuthorizedSession>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, &'static str)> {
    let _permit = state.upload_slots.clone().try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "Demasiadas transferencias simultáneas."))?;
    let mut received_fields = 0usize;
    let mut total_bytes = 0u64;
    let mut receipts = Vec::new();

    loop {
        let next_field = tokio::select! {
            _ = state.server_shutdown.cancelled() => {
                return Err((StatusCode::SERVICE_UNAVAILABLE, "AetherDrop se está cerrando."));
            }
            _ = session.cancellation.cancelled() => {
                return Err((StatusCode::UNAUTHORIZED, "El dispositivo ha sido desvinculado."));
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(session.expires_at)) => {
                return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado."));
            }
            result = multipart.next_field() => result,
        };
        let mut field = match next_field {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => return Err((StatusCode::BAD_REQUEST, "La petición multipart no es válida.")),
        };
        received_fields += 1;
        if received_fields > MAX_UPLOAD_FILES {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "La transferencia supera el límite de archivos."));
        }

        let supplied_name = field.file_name()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("archivo_{}.bin", uuid::Uuid::new_v4()));
        let Some(file_name) = sanitize_upload_filename(&supplied_name) else {
            return Err((StatusCode::BAD_REQUEST, "El nombre del archivo no es válido."));
        };

        let dir = state.save_dir.read().await.clone();
        tokio::fs::create_dir_all(&dir).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo preparar la carpeta de destino."))?;
        let filepath = dir.join(&file_name);
        let temp_path = dir.join(format!(".aetherdrop-upload-{}.part", uuid::Uuid::new_v4()));

        // Do not clean up a path if create_new fails: an existing file may own it.
        let temp_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo crear el archivo temporal."))?;

        let received: Result<UploadReceipt, (StatusCode, &'static str)> = async {
            let mut output = temp_file;
            let mut stream_hash = Sha256::new();
            let mut file_size = 0u64;
            loop {
                let next_chunk = tokio::select! {
                    _ = state.server_shutdown.cancelled() => {
                        return Err((StatusCode::SERVICE_UNAVAILABLE, "AetherDrop se está cerrando."));
                    }
                    _ = session.cancellation.cancelled() => {
                        return Err((StatusCode::UNAUTHORIZED, "El dispositivo ha sido desvinculado."));
                    }
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(session.expires_at)) => {
                        return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado."));
                    }
                    result = field.try_next() => result,
                };
                let chunk = match next_chunk {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break,
                    Err(_) => return Err((StatusCode::BAD_REQUEST, "La subida se ha interrumpido o el contenido no es válido.")),
                };
                let chunk_size = chunk.len() as u64;
                if file_size.saturating_add(chunk_size) > MAX_UPLOAD_FILE_BYTES {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, "El archivo supera el límite permitido."));
                }
                if total_bytes.saturating_add(chunk_size) > MAX_UPLOAD_REQUEST_BYTES as u64 {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, "La petición supera el límite total permitido."));
                }
                output.write_all(&chunk).await
                    .map_err(|_| (StatusCode::INSUFFICIENT_STORAGE, "No se pudo escribir el archivo; comprueba el espacio disponible."))?;
                stream_hash.update(&chunk);
                file_size += chunk_size;
                total_bytes += chunk_size;
            }

            output.flush().await
                .map_err(|_| (StatusCode::INSUFFICIENT_STORAGE, "No se pudo finalizar la escritura del archivo."))?;
            output.sync_all().await
                .map_err(|_| (StatusCode::INSUFFICIENT_STORAGE, "No se pudo sincronizar el archivo con el disco."))?;
            drop(output);

            let received_digest = format!("{:x}", stream_hash.finalize());
            let mut verification_file = tokio::fs::File::open(&temp_path).await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "No se pudo verificar el archivo guardado."))?;
            let mut verification_hash = Sha256::new();
            let mut verified_size = 0u64;
            let mut buffer = vec![0u8; 128 * 1024];
            loop {
                let count = verification_file.read(&mut buffer).await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Falló la lectura de verificación del archivo."))?;
                if count == 0 {
                    break;
                }
                verified_size += count as u64;
                verification_hash.update(&buffer[..count]);
            }
            let verified_digest = format!("{:x}", verification_hash.finalize());
            if verified_size != file_size || verified_digest != received_digest {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "La verificación de integridad del archivo ha fallado."));
            }

            Ok(UploadReceipt {
                filename: file_name.clone(),
                size_bytes: file_size,
                sha256: verified_digest,
            })
        }.await;

        let receipt = match received {
            Ok(receipt) => receipt,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(error);
            }
        };
        // This endpoint accepts exactly one file per request. The mobile client
        // batches multiple user selections as independent requests, allowing precise
        // per-file receipts and preventing a late malformed field from partially
        // succeeding under a single HTTP request.
        let next_field = tokio::select! {
            _ = state.server_shutdown.cancelled() => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err((StatusCode::SERVICE_UNAVAILABLE, "AetherDrop se está cerrando."));
            }
            _ = session.cancellation.cancelled() => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err((StatusCode::UNAUTHORIZED, "El dispositivo ha sido desvinculado."));
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(session.expires_at)) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err((StatusCode::UNAUTHORIZED, "La sesión ha caducado."));
            }
            result = multipart.next_field() => result,
        };
        match next_field {
            Ok(None) => {}
            Ok(Some(_)) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err((StatusCode::BAD_REQUEST, "Envía un archivo por petición; el cliente puede hacer varias peticiones seguidas."));
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err((StatusCode::BAD_REQUEST, "La petición multipart contiene datos adicionales no válidos."));
            }
        }

        if !session_is_authorized(&state, &session).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err((StatusCode::UNAUTHORIZED, "El dispositivo ha sido desvinculado o la sesión ha caducado."));
        }

        match tokio::fs::hard_link(&temp_path, &filepath).await {
            Ok(()) => {
                if let Err(error) = tokio::fs::remove_file(&temp_path).await {
                    eprintln!("AetherDrop: no se pudo retirar el temporal {:?}: {}", temp_path, error);
                }
                receipts.push(receipt);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err((StatusCode::CONFLICT, "Ya existe un archivo con ese nombre. Cambia el nombre y vuelve a intentarlo."));
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "El sistema de archivos no permite publicar el archivo de forma atómica."));
            }
        }
    }

    if received_fields == 0 {
        return Err((StatusCode::BAD_REQUEST, "No se ha recibido ningún archivo."));
    }
    Ok(Json(UploadResponse { files: receipts }))
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
    Path(id): Path<String>,
) -> axum::response::Response {
    // Release the shared file-list lock before opening/streaming the file.
    let path = {
        let files = state.pc_files.read().await;
        files.iter().find(|(file_id, _)| file_id == &id).map(|(_, path)| path.clone())
    };
    let Some(path) = path else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let file = match tokio::fs::File::open(&path).await {
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
    let stream = ReaderStream::new(file).and_then(move |chunk| {
        let state = stream_state.clone();
        let session = stream_session.clone();
        async move {
            if !session_is_authorized(&state, &session).await {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Session revoked"));
            }
            Ok::<Bytes, std::io::Error>(chunk)
        }
    });

    match axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Disposition", disposition)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", metadata.len().to_string())
        .header("X-Content-Type-Options", "nosniff")
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
            Ok(()) => {
                if let Ok(mut slot) = state.mdns_daemon.lock() {
                    *slot = Some(daemon);
                }
            }
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
                eprintln!("AetherDrop: no se pudo crear el runtime HTTP: {}", error);
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
                            let directory = maintenance_state.save_dir.read().await.clone();
                            cleanup_stale_uploads(&directory).await;
                        }
                    }
                }
            });

            let status = state.server_status.clone();
            let server_shutdown = state.server_shutdown.clone();
            let app = Router::new()
                .route("/", get(serve_ui))
                .route("/mobile.js", get(serve_mobile_js))
                .route("/auth", post(handle_auth))
                .route("/session", get(check_session))
                .route("/upload", post(handle_upload))
                .route("/files", get(list_pc_files))
                .route("/download-ticket/:id", post(create_download_ticket))
                .route("/download/:id", get(download_pc_file))
                .route("/clipboard", get(get_clipboard).post(set_clipboard))
                .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
                .with_state(state)
                .layer(DefaultBodyLimit::max(MAX_UPLOAD_REQUEST_BYTES));

            if let Err(error) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            ).with_graceful_shutdown(async move {
                server_shutdown.cancelled().await;
            }).await {
                let message = format!("El servidor local se ha detenido: {}", error);
                eprintln!("AetherDrop: {}", message);
                *status.write().await = ServerStatus::Failed(message);
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
