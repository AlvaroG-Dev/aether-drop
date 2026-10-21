use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    middleware::{self, Next},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures_util::TryStreamExt;
use local_ip_address::local_ip;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::collections::HashMap;
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

use base64::{engine::general_purpose, Engine as _};
use std::io::Cursor;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use arboard::Clipboard;

#[derive(Clone)]
struct AppState {
    save_dir: Arc<RwLock<PathBuf>>,
    pc_files: Arc<RwLock<Vec<(String, PathBuf)>>>,
    pin: String,
    trusted_devices: Arc<RwLock<Vec<String>>>,
    clipboard_text: Arc<RwLock<String>>,
    session_tokens: Arc<RwLock<HashMap<String, String>>>,
    auth_failures: Arc<RwLock<(u32, std::time::Instant)>>,
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
    let my_ip = local_ip().map_err(|e| e.to_string())?;
    let url = format!("http://{}:8080", my_ip);

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
    let mut dir = state.save_dir.write().await;
    *dir = PathBuf::from(&path);
    Ok(path)
}

#[tauri::command]
async fn share_pc_file(path: String, state: tauri::State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let path_buf = PathBuf::from(&path);
    if path_buf.exists() {
        let id = uuid::Uuid::new_v4().to_string();
        let mut files = state.pc_files.write().await;
        files.push((id, path_buf));
    }
    get_shared_files_internal(&state).await
}

#[tauri::command]
async fn remove_pc_file(id: String, state: tauri::State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let mut files = state.pc_files.write().await;
    files.retain(|(file_id, _)| file_id != &id);
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
    let mut devices = state.trusted_devices.write().await;
    devices.retain(|d| d != &device_id);
    Ok(devices.clone())
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
async fn serve_ui() -> axum::response::Html<&'static str> {
    axum::response::Html(r###"
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AetherDrop - Secure PWA</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <style>
              .transfer-bridge{position:relative;min-height:118px;overflow:hidden;border:1px solid rgba(71,85,105,.55);border-radius:22px;background:radial-gradient(ellipse at center,rgba(56,189,248,.13),rgba(2,6,23,.2) 70%)}
              .transfer-device{position:absolute;top:24px;width:46px;height:46px;border-radius:15px;display:grid;place-items:center;font-size:21px;background:linear-gradient(145deg,#0f172a,#1e293b);border:1px solid rgba(125,211,252,.35);z-index:2}
              .transfer-device.phone{left:calc(50% - 104px)}.transfer-device.pc{right:calc(50% - 104px)}
              .transfer-orb{position:absolute;left:50%;top:47px;transform:translate(-50%,-50%);width:34px;height:34px;border-radius:50%;display:grid;place-items:center;color:white;background:linear-gradient(135deg,#38bdf8,#6366f1);box-shadow:0 0 20px rgba(56,189,248,.35);z-index:2}
              .transfer-line{position:absolute;left:calc(50% - 82px);right:calc(50% - 82px);top:47px;height:2px;background:linear-gradient(90deg,rgba(56,189,248,.08),rgba(56,189,248,.65),rgba(129,140,248,.65),rgba(129,140,248,.08))}
              .transfer-packet{position:absolute;left:calc(50% - 75px);top:44px;width:7px;height:7px;border-radius:50%;background:#7dd3fc;box-shadow:0 0 12px #38bdf8;opacity:0}
              .transfer-bridge.transferring .transfer-packet{opacity:1;animation:transfer-flight 1.3s linear infinite}
              .transfer-bridge.transferring .transfer-packet.p2{animation-delay:.43s}.transfer-bridge.transferring .transfer-packet.p3{animation-delay:.86s}
              .transfer-bridge.paired .transfer-orb,.transfer-bridge.transferring .transfer-orb{animation:transfer-glow 1.8s ease-in-out infinite}
              .transfer-caption{position:absolute;bottom:11px;left:8px;right:8px;text-align:center;font-size:11px;color:#cbd5e1}
              @keyframes transfer-flight{0%{transform:translateX(0) scale(.65);opacity:0}15%{opacity:1}85%{opacity:1}100%{transform:translateX(150px) scale(1.15);opacity:0}}
              @keyframes transfer-glow{0%,100%{box-shadow:0 0 15px rgba(56,189,248,.3)}50%{box-shadow:0 0 30px rgba(56,189,248,.8)}}
              @media(prefers-reduced-motion:reduce){.transfer-bridge *{animation:none!important}.transfer-packet{display:none}}
            </style>
        </head>
        <body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col items-center justify-center p-4">
            
            <!-- Modal de PIN -->
            <div id="pinModal" class="fixed inset-0 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4 z-50">
                <div class="bg-slate-900 border border-slate-800 p-6 rounded-3xl w-full max-w-sm text-center shadow-2xl">
                    <h2 class="text-xl font-bold text-sky-400 mb-2">Autenticación Requerida</h2>
                    <p class="text-xs text-slate-400 mb-4">Introduce el PIN de 6 dígitos que aparece en la pantalla de tu PC.</p>
                    <input type="password" id="pinInput" maxlength="6" inputmode="numeric" autocomplete="one-time-code" placeholder="••••••" class="w-full bg-slate-950 border border-slate-700 text-center text-2xl tracking-widest py-3 rounded-xl mb-4 text-white focus:outline-none focus:border-sky-500">
                    <button onclick="verifyPin()" class="w-full bg-sky-600 hover:bg-sky-500 text-white font-semibold py-3 rounded-xl transition shadow-lg shadow-sky-900/30">Conectar</button>
                    <p id="pinError" class="text-xs text-rose-400 mt-3 hidden">PIN incorrecto.</p>
                </div>
            </div>

            <!-- App Principal -->
            <div id="mainApp" class="w-full max-w-md bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-3xl shadow-2xl p-6 text-center hidden">
                <div class="flex items-center justify-between mb-6">
                    <div>
                        <h1 class="text-2xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-sky-400 to-indigo-400">AetherDrop</h1>
                        <p class="text-[11px] text-slate-400">Dispositivo vinculado</p>
                    </div>
                    <span class="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">● En línea</span>
                </div>

                <div id="mobileBridge" class="transfer-bridge mb-6" aria-label="Conexión visual entre móvil y ordenador">
                    <div class="transfer-line"></div>
                    <span class="transfer-packet"></span><span class="transfer-packet p2"></span><span class="transfer-packet p3"></span>
                    <div class="transfer-device phone" aria-hidden="true">▯</div>
                    <div class="transfer-orb" aria-hidden="true">✦</div>
                    <div class="transfer-device pc" aria-hidden="true">▣</div>
                    <div id="bridgeCaption" class="transfer-caption">Vincula tu móvil con el ordenador</div>
                </div>

                <!-- Enviar al PC (Con opción Múltiple) -->
                <div class="mb-6">
                    <label class="block w-full bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white font-semibold py-3.5 px-4 rounded-2xl cursor-pointer transition shadow-lg shadow-indigo-900/30">
                        Enviar Archivos o Vídeos
                        <input type="file" id="fileInput" multiple class="hidden" onchange="uploadFiles()">
                    </label>
                    
                    <!-- Barra de progreso -->
                    <div id="progressContainer" class="mt-4 hidden text-left">
                        <div class="flex justify-between items-center text-xs text-slate-300 mb-1">
                            <span id="progressStatus" class="truncate max-w-[220px]">Subiendo...</span>
                            <span id="progressPercent" class="font-bold text-sky-400">0%</span>
                        </div>
                        <div class="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                            <div id="progressBar" class="bg-gradient-to-r from-sky-500 to-indigo-500 h-2 rounded-full transition-all duration-150" style="width: 0%"></div>
                        </div>
                    </div>

                    <!-- Notificaciones de estado / Toast -->
                    <div id="toast" class="mt-3 text-xs font-semibold p-2.5 rounded-xl hidden transition-all"></div>
                </div>

                <!-- Portapapeles Sincronizado -->
                <div class="mb-6 bg-slate-950/60 p-4 rounded-2xl border border-slate-800/80 text-left">
                    <div class="flex justify-between items-center mb-2">
                        <span class="text-xs font-bold text-slate-300 uppercase tracking-wider">Portapapeles Compartido</span>
                        <button onclick="syncClipboard()" class="text-sky-400 hover:text-sky-300 text-xs font-medium">Actualizar</button>
                    </div>
                    <textarea id="clipboardText" rows="2" placeholder="Escribe o pega texto aquí para sincronizar con el PC..." class="w-full bg-slate-900 border border-slate-800 rounded-xl p-2.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 resize-none"></textarea>
                    <button onclick="sendClipboard()" class="mt-2 w-full bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs py-2 rounded-xl font-medium transition">Enviar al Portapapeles del PC</button>
                </div>

                <hr class="border-slate-800/80 mb-6">

                <!-- Descargar desde PC -->
                <div class="text-left">
                    <h2 class="text-xs font-bold text-slate-300 mb-3 uppercase tracking-wider">Archivos desde el PC</h2>
                    <div id="fileList" class="space-y-2 max-h-40 overflow-y-auto pr-1">
                        <p class="text-xs text-slate-500 text-center py-2">No hay archivos disponibles.</p>
                    </div>
                </div>
            </div>

            <script>
                let deviceId = localStorage.getItem('aether_device_id');
                if (!deviceId) {
                    deviceId = 'dev_' + Math.random().toString(36).substring(2, 10);
                    localStorage.setItem('aether_device_id', deviceId);
                }

                function setBridgeState(state, caption) {
                    const bridge = document.getElementById('mobileBridge');
                    bridge.classList.remove('paired', 'transferring');
                    if (state) bridge.classList.add(state);
                    document.getElementById('bridgeCaption').textContent = caption;
                }

                function authHeaders() {
                    const token = localStorage.getItem('aether_token');
                    return token ? { 'Authorization': `Bearer ${token}` } : {};
                }

                async function checkAuth() {
                    const token = localStorage.getItem('aether_token');
                    if (!token || token === 'true') {
                        localStorage.removeItem('aether_token');
                        return;
                    }
                    try {
                        const response = await fetch('/session', { headers: authHeaders() });
                        if (!response.ok) throw new Error('Session expired');
                        document.getElementById('pinModal').classList.add('hidden');
                        document.getElementById('mainApp').classList.remove('hidden');
                        setBridgeState('paired', 'Móvil vinculado · listo para transferir');
                        startSync();
                    } catch (_) {
                        localStorage.removeItem('aether_token');
                    }
                }

                async function verifyPin() {
                    const pinInput = document.getElementById('pinInput');
                    const pinError = document.getElementById('pinError');
                    const pin = pinInput.value.trim();

                    if (pin.length !== 6 || !/^\d{6}$/.test(pin)) {
                        pinError.innerText = "El PIN debe tener 6 dígitos.";
                        pinError.classList.remove('hidden');
                        return;
                    }

                    try {
                        const res = await fetch('/auth', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ pin: pin, device_id: deviceId })
                        });

                        if (res.ok) {
                            const authData = await res.json();
                            localStorage.setItem('aether_token', authData.token);
                            pinError.classList.add('hidden');
                            document.getElementById('pinModal').classList.add('hidden');
                            document.getElementById('mainApp').classList.remove('hidden');
                            setBridgeState('paired', 'Móvil vinculado · listo para transferir');
                            startSync();
                        } else {
                            pinError.innerText = "PIN incorrecto.";
                            pinError.classList.remove('hidden');
                        }
                    } catch (e) {
                        pinError.innerText = "Error de conexión con el servidor.";
                        pinError.classList.remove('hidden');
                    }
                }

                function escapeHtml(value) {
                    const element = document.createElement('span');
                    element.textContent = String(value);
                    return element.innerHTML;
                }

                function showToast(message, isSuccess) {
                    const toast = document.getElementById('toast');
                    toast.innerText = message;
                    toast.className = `mt-3 text-xs font-semibold p-2.5 rounded-xl border ${
                        isSuccess 
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                        : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                    }`;
                    toast.classList.remove('hidden');
                    setTimeout(() => toast.classList.add('hidden'), 5000);
                }

                function uploadFiles() {
                    const input = document.getElementById('fileInput');
                    if (input.files.length === 0) return;
                    
                    const files = Array.from(input.files);
                    const formData = new FormData();
                    files.forEach(file => formData.append('file', file));

                    const progressContainer = document.getElementById('progressContainer');
                    const progressStatus = document.getElementById('progressStatus');
                    const progressPercent = document.getElementById('progressPercent');
                    const progressBar = document.getElementById('progressBar');

                    setBridgeState('transferring', 'Enviando archivos al ordenador…');
                    progressContainer.classList.remove('hidden');
                    progressStatus.innerText = files.length > 1 ? `Subiendo ${files.length} archivos...` : `Subiendo ${files[0].name}...`;
                    progressBar.style.width = '0%';
                    progressPercent.innerText = '0%';

                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/upload', true);
                    const token = localStorage.getItem('aether_token');
                    if (token && token !== 'true') xhr.setRequestHeader('Authorization', `Bearer ${token}`);

                    xhr.upload.onprogress = (e) => {
                        if (e.lengthComputable) {
                            const percent = Math.round((e.loaded / e.total) * 100);
                            progressBar.style.width = percent + '%';
                            progressPercent.innerText = percent + '%';
                        }
                    };

                    xhr.onload = () => {
                        progressContainer.classList.add('hidden');
                        if (xhr.status === 200) {
                            showToast(files.length > 1 ? "¡Todos los archivos enviados con éxito al PC!" : "¡Archivo enviado con éxito al PC!", true);
                            input.value = "";
                            setBridgeState('paired', 'Transferencia completada');
                        } else {
                            showToast("Error en el servidor al guardar el archivo.", false);
                            setBridgeState('paired', 'No se pudo completar la transferencia');
                        }
                    };

                    xhr.onerror = () => {
                        progressContainer.classList.add('hidden');
                        showToast("Error de conexión con la red local.", false);
                        setBridgeState('paired', 'Conexión interrumpida');
                    };

                    xhr.send(formData);
                }

                async function fetchFiles() {
                    try {
                        const res = await fetch('/files', { headers: authHeaders() });
                        const files = await res.json();
                        const list = document.getElementById('fileList');
                        if (files.length === 0) {
                            list.innerHTML = '<p class="text-xs text-slate-500 text-center py-2">No hay archivos disponibles.</p>';
                            return;
                        }
                        list.innerHTML = files.map(f => `
                            <div class="flex items-center justify-between bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                                <span class="text-xs truncate max-w-[200px] text-slate-200">${escapeHtml(f.name)}</span>
                                <a href="/download/${f.id}" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-3 py-1.5 rounded-lg font-medium transition shadow">Descargar</a>
                            </div>
                        `).join('');
                    } catch(e) {}
                }

                async function syncClipboard() {
                    try {
                        const res = await fetch('/clipboard', { headers: authHeaders() });
                        const data = await res.json();
                        if (data.text !== undefined) {
                            document.getElementById('clipboardText').value = data.text;
                        }
                    } catch(e) {}
                }

                async function sendClipboard() {
                    const text = document.getElementById('clipboardText').value;
                    await fetch('/clipboard', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', ...authHeaders() },
                        body: JSON.stringify({ text })
                    });
                    showToast("Portapapeles enviado al PC", true);
                }

                function startSync() {
                    setInterval(fetchFiles, 3000);
                    setInterval(syncClipboard, 3000);
                    fetchFiles();
                    syncClipboard();
                }

                checkAuth();
            </script>
        </body>
        </html>
    "###)
}


async fn require_auth(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    // The landing page and PIN exchange are the only unauthenticated routes.
    if request.uri().path() == "/" || request.uri().path() == "/auth" {
        return next.run(request).await;
    }
    let token = request.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let authorized = if let Some(token) = token {
        { let sessions = state.session_tokens.read().await; if let Some(device_id) = sessions.get(token) { state.trusted_devices.read().await.contains(device_id) } else { false } }
    } else {
        false
    };
    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

async fn check_session() -> StatusCode { StatusCode::OK }

async fn handle_auth(State(state): State<AppState>, Json(payload): Json<PinRequest>) -> impl IntoResponse {
    {
        let mut failures = state.auth_failures.write().await;
        if failures.1.elapsed() >= std::time::Duration::from_secs(60) {
            *failures = (0, std::time::Instant::now());
        }
        if failures.0 >= 10 {
            return (StatusCode::TOO_MANY_REQUESTS, "Too many PIN attempts; wait one minute").into_response();
        }
        if payload.pin != state.pin || payload.device_id.len() > 64 || payload.device_id.is_empty() || !payload.device_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            failures.0 += 1;
            return StatusCode::UNAUTHORIZED.into_response();
        }
        failures.0 = 0;
        failures.1 = std::time::Instant::now();
    }
    let mut devices = state.trusted_devices.write().await;
    if !devices.contains(&payload.device_id) {
        devices.push(payload.device_id.clone());
    }
    drop(devices);
    // Issue an unguessable bearer token; a client-side boolean is never authentication.
    let token = uuid::Uuid::new_v4().to_string() + &uuid::Uuid::new_v4().to_string();
    state.session_tokens.write().await.insert(token.clone(), payload.device_id.clone());
    (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
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
    let fallback = fallback.trim_matches([' ', '.']);
    let fallback = if fallback.is_empty() { "download" } else { fallback };

    let mut encoded = String::new();
    for byte in filename.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(*byte, b'!' | b'#' | b'

// Streaming multipart receiver. Malformed multipart envelopes must never look successful.
async fn handle_upload(State(state): State<AppState>, mut multipart: Multipart) -> (StatusCode, &'static str) {
    let mut received_fields = 0usize;
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid multipart request"),
        };
        received_fields += 1;

        let supplied_name = field.file_name()
            .map(|s| s.replace('\\', "/"))
            .unwrap_or_else(|| format!("archivo_{}.bin", uuid::Uuid::new_v4()));
        // Never trust a client-provided path. Keep only a short, plain filename.
        let Some(file_name) = sanitize_upload_filename(&supplied_name) else {
            return (StatusCode::BAD_REQUEST, "Invalid filename");
        };

        let dir = state.save_dir.read().await.clone();
        if tokio::fs::create_dir_all(&dir).await.is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Cannot prepare destination");
        }
        let filepath = dir.join(&file_name);

        // create_new prevents an upload from silently overwriting an existing file.
        let mut file = match tokio::fs::OpenOptions::new().write(true).create_new(true).open(&filepath).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return (StatusCode::CONFLICT, "File already exists");
            }
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Cannot create destination file"),
        };
        loop {
            match field.try_next().await {
                Ok(Some(chunk)) => {
                    if file.write_all(&chunk).await.is_err() {
                        let _ = tokio::fs::remove_file(&filepath).await;
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed writing upload");
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = tokio::fs::remove_file(&filepath).await;
                    return (StatusCode::BAD_REQUEST, "Invalid upload stream");
                }
            }
        }
        if file.flush().await.is_err() {
            let _ = tokio::fs::remove_file(&filepath).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed finalizing upload");
        }
    }
    if received_fields == 0 {
        return (StatusCode::BAD_REQUEST, "No files supplied");
    }
    (StatusCode::OK, "OK")
}

async fn list_pc_files(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let files = state.pc_files.read().await;
    let list: Vec<_> = files.iter().map(|(id, path)| {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        serde_json::json!({ "id": id, "name": name })
    }).collect();
    Json(list)
}

async fn download_pc_file(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let files = state.pc_files.read().await;
    if let Some((_, path)) = files.iter().find(|(file_id, _)| file_id == &id) {
        if let Ok(bytes) = tokio::fs::read(path).await {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            let disposition = content_disposition_value(&filename);
            if let Ok(response) = axum::response::Response::builder()
                .header("Content-Disposition", disposition)
                .body(axum::body::Body::from(bytes))
            {
                return response;
            }
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    axum::http::StatusCode::NOT_FOUND.into_response()
}

async fn get_clipboard(State(state): State<AppState>) -> Json<serde_json::Value> {
    let text = state.clipboard_text.read().await.clone();
    Json(serde_json::json!({ "text": text }))
}

async fn set_clipboard(State(state): State<AppState>, Json(payload): Json<ClipboardRequest>) -> &'static str {
    let mut cb = state.clipboard_text.write().await;
    *cb = payload.text.clone();
    if let Ok(mut clipboard) = Clipboard::new() {
        let _ = clipboard.set_text(payload.text);
    }
    "OK"
}

fn start_local_server(state: AppState) {
    std::thread::spawn(|| {
        if let Ok(daemon) = ServiceDaemon::new() {
            let ip = local_ip().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
            let service_info = ServiceInfo::new(
                "_aetherdrop._tcp.local.",
                "AetherDropPC",
                "aetherdrop.local.",
                ip.to_string().as_str(),
                8080,
                None,
            ).unwrap();
            let _ = daemon.register(service_info);
        }
    });

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let app = Router::new()
                .route("/", get(serve_ui))
                .route("/auth", post(handle_auth))
                .route("/session", get(check_session))
                .route("/upload", post(handle_upload))
                .route("/files", get(list_pc_files))
                .route("/download/:id", get(download_pc_file))
                .route("/clipboard", get(get_clipboard).post(set_clipboard))
                .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
                .with_state(state)
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024));

            let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            let _ = axum::serve(listener, app).await;
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
        auth_failures: Arc::new(RwLock::new((0, std::time::Instant::now()))),
    };

    start_local_server(state.clone());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(state)
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
} | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
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
    use super::{content_disposition_value, sanitize_upload_filename};

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
    fn content_disposition_encodes_unicode_and_blocks_header_injection() {
        let value = content_disposition_value("foto \"ñ\r\nX-Evil: yes.png");
        assert!(value.starts_with("attachment; filename=\"foto ___X-Evil_ yes.png\"; filename*=UTF-8''"));
        assert!(!value.contains("\r"));
        assert!(!value.contains("\n"));
        assert!(value.contains("%C3%B1"));
    }
}

// Receptor streaming multipart compatible con múltiples archivos en simultáneo
async fn handle_upload(State(state): State<AppState>, mut multipart: Multipart) -> (StatusCode, &'static str) {
    while let Ok(Some(mut field)) = multipart.next_field().await {
        let supplied_name = field.file_name()
            .map(|s| s.replace('\\', "/"))
            .unwrap_or_else(|| format!("archivo_{}.bin", uuid::Uuid::new_v4()));
        // Never trust a client-provided path. Keep only a short, plain filename.
        let Some(file_name) = sanitize_upload_filename(&supplied_name) else {
            return (StatusCode::BAD_REQUEST, "Invalid filename");
        };

        let dir = state.save_dir.read().await.clone();
        if tokio::fs::create_dir_all(&dir).await.is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Cannot prepare destination");
        }
        let filepath = dir.join(&file_name);

        // create_new prevents an upload from silently overwriting an existing file.
        let mut file = match tokio::fs::OpenOptions::new().write(true).create_new(true).open(&filepath).await {
            Ok(file) => file,
            Err(_) => return (StatusCode::CONFLICT, "File already exists or cannot be created"),
        };
        loop {
            match field.try_next().await {
                Ok(Some(chunk)) => {
                    if file.write_all(&chunk).await.is_err() {
                        let _ = tokio::fs::remove_file(&filepath).await;
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed writing upload");
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = tokio::fs::remove_file(&filepath).await;
                    return (StatusCode::BAD_REQUEST, "Invalid upload stream");
                }
            }
        }
        if file.flush().await.is_err() {
            let _ = tokio::fs::remove_file(&filepath).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed finalizing upload");
        }
    }
    (StatusCode::OK, "OK")
}

async fn list_pc_files(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let files = state.pc_files.read().await;
    let list: Vec<_> = files.iter().map(|(id, path)| {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        serde_json::json!({ "id": id, "name": name })
    }).collect();
    Json(list)
}

async fn download_pc_file(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let files = state.pc_files.read().await;
    if let Some((_, path)) = files.iter().find(|(file_id, _)| file_id == &id) {
        if let Ok(bytes) = tokio::fs::read(path).await {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            return axum::response::Response::builder()
                .header("Content-Disposition", format!("attachment; filename=\"{}\"", filename))
                .body(axum::body::Body::from(bytes))
                .unwrap();
        }
    }
    axum::http::StatusCode::NOT_FOUND.into_response()
}

async fn get_clipboard(State(state): State<AppState>) -> Json<serde_json::Value> {
    let text = state.clipboard_text.read().await.clone();
    Json(serde_json::json!({ "text": text }))
}

async fn set_clipboard(State(state): State<AppState>, Json(payload): Json<ClipboardRequest>) -> &'static str {
    let mut cb = state.clipboard_text.write().await;
    *cb = payload.text.clone();
    if let Ok(mut clipboard) = Clipboard::new() {
        let _ = clipboard.set_text(payload.text);
    }
    "OK"
}

fn start_local_server(state: AppState) {
    std::thread::spawn(|| {
        if let Ok(daemon) = ServiceDaemon::new() {
            let ip = local_ip().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
            let service_info = ServiceInfo::new(
                "_aetherdrop._tcp.local.",
                "AetherDropPC",
                "aetherdrop.local.",
                ip.to_string().as_str(),
                8080,
                None,
            ).unwrap();
            let _ = daemon.register(service_info);
        }
    });

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let app = Router::new()
                .route("/", get(serve_ui))
                .route("/auth", post(handle_auth))
                .route("/session", get(check_session))
                .route("/upload", post(handle_upload))
                .route("/files", get(list_pc_files))
                .route("/download/:id", get(download_pc_file))
                .route("/clipboard", get(get_clipboard).post(set_clipboard))
                .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
                .with_state(state)
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024));

            let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            let _ = axum::serve(listener, app).await;
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
        auth_failures: Arc::new(RwLock::new((0, std::time::Instant::now()))),
    };

    start_local_server(state.clone());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(state)
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