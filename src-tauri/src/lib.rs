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
                <button onclick="verifyPin()" class="pin-submit">Conectar dispositivo</button>
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
                  <input type="file" id="fileInput" multiple onchange="uploadFiles()">
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
                  <button onclick="sendClipboard()" class="secondary-button">Enviar texto al ordenador</button>
                  <button onclick="syncClipboard()" class="secondary-button" style="margin-top:6px">Actualizar desde el ordenador</button>
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
                    toast.className = 'toast ' + (isSuccess ? 'success' : 'error');
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
                            let detail = (xhr.responseText || '').trim();
                            const known = {
                              400: 'La petición o el nombre del archivo no son válidos.',
                              401: 'La sesión ha caducado. Vuelve a vincular el móvil con el PIN.',
                              409: 'Ya existe un archivo con ese nombre en el PC.',
                              413: 'El archivo o la petición supera el límite permitido.',
                              429: 'Demasiados intentos. Espera un minuto y vuelve a probar.',
                              500: 'El PC no pudo guardar el archivo. Comprueba permisos y espacio disponible.'
                            };
                            if (!detail || detail.length > 240) detail = known[xhr.status] || 'El servidor rechazó la transferencia.';
                            if (xhr.status === 409) detail = 'Ya existe un archivo con ese nombre. Cambia el nombre del archivo y vuelve a intentarlo.';
                            showToast('Error HTTP ' + xhr.status + ': ' + detail, false);
                            setBridgeState('paired', 'No se pudo completar la transferencia');
                        }
                    };

                    xhr.onerror = () => {
                        progressContainer.classList.add('hidden');
                        showToast("No se pudo conectar con el PC. Comprueba la Wi-Fi, el firewall y que AetherDrop siga abierto.", false);
                        setBridgeState('paired', 'Conexión interrumpida');
                    };
                    xhr.onabort = () => {
                        progressContainer.classList.add('hidden');
                        showToast("La subida se canceló antes de terminar. El archivo no se considera transferido.", false);
                        setBridgeState('paired', 'Transferencia cancelada');
                    };

                    xhr.send(formData);
                }

                async function fetchFiles() {
                    try {
                        const res = await fetch('/files', { headers: authHeaders() });
                        const files = await res.json();
                        const list = document.getElementById('fileList');
                        if (files.length === 0) {
                            list.innerHTML = '<p class="mobile-empty">No hay archivos disponibles.</p>';
                            return;
                        }
                        list.innerHTML = files.map(f => `
                            <div class="mobile-file-item">
                                <span class="mobile-file-name">${escapeHtml(f.name)}</span>
                                <a href="/download/${f.id}" class="download-link">Descargar</a>
                            </div>
                        `).join('');
                    } catch(e) {}
                }

                let lastServerClipboard = null;
                let clipboardDirty = false;
                const clipboardField = document.getElementById('clipboardText');
                clipboardField.addEventListener('input', () => {
                    clipboardDirty = clipboardField.value !== lastServerClipboard;
                });

                async function syncClipboard(force = false) {
                    try {
                        const res = await fetch('/clipboard', { headers: authHeaders(), cache: 'no-store' });
                        if (!res.ok) throw new Error('HTTP ' + res.status);
                        const data = await res.json();
                        if (typeof data.text !== 'string') return;
                        if (!force && (clipboardDirty || document.activeElement === clipboardField)) return;
                        if (data.text !== lastServerClipboard || force) {
                            clipboardField.value = data.text;
                            lastServerClipboard = data.text;
                            clipboardDirty = false;
                        }
                    } catch(e) { /* transient network errors are retried on the next poll */ }
                }

                async function sendClipboard() {
                    const text = clipboardField.value;
                    try {
                        const res = await fetch('/clipboard', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', ...authHeaders() },
                            body: JSON.stringify({ text })
                        });
                        if (!res.ok) throw new Error('HTTP ' + res.status);
                        lastServerClipboard = text;
                        clipboardDirty = false;
                        showToast("Texto enviado al ordenador.", true);
                        clipboardField.blur();
                    } catch (e) {
                        showToast("No se pudo enviar el texto: " + String(e), false);
                    }
                }

                function startSync() {
                    setInterval(fetchFiles, 3000);
                    setInterval(() => syncClipboard(false), 3000);
                    fetchFiles();
                    syncClipboard(true);
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
    fn content_disposition_preserves_unicode_filename_metadata() {
        let value = content_disposition_value("foto ñ.png");
        assert!(value.starts_with("attachment; filename=\"foto _.png\"; filename*=UTF-8''"));
        assert!(value.contains("%C3%B1"));
    }
}

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
}
