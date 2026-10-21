use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures_util::TryStreamExt;
use local_ip_address::local_ip;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use base64::{engine::general_purpose, Engine as _};
use std::io::Cursor;
use qrcode::QrCode;
use serde::Serialize;

#[derive(Clone)]
struct AppState {
    save_dir: Arc<RwLock<PathBuf>>,
    pc_files: Arc<RwLock<Vec<(String, PathBuf)>>>, // (uuid, ruta_real)
}

#[derive(Serialize)]
pub struct ConnectionInfo {
    url: String,
    qr_base64: String,
    save_path: String,
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

async fn get_shared_files_internal(state: &AppState) -> Result<Vec<serde_json::Value>, String> {
    let files = state.pc_files.read().await;
    let list: Vec<_> = files.iter().map(|(id, path)| {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        serde_json::json!({ "id": id, "name": name })
    }).collect();
    Ok(list)
}

// Interfaz Web Móvil (PWA)
async fn serve_ui() -> axum::response::Html<&'static str> {
    axum::response::Html(r###"
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AetherDrop - Red Local</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col items-center justify-center p-4">
            <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 text-center">
                <h1 class="text-2xl font-bold text-sky-400 mb-1">AetherDrop</h1>
                <p class="text-slate-400 text-sm mb-6">Transferencia ultra-rápida sin límites</p>

                <!-- Subir al PC -->
                <div class="mb-8">
                    <label class="block w-full bg-sky-600 hover:bg-sky-500 active:bg-sky-700 text-white font-semibold py-3 px-4 rounded-xl cursor-pointer transition shadow-lg shadow-sky-900/30">
                        Enviar Archivo o Vídeo al PC
                        <input type="file" id="fileInput" class="hidden" onchange="uploadFile()">
                    </label>
                    <div id="status" class="mt-3 text-sm font-medium text-slate-400"></div>
                </div>

                <hr class="border-slate-800 mb-6">

                <!-- Descargar desde el PC -->
                <div class="text-left">
                    <h2 class="text-sm font-semibold text-slate-300 mb-3 uppercase tracking-wider">Archivos compartidos por el PC</h2>
                    <div id="fileList" class="space-y-2 max-h-48 overflow-y-auto pr-1">
                        <p class="text-xs text-slate-500">No hay archivos disponibles.</p>
                    </div>
                </div>
            </div>

            <script>
                async function uploadFile() {
                    const input = document.getElementById('fileInput');
                    const status = document.getElementById('status');
                    if (input.files.length === 0) return;
                    
                    const file = input.files[0];
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    status.style.color = "#38bdf8";
                    status.innerText = "Subiendo " + file.name + " (puede tardar si es muy pesado)...";
                    
                    try {
                        const response = await fetch('/upload', { method: 'POST', body: formData });
                        if (response.ok) {
                            status.style.color = "#34d399";
                            status.innerText = "¡Recibido con éxito en el PC!";
                            input.value = "";
                        } else {
                            status.style.color = "#f87171";
                            status.innerText = "Error en el servidor al guardar.";
                        }
                    } catch (e) {
                        status.style.color = "#f87171";
                        status.innerText = "Error de red local.";
                    }
                }

                async function fetchFiles() {
                    try {
                        const res = await fetch('/files');
                        const files = await res.json();
                        const list = document.getElementById('fileList');
                        if (files.length === 0) {
                            list.innerHTML = '<p class="text-xs text-slate-500">No hay archivos disponibles.</p>';
                            return;
                        }
                        list.innerHTML = files.map(f => `
                            <div class="flex items-center justify-between bg-slate-800 p-2.5 rounded-lg border border-slate-700/50">
                                <span class="text-xs truncate max-w-[200px] text-slate-200">${f.name}</span>
                                <a href="/download/${f.id}" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-3 py-1.5 rounded-md font-medium transition">Descargar</a>
                            </div>
                        `).join('');
                    } catch(e) {}
                }
                setInterval(fetchFiles, 3000);
                fetchFiles();
            </script>
        </body>
        </html>
    "###)
}

// Receptor streaming: Soporta archivos gigantes sin desbordar la memoria RAM
async fn handle_upload(State(state): State<AppState>, mut multipart: Multipart) -> &'static str {
    while let Ok(Some(mut field)) = multipart.next_field().await {
        let file_name = field.file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("archivo_{}.bin", uuid::Uuid::new_v4()));
        
        let dir = state.save_dir.read().await.clone();
        let _ = tokio::fs::create_dir_all(&dir).await;
        let filepath = dir.join(&file_name);

        if let Ok(mut file) = tokio::fs::File::create(&filepath).await {
            while let Ok(Some(chunk)) = field.try_next().await {
                if file.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = file.flush().await;
            println!("Archivo masivo guardado correctamente en: {:?}", filepath);
        }
    }
    "OK"
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

fn start_local_server(state: AppState) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let app = Router::new()
                .route("/", get(serve_ui))
                .route("/upload", post(handle_upload))
                .route("/files", get(list_pc_files))
                .route("/download/:id", get(download_pc_file))
                .with_state(state)
                .layer(DefaultBodyLimit::max(10 * 1024 * 1024 * 1024)) // Límite ampliado a 10 GB
                .layer(CorsLayer::permissive());

            let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            println!("🚀 Servidor Axum optimizado corriendo en puerto 8080");
            let _ = axum::serve(listener, app).await;
        });
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let default_dir = dirs::download_dir().unwrap_or_else(|| PathBuf::from("."));
    let state = AppState {
        save_dir: Arc::new(RwLock::new(default_dir)),
        pc_files: Arc::new(RwLock::new(Vec::new())),
    };

    start_local_server(state.clone());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_connection_info,
            set_save_directory,
            share_pc_file,
            remove_pc_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}