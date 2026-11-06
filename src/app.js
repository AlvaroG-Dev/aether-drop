const { invoke } = window.__TAURI__.core;
const { open } = window.__TAURI__.dialog;
const tauriWindowApi = window.__TAURI__?.window;
const currentWindow = tauriWindowApi?.getCurrentWindow?.();
const isMacOS = /Macintosh|MacIntel|MacPPC|Mac68K/i.test(navigator.userAgent + " " + navigator.platform);
if (!isMacOS) document.body.classList.add("custom-chrome");

let latestUrl = '';
let latestPin = '';
let latestQrBase64 = '';
let knownReceivedFileIds = new Set();
let activeReceivedToastTimer = null;

function showAppAlert(message, success = false) {
  const el = document.getElementById("appAlert");
  if (!el) return;
  el.textContent = message;
  el.className = "app-alert show " + (success ? "success" : "error");
}

function showToastCopy(message = "¡Copiado al portapapeles!") {
  const toast = document.getElementById("toastCopy");
  const text = document.getElementById("toastCopyText");
  if (!toast || !text) return;
  text.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2200);
}

async function copyToClipboard(text, successMsg) {
  if (!text) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const input = document.createElement("input");
      input.value = text;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      document.body.removeChild(input);
    }
    showToastCopy(successMsg);
  } catch (err) {
    showAppAlert("No se pudo copiar: " + String(err));
  }
}

// ── Formateo de bytes ──────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ── Ventana Controles (Windows/Linux) ──────────────────────────────────
async function runWindowAction(action) {
  try {
    if (!currentWindow) throw new Error("La API de ventana de Tauri no está disponible.");
    await action();
  } catch (e) {
    showAppAlert("No se pudo controlar la ventana: " + String(e));
  }
}

window.minimizeApp = () => runWindowAction(() => currentWindow.minimize());
window.toggleMaximizeApp = () => runWindowAction(async () => {
  await currentWindow.toggleMaximize();
  await updateMaximizeControl();
});
window.closeApp = () => runWindowAction(() => currentWindow.close());

async function updateMaximizeControl() {
  if (!currentWindow || isMacOS) return;
  try {
    const maximized = await currentWindow.isMaximized();
    const button = document.getElementById("windowMaximize");
    if (!button) return;
    button.title = maximized ? "Restaurar" : "Maximizar";
    button.setAttribute("aria-label", button.title);
    button.innerHTML = maximized
      ? '<svg viewBox="0 0 12 12" aria-hidden="true"><rect x="3.5" y="1.5" width="7" height="7" rx=".6"/><path d="M2 4.5v6h6"/></svg>'
      : '<svg viewBox="0 0 12 12" aria-hidden="true"><rect x="2" y="2" width="8" height="8" rx=".6"/></svg>';
  } catch (e) { /* silent */ }
}

if (!isMacOS) {
  document.getElementById("windowMinimize")?.addEventListener("click", window.minimizeApp);
  document.getElementById("windowMaximize")?.addEventListener("click", window.toggleMaximizeApp);
  document.getElementById("windowClose")?.addEventListener("click", window.closeApp);
  document.getElementById("customTitlebar")?.addEventListener("pointerdown", event => {
    if (event.button !== 0 || event.target.closest("button")) return;
    runWindowAction(() => currentWindow.startDragging());
  });
  document.getElementById("customTitlebar")?.addEventListener("dblclick", event => {
    if (!event.target.closest("button")) window.toggleMaximizeApp();
  });
  updateMaximizeControl();
}

// ── QR Modal ───────────────────────────────────────────────────────────
function openQrModal() {
  const modal = document.getElementById("qrModal");
  const modalImg = document.getElementById("qrModalImage");
  const modalPin = document.getElementById("modalPinDisplay");
  if (!modal) return;
  if (latestQrBase64) {
    modalImg.src = latestQrBase64;
  }
  if (modalPin && latestPin) {
    modalPin.textContent = latestPin;
  }
  modal.classList.add("open");
}

function closeQrModal() {
  document.getElementById("qrModal")?.classList.remove("open");
}

document.getElementById("qrContainer")?.addEventListener("click", openQrModal);
document.getElementById("qrModalClose")?.addEventListener("click", closeQrModal);
document.getElementById("modalBtnClose")?.addEventListener("click", closeQrModal);
document.getElementById("qrModal")?.addEventListener("click", e => {
  if (e.target.id === "qrModal") closeQrModal();
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape") closeQrModal();
});

// ── Copy buttons ───────────────────────────────────────────────────────
document.getElementById("btnCopyUrl")?.addEventListener("click", e => {
  e.stopPropagation();
  copyToClipboard(latestUrl, "¡Enlace copiado al portapapeles!");
});
document.getElementById("modalBtnCopy")?.addEventListener("click", () => {
  copyToClipboard(latestUrl, "¡Enlace copiado al portapapeles!");
});
document.getElementById("btnCopyPin")?.addEventListener("click", () => {
  copyToClipboard(latestPin, "¡PIN " + latestPin + " copiado!");
});

// ── Pestañas Recibidos / Enviar ─────────────────────────────────────────
const tabReceivedBtn = document.getElementById("tabReceivedBtn");
const tabSendBtn = document.getElementById("tabSendBtn");
const viewReceived = document.getElementById("viewReceived");
const viewSend = document.getElementById("viewSend");

tabReceivedBtn?.addEventListener("click", () => {
  tabReceivedBtn.classList.add("active");
  tabSendBtn.classList.remove("active");
  viewReceived.style.display = "flex";
  viewSend.style.display = "none";
});

tabSendBtn?.addEventListener("click", () => {
  tabSendBtn.classList.add("active");
  tabReceivedBtn.classList.remove("active");
  viewSend.style.display = "flex";
  viewReceived.style.display = "none";
});

// ── Banner Archivo Recibido (Punto 1 Resuelto) ─────────────────────────
function showReceivedBanner(file) {
  const banner = document.getElementById("receivedToastBanner");
  const nameEl = document.getElementById("recToastName");
  const sizeEl = document.getElementById("recToastSize");
  const btnOpen = document.getElementById("recToastBtnOpen");
  const btnFolder = document.getElementById("recToastBtnFolder");
  if (!banner) return;

  nameEl.textContent = file.filename;
  sizeEl.textContent = `${formatBytes(file.size_bytes)} · Guardado en Descargas`;

  btnOpen.onclick = () => {
    invoke('open_received_file', { path: file.path }).catch(e => showAppAlert(String(e)));
  };
  btnFolder.onclick = () => {
    invoke('open_save_folder').catch(e => showAppAlert(String(e)));
  };

  banner.classList.add("show");

  // Sonido suave de notificación (Web Audio API nativo sin assets externos)
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.15); // A5
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.35);
  } catch (_) {}

  if (activeReceivedToastTimer) clearTimeout(activeReceivedToastTimer);
  activeReceivedToastTimer = setTimeout(() => {
    banner.classList.remove("show");
  }, 10000);
}

document.getElementById("recToastClose")?.addEventListener("click", () => {
  document.getElementById("receivedToastBanner")?.classList.remove("show");
});

document.getElementById("btnOpenFolder")?.addEventListener("click", () => {
  invoke('open_save_folder').catch(e => showAppAlert(String(e)));
});

// ── App init ───────────────────────────────────────────────────────────
async function initApp() {
  try {
    const info = await invoke('get_connection_info');
    const qr = document.getElementById('qrImage');
    const placeholder = document.getElementById('qrPlaceholder');
    const webtransportLink = document.getElementById('webtransportProbeLink');
    const secureUrl = info.webtransport_probe_url;
    const secureQr = info.webtransport_probe_qr_base64;

    latestUrl = secureUrl || info.url || '';
    latestPin = info.pin || '';
    latestQrBase64 = secureQr || info.qr_base64 || '';

    const urlDisplay = document.getElementById('serverUrl');
    if (urlDisplay) {
      urlDisplay.innerText = latestUrl ? latestUrl.replace(/^https?:\/\//, '') : 'Canal seguro no disponible';
      urlDisplay.title = latestUrl;
    }

    if (secureUrl && secureQr) {
      qr.onload = () => {
        placeholder.hidden = true;
        qr.hidden = false;
      };
      qr.onerror = () => {
        qr.hidden = true;
        placeholder.hidden = false;
        placeholder.textContent = 'Error al cargar QR';
      };
      qr.src = secureQr;
      if (webtransportLink) {
        webtransportLink.href = secureUrl;
        webtransportLink.style.display = 'inline-block';
      }
    } else {
      qr.hidden = true;
      placeholder.hidden = false;
      placeholder.textContent = info.webtransport_error || 'Canal seguro no disponible';
      if (webtransportLink) webtransportLink.style.display = 'none';
    }

    const savePathEl = document.getElementById('savePath');
    if (savePathEl) savePathEl.innerText = info.save_path;
    const pinDisplayEl = document.getElementById('pinDisplay');
    if (pinDisplayEl) pinDisplayEl.innerText = info.pin;
  } catch (e) {
    document.getElementById('serverUrl').innerText = 'Servidor local no disponible';
    document.getElementById('qrPlaceholder').textContent = 'Servidor no disponible';
    showAppAlert('No se pudo iniciar el servidor local: ' + String(e));
  }

  await loadData();
}

window.changeDirectory = async () => {
  try {
    const selected = await open({ directory: true, multiple: false });
    if (selected) {
      const newPath = await invoke('set_save_directory', { path: selected });
      document.getElementById('savePath').innerText = newPath;
      showToastCopy("Carpeta actualizada correctamente");
    }
  } catch (e) { showAppAlert('No se pudo cambiar la carpeta: ' + String(e)); }
};

window.shareFile = async () => {
  try {
    const selected = await open({ multiple: false });
    if (selected) {
      renderSharedFiles(await invoke('share_pc_file', { path: selected }));
      showToastCopy("Archivo añadido para compartir");
    }
  } catch (e) { showAppAlert('No se pudo añadir el archivo: ' + String(e)); }
};

window.removeFile = async (id) => {
  try {
    renderSharedFiles(await invoke('remove_pc_file', { id }));
    showAppAlert('Archivo quitado de la lista de compartidos.', true);
  } catch (e) { showAppAlert('No se pudo quitar el archivo: ' + String(e)); }
};

window.revokeDevice = async (deviceId) => {
  try {
    renderDevices(await invoke('revoke_trusted_device', { deviceId }));
    showAppAlert('Dispositivo desvinculado.', true);
  } catch (e) { showAppAlert('No se pudo desvincular el dispositivo: ' + String(e)); }
};

async function loadData() {
  try {
    renderSharedFiles(await invoke('get_shared_files'));
    renderDevices(await invoke('get_trusted_devices'));
    await checkReceivedFiles(true); // Carga inicial sin disparar alerta
  } catch (e) { console.error('No se pudieron cargar los datos:', e); }
}

async function checkReceivedFiles(isInitial = false) {
  try {
    const files = await invoke('get_received_files');
    renderReceivedFiles(files);

    if (isInitial) {
      // Guardar IDs existentes para no alertar de archivos antiguos
      files.forEach(f => knownReceivedFileIds.add(f.id));
      return;
    }

    // Detectar si hay alguno nuevo
    for (const file of files) {
      if (!knownReceivedFileIds.has(file.id)) {
        knownReceivedFileIds.add(file.id);
        // ¡MOSTRAR MENSAJE Y BANNER EN EL PC!
        showReceivedBanner(file);
        break; // Alertar el más reciente
      }
    }
  } catch (e) {
    console.error('Error al comprobar archivos recibidos:', e);
  }
}

function escapeHtml(value) {
  const el = document.createElement('span');
  el.textContent = String(value);
  return el.innerHTML;
}

function escapeAttribute(value) {
  return String(value)
    .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&#39;');
}

function renderReceivedFiles(files) {
  const list = document.getElementById('receivedList');
  const badge = document.getElementById('receivedBadge');
  if (badge) badge.textContent = files.length;

  if (!files || files.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        Los archivos que envíes desde el móvil aparecerán aquí.
      </div>
    `;
    return;
  }

  list.innerHTML = files.map(f => `
    <div class="received-item">
      <span class="received-item-name" title="${escapeHtml(f.filename)}">${escapeHtml(f.filename)}</span>
      <span class="received-item-size">${formatBytes(f.size_bytes)}</span>
      <div class="received-actions">
        <button class="btn-sm-action" data-action="open" data-path="${escapeAttribute(f.path)}">Abrir</button>
      </div>
    </div>
  `).join('');

  list.querySelectorAll('[data-action="open"]').forEach(btn => {
    btn.addEventListener('click', () => {
      invoke('open_received_file', { path: btn.dataset.path }).catch(e => showAppAlert(String(e)));
    });
  });
}

function renderSharedFiles(files) {
  const list = document.getElementById('sharedList');
  const badge = document.getElementById('sendBadge');
  if (badge) badge.textContent = files.length;

  if (!files || files.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10z"/><path d="M13 3v7h7M8 15h8M8 18h5"/>
        </svg>
        Aún no has añadido archivos para compartir.
      </div>
    `;
    return;
  }

  list.innerHTML = files.map(f => `
    <div class="file-item">
      <span class="item-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10z"/><path d="M13 3v7h7"/></svg></span>
      <span class="item-name">${escapeHtml(f.name)}</span>
      <button data-action="remove-file" data-file-id="${escapeAttribute(f.id)}" class="item-action" aria-label="Quitar archivo" title="Quitar archivo">Quitar</button>
    </div>
  `).join('');

  list.querySelectorAll('[data-action="remove-file"]').forEach(button => {
    button.addEventListener('click', () => window.removeFile(button.dataset.fileId));
  });
}

function renderDevices(devices) {
  const bridge = document.getElementById('deviceBridge');
  const bridgeStatus = document.getElementById('bridgeStatus');
  const bridgeNote = document.getElementById('bridgeNote');
  const connected = Boolean(devices && devices.length > 0);

  bridge?.classList.toggle('connected', connected);
  if (bridgeStatus) {
    bridgeStatus.innerHTML =
      '<span class="bridge-status-dot"></span>' +
      (connected ? 'Dispositivo vinculado · Listo' : 'Esperando un dispositivo');
  }
  if (bridgeNote) {
    bridgeNote.textContent = connected
      ? 'Conexión P2P activa y lista para transferir'
      : 'Tu móvil aparecerá aquí al vincularse';
  }

  document.getElementById('deviceCount').textContent =
    devices.length + (devices.length === 1 ? ' dispositivo' : ' dispositivos');

  const list = document.getElementById('deviceList');
  if (!devices || devices.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M10 18h4"/>
        </svg>
        Cuando vincules tu móvil con el PIN, aparecerá aquí.
      </div>
    `;
    return;
  }

  list.innerHTML = devices.map(d => `
    <div class="device-item">
      <span class="item-icon" style="background:rgba(52,211,153,.15);color:#34d399"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M10 18h4"/></svg></span>
      <span class="item-name" title="${escapeHtml(d)}">${escapeHtml(d)}</span>
      <button data-action="revoke-device" data-device-id="${escapeAttribute(d)}" class="item-action" aria-label="Revocar dispositivo">Revocar</button>
    </div>
  `).join('');

  list.querySelectorAll('[data-action="revoke-device"]').forEach(button => {
    button.addEventListener('click', () => window.revokeDevice(button.dataset.deviceId));
  });
}

document.getElementById('addSharedFileButton')?.addEventListener('click', () => window.shareFile());
document.getElementById('changeDirectoryButton')?.addEventListener('click', () => window.changeDirectory());

initApp();

// Refrescar cada 1.5s dispositivos y archivos recibidos
setInterval(async () => {
  try {
    renderDevices(await invoke('get_trusted_devices'));
    await checkReceivedFiles(false);
  } catch (e) { /* ignore */ }
}, 1500);
