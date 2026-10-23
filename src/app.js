    const { invoke } = window.__TAURI__.core;
    const { open } = window.__TAURI__.dialog;
    const tauriWindowApi = window.__TAURI__?.window;
    const currentWindow = tauriWindowApi?.getCurrentWindow?.();
    const isMacOS = /Macintosh|MacIntel|MacPPC|Mac68K/i.test(navigator.userAgent + " " + navigator.platform);
    if (!isMacOS) document.body.classList.add("custom-chrome");
    // Use the compact desktop layout from first paint so the window never flashes
    // a tall layout or exposes a vertical scrollbar while content is measured.
    document.body.classList.add("compact-layout");
    function showAppAlert(message, success=false) { const el=document.getElementById("appAlert"); if(!el)return; el.textContent=message; el.className="app-alert show "+(success?"success":"error"); }
    async function runWindowAction(action) {
      try {
        if (!currentWindow) throw new Error("La API de ventana de Tauri no está disponible.");
        await action();
      } catch (e) {
        showAppAlert("No se pudo controlar la ventana: " + String(e));
      }
    }
    window.minimizeApp = () => runWindowAction(() => currentWindow.minimize());
    window.toggleMaximizeApp = () => runWindowAction(async () => { await currentWindow.toggleMaximize(); await updateMaximizeControl(); });
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
      } catch (e) { /* La acción mostrará el error si el permiso no está disponible. */ }
    }
    if (!isMacOS) {
      document.getElementById("windowMinimize").addEventListener("click", window.minimizeApp);
      document.getElementById("windowMaximize").addEventListener("click", window.toggleMaximizeApp);
      document.getElementById("windowClose").addEventListener("click", window.closeApp);
      document.getElementById("customTitlebar").addEventListener("pointerdown", event => {
        if (event.button !== 0 || event.target.closest("button")) return;
        runWindowAction(() => currentWindow.startDragging());
      });
      document.getElementById("customTitlebar").addEventListener("dblclick", event => {
        if (!event.target.closest("button")) window.toggleMaximizeApp();
      });
      updateMaximizeControl();
    }
    let fitScheduled = false;
    let fitRunning = false;
    function scheduleWindowFit() {
      if (fitScheduled) return;
      fitScheduled = true;
      requestAnimationFrame(() => {
        fitScheduled = false;
        fitWindowToContent().catch(e => console.warn("No se pudo adaptar el tamaño de ventana:", e));
      });
    }
    async function fitWindowToContent() {
      if (!currentWindow || fitRunning) return;
      fitRunning = true;
      try {
        const app = document.querySelector(".app");
        if (!app) return;
        const scale = await currentWindow.scaleFactor();
        const monitor = await currentWindow.currentMonitor();
        const screenHeight = monitor ? monitor.size.height / scale : window.screen.availHeight;
        const maxHeight = Math.max(520, Math.floor(Math.min(screenHeight, window.screen.availHeight) - 36));
        let desired = app.scrollHeight + (document.body.classList.contains("custom-chrome") ? 40 : 0) + 4;
        document.body.classList.toggle("compact-layout", desired > maxHeight);
        await new Promise(resolve => requestAnimationFrame(resolve));
        desired = app.scrollHeight + (document.body.classList.contains("custom-chrome") ? 40 : 0) + 4;
        const targetHeight = Math.max(520, Math.min(Math.ceil(desired), maxHeight));
        const inner = await currentWindow.innerSize();
        const targetWidth = Math.max(640, Math.min(Math.ceil(inner.width / scale), 840, Math.floor(window.screen.availWidth - 24)));
        const LogicalSize = window.__TAURI__?.dpi?.LogicalSize;
        if (!LogicalSize) throw new Error("No está disponible LogicalSize en Tauri.");
        if (Math.abs(inner.height / scale - targetHeight) > 18 || Math.abs(inner.width / scale - targetWidth) > 18) {
          await currentWindow.setSize(new LogicalSize(targetWidth, targetHeight));
        }
      } finally { fitRunning = false; }
    }
    const appResizeObserver = new ResizeObserver(scheduleWindowFit);
    appResizeObserver.observe(document.querySelector(".app"));
    window.addEventListener("load", () => { scheduleWindowFit(); setTimeout(scheduleWindowFit, 220); });

    async function initApp() {
      try {
        const info = await invoke('get_connection_info');
        document.getElementById('serverUrl').innerText = info.url;
        const qr = document.getElementById('qrImage');
        qr.onload = () => { document.getElementById('qrPlaceholder').hidden = true; };
        qr.onerror = () => { document.getElementById('qrPlaceholder').textContent = 'No se pudo cargar el QR'; };
        qr.src = info.qr_base64;
        document.getElementById('savePath').innerText = info.save_path;
        document.getElementById('pinDisplay').innerText = info.pin;

        const webtransportStatus = document.getElementById('webtransportStatus');
        const webtransportQr = document.getElementById('webtransportQr');
        const webtransportLink = document.getElementById('webtransportProbeLink');
        if (info.webtransport_probe_url && info.webtransport_probe_qr_base64) {
          webtransportQr.src = info.webtransport_probe_qr_base64;
          webtransportQr.hidden = false;
          webtransportLink.href = info.webtransport_probe_url;
          webtransportLink.style.display = 'inline-block';
          webtransportStatus.textContent = 'Escanea este segundo QR desde el móvil. La página de prueba necesita Internet para cargarse; la conexión de prueba va directa al PC y no envía archivos.';
        } else {
          webtransportStatus.textContent = info.webtransport_error
            ? 'Prueba no disponible: ' + info.webtransport_error
            : 'El canal seguro todavía se está iniciando. Reinicia la aplicación si no aparece.';
        }
      } catch (e) {
        document.getElementById('serverUrl').innerText = 'Servidor local no disponible';
        document.getElementById('qrPlaceholder').textContent = 'Servidor no disponible';
        showAppAlert('No se pudo iniciar o consultar el servidor local: ' + String(e));
      }
      await loadData();
      scheduleWindowFit();
    }

    window.changeDirectory = async () => {
      try {
        const selected = await open({ directory: true, multiple: false });
        if (selected) {
          const newPath = await invoke('set_save_directory', { path: selected });
          document.getElementById('savePath').innerText = newPath;
        }
      } catch (e) { showAppAlert('No se pudo cambiar la carpeta: ' + String(e)); }
    };

    window.shareFile = async () => {
      try {
        const selected = await open({ multiple: false });
        if (selected) { renderSharedFiles(await invoke('share_pc_file', { path: selected })); scheduleWindowFit(); }
      } catch (e) { showAppAlert('No se pudo añadir el archivo: ' + String(e)); }
    };

    window.removeFile = async (id) => {
      try { renderSharedFiles(await invoke('remove_pc_file', { id })); showAppAlert('Archivo quitado de la lista de compartidos.', true); scheduleWindowFit(); }
      catch (e) { showAppAlert('No se pudo quitar el archivo: ' + String(e)); }
    };

    window.revokeDevice = async (deviceId) => {
      try { renderDevices(await invoke('revoke_trusted_device', { deviceId })); showAppAlert('Dispositivo desvinculado.', true); }
      catch (e) { showAppAlert('No se pudo desvincular el dispositivo: ' + String(e)); }
    };

    async function loadData() {
      try {
        renderSharedFiles(await invoke('get_shared_files'));
        renderDevices(await invoke('get_trusted_devices'));
      } catch (e) { console.error('No se pudieron cargar los datos:', e); }
    }

    function escapeHtml(value) {
      const element = document.createElement('span');
      element.textContent = String(value);
      return element.innerHTML;
    }

    function escapeAttribute(value) {
      return String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
        .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&#39;');
    }

    function emptyState(kind, message) {
      const icon = kind === 'file'
        ? '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10z"/><path d="M13 3v7h7M8 15h8"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M10 18h4"/></svg>';
      return '<div class="empty-state">' + icon + escapeHtml(message) + '</div>';
    }

    function renderSharedFiles(files) {
      const list = document.getElementById('sharedList');
      document.getElementById('fileCount').textContent = files.length + (files.length === 1 ? ' archivo' : ' archivos');
      if (!files || files.length === 0) {
        list.innerHTML = emptyState('file', 'Aún no has añadido archivos.');
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
      bridge.classList.toggle('connected', connected);
      bridgeStatus.innerHTML = '<span class="bridge-status-dot"></span>' + (connected ? 'Dispositivo vinculado' : 'Esperando un dispositivo');
      bridgeNote.textContent = connected ? 'Tu dispositivo está listo para compartir' : 'Tu móvil aparecerá aquí al vincularse';
      document.getElementById('deviceCount').textContent = devices.length + (devices.length === 1 ? ' dispositivo' : ' dispositivos');
      const list = document.getElementById('deviceList');
      if (!devices || devices.length === 0) {
        list.innerHTML = emptyState('device', 'Cuando vincules un móvil, aparecerá aquí.');
        return;
      }
      list.innerHTML = devices.map(d => `
        <div class="device-item">
          <span class="item-icon" style="background:var(--green-soft);color:var(--green)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M10 18h4"/></svg></span>
          <span class="item-name" title="${escapeHtml(d)}">${escapeHtml(d)}</span>
          <button data-action="revoke-device" data-device-id="${escapeAttribute(d)}" class="item-action" aria-label="Revocar dispositivo">Revocar</button>
        </div>
      `).join('');
      list.querySelectorAll('[data-action="revoke-device"]').forEach(button => {
        button.addEventListener('click', () => window.revokeDevice(button.dataset.deviceId));
      });
    }

    document.getElementById('addSharedFileButton').addEventListener('click', () => window.shareFile());
    document.getElementById('changeDirectoryButton').addEventListener('click', () => window.changeDirectory());

    initApp();
    // Refresh device state after pairing/revocation without requiring an app restart.
    setInterval(async () => { try { renderDevices(await invoke('get_trusted_devices')); } catch (e) { showAppAlert('No se pudo actualizar el estado de los dispositivos: ' + String(e)); } }, 2000);
