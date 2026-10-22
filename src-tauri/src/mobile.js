                let activeUploadXhr = { current: null };
                let revocationHandled = false;
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

                function handleAuthorizationRevoked() {
                    if (revocationHandled) return;
                    revocationHandled = true;
                    localStorage.removeItem('aether_token');
                    const xhr = activeUploadXhr.current;
                    if (xhr && xhr.readyState !== XMLHttpRequest.DONE) {
                        xhr._aetherRevoked = true;
                        xhr.abort();
                    }
                    activeUploadXhr.current = null;
                    document.getElementById('mainApp').classList.add('hidden');
                    document.getElementById('pinModal').classList.remove('hidden');
                    document.getElementById('pinInput').value = '';
                    const error = document.getElementById('pinError');
                    error.textContent = 'Este dispositivo se ha desvinculado. Introduce de nuevo el PIN del ordenador para conectarlo.';
                    error.classList.remove('hidden');
                    setBridgeState('', 'Dispositivo desvinculado');
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
                            revocationHandled = false;
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

                function escapeAttribute(value) {
                    return String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
                        .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&#39;');
                }

                async function downloadFile(fileId, filename) {
                    try {
                        const response = await fetch('/download-ticket/' + encodeURIComponent(fileId), {
                            method: 'POST',
                            headers: authHeaders(),
                            cache: 'no-store'
                        });
                        if (response.status === 401) { handleAuthorizationRevoked(); return; }
                        if (!response.ok) {
                            const message = (await response.text()).trim();
                            throw new Error(message || ('HTTP ' + response.status));
                        }
                        const data = await response.json();
                        if (!data.ticket) throw new Error('El servidor no devolvió un ticket de descarga.');
                        const link = document.createElement('a');
                        link.href = '/download/' + encodeURIComponent(fileId) + '?ticket=' + encodeURIComponent(data.ticket);
                        link.download = filename || 'download';
                        link.rel = 'noreferrer';
                        link.style.display = 'none';
                        document.body.appendChild(link);
                        link.click();
                        link.remove();
                    } catch (error) {
                        showToast('No se pudo iniciar la descarga: ' + String(error), false);
                    }
                }

                function showToast(message, isSuccess) {
                    const toast = document.getElementById('toast');
                    toast.innerText = message;
                    toast.className = 'toast ' + (isSuccess ? 'success' : 'error');
                    toast.classList.remove('hidden');
                    setTimeout(() => toast.classList.add('hidden'), 5000);
                }

                let uploadInProgress = false;

                async function uploadFiles() {
                    const input = document.getElementById('fileInput');
                    if (input.files.length === 0 || uploadInProgress) return;

                    const files = Array.from(input.files);
                    if (files.length > 32) {
                        showToast("Selecciona como máximo 32 archivos por operación.", false);
                        input.value = "";
                        return;
                    }

                    uploadInProgress = true;
                    input.disabled = true;
                    const progressContainer = document.getElementById('progressContainer');
                    const progressStatus = document.getElementById('progressStatus');
                    const progressPercent = document.getElementById('progressPercent');
                    const progressBar = document.getElementById('progressBar');
                    const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
                    let uploadedBytes = 0;
                    let sentFiles = 0;
                    const failures = [];

                    function updateProgress(currentFileFraction) {
                        const projected = uploadedBytes + (currentFileFraction || 0);
                        const percent = totalBytes > 0
                            ? Math.max(0, Math.min(100, Math.floor((projected / totalBytes) * 100)))
                            : Math.floor((sentFiles / files.length) * 100);
                        progressBar.style.width = percent + '%';
                        progressPercent.innerText = percent + '%';
                    }

                    setBridgeState('transferring', 'Enviando archivos al ordenador…');
                    progressContainer.classList.remove('hidden');
                    progressBar.style.width = '0%';
                    progressPercent.innerText = '0%';

                    try {
                        for (let index = 0; index < files.length; index++) {
                            if (revocationHandled || !localStorage.getItem('aether_token')) break;
                            const file = files[index];
                            progressStatus.innerText = 'Subiendo ' + file.name + ' (' + (index + 1) + ' de ' + files.length + ')…';

                            const result = await new Promise(resolve => {
                                const formData = new FormData();
                                formData.append('file', file, file.name);
                                const xhr = new XMLHttpRequest();
                                activeUploadXhr.current = xhr;
                                xhr.open('POST', '/upload', true);
                                xhr.timeout = 0;
                                const token = localStorage.getItem('aether_token');
                                if (token) xhr.setRequestHeader('Authorization', 'Bearer ' + token);

                                xhr.upload.onprogress = event => {
                                    if (event.lengthComputable) {
                                        const fraction = Math.max(0, Math.min(1, event.loaded / event.total));
                                        updateProgress(file.size * fraction);
                                    }
                                };

                                xhr.onload = () => {
                                    if (activeUploadXhr.current === xhr) activeUploadXhr.current = null;
                                    if (xhr.status === 401) {
                                        handleAuthorizationRevoked();
                                        resolve({ ok: false, revoked: true, message: 'Sesión revocada.' });
                                        return;
                                    }
                                    if (xhr.status === 200) {
                                        try {
                                            const receipt = JSON.parse(xhr.responseText);
                                            const uploaded = receipt.files && receipt.files[0];
                                            if (!uploaded || uploaded.filename !== file.name ||
                                                Number(uploaded.size_bytes) !== file.size ||
                                                !/^[a-f0-9]{64}$/.test(uploaded.sha256)) {
                                                resolve({ ok: false, message: 'La respuesta de integridad del servidor no es válida.' });
                                                return;
                                            }
                                            resolve({ ok: true, receipt: uploaded });
                                        } catch (_) {
                                            resolve({ ok: false, message: 'El servidor devolvió una respuesta de transferencia no válida.' });
                                        }
                                        return;
                                    }
                                    const detail = (xhr.responseText || '').trim();
                                    const known = {
                                        400: 'La petición o el nombre del archivo no son válidos.',
                                        401: 'La sesión ha caducado. Vuelve a vincular el móvil con el PIN.',
                                        409: 'Ya existe un archivo con ese nombre en el PC.',
                                        413: 'El archivo o la petición supera el límite permitido.',
                                        429: 'Hay demasiadas transferencias o intentos. Espera y vuelve a probar.',
                                        507: 'No hay espacio suficiente o no se puede escribir el archivo.'
                                    };
                                    resolve({
                                        ok: false,
                                        message: detail && detail.length < 220 ? detail : (known[xhr.status] || 'Error HTTP ' + xhr.status + '.')
                                    });
                                };

                                xhr.onerror = () => {
                                    if (activeUploadXhr.current === xhr) activeUploadXhr.current = null;
                                    resolve({ ok: false, message: 'No se pudo conectar con el PC. Comprueba la Wi-Fi y el firewall.' });
                                };
                                xhr.onabort = () => {
                                    if (activeUploadXhr.current === xhr) activeUploadXhr.current = null;
                                    if (xhr._aetherRevoked || revocationHandled) {
                                        resolve({ ok: false, revoked: true, message: 'Sesión revocada.' });
                                    } else {
                                        resolve({ ok: false, message: 'La transferencia se canceló antes de terminar.' });
                                    }
                                };
                                xhr.send(formData);
                            });

                            if (result.revoked || revocationHandled) break;
                            if (result.ok) {
                                sentFiles++;
                                uploadedBytes += file.size;
                                updateProgress(0);
                            } else {
                                failures.push(file.name + ': ' + result.message);
                            }
                        }
                    } finally {
                        uploadInProgress = false;
                        input.disabled = false;
                        progressContainer.classList.add('hidden');
                    }

                    if (revocationHandled) return;
                    if (sentFiles === files.length) {
                        input.value = '';
                        setBridgeState('paired', 'Transferencia completada');
                        showToast(files.length === 1
                            ? 'Archivo enviado y comprobado correctamente.'
                            : 'Todos los archivos se enviaron y comprobaron correctamente.', true);
                    } else if (sentFiles > 0) {
                        setBridgeState('paired', 'Transferencia parcial');
                        showToast('Se enviaron ' + sentFiles + ' de ' + files.length + ' archivos. ' + failures[0], false);
                    } else {
                        setBridgeState('paired', 'No se pudo completar la transferencia');
                        showToast(failures[0] || 'La transferencia no se completó. Comprueba la conexión y vuelve a intentarlo.', false);
                    }
                }

                async function fetchFiles() {
                    try {
                        const res = await fetch('/files', { headers: authHeaders() });
                        if (res.status === 401) { handleAuthorizationRevoked(); return; }
                        if (!res.ok) throw new Error('HTTP ' + res.status);
                        const files = await res.json();
                        const list = document.getElementById('fileList');
                        if (files.length === 0) {
                            list.innerHTML = '<p class="mobile-empty">No hay archivos disponibles.</p>';
                            return;
                        }
                        list.innerHTML = files.map(f => `
                            <div class="mobile-file-item">
                                <span class="mobile-file-name">${escapeHtml(f.name)}</span>
                                <a href="#" class="download-link" data-file-id="${escapeAttribute(f.id)}" data-file-name="${escapeAttribute(f.name)}">Descargar</a>
                            </div>
                        `).join('');
                        list.querySelectorAll('.download-link').forEach(link => {
                            link.addEventListener('click', event => {
                                event.preventDefault();
                                downloadFile(link.dataset.fileId, link.dataset.fileName);
                            });
                        });
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
                        if (res.status === 401) { handleAuthorizationRevoked(); return; }
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
                        if (res.status === 401) { handleAuthorizationRevoked(); return; }
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
