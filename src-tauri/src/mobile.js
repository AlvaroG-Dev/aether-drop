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
                let cancelRequested = false;
                let activeTransferId = null;

                function uploadStorageKey(file) {
                    return 'aetherdrop_upload_v1:' + deviceId + ':' + file.name + ':' + file.size + ':' + file.lastModified;
                }

                async function responseError(response, fallback) {
                    let detail = '';
                    try { detail = (await response.text()).trim(); } catch (_) {}
                    return detail && detail.length < 240 ? detail : (fallback || ('Error HTTP ' + response.status + '.'));
                }

                async function authorizedFetch(url, options = {}) {
                    const res = await fetch(url, {
                        cache: 'no-store',
                        ...options,
                        headers: { ...authHeaders(), ...(options.headers || {}) }
                    });
                    if (res.status === 401) handleAuthorizationRevoked();
                    return res;
                }

                async function getUploadStatus(transferId) {
                    const response = await authorizedFetch('/upload/status/' + encodeURIComponent(transferId));
                    if (!response.ok) {
                        return {
                            ok: false,
                            revoked: response.status === 401,
                            status: response.status,
                            message: await responseError(response, 'No se pudo consultar el estado de la transferencia.')
                        };
                    }
                    try { return { ok: true, status: await response.json() }; }
                    catch (_) { return { ok: false, message: 'El servidor devolvió un estado de transferencia no válido.' }; }
                }

                async function getOrStartUpload(file, storageKey) {
                    let saved = null;
                    try { saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch (_) {}
                    if (saved && saved.transfer_id && saved.filename === file.name &&
                        Number(saved.size_bytes) === file.size &&
                        Number(saved.last_modified) === file.lastModified &&
                        saved.device_id === deviceId) {
                        const status = await getUploadStatus(saved.transfer_id);
                        if (status.revoked) return { revoked: true, message: status.message };
                        if (status.ok && status.status.filename === file.name &&
                            Number(status.status.size_bytes) === file.size) {
                            return { ok: true, transferId: saved.transfer_id, status: status.status, storageKey, resumed: true };
                        }
                        try { sessionStorage.removeItem(storageKey); } catch (_) {}
                    }

                    const response = await authorizedFetch('/upload/start', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ filename: file.name, size_bytes: file.size })
                    });
                    if (response.status === 401) {
                        return { revoked: true, message: 'La sesión ha caducado. Vuelve a vincular el móvil con el PIN.' };
                    }
                    if (!response.ok) {
                        return {
                            ok: false,
                            status: response.status,
                            message: await responseError(response, 'No se pudo iniciar la transferencia.')
                        };
                    }
                    let data;
                    try { data = await response.json(); }
                    catch (_) { return { ok: false, message: 'El servidor devolvió una respuesta de inicio no válida.' }; }
                    if (!data.transfer_id ||
                        !Number.isSafeInteger(Number(data.chunk_size)) ||
                        Number(data.chunk_size) < 1 ||
                        Number(data.chunks_total) !== Math.ceil(file.size / Number(data.chunk_size))) {
                        return { ok: false, message: 'Los parámetros de transferencia del servidor no son válidos.' };
                    }
                    try {
                        sessionStorage.setItem(storageKey, JSON.stringify({
                            transfer_id: data.transfer_id,
                            filename: file.name,
                            size_bytes: file.size,
                            last_modified: file.lastModified,
                            device_id: deviceId
                        }));
                    } catch (_) {}
                    return {
                        ok: true,
                        transferId: data.transfer_id,
                        status: {
                            filename: file.name,
                            size_bytes: file.size,
                            received_bytes: 0,
                            next_chunk: Number(data.next_chunk) || 0,
                            chunks_total: Number(data.chunks_total),
                            chunk_size: Number(data.chunk_size),
                            chunk_hashes: []
                        },
                        storageKey,
                        resumed: false
                    };
                }

                function postUploadChunk(transferId, chunkIndex, buffer, chunkHash, onProgress) {
                    return new Promise(resolve => {
                        const xhr = new XMLHttpRequest();
                        activeUploadXhr.current = xhr;
                        xhr.open('POST', '/upload/chunk/' + encodeURIComponent(transferId) + '/' + chunkIndex, true);
                        xhr.timeout = 120000;
                        const token = localStorage.getItem('aether_token');
                        if (token) xhr.setRequestHeader('Authorization', 'Bearer ' + token);
                        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
                        xhr.setRequestHeader('X-Chunk-SHA256', chunkHash);

                        xhr.upload.onprogress = event => {
                            if (event.lengthComputable && onProgress) {
                                onProgress(Math.max(0, Math.min(buffer.byteLength, event.loaded)));
                            }
                        };
                        xhr.onload = () => {
                            if (activeUploadXhr.current === xhr) activeUploadXhr.current = null;
                            if (xhr.status === 401) {
                                handleAuthorizationRevoked();
                                resolve({ ok: false, revoked: true, status: 401, message: 'La sesión se ha revocado.' });
                                return;
                            }
                            if (xhr.status === 200) {
                                try { resolve({ ok: true, progress: JSON.parse(xhr.responseText) }); }
                                catch (_) { resolve({ ok: false, retryable: true, message: 'Respuesta de bloque no válida.' }); }
                                return;
                            }
                            const retryable = xhr.status === 0 || [408, 425, 429, 500, 502, 503, 504].includes(xhr.status);
                            resolve({
                                ok: false,
                                retryable,
                                status: xhr.status,
                                message: (xhr.responseText || '').trim() || ('Error HTTP ' + xhr.status + '.')
                            });
                        };
                        xhr.onerror = () => {
                            if (activeUploadXhr.current === xhr) activeUploadXhr.current = null;
                            resolve({ ok: false, retryable: true, message: 'La conexión se interrumpió durante el envío del bloque.' });
                        };
                        xhr.ontimeout = () => {
                            if (activeUploadXhr.current === xhr) activeUploadXhr.current = null;
                            resolve({ ok: false, retryable: true, message: 'El bloque tardó demasiado; se comprobará si llegó al PC.' });
                        };
                        xhr.onabort = () => {
                            if (activeUploadXhr.current === xhr) activeUploadXhr.current = null;
                            if (xhr._aetherRevoked || revocationHandled) {
                                resolve({ ok: false, revoked: true, message: 'Sesión revocada.' });
                            } else if (cancelRequested) {
                                resolve({ ok: false, cancelled: true, message: 'Transferencia cancelada.' });
                            } else {
                                resolve({ ok: false, retryable: true, message: 'La petición se interrumpió; se comprobará el estado antes de reintentar.' });
                            }
                        };
                        xhr.send(buffer);
                    });
                }

                async function transferFileInChunks(file, transferId, status, totalBytes, completedBytes) {
                    const chunkSize = Number(status.chunk_size);
                    if (!Number.isSafeInteger(chunkSize) || chunkSize < 1) {
                        return { ok: false, status: 500, message: 'El tamaño de bloque del servidor no es válido.' };
                    }
                    let current = status;
                    let failedAttempts = 0;
                    const wholeFileHasher = window.sha256.create();

                    // Revalidate every already-committed block against the currently
                    // selected File before resuming. Matching names/sizes/timestamps
                    // are not enough to prove it is the same content.
                    const committedChunks = Number(current.next_chunk) || 0;
                    const committedHashes = Array.isArray(current.chunk_hashes) ? current.chunk_hashes : [];
                    if (committedHashes.length !== committedChunks) {
                        return { ok: false, status: 409, message: 'El servidor no tiene un historial de hashes coherente. Cancela esa transferencia e inicia otra.' };
                    }
                    for (let i = 0; i < committedChunks; i++) {
                        if (cancelRequested) return { cancelled: true, progress: current };
                        if (revocationHandled) return { revoked: true, progress: current };
                        const offset = i * chunkSize;
                        const buffer = await file.slice(offset, Math.min(file.size, offset + chunkSize)).arrayBuffer();
                        const view = new Uint8Array(buffer);
                        const localHash = window.sha256(view);
                        if (localHash !== committedHashes[i]) {
                            return {
                                ok: false,
                                status: 409,
                                message: 'El contenido del archivo seleccionado no coincide con los bloques ya recibidos. Cancela esa transferencia y vuelve a empezar.'
                            };
                        }
                        wholeFileHasher.update(view);
                    }

                    while (Number(current.next_chunk) < Number(current.chunks_total)) {
                        if (cancelRequested) return { cancelled: true, progress: current };
                        if (revocationHandled) return { revoked: true, progress: current };
                        const chunkIndex = Number(current.next_chunk);
                        const offset = chunkIndex * chunkSize;
                        const buffer = await file.slice(offset, Math.min(file.size, offset + chunkSize)).arrayBuffer();
                        const view = new Uint8Array(buffer);
                        const chunkHash = window.sha256(view);
                        if (cancelRequested) return { cancelled: true, progress: current };

                        const response = await postUploadChunk(
                            transferId,
                            chunkIndex,
                            buffer,
                            chunkHash,
                            sentInChunk => {
                                const loaded = completedBytes + Number(current.received_bytes) + sentInChunk;
                                const percent = totalBytes > 0
                                    ? Math.max(0, Math.min(100, Math.floor((loaded / totalBytes) * 100)))
                                    : 0;
                                document.getElementById('progressBar').style.width = percent + '%';
                                document.getElementById('progressPercent').innerText = percent + '%';
                            }
                        );
                        if (response.cancelled || cancelRequested) return { cancelled: true, progress: current };
                        if (response.revoked || revocationHandled) return { revoked: true, message: response.message };

                        if (response.ok) {
                            const received = response.progress;
                            if (!Array.isArray(received.chunk_hashes) ||
                                received.chunk_hashes[chunkIndex] !== chunkHash ||
                                Number(received.next_chunk) !== chunkIndex + 1) {
                                return { ok: false, status: 500, message: 'El servidor no confirmó el hash del bloque recibido.' };
                            }
                            current = received;
                            wholeFileHasher.update(view);
                            failedAttempts = 0;
                            continue;
                        }

                        if (response.retryable || response.status === 409) {
                            const refreshed = await getUploadStatus(transferId);
                            if (refreshed.revoked) return { revoked: true, message: refreshed.message };
                            if (refreshed.ok) {
                                const latest = refreshed.status;
                                const nextIndex = Number(latest.next_chunk);
                                if (nextIndex > chunkIndex) {
                                    if (!Array.isArray(latest.chunk_hashes) ||
                                        latest.chunk_hashes[chunkIndex] !== chunkHash) {
                                        return {
                                            ok: false,
                                            status: 409,
                                            message: 'El PC confirma un bloque distinto al del archivo seleccionado. Cancela y empieza de nuevo.'
                                        };
                                    }
                                    wholeFileHasher.update(view);
                                    current = latest;
                                    failedAttempts = 0;
                                    continue;
                                }
                                if (nextIndex < chunkIndex) {
                                    return {
                                        ok: false,
                                        status: 409,
                                        message: 'El estado de la transferencia retrocedió inesperadamente. Cancela y empieza de nuevo.'
                                    };
                                }
                                current = latest;
                            }
                            if (failedAttempts < 3 && !cancelRequested && !revocationHandled) {
                                await new Promise(resolve => setTimeout(resolve, 350 * (2 ** failedAttempts)));
                                failedAttempts++;
                                continue;
                            }
                        }

                        return {
                            ok: false,
                            status: response.status,
                            message: response.message || 'No se pudo transferir un bloque del archivo.',
                            progress: current,
                            retryable: response.retryable
                        };
                    }
                    return { ok: true, progress: current, sha256: wholeFileHasher.hex() };
                }

                async function finalizeUpload(transferId) {
                    let response = await authorizedFetch('/upload/finish/' + encodeURIComponent(transferId), { method: 'POST' });
                    if (response.status === 401) {
                        return { revoked: true, message: 'La sesión se ha revocado.' };
                    }
                    if (!response.ok && response.status === 409) {
                        // A lost chunk response is recovered through status. If the
                        // server still says incomplete, do not claim completion.
                        const status = await getUploadStatus(transferId);
                        if (status.revoked) return { revoked: true, message: status.message };
                        if (status.ok && Number(status.status.received_bytes) === Number(status.status.size_bytes)) {
                            response = await authorizedFetch('/upload/finish/' + encodeURIComponent(transferId), { method: 'POST' });
                        }
                    }
                    if (!response.ok) {
                        return {
                            ok: false,
                            status: response.status,
                            message: await responseError(response, 'No se pudo verificar y finalizar el archivo.')
                        };
                    }
                    try {
                        const data = await response.json();
                        if (!data.files || data.files.length !== 1) {
                            return { ok: false, message: 'La respuesta de finalización no contiene exactamente un archivo.' };
                        }
                        return { ok: true, receipt: data.files[0] };
                    } catch (_) {
                        return { ok: false, message: 'El servidor devolvió una respuesta de integridad no válida.' };
                    }
                }

                async function cancelPendingUpload(transferId, storageKey) {
                    if (transferId && !revocationHandled && localStorage.getItem('aether_token')) {
                        try {
                            await authorizedFetch('/upload/cancel/' + encodeURIComponent(transferId), { method: 'DELETE' });
                        } catch (_) {}
                    }
                    if (storageKey) {
                        try { sessionStorage.removeItem(storageKey); } catch (_) {}
                    }
                }

                async function cancelCurrentUpload() {
                    if (!uploadInProgress) return;
                    cancelRequested = true;
                    const xhr = activeUploadXhr.current;
                    if (xhr && xhr.readyState !== XMLHttpRequest.DONE) xhr.abort();
                    const status = document.getElementById('progressStatus');
                    if (status) status.innerText = 'Cancelando y limpiando el archivo temporal…';
                }

                async function uploadFiles() {
                    const input = document.getElementById('fileInput');
                    if (input.files.length === 0 || uploadInProgress) return;

                    const files = Array.from(input.files);
                    if (files.length > 32) {
                        showToast('Selecciona como máximo 32 archivos por operación.', false);
                        input.value = '';
                        return;
                    }
                    if (!window.sha256 || typeof window.sha256 !== 'function') {
                        showToast('No se pudo cargar el módulo de verificación SHA-256. Recarga la página e inténtalo de nuevo.', false);
                        return;
                    }

                    uploadInProgress = true;
                    cancelRequested = false;
                    input.disabled = true;
                    const progressContainer = document.getElementById('progressContainer');
                    const progressStatus = document.getElementById('progressStatus');
                    const progressPercent = document.getElementById('progressPercent');
                    const progressBar = document.getElementById('progressBar');
                    const cancelButton = document.getElementById('cancelUploadButton');
                    const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
                    let completedBytes = 0;
                    let sentFiles = 0;
                    let userCancelled = false;
                    const failures = [];

                    function setProgress(loadedBytes) {
                        const percent = totalBytes > 0
                            ? Math.max(0, Math.min(100, Math.floor((loadedBytes / totalBytes) * 100)))
                            : (sentFiles === files.length ? 100 : 0);
                        progressBar.style.width = percent + '%';
                        progressPercent.innerText = percent + '%';
                    }

                    setBridgeState('transferring', 'Enviando archivos en bloques verificados…');
                    progressContainer.classList.remove('hidden');
                    cancelButton.classList.remove('hidden');
                    setProgress(0);

                    try {
                        for (let index = 0; index < files.length; index++) {
                            if (revocationHandled || !localStorage.getItem('aether_token')) break;
                            if (cancelRequested) { userCancelled = true; break; }
                            const file = files[index];
                            const storageKey = uploadStorageKey(file);
                            let transferId = null;
                            activeTransferId = null;
                            progressStatus.innerText = 'Preparando ' + file.name + ' (' + (index + 1) + ' de ' + files.length + ')…';

                            try {
                                const started = await getOrStartUpload(file, storageKey);
                                if (started.revoked || revocationHandled) break;
                                if (!started.ok) throw new Error(started.message || 'No se pudo iniciar la transferencia.');
                                transferId = started.transferId;
                                activeTransferId = transferId;
                                let status = started.status;
                                const alreadyReceived = Number(status.received_bytes) || 0;
                                setProgress(completedBytes + alreadyReceived);
                                progressStatus.innerText = (started.resumed ? 'Reanudando ' : 'Subiendo ') +
                                    file.name + ' · bloque ' + (Number(status.next_chunk) + 1) + ' de ' + status.chunks_total;

                                const chunks = await transferFileInChunks(file, transferId, status, totalBytes, completedBytes);
                                if (chunks.revoked || revocationHandled) break;
                                if (chunks.cancelled || cancelRequested) {
                                    await cancelPendingUpload(transferId, storageKey);
                                    userCancelled = true;
                                    break;
                                }
                                if (!chunks.ok) {
                                    if ([400, 403, 404, 409, 413].includes(chunks.status)) {
                                        await cancelPendingUpload(transferId, storageKey);
                                    }
                                    throw new Error(chunks.message || 'La transferencia se ha interrumpido.');
                                }

                                progressStatus.innerText = 'Verificando en disco ' + file.name + '…';
                                cancelButton.disabled = true;
                                const finished = await finalizeUpload(transferId);
                                cancelButton.disabled = false;
                                if (finished.revoked || revocationHandled) break;
                                if (!finished.ok) {
                                    if ([400, 403, 404, 409, 413].includes(finished.status)) {
                                        await cancelPendingUpload(transferId, storageKey);
                                    }
                                    throw new Error(finished.message || 'No se pudo finalizar la transferencia.');
                                }

                                const receipt = finished.receipt;
                                if (receipt.filename !== file.name ||
                                    Number(receipt.size_bytes) !== file.size ||
                                    !/^[a-f0-9]{64}$/.test(receipt.sha256) ||
                                    receipt.sha256 !== chunks.sha256) {
                                    await cancelPendingUpload(transferId, storageKey);
                                    throw new Error('La respuesta de integridad del servidor no coincide con el archivo.');
                                }
                                try { sessionStorage.removeItem(storageKey); } catch (_) {}
                                sentFiles++;
                                completedBytes += file.size;
                                setProgress(completedBytes);
                            } catch (error) {
                                if (revocationHandled) break;
                                if (cancelRequested) {
                                    await cancelPendingUpload(transferId, storageKey);
                                    userCancelled = true;
                                    break;
                                }
                                failures.push(file.name + ': ' + String(error));
                                // Keep transfer IDs on transient/network failure so the
                                // next selection of the same file can resume at its next block.
                            } finally {
                                if (activeTransferId === transferId) activeTransferId = null;
                            }
                        }
                    } finally {
                        uploadInProgress = false;
                        input.disabled = false;
                        cancelButton.disabled = false;
                        cancelButton.classList.add('hidden');
                        progressContainer.classList.add('hidden');
                        activeUploadXhr.current = null;
                        activeTransferId = null;
                        cancelRequested = false;
                    }

                    if (revocationHandled) return;
                    if (userCancelled) {
                        setBridgeState('paired', 'Transferencia cancelada');
                        showToast('Transferencia cancelada. Se ha intentado borrar el temporal del PC.', false);
                    } else if (sentFiles === files.length) {
                        input.value = '';
                        setBridgeState('paired', 'Transferencia completada');
                        showToast(files.length === 1
                            ? 'Archivo enviado y verificado correctamente.'
                            : 'Todos los archivos se enviaron y verificaron correctamente.', true);
                    } else if (sentFiles > 0) {
                        setBridgeState('paired', 'Transferencia parcial');
                        showToast('Se enviaron ' + sentFiles + ' de ' + files.length + ' archivos. ' + (failures[0] || ''), false);
                    } else {
                        setBridgeState('paired', 'No se pudo completar la transferencia');
                        showToast(failures[0] || 'La transferencia no se completó. Comprueba la conexión y vuelve a intentarlo.', false);
                    }
                }

                document.getElementById('cancelUploadButton').addEventListener('click', cancelCurrentUpload);

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

                document.getElementById('pinSubmit').addEventListener('click', verifyPin);
                document.getElementById('pinInput').addEventListener('keydown', event => {
                    if (event.key === 'Enter') verifyPin();
                });
                document.getElementById('fileInput').addEventListener('change', uploadFiles);
                document.getElementById('sendClipboardButton').addEventListener('click', sendClipboard);
                document.getElementById('refreshClipboardButton').addEventListener('click', () => syncClipboard(true));

                checkAuth();
