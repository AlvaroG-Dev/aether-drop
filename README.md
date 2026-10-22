# AetherDrop

**Transferencia local entre ordenador y móvil, sin nube.**

AetherDrop es un prototipo de escritorio construido con Rust + Tauri 2 y Axum. El ordenador sirve una aplicación web móvil en la red local y permite compartir archivos desde y hacia el PC.

> **Estado: prototipo de desarrollo. No uses esta versión para información confidencial.** El transporte sigue usando HTTP sin cifrar. Ni el PIN, ni los tokens, ni SHA-256 convierten una conexión HTTP en una conexión cifrada o autenticada frente a un atacante activo de la red. No se debe anunciar como cifrado de extremo a extremo.

## Implementado

### Transferencias y almacenamiento
- Subidas en streaming: los archivos no se cargan completos en la RAM.
- Cada archivo se escribe en un temporal aleatorio situado en la misma carpeta de destino.
- Antes de publicarlo, el servidor sincroniza el temporal, calcula SHA-256 sobre el flujo recibido y vuelve a leer el temporal en bloques de 128 KiB. Comprueba que tamaño y hash de los bytes guardados coinciden con los del flujo.
- Publicación sin sobrescritura mediante un enlace duro atómico. Si el nombre ya existe, la operación devuelve conflicto; no reemplaza el archivo anterior.
- Un archivo por petición HTTP de subida. Si el usuario elige varios, el cliente los envía secuencialmente y comunica resultados parciales sin presentar como correcto un archivo fallido.
- Descargas por streaming; el servidor no hace `read()` del archivo entero.
- Tickets de descarga aleatorios, de un solo uso, vinculados al dispositivo, archivo y sesión, con expiración de 60 segundos.
- Temporales incompletos se eliminan al producirse un error y los temporales abandonados con más de 24 horas se limpian en el arranque, al cambiar de carpeta y periódicamente.

### Límites actuales
- Tamaño máximo del cuerpo de subida: 2 GiB.
- Máximo por archivo: 2 GiB menos 1 MiB para dejar margen al envoltorio multipart.
- Máximo de tres subidas simultáneas.
- El cliente permite elegir hasta 32 archivos en una selección, enviándolos como peticiones independientes.
- Máximo de 256 archivos en la lista «Archivos para enviar».
- Portapapeles limitado a 1 MiB de texto.
- Las peticiones de autenticación tienen limitación de intentos por IP y los bloqueos y sesiones caducadas se limpian periódicamente.

Estos valores son límites defensivos del prototipo, no cuotas de almacenamiento ni garantía contra llenar un disco.

### Sesiones y servidor
- PIN de seis dígitos, tokens de sesión aleatorios con duración de 12 horas, y cancelación de sesiones al revocar un dispositivo.
- La revocación cancela transferencias activas; las subidas comprueban cancelación y expiración mientras leen el cuerpo.
- El límite de intentos de PIN es por IP (10 intentos en la ventana de un minuto, seguido de un bloqueo temporal).
- Se comprueban los encabezados Host y Origin para reducir accesos por DNS rebinding y peticiones cruzadas desde páginas web.
- El servidor comunica fallos al abrir el puerto, deja de anunciar mDNS si no puede enlazar el puerto y tiene un cierre ordenado.
- Los errores del portapapeles del sistema se devuelven explícitamente; la aplicación no responde con éxito si el portapapeles del sistema ha fallado.
- La interfaz móvil y el escritorio cargan JavaScript externo. Se han añadido políticas CSP y encabezados de seguridad básicos.

## Limitaciones de seguridad conocidas

- **El transporte sigue usando HTTP en el puerto 8080 y escucha en las interfaces de red locales.** El token Bearer, el PIN y el contenido pueden ser observados o manipulados por un atacante capaz de interceptar la red.
- El SHA-256 de una subida compara los bytes recibidos con una lectura posterior del archivo temporal. Detecta discrepancias de escritura/almacenamiento, pero no constituye una prueba criptográfica del archivo original en el móvil ni protege el contenido frente a un atacante de red.
- La comprobación Host/Origin reduce algunas rutas de ataque del navegador, pero no es sustituto de TLS.
- Los tickets de descarga evitan poner el token Bearer en el enlace; siguen viajando por HTTP y su protección depende de la seguridad de esa conexión.
- Los bloqueos de sesión son en memoria y desaparecen al reiniciar. No hay persistencia de dispositivos ni recuperación de transferencias interrumpidas.
- La publicación mediante enlaces duros atómicos requiere que el sistema de archivos de destino soporte hard links. Si no lo soporta, la transferencia falla de forma explícita en vez de degradar a una publicación con riesgo de sobrescritura.
- El proyecto no ha completado una auditoría de seguridad ni pruebas de transferencia entre dispositivos reales. No expongas el puerto 8080 a Internet ni uses esta versión con archivos sensibles.

Para un transporte realmente seguro hace falta diseñar una identidad de servidor que el navegador móvil pueda verificar —no basta con añadir un certificado autofirmado— o pasar a un cliente móvil nativo con una estrategia de confianza de claves verificable. Solo entonces debe evaluarse si procede afirmar cifrado de extremo a extremo.

## Desarrollo

Instala las dependencias del sistema para [Tauri 2](https://v2.tauri.app/start/prerequisites/), Rust y Node.js 22.

```bash
npm install
npm run tauri dev
```

Comprobaciones locales equivalentes a CI:

```bash
node --check src/app.js
node --check src-tauri/src/mobile.js
cargo fmt --manifest-path src-tauri/Cargo.toml --all
cargo test --locked --manifest-path src-tauri/Cargo.toml
cargo check --locked --manifest-path src-tauri/Cargo.toml
cargo clippy --all-targets --locked --manifest-path src-tauri/Cargo.toml
```

El workflow de GitHub Actions ejecuta estas comprobaciones de JavaScript y Rust en Ubuntu, incluidos tests, compilación y Clippy. Una CI correcta no sustituye las pruebas de interfaz y transferencia en Windows, Linux y teléfonos físicos.

## Contribuir

Al informar de un fallo, incluye sistema operativo, navegador/teléfono, tamaño del archivo y pasos para reproducirlo. No adjuntes archivos privados, PIN, tokens ni datos sensibles.
