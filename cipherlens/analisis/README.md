# TLS Analyzer - Handshake Inspector & Vulnerability Scanner

Herramienta para analizar el handshake TLS de cualquier servidor, visualizar sus detalles y detectar vulnerabilidades de configuración.

## Requisitos

- Python 3.10+
- pip

## Instalación

```bash
cd pfi-tls
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

### Dependencia opcional: sslyze (detección SSLv3)

Para detectar soporte SSLv3 (necesario para CVE POODLE), instalar sslyze:

```bash
pip install -e .[sslyze]
```

Sin sslyze, el scanner no puede detectar SSLv3 porque Python's OpenSSL 3.0 lo tiene deshabilitado. La detección de TLS 1.0/1.1 funciona sin sslyze (usa curl/SChannel como fallback).

## Uso

### CLI (línea de comandos)

```bash
# Scan completo con output visual
python -m tls_analyzer scan example.com

# Scan con puerto custom
python -m tls_analyzer scan example.com:8443

# Scan con output JSON
python -m tls_analyzer scan example.com --json

# Scan con timeout personalizado
python -m tls_analyzer scan example.com --timeout 15

# Scan y guardar resultado en archivo JSON
python -m tls_analyzer scan example.com --save

# Scan, guardar JSON y mostrar en terminal
python -m tls_analyzer scan example.com --json --save

# Scan evaluando contra NIST SP 800-52 Rev.2 con perfil government-only
python -m tls_analyzer scan example.com --profile government-only

# Evaluar un JSON guardado (scans/*.json) contra NIST SP 800-52 Rev.2
python -m tls_analyzer nist scans/example.com_443_20260101_000000.json

# Evaluar contra los tres estándares (SP 800-52, SP 800-57 Part 1 y SP 800-131A) - default
python -m tls_analyzer nist scans/example.com_443_20260101_000000.json --standard all

# Evaluar contra un solo estándar
python -m tls_analyzer nist scans/example.com_443_20260101_000000.json --standard 800131a

# Fijar la fecha de evaluación (afecta las reglas de transición de SP 800-131A y el cronograma de 800-57)
python -m tls_analyzer nist scans/example.com_443_20260101_000000.json --evaluation-date 2026-08-02

# Evaluar un servidor directamente (handshake en vivo) sin archivo previo
python -m tls_analyzer nist https://example.com

# Igual, pero con perfil government-only, timeout de 15s y guardando el scan JSON crudo
python -m tls_analyzer nist example.com:443 --profile government-only --timeout 15 --save

# Evaluar y guardar el reporte NIST en otro archivo
python -m tls_analyzer nist scans/example.com_443_20260101_000000.json --output reporte.json

# Evaluar con salida JSON cruda
python -m tls_analyzer nist scans/example.com_443_20260101_000000.json --json
```

Los archivos guardados se crean en la carpeta `scans/` con formato `{host}_{puerto}_{fecha}_{hora}.json`.

### Web (interfaz gráfica)

```bash
python -m tls_analyzer serve
# Abrir http://localhost:5000 en el navegador
```

Opciones del servidor web:

```bash
python -m tls_analyzer serve --host 0.0.0.0 --port 8080 --debug
```

La interfaz web tiene un botón "Download JSON" para descargar los resultados del scan.

### API REST (FastAPI)

```bash
# Levantar el servidor API (puerto 8000 por defecto)
uvicorn tls_analyzer.api.main:app --reload --port 8000

# Abrir http://localhost:8000/docs para ver la documentación Swagger
```

La API key se genera desde los endpoints o la tabla `api_keys`. Se pasa como header `X-API-Key`.

### Seed de CVEs

Pobla la tabla local de CVEs con el detalle real desde NVD (score CVSS, resumen, fechas).
Ejecutar una vez después de la instalación inicial, o periódicamente para actualizar:

```bash
python -m tls_analyzer.scripts.seed_cves
```

> Nota: usa la API pública de NVD (5 requests/30s sin key). Tarda ~2 minutos para los 10 CVEs del mapping.

### Migraciones de base de datos (Alembic)

El esquema se gestiona con Alembic (`alembic.ini` + `migrations/`). La migración baseline
(`migrations/versions/`) crea todas las tablas del esquema actual.

**Base nueva:**

```bash
alembic upgrade head
```

**Base existente** (creada antes con `Base.metadata.create_all`, con datos): marcar como actual
sin ejecutar DDL sobre las tablas:

```bash
alembic stamp head
```

A partir de ahí, cada cambio de esquema se entrega como una migración nueva:

```bash
alembic revision --autogenerate -m "descripcion del cambio"
alembic upgrade head
```

> Nota: `autogenerate` se debe correr con `DATABASE_URL` apuntando a la base que se quiere usar
> como referencia. Para una base existente, `stamp` deja `alembic_version` en la baseline; las
> migraciones siguientes aplican solo los cambios nuevos. El arranque de la app sigue ejecutando
> `create_all` (idempotente) para no romper entornos de desarrollo y tests.

### Como librería Python

```python
from tls_analyzer.handshake import analyze_handshake
from tls_analyzer.certificate import fetch_certificate_chain
from tls_analyzer.scanner import scan

# Analizar handshake
handshake = analyze_handshake("example.com", 443)

# Obtener certificados
certs = fetch_certificate_chain("example.com", 443)

# Escanear vulnerabilidades
result = scan(handshake, certs, "example.com")

print(result.score)       # 0-100
print(result.to_json())   # JSON completo
```

## Estructura del proyecto

```
pfi-tls/
├── pyproject.toml                   # Configuración del paquete y dependencias
├── scans/                           # Archivos JSON guardados (--save)
│
├── src/tls_analyzer/
│   ├── __init__.py                  # Versión del paquete
│   ├── __main__.py                  # Entry point para `python -m tls_analyzer`
│   ├── main.py                      # Función main() que llama al CLI
│   │
│   ├── handshake.py                 # Core del handshake TLS
│   ├── certificate.py               # Análisis de certificados X.509
│   ├── scanner.py                   # Scanner de vulnerabilidades (deduplica hallazgos de los 3 estándares)
│   ├── nist.py                      # Reglas NIST SP 800-52 Rev.2
│   ├── nist80057.py                 # Reglas NIST SP 800-57 Part 1 Rev.5
│   ├── nist800131a.py               # Reglas NIST SP 800-131A Rev.2
│   ├── crypto_strength.py           # Helpers compartidos de fuerza criptográfica
│   ├── issues.py                    # Registro canónico de defectos (dedup entre estándares)
│   ├── compliance.py                # Reporte combinado de los 3 estándares
│   ├── serializers.py               # Conversión motor → DTO del frontend (camelCase)
│   │
│   ├── fingerprint/                 # OS/Service Fingerprint (compartido con Network Discovery)
│   │   ├── models.py                # ServiceFingerprint dataclass
│   │   ├── service_banner.py        # Banner grabbing (HTTP, SSH, SMTP)
│   │   └── tls_fingerprint.py       # JA3/JA3S hashes desde ClientHello/ServerHello
│   │
│   ├── cve_mapping.py               # Tabla estática rule_id → CVE IDs (POODLE, Sweet32, etc.)
│   ├── cpe_mapping.py               # Mapeo software_name → CPE (nginx, Apache, OpenSSH, etc.)
│   ├── nvd_client.py                # Cliente NVD REST API 2.0 (rate limited)
│   │
│   ├── report.py                    # Formateo de resultados para Rich (terminal)
│   ├── cli.py                       # CLI: parseo de argumentos, orquestación
│   │
│   ├── api/                         # Backend FastAPI
│   │   ├── main.py                  # App FastAPI + lifespan
│   │   ├── config.py                # Settings (env vars)
│   │   ├── db.py                    # SQLAlchemy engine + session
│   │   ├── deps.py                  # Auth dependency (API key)
│   │   ├── models.py                # ORM: Asset, Service, Certificate, Scan, Finding, Cve, ScanCveMatch, ...
│   │   ├── schemas.py               # Pydantic request/response (camelCase)
│   │   ├── seed.py                  # Seed data inicial
│   │   ├── routers/
│   │   │   ├── scans.py             # POST /api/scans, GET /api/scans
│   │   │   ├── cves.py              # GET /api/cves/{id}, GET /api/scans/{id}/cves, POST /api/cves/refresh
│   │   │   ├── discovery.py         # Network Discovery endpoints
│   │   │   └── ...                  # history, certificates, services, dashboard, etc.
│   │   └── services/
│   │       ├── scan_service.py      # Pipeline: handshake → fingerprint → CVEs → persist
│   │       ├── cve_service.py       # Lookup CVEs + cache 7d + NVD live query
│   │       └── ...                  # discovery, certificate, dashboard, etc.
│   │
│   ├── scripts/
│   │   └── seed_cves.py             # Seed de CVEs contra NVD
│   │
│   └── web/                         # Flask legacy (CLI web mode)
│       ├── app.py
│       └── templates/
│
└── tests/                           # 106 tests
    ├── test_handshake.py
    ├── test_certificate.py
    ├── test_scanner.py
    ├── test_nist.py
    ├── test_nist80057.py
    ├── test_nist800131a.py
    ├── test_compliance.py
    ├── test_serializers.py
    ├── test_discovery.py
    ├── test_api.py
    ├── test_alerts_engine.py
    ├── test_ai_recommendations.py
    └── test_web.py
```

## Qué hace cada módulo

### `handshake.py` - Conexión y handshake TLS

Se conecta al servidor por socket TCP + SSL/TLS y captura:

- **Protocolo negociado**: versión TLS acordada (1.0, 1.1, 1.2, 1.3)
- **Cipher suite negociada**: algoritmo de cifrado usado en la conexión
- **Protocolos soportados**: prueba cada versión TLS para ver cuáles acepta el servidor
- **Cipher suites aceptadas**: prueba cada cipher suite individualmente para mapear lo que acepta
- **Extensiones**: ALPN, NPN, compresión TLS
- **Certificado peer**: captura el certificado en formato DER para análisis posterior

Usa `ssl` y `socket` de la stdlib de Python.

### `certificate.py` - Análisis de certificados X.509

Parsea certificados usando la librería `cryptography`. Extrae:

- **Subject/Issuer**: CN, O, OU, C, ST, L
- **SAN**: Subject Alternative Names (DNS, IP, URI, email)
- **Validez**: fechas notBefore/notAfter, si está expirado, días restantes
- **Clave**: tipo (RSA, EC, Ed25519), tamaño en bits
- **Firmas**: algoritmo de firma (SHA-256, SHA-1, etc.)
- **Extensiones**: Key Usage, Extended Key Usage, Basic Constraints, OCSP Must-Staple
- **CA issuers y CRL distribution points**
- **Validación**: hostname mismatch, wildcard matching, cadena de confianza

### `scanner.py` - Detección de vulnerabilidades

Analiza los datos del handshake + certificado contra **tres estándares NIST**:

1. **NIST SP 800-52 Rev.2** (`nist.py`, agosto 2019) — guía de selección, configuración y uso de TLS.
2. **NIST SP 800-57 Part 1 Rev.5** (`nist80057.py`, mayo 2020) — fuerza de seguridad de claves y hashes, cronograma de la Tabla 4 (112 bits deja de ser aceptable en 2031).
3. **NIST SP 800-131A Rev.2** (`nist800131a.py`, marzo 2019) — fechas exactas de transición de algoritmos con los estados `acceptable` / `deprecated` / `legacy use` / `disallowed`.

Cada hallazgo cita la sección exacta del documento y tiene severidad:

| Severidad | Puntuación | Palabra clave NIST |
|-----------|-----------|--------------------|
| CRITICAL | -25 | "shall" / "shall not" |
| HIGH | -15 | "shall" / "shall not" |
| MEDIUM | -8 | "should" / "should not" |
| LOW | -3 | (retrocompatibilidad) |
| INFO | 0 | "may" (opcional) / cumple |
| NOT_EVALUABLE | 0 | Requiere info fuera del alcance del JSON |

**Deduplicación por defecto subyacente**: el mismo problema detectado por varios estándares (ej. una clave RSA de 1024 bits la marcan `80052-CERT-03`, `80057-KEY-01` y `800131a-SIG-01`) produce **un solo finding** cuyo id es el del estándar más severo (SP 800-52 primero). Los `details` del finding listan todos los estándares y rule-ids que lo detectaron (`standards` / `rule_ids`), y el score descuenta **una sola vez por defecto**.

Checks de SP 800-52 (todas en `src/tls_analyzer/nist.py`):

- **PROTO** (Sección 3.1): SSL 2.0/3.0, TLS 1.0/1.1, TLS 1.2 ausente, TLS 1.3 ausente
- **CERT** (Sección 3.2 / Tabla 3-1): cert expirado, vigencia > 3 años, clave débil, curva no aprobada, firma MD5/SHA-1, sin SAN, sin serverAuth, OCSP, AIA, autofirmado, Basic Constraints
- **CIPH** (Sección 3.3.1): 3DES/DES, suites fuera de las listas permitidas, sin forward secrecy, clave efímera débil, orden de preferencia, RSA key transport, CBC sin Encrypt-then-MAC, suites TLS 1.3
- **EXT** (Sección 3.4): renegotiation_info, extended_master_secret, OCSP stapling, supported_groups, key_share, raw public keys, client_certificate_url, early data, fallback SCSV
- **COMP** (Sección 3.7): compresión distinta de null
- **NOT_EVALUABLE** (Sección 3.6): FIPS 140, splicing, trust anchor store, 0-RTT, parcheo del SO

Reglas de SP 800-57 Part 1 (`nist80057.py`): KEY-01..07 (fuerza de claves, Tabla 2), HASH-01..03 (Tabla 3 y combinación 5.6.2), SCHED-01..04 (cronograma Tabla 4), COMBO-01..04 (fuerza efectiva), PQC-01 (vigilancia post-cuántica), CRYPTO-01/02 (cryptoperiods), REDUCE-01/02 (reducción de fuerza). Expone `compute_strengths()` con la fuerza efectiva de la conexión.

Reglas de SP 800-131A (`nist800131a.py`): BLK-01..05 (TDEA/SKIPJACK/AES), SIG-01..06 (firmas, con `len(n) >= 224` para ECC), RBG-01 (no observable), DH-01..06 (acuerdos DH/MQV; x25519 → `NOT_EVALUABLE` con nota de cobertura), RSA-01..04 (key transport PKCS#1 v1.5 → CRITICAL desde 2024), HASH-01..04 (SHA-1 en firma disallowed, SHA-1 como HMAC aceptable), MAC-01..03. Expone `classify()` que centraliza la lógica de las tablas.

Perfiles de aplicación (Sección 3.1 de SP 800-52): `citizen-facing` (default) y `government-only`.

El comando `nist` del CLI produce el **reporte combinado** (`compliance.py` → `evaluate_all()`): corre los estándares seleccionados sobre el mismo JSON y prefija cada rule-id con el código del estándar (ej. `80057-HASH-01` vs `800131a-HASH-01`) para máxima trazabilidad, además de un resumen por estándar.

### `report.py` - Formateo para terminal

Funciones que usan Rich para renderizar tablas y paneles con colores en la terminal. Se encarga de:

- Barra de score con colores (verde/amarillo/rojo)
- Tabla de cipher suites aceptadas
- Panel de info del certificado
- Lista de hallazgos ordenados por severidad

### `cli.py` - Interfaz de línea de comandos

Orquesta todo el flujo:

1. Parsea el argumento (host:port)
2. Llama a `analyze_handshake()`
3. Llama a `fetch_certificate_chain()`
4. Llama a `scan()`
5. Imprime resultados con Rich (`report.py`)
6. Si `--save`, guarda el JSON en `scans/`

También maneja `--json` para output estructurado y `serve` para lanzar Flask.

### `web/app.py` - Interfaz web (Flask)

- `GET /` - Muestra el formulario de scan
- `POST /scan` - Ejecuta scan y muestra resultados en HTML
- `POST /api/scan` - API JSON para consumo programático
- `POST /download` - Descarga los resultados como archivo JSON

El template `index.html` muestra score, handshakes, certificados y hallazgos con CSS customizado (tema oscuro).

## Tests

```bash
python -m pytest tests/ -v
```

106 tests que cubren:
- Parseo de targets (host, host:port, https://host)
- Serialización de HandshakeResult (dict, JSON)
- Validación de hostname (exacto, wildcard, SAN)
- Cálculo de score de seguridad
- Manejo de errores de conexión
- Motor NIST SP 800-52: reglas PROTO/CERT/CIPH/EXT/COMP, severidad NOT_EVALUABLE, perfiles citizen-facing/government-only
- Motor NIST SP 800-57 Part 1: fuerza de claves (KEY), hashes (HASH), cronograma (SCHED), combinación (COMBO), cryptoperiods (CRYPTO), fuerza efectiva
- Motor NIST SP 800-131A: `classify()` (4 estados), TDEA/SKIPJACK, firmas con len(n), x25519 → NOT_EVALUABLE, PKCS#1 v1.5 → CRITICAL, SHA-1 firma vs. HMAC
- Deduplicación en `scan()`: RSA-1024 detectado por los 3 estándares → un solo finding con `rule_ids` completo; el score descuenta una vez por defecto
- Reporte combinado `evaluate_all()`: 3 reportes, ids prefijados, resumen = suma de los resúmenes
- Fixture `github.com_443_20260727_214545.json` pasa limpio bajo los 3 estándares (sin CRITICAL/HIGH)
- Detección de archivo vs. target en el comando `nist`
- Web: template renderiza JSON válido en `#scan-data` (botón Download JSON), rutas `/` y `/download`
- Fingerprint: cálculo JA3/JA3S, parseo de banners HTTP/SSH/SMTP, ServiceFingerprint dataclass
- CVE mapping: tabla estática rule→CVE, CPE mapping, serialización relatedCves y liveCveMatches en DTOs
- Discovery: fingerprint reutilizado desde módulo compartido

---

## Guía de extensibilidad

Si querés agregar un parámetro nuevo de análisis (por ejemplo: verificar HSTS, detectar ROBOT, comprobar OCSP stapling, etc.), estos son los archivos que tenés que modificar:

### 1. `nist.py` - Agregar una regla nueva

Las reglas viven en `src/tls_analyzer/nist.py`, cada una con su ID (PROTO/CERT/CIPH/EXT/COMP/NE) y su sección de referencia del estándar.

**a) Crear la regla:** seguí el patrón de las existentes (usando `_mkfinding`), p. ej.:

```python
findings.append(_mkfinding(
    "CIPH-09",
    "Titulo de la regla",
    SEVERITY_HIGH,
    "SP 800-52 Rev.2, Section 3.3.1",
    "Normative statement del documento (shall / should)",
    f"observed_value con el dato detectado",
    "Recomendacion para corregirlo",
))
```

**b) Registrar la regla en `evaluate()`:** agregá la llamada (o la lista de checks de su familia) dentro de `def evaluate(data, profile)`.

**c) Si necesitás datos nuevos del scan**, agregalos en `handshake.py` / `certificate.py`:

- Para datos del certificado: agregá campos en `CertificateInfo` en `certificate.py` y parsealos en `_parse_cert()`
- Para datos de la conexión TLS: agregá campos en `HandshakeResult` en `handshake.py` y capturalos en `_do_handshake()`

### 2. `report.py` - Mostrar en terminal

Si el finding se muestra automáticamente (porque usa `_mkfinding` y el dict de severidad), no necesitás cambiar nada acá. Pero si querés agregar un panel especial, agregá una función de print y llamala desde `cli.py`.

### 3. `web/templates/index.html` - Mostrar en web

Los findings se renderizan automáticamente con el loop de Jinja (severidad, sección NIST, citación y valor observado). Solo necesitás cambiar algo si querés un estilo especial para tu nueva categoría.

### 4. `tests/test_nist.py` - Testear

```python
def test_mi_nueva_regla():
    data = _clean_data()  # scan JSON de base que no dispara reglas
    data["handshake"]["..."] = "..."  # forzar la condición a detectar
    report = evaluate(data)
    assert "MI_REGLA_ID" in _ids(report)
```

### Resumen rápido de qué archivo modificar

| Qué querés agregar | Archivos a modificar |
|--------------------|--------------------|
| Nueva regla NIST | `nist.py` |
| Nuevo dato del handshake TLS | `handshake.py` |
| Nuevo dato del certificado | `certificate.py` |
| Nuevo output visual (CLI) | `report.py` + `cli.py` |
| Nuevo output visual (web) | `web/templates/index.html` |
| Nuevo endpoint web | `web/app.py` |
| Nuevo argumento CLI | `cli.py` |
| Nuevo test | `tests/test_nist.py` |

## Ejemplo de output

Output de `python -m tls_analyzer scan cloudflare.com`:

```
+------------------------------- TLS Analyzer --------------------------------+
| Target: cloudflare.com:443                                                   |
| Time: 2026-07-27 20:28:26                                                    |
| Profile: citizen-facing                                                      |
+------------------------------------------------------------------------------+

+------------------------------- TLS Handshake --------------------------------+
|   Host        cloudflare.com                                                 |
|   IP          104.16.132.229                                                 |
|   Protocol    TLSv1.3                                                        |
|   Cipher      TLS_AES_256_GCM_SHA384                                         |
+------------------------------------------------------------------------------+

+-------------------- Certificate: cloudflare.com (Leaf) ---------------------+
|   Subject CN       cloudflare.com                                            |
|   Issuer           WE1                                                       |
|   Key Type         EC (secp256r1) 256-bit                                    |
|   Valid Until      2026-10-06 (70 days left)                                 |
|   SAN              cloudflare.com, *.cloudflare.com, ...                     |
+------------------------------------------------------------------------------+

+------------------------------- Scan Summary ---------------------------------+
| Security Score: #################### 100/100                                 |
| Findings: 6 total (0 critical, 0 high, 0 medium, 0 info, 6 not evaluable)    |
+------------------------------------------------------------------------------+
```

Output de `python -m tls_analyzer nist https://example.com` (reporte NIST). Por defecto evalúa los tres estándares y muestra el reporte combinado con ids prefijados (ej. `80052-NE-01`); con `--standard 80052` muestra solo SP 800-52:

```
+---------------------- NIST SP 800-52 Rev.2 Compliance ----------------------+
| Host: example.com:443                                                       |
| Profile: citizen-facing                                                     |
| Standard: NIST SP 800-52 Rev.2 (Aug 2019)                                   |
| Findings: 0 critical, 0 high, 0 medium, 0 info, 6 not evaluable             |
+-----------------------------------------------------------------------------+
+--------------------------- NOT_EVALUABLE | NE-01 ---------------------------+
| Validacion de modulo criptografico FIPS 140                                 |
| cryptographic modules shall be validated to FIPS 140                        |
| Reference: SP 800-52 Rev.2, Section 3.3.3                                   |
+-----------------------------------------------------------------------------+
```
