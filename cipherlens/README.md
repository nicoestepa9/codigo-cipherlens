# CryptoGuard - TLS Security Platform

Plataforma de análisis de seguridad TLS con scanner en vivo, monitoreo de expiración de certificados, discovery de servicios y alertas.

La plataforma se compone de dos procesos:

| Componente | Carpeta | Tecnología | Puerto |
|---|---|---|---|
| **Backend (API)** | `analisis/` | Python + FastAPI + SQLite | `8000` |
| **Frontend (UI)** | `frontend/` | Next.js (React) | `3000` |

El frontend se comunica con el backend a través de un proxy interno: toda ruta `/api/*` del frontend se reenvía a `http://127.0.0.1:8000/api/*`. **El backend debe estar corriendo para que la UI muestre datos reales.**

---

## Requisitos

- **Python** 3.10+
- **Node.js** 20+ (viene con `npm`)
- Sistema operativo: Windows (los comandos del README asumen PowerShell)

---

## 1. Backend (FastAPI)

### Instalación (solo la primera vez)

```powershell
cd cipherlens\analisis
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

### Ejecución

> [!IMPORTANT]
> Para desarrollo arrancá el backend **siempre** con `ENV=dev` y `DISABLE_API_AUTH=true` (esta última solo se acepta con `ENV=dev`; el default de `ENV` es `production`). Si lo levantás sin `DISABLE_API_AUTH`, la API exige el header `X-API-Key` y el frontend recibe `401 Unauthorized` (los requests de la UI fallan).

```powershell
cd cipherlens\analisis
.venv\Scripts\activate
$env:ENV = "dev"
$env:DISABLE_API_AUTH = "true"
$env:ALERTS_ENABLED = "false"
python -m tls_analyzer.main serve-api
```

Opciones:

```powershell
# Puerto/host custom
python -m tls_analyzer.main serve-api --port 8000 --host 127.0.0.1

# Auto-reload (modo desarrollo, reinicia al editar código)
python -m tls_analyzer.main serve-api --reload

# Accesible desde otra máquina/VM (necesario si abrís la UI desde 192.168.56.1)
python -m tls_analyzer.main serve-api --host 0.0.0.0
```

> Para usar la API real con API key (modo producción), generá una key en la UI (**Integrations / API**) y enviá el header `X-API-Key: cg_...` en cada request.

### Variables de entorno (opcionales)

La configuración se lee de variables de entorno; los valores por defecto son los que se muestran:

```powershell
$env:DATABASE_URL     = "sqlite:///cryptoguard.db"   # Base de datos SQLite
$env:ENV              = "dev"                        # Requerido para poder desactivar la auth (default: production)
$env:DISABLE_API_AUTH = "true"                       # Desactiva el check de API key (solo con ENV=dev)
$env:ALERTS_ENABLED   = "false"                      # Desactiva el scheduler de alertas
$env:ALERTS_INTERVAL_MINUTES = "15"                  # Frecuencia del scheduler de alertas
$env:JWT_SECRET       = "cambio_este_valor_por_un_secreto_real"  # Requerido fuera de ENV=dev; en dev se genera uno efímero automáticamente. Para producción, generá uno con `python -c "import secrets; print(secrets.token_urlsafe(48))"` y exportá la variable.
$env:CORS_ORIGINS     = "*"                          # Orígenes permitidos (separados por coma)
$env:SCAN_TIMEOUT     = "10.0"                       # Timeout por defecto de los scans (segundos)
```

Receta típica para desarrollo local:

```powershell
cd cipherlens\analisis
$env:ENV = "dev"
$env:DISABLE_API_AUTH = "true"
$env:ALERTS_ENABLED = "false"
.venv\Scripts\activate
python -m tls_analyzer.main serve-api
```

### Recomendaciones con IA (opcional)

Los scans exponen una recomendación generada con IA. Por defecto usa un proveedor local (`template`). Para usar Anthropic:

```powershell
$env:AI_PROVIDER = "anthropic"
$env:AI_API_KEY  = "sk-ant-..."     # o ANTHROPIC_API_KEY
$env:AI_MODEL    = "claude-3-5-sonnet-latest"   # opcional
$env:AI_API_URL  = "https://api.anthropic.com/v1/messages"  # opcional
```

### Verificación

- Swagger UI (documentación interactiva): <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>
- Ruta raíz: <http://127.0.0.1:8000/> (info del servicio)

---

## 2. Frontend (Next.js)

### Instalación (solo la primera vez)

```powershell
cd cipherlens\frontend
npm install
```

### Ejecución

```powershell
cd cipherlens\frontend
npm run dev
```

Abrir <http://localhost:3000> en el navegador.

### Acceso desde otra máquina / VM

Si abrís la UI desde otra máquina o una VM (por ejemplo `http://192.168.56.1:3000` desde un VirtualBox host-only), necesitás dos ajustes:

1. **Permitir el origen en el dev server de Next.js.** En `frontend/next.config.ts` ya están configurados `allowedDevOrigins` con `127.0.0.1` y `192.168.56.1`. Si usás otra IP, agregala ahí y **reiniciá el dev server** (los cambios de `next.config.ts` no aplican con hot-reload):

   ```ts
   allowedDevOrigins: ["127.0.0.1", "192.168.56.1"],
   ```

2. **El backend también debe escuchar en esa red.** Por defecto `serve-api` bindea a `127.0.0.1`, así que arrancalo expuesto:

   ```powershell
   python -m tls_analyzer.main serve-api --host 0.0.0.0
   ```

   Y asegurate de que el proxy del frontend apunte al backend correcto (`NEXT_PUBLIC_API_PROXY_TARGET`, default `http://127.0.0.1:8000`).

Si ves `401 Unauthorized` en la consola del navegador al cargar los datos, es porque el backend arrancó sin `DISABLE_API_AUTH=true` (ver sección Backend → Ejecución).

### Variables de entorno (opcionales)

```powershell
$env:NEXT_PUBLIC_API_PROXY_TARGET = "http://127.0.0.1:8000"   # A dónde reenvía /api/* (default)
$env:NEXT_PUBLIC_USE_MOCK          = "true"                    # Forza datos mock desde el arranque
```

- `NEXT_PUBLIC_API_PROXY_TARGET`: destino del proxy `/api/*`. Solo hay que cambiarla si el backend corre en otra máquina/puerto (en ese caso también habría que apuntar `API_BASE_URL`).
- `NEXT_PUBLIC_USE_MOCK`: si se setea en `"true"`, la app arranca usando datos de muestra sin necesidad de backend. **Por defecto la app usa el backend real.**

### Toggle "mock vs real" desde la UI

En **Settings → Data Source** hay un switch **"Use mock data"**:

- **Off (default)**: la app consulta el backend real en `/api`.
- **On**: la app usa datos de muestra (no requiere backend).

La elección se guarda en `localStorage` y se aplica en la próxima navegación. Útil para demos o para desarrollar sin tener el backend levantado.

---

## 3. Flujo completo (inicio rápido)

En **dos terminales separadas**:

**Terminal 1 — Backend:**

```powershell
cd cipherlens\analisis
$env:ENV = "dev"
$env:DISABLE_API_AUTH = "true"
$env:ALERTS_ENABLED = "false"
.venv\Scripts\activate
python -m tls_analyzer.main serve-api
```

**Terminal 2 — Frontend:**

```powershell
cd cipherlens\frontend
npm run dev
```

Luego abrir <http://localhost:3000>.

---

## 4. Tests

### Backend

```powershell
cd cipherlens\analisis
.venv\Scripts\activate
python -m pytest tests/ -v
```

### Frontend

```powershell
cd cipherlens\frontend
npm run lint
npx tsc --noEmit
```

---

## 5. Estructura de carpetas

```
cipherlens/
├── README.md                       # Este archivo
│
├── analisis/                       # Backend
│   ├── pyproject.toml              # Paquete y dependencias Python
│   ├── cryptoguard.db              # Base SQLite (se genera sola)
│   ├── src/tls_analyzer/
│   │   ├── main.py / cli.py        # CLI: scan, nist, serve, serve-api
│   │   ├── api/                    # FastAPI: routers, services, models, schemas
│   │   └── handshake.py, certificate.py, scanner.py, nist.py, ...
│   └── tests/                      # Suite pytest (106 tests)
│
└── frontend/                       # Frontend
    ├── package.json
    ├── next.config.ts              # Proxy /api/* -> http://127.0.0.1:8000/api/*
    └── src/
        ├── app/                    # Páginas (dashboard, scanner, certificates, ...)
        └── services/               # Clientes de la API y mocks (config.ts, *Service.ts)
```
