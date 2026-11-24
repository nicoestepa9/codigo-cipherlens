# Despliegue cloud con Docker Compose

Este directorio contiene el despliegue de referencia del **backend** CryptoGuard:
PostgreSQL 16, API FastAPI y Caddy como terminador TLS. El frontend Next.js se
despliega por separado (build estatico o `next start`) y consume esta API.

## Alcance y decisiones

- Caddy publica solo `80/443`, obtiene el certificado automaticamente y hace
  reverse proxy a `backend:8000`. El backend no publica puertos.
- PostgreSQL queda en la red `data`, marcada como `internal`; no tiene salida a
  Internet ni puertos publicados.
- El backend corre con un unico worker y una unica replica. Los schedulers,
  rate-limits y tareas en curso viven en memoria: **no escalar horizontalmente
  todavia** (ver `docs/hardening.md`).
- Las migraciones Alembic corren al iniciar el contenedor. Para desactivarlas,
  setear `RUN_MIGRATIONS=false` y ejecutarlas como paso separado.
- El contenedor del backend es `read_only`, con `/tmp` en `tmpfs`, `cap_drop:
  ALL`, `no-new-privileges` y usuario no-root.

## Prerrequisitos

- VM Linux con Docker Engine 27+ y Docker Compose v2.
- DNS: registro `A`/`AAAA` de `CRYPTOGUARD_DOMAIN` apuntando a la VM.
- Puertos `80/tcp`, `443/tcp` y `443/udp` abiertos para ACME/HTTP3.
- Egress `443/tcp` hacia NVD y, si se usa, el proveedor LLM.
- Frontend desplegado en otro origen HTTPS; ese origen exacto va en
  `CORS_ORIGINS`.

## Puesta en marcha

```bash
cd cipherlens/analisis
cp deploy/.env.example deploy/.env
# Editar deploy/.env: dominio, password de PostgreSQL, JWT_SECRET, CORS y admin.
docker compose -f deploy/docker-compose.cloud.yml up -d --build
docker compose -f deploy/docker-compose.cloud.yml ps
docker compose -f deploy/docker-compose.cloud.yml logs -f backend
```

Docker Compose carga automaticamente `deploy/.env` porque el archivo compose
esta en ese directorio. No commitear `deploy/.env`.

Validar:

```bash
curl -fsS "https://TU_DOMINIO/health"
docker compose -f deploy/docker-compose.cloud.yml exec backend python -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').status)"
```

El primer arranque crea el esquema y el admin inicial si
`BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` estan definidos y todavia no
hay usuarios. Despues del primer login, quitar esas dos variables de
`deploy/.env` y recrear el backend, o cambiar la password desde la UI.

## Variables obligatorias

| Variable | Uso |
|---|---|
| `CRYPTOGUARD_DOMAIN` | Dominio publico de la API; Caddy pide el certificado para ese nombre. |
| `POSTGRES_PASSWORD` | Password de PostgreSQL. Usar solo caracteres URL-safe (`A-Z a-z 0-9 . _ ~ -`) porque se interpola en `DATABASE_URL`. |
| `JWT_SECRET` | Firma de access tokens. Generar con `python -c "import secrets; print(secrets.token_urlsafe(48))"`. |
| `CORS_ORIGINS` | Origen exacto del frontend (lista separada por comas). No usar `*`. |
| `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` | Admin inicial opcional. Quitar tras el primer arranque. |

Variables opcionales utiles: `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`,
`DB_POOL_TIMEOUT`, `DB_POOL_RECYCLE`, `MAX_CONCURRENT_SCANS`,
`ALERTS_ENABLED`, `AI_PROVIDER`, `LOG_LEVEL`, `TZ`.

## Operacion

```bash
# Estado y logs
docker compose -f deploy/docker-compose.cloud.yml ps
docker compose -f deploy/docker-compose.cloud.yml logs --tail=200 backend caddy

# Backup logico de PostgreSQL
docker compose -f deploy/docker-compose.cloud.yml exec -T db \
  pg_dump -U cryptoguard -d cryptoguard -Fc > cryptoguard-$(date +%Y%m%d-%H%M).dump

# Restaurar en una base nueva (probar antes de produccion)
docker compose -f deploy/docker-compose.cloud.yml exec -T db \
  createdb -U cryptoguard cryptoguard_restore
docker compose -f deploy/docker-compose.cloud.yml exec -T db \
  pg_restore -U cryptoguard -d cryptoguard_restore < cryptoguard-YYYYMMDD-HHMM.dump
```

Los datos persistentes estan en los volumenes `pgdata`, `caddy_data` y
`caddy_config`. No borrar `pgdata` sin backup.

## Actualizacion

1. Backup de PostgreSQL.
2. `git pull` en la VM.
3. `docker compose -f deploy/docker-compose.cloud.yml build backend`
4. `docker compose -f deploy/docker-compose.cloud.yml up -d`
5. Revisar logs de migraciones y `https://TU_DOMINIO/health`.

Si una migracion falla, el backend no arranca y queda en restart loop. No
reintentar a ciegas: restaurar el backup o corregir la migracion en una copia
antes de volver a levantar.

## Limitaciones conocidas

- Una sola instancia/worker del backend (schedulers y rate-limit en memoria).
- Sin RLS de PostgreSQL; el aislamiento multi-tenant es a nivel ORM y
  constraints (ver `docs/multitenant.md`).
- Sin balanceador, cola de trabajos ni scheduler distribuido.
- Caddy sirve solo la API. Si se decide servir el frontend desde el mismo
  Caddy, hay que agregar el sitio y ajustar CSP; la CSP actual
  (`default-src 'none'`) es para respuestas de API.

## Troubleshooting

- **Caddy no obtiene certificado**: verificar DNS, puertos 80/443 y logs de
  `caddy`. Para una prueba local, usar `localhost` (Caddy usa CA interna).
- **502 desde Caddy**: revisar `docker compose ps`; el backend depende de que
  PostgreSQL este healthy y de que las migraciones terminen.
- **Error de conexion a PostgreSQL**: la password debe ser URL-safe o hay que
  sobreescribir `DATABASE_URL` completo con el valor URL-encoded.
- **CORS**: `CORS_ORIGINS` debe coincidir exactamente con el origen del
  frontend, incluido esquema y puerto.
- **Entrypoint con CRLF**: el repo fuerza LF para `*.sh` con `.gitattributes`.
