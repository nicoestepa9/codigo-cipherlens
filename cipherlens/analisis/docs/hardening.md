# Hardening y checklist de produccion

Documento operativo para el despliegue de referencia (`deploy/docker-compose.cloud.yml`).
No reemplaza una auditoria ni una prueba de penetracion. Describe el estado real
del codigo y lo que falta antes de exponer el servicio a Internet.

## 1. Estado actual del despliegue

| Control | Estado |
|---|---|
| TLS publico | Caddy con ACME automatico; solo se publican `80/443`. |
| Backend expuesto | No publica puertos; solo accesible por la red `edge` desde Caddy. |
| Base de datos | PostgreSQL 16 en red `data` interna, sin puertos publicados. |
| Contenedor backend | Usuario no-root, `read_only`, `/tmp` en `tmpfs`, `cap_drop: ALL`, `no-new-privileges`. |
| Migraciones | `alembic upgrade head` al arrancar (se puede desactivar con `RUN_MIGRATIONS=false`). |
| Documentacion de API | `EXPOSE_DOCS=false` por defecto; no se monta Swagger/OpenAPI. |
| Auth | JWT + refresh rotativo, Argon2id, RBAC, bloqueo por intentos, API keys. |
| Multi-tenant | Aislamiento por ORM/contexto tenant y constraints; **sin RLS**. |
| Proceso | Un worker y una replica; schedulers/rate-limits en memoria. |
| Secretos | Variables de entorno en `deploy/.env`; no versionado. |
| Backups | Manuales con `pg_dump`; no hay backup automatico incluido. |
| Observabilidad | Logs de Caddy/backend a stdout, `/health`; sin metricas ni alertas de infra. |

## 2. Checklist antes de produccion

### Secretos y cuentas

- [ ] `JWT_SECRET` aleatorio de al menos 32 bytes; distinto por ambiente.
- [ ] `POSTGRES_PASSWORD` largo y URL-safe, o `DATABASE_URL` URL-encoded.
- [ ] `BOOTSTRAP_ADMIN_PASSWORD` fuerte; eliminar las variables de bootstrap
      despues del primer arranque.
- [ ] `deploy/.env` con permisos restringidos (`chmod 600`) y fuera de git.
- [ ] Rotar credenciales ante cualquier sospecha; revocar API keys de agentes
      comprometidos.
- [ ] No reutilizar el password de PostgreSQL para otros servicios.

### Red y TLS

- [ ] DNS `A`/`AAAA` correcto antes de levantar Caddy.
- [ ] Puertos `80/tcp`, `443/tcp`, `443/udp` abiertos; el resto cerrado.
- [ ] Firewall de la VM limita SSH a IPs administrativas.
- [ ] `CRYPTOGUARD_DOMAIN` es el dominio real; no usar `localhost` en produccion.
- [ ] Renovacion ACME verificada (Caddy usa los volumenes `caddy_data`/`caddy_config`).
- [ ] Egress permitido solo a NVD y, si aplica, al proveedor LLM.
- [ ] Si se usa un proxy/WAF externo, no romper `X-Forwarded-*` y restringir
      quien puede llegar al backend.
- [ ] Confirmar que Caddy solo sirve la API o ajustar CSP si tambien sirve el
      frontend (la CSP actual es `default-src 'none'`).

### Aplicacion

- [ ] `ENV=production`.
- [ ] `DISABLE_API_AUTH` ausente o `false` (el codigo lo rechaza fuera de `dev`).
- [ ] `COOKIE_SECURE=true`.
- [ ] `CORS_ORIGINS` con el origen exacto del frontend; nunca `*`.
- [ ] `EXPOSE_DOCS=false`.
- [ ] `CLOUD_SCAN_BLOCK_PRIVATE=true`.
- [ ] `AI_PROVIDER=template` si no se aprobo el envio de datos a un LLM externo.
- [ ] Rate-limit de auth y de ingesta revisado para el trafico esperado.
- [ ] Un solo worker y una sola replica del backend.
- [ ] Confirmar que `/health` responde y que `/docs`/`/openapi.json` no son
      accesibles sin autenticacion.
- [ ] Revisar que los logs no contengan passwords, tokens, API keys ni payloads
      completos con datos sensibles.

### Base de datos

- [ ] Backup inicial tomado antes de la primera migracion.
- [ ] Probar restore en una base descartable.
- [ ] Backup programado y retencion definida.
- [ ] Migraciones probadas contra una copia de produccion.
- [ ] Pool (`DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT`,
      `DB_POOL_RECYCLE`) ajustado al limite de conexiones de PostgreSQL.
- [ ] Confirmar que el usuario actual de PostgreSQL es propietario del esquema.
      Para produccion se recomienda separar un rol migrador de un rol runtime con
      permisos minimos; **hoy el compose no hace esa separacion**.
- [ ] `PRAGMA foreign_key_check` no aplica; en PostgreSQL revisar constraints y
      migraciones aplicadas (`alembic current`).

### Agentes y datos

- [ ] Cada agente tiene su propia API key; no compartir claves entre sitios.
- [ ] El agente usa HTTPS y un `server_url` valido.
- [ ] `upload_level` y `pseudonymize` definidos por politica de datos.
- [ ] Revisar que el agente no envie `rawResult` ni datos internos innecesarios
      (`upload_level=full` solo para depuracion).
- [ ] Documentar que las consultas a NVD revelan CPE/producto/version y que el
      LLM externo recibe datos anonimizados (ver `docs/data_flow.md`).
- [ ] Definir retencion de scans, discovery, issues y logs.
- [ ] Validar autorizacion escrita del cliente antes de escanear objetivos.

### Operacion

- [ ] Healthcheck del backend y de PostgreSQL activos.
- [ ] Restart policy verificada.
- [ ] Monitoreo de disco (especialmente `pgdata` y logs) y de memoria.
- [ ] Alertas de caida, errores 5xx, fallos de migracion y espacio en disco.
- [ ] Runbook de incidentes y contacto responsable.
- [ ] Procedimiento de rollback documentado (imagen anterior + restore de DB).
- [ ] Actualizaciones de dependencias e imagenes revisadas y pineadas.

## 3. Riesgos y limites conocidos

1. **Sin RLS**: el aislamiento multi-tenant se apoya en el contexto de sesion,
   eventos ORM y constraints. Un bug de codigo podria omitir el filtro. RLS con
   `SET app.current_org` y politicas por tabla es trabajo futuro.
2. **Un solo proceso**: los schedulers de alertas/scans recurrentes, el
   rate-limit y las tareas en curso viven en memoria. Reiniciar el backend
   reinicia esos contadores y puede demorar tareas. No escalar a mas de una
   replica ni a mas de un worker sin redisenar esto.
3. **Rate-limit en memoria**: no se comparte entre procesos ni sobrevive
   reinicios; no es una defensa completa contra fuerza bruta distribuida.
4. **Sin cola de trabajos**: los scans corren en el proceso de la API. Un pico de
   carga compite con las requests.
5. **Sin separacion de roles DB**: el compose usa el usuario propietario para
   migraciones y runtime. Endurecerlo requiere un rol runtime sin DDL.
6. **Sin backup automatico**: `pg_dump` es manual. Programar backups y probar
   restores es obligatorio antes de produccion.
7. **Sin observabilidad de infraestructura**: solo logs y `/health`; no hay
   metricas, trazas ni alertas incluidas.
8. **Caddyfile de API**: si se sirve el frontend desde el mismo Caddy, la CSP
   actual bloquea los assets y hay que redisenarla.
9. **Superficie de escaneo**: habilitar escaneos cloud solo con autorizacion y
   mantener `CLOUD_SCAN_BLOCK_PRIVATE=true` fuera de desarrollo.
10. **LLM externo**: aunque se anonimiza, el envio a terceros implica una
    decision de privacidad y transferencia internacional que debe aprobarse.

## 4. Verificacion rapida del despliegue

```bash
# Servicios y salud
docker compose -f deploy/docker-compose.cloud.yml ps
curl -fsS "https://TU_DOMINIO/health"

# Migraciones aplicadas
docker compose -f deploy/docker-compose.cloud.yml exec backend alembic current

# Confirmar que no hay puertos del backend/db publicados
docker compose -f deploy/docker-compose.cloud.yml ps --format json

# Confirmar que docs no es publica
curl -s -o /dev/null -w "%{http_code}\n" "https://TU_DOMINIO/docs"

# Logs recientes
docker compose -f deploy/docker-compose.cloud.yml logs --tail=100 backend caddy
```

## 5. Trabajo futuro recomendado

- RLS de PostgreSQL con contexto de organizacion y tests de aislamiento a nivel DB.
- Rol runtime separado del rol migrador.
- Scheduler distribuido + cola (por ejemplo Celery/Redis) y workers separados.
- Rate-limit compartido (Redis) y limites de request en Caddy/WAF.
- Backups automaticos con verificacion de restore.
- Metricas (Prometheus), trazas y alertas.
- Rotacion/expuracion de secretos y escaneo de dependencias en CI.
- Pruebas de carga y de penetracion antes de exponer datos reales.
