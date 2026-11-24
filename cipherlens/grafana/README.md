# CryptoGuard en Grafana (Parte 6)

Grafana como código: un Grafana con el plugin **Infinity** preinstalado que
consume los endpoints de solo lectura `/api/reports/*` de CryptoGuard y muestra
un dashboard de overview.

## Requisitos

- Docker y Docker Compose.
- Un backend CryptoGuard accesible desde el contenedor.
- Una **ApiKey de rol `viewer`** (ver abajo).

## 1. Crear la ApiKey de rol `viewer`

La key la crea un administrador. Desde el frontend (página **Integrations /
API**) o por API:

```bash
curl -X POST "$CRYPTOGUARD_URL/api/api-keys" \
  -H "Authorization: Bearer <token-admin>" \
  -H "Content-Type: application/json" \
  -d '{"name":"grafana","role":"viewer","expiresInDays":365}'
```

La respuesta incluye el campo `key` (se muestra una sola vez). Copiá ese valor.

> Una key de rol `viewer` solo puede leer reportes; no puede modificar nada.

## 2. Configurar

```bash
cp .env.example .env
# editar CRYPTOGUARD_URL y CRYPTOGUARD_API_KEY
```

- `CRYPTOGUARD_URL`: base de la API. Si Grafana corre en Docker y el backend en
  el host, usá `http://host.docker.internal:8000`.
- `CRYPTOGUARD_API_KEY`: la key `viewer` creada arriba.

Estos valores se inyectan en el datasource provisionado
(`provisioning/datasources/cryptoguard.yaml`, campos `jsonData.allowedHosts` y
`secureJsonData.apiKeyValue`). **Nunca** se commitean valores reales.

## 3. Levantar

```bash
docker compose up -d
```

Grafana queda en <http://localhost:3001> (credenciales `GF_ADMIN_USER` /
`GF_ADMIN_PASSWORD`, por defecto `admin`/`admin`).

El dashboard **CryptoGuard - Overview** aparece en la carpeta `CryptoGuard`.

## Estructura

```
grafana/
  docker-compose.yml                 # Grafana + Infinity (versiones fijadas)
  .env.example                       # sin secretos
  provisioning/
    datasources/cryptoguard.yaml     # datasource Infinity (X-API-Key)
    dashboards/dashboards.yaml       # proveedor de dashboards
  dashboards/
    cryptoguard-overview.json        # dashboard exportado (uid estable)
```

## Variables del dashboard

`agent` (sitio), `team` y `service` se pueblan desde `/api/reports/dimensions`
mediante Infinity. Al elegir "Todos" (`allValue: "__all__"`) los filtros se omiten.

## Notas

- Los reportes se calculan bajo demanda y usan por defecto los últimos 90 días
  con `bucket=day`; el selector de rango de Grafana no se traduce a `from`/`to`
  (limitación documentada en `../analisis/docs/grafana_investigacion.md`).
- Si la Parte 5 (agentes) no está desplegada, el panel de agentes queda vacío
  sin romper el dashboard.
- El acceso a nivel de dashboard/organización se gestiona dentro de Grafana;
  la API solo garantiza el rol `viewer`.
