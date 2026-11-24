# Aislamiento multi-tenant

## 1. Modelo

- **Organizacion = tenant = cliente.** Un usuario pertenece a una sola
  organizacion (`User.organization_id`).
- No existe super-admin cross-org por API ni UI. Las organizaciones se crean,
  deshabilitan y purgan con la CLI del operador (`python -m tls_analyzer.cli
  create-org|list-orgs|disable-org|enable-org|delete-org --purge`). Un `admin`
  solo administra su organizacion.
- Un agente pertenece a una organizacion. La organizacion de los datos que
  ingesta se deriva del agente/API key, nunca del cuerpo del payload.
- Una instalacion dedicada es simplemente una instancia con una organizacion;
  el aislamiento esta siempre activo.

## 2. Mecanismo de filtro

### 2.1 Modo de sesion

Cada `Session` debe declarar explicitamente su modo antes de consultar
(`api/tenancy.py`):

| Modo | Uso | organization_id |
|---|---|---|
| `tenant` | Requests autenticadas de una organizacion | Obligatorio |
| `system` | Auth, schedulers, CLI, migraciones/backfill | No aplica; puede cruzar organizaciones |

Si una sesion no declara modo, o declara `tenant` sin `organization_id`, toda
consulta ORM falla con `RuntimeError` (**fail-closed**). `api/db.py::get_db`
asigna `system` solo a rutas `/api/auth/`; el resto de requests autenticadas
recibe `tenant` con la organizacion del contexto de auth.

### 2.2 Filtro ORM automatico

`api/tenancy.py::install_tenancy` instala eventos sobre la clase de sesion:

- `do_orm_execute`: para cada `SELECT`/`UPDATE`/`DELETE` ORM agrega
  `with_loader_criteria` a todos los modelos `TenantMixin` con
  `organization_id == <org de la sesion>`. Cubre queries, `count()`, joins y
  relaciones.
- En sesion `tenant`, rechaza SQL textual (`TextClause`) y queries Core que
  referencien tablas tenant; no intenta reescribir SQL que no puede acotar.
- `UPDATE` en sesion tenant no puede asignar `organization_id`.
- `before_flush` completa `organization_id` en objetos nuevos, rechaza inserts
  con otra organizacion y rechaza cambios de `organization_id` en objetos
  existentes.
- `api/db.py::TenantSession` sobreescribe `get`, `refresh` y `merge` para que
  una PK de otra organizacion devuelva `None` o falle, en vez de filtrar datos
  ajenos.

### 2.3 Regla de 404

Un recurso que existe pero pertenece a otra organizacion se trata como
inexistente: **404**, no 403. Esto evita confirmar IDs de otros tenants. Los
tests de aislamiento recorren rutas con dos organizaciones y verifican 404 en
scans, servicios, certificados, issues, agentes, tareas y reportes.

## 3. Tablas con `organization_id`

Usan `TenantMixin` (`api/models.py`), con FK no nula a `organizations.id`:

`assets`, `services`, `certificates`, `scans`, `findings`, `teams`,
`team_members`, `issues`, `issue_history`, `alerts`, `alert_thresholds`,
`compliance_windows`, `discovery_jobs`, `discovery_results`, `api_keys`,
`integrations`, `agents`, `agent_tasks`, `scan_cve_matches`, `recurring_scans`,
`users`, `refresh_tokens`, `audit_logs`.

Tablas globales (sin `organization_id`, por diseno): `organizations`, `cves`,
`cve_query_cache` y `alembic_version`. La cache CVE no contiene datos del
cliente.

### Indices y constraints representativos

- `services`: unico `(organization_id, host, port)` para servicios plataforma
  (sin agente); indices por `organization_id` y `agent_id`.
- `assets`: unico `(organization_id, ip_address, hostname)` para activos
  plataforma.
- `teams`: unico `(organization_id, name)`.
- `issues`: identidad por organizacion (`organization_id` + `service_id` +
  `source_document` + `rule_id`), mas indices por estado/severidad/owner.
- `agent_tasks`: indice `(organization_id, status, created_at)` para el claim.
- Migracion de aislamiento: `da42b1f2c841_multi_tenant_isolation.py`; FKs tenant
  restauradas en `e91f3a7c2d10_restore_tenant_parent_foreign_keys.py`.

## 4. Flujo de auth y scoping

1. El middleware valida JWT, refresh token o API key y arma `AuthContext`
   (`api/deps.py`).
2. Para usuario, la organizacion sale de `User.organization_id`; si esta
   deshabilitada, se rechaza el login/refresh/API key.
3. Para API key de agente, la organizacion sale del agente asociado; una key no
   puede sobrescribirla con un campo del payload.
4. `get_db` abre `TenantSession` y llama `set_tenant_session(db, org_id)`.
5. Servicios, routers y reportes consultan sin filtro manual; el evento ORM lo
   aplica. Los schedulers abren sesiones `system` y pasan explicitamente el
   `organization_id` de cada fila que procesan.
6. Bootstrap, backfills y CLI usan sesiones `system`; los inserts de filas
   tenant deben declarar `organization_id` explicitamente.

## 5. CLI del operador

```bash
python -m tls_analyzer.cli list-orgs
python -m tls_analyzer.cli create-org --name "Cliente A" \
  --admin-email admin@cliente-a.example --slug cliente-a \
  --ai-mode template --max-agents 10 --max-cloud-scans-per-hour 60 \
  --max-recurring-scans 10
python -m tls_analyzer.cli disable-org --slug cliente-a
python -m tls_analyzer.cli enable-org --slug cliente-a
python -m tls_analyzer.cli delete-org --slug cliente-a --purge
```

`delete-org --purge` pide confirmacion escribiendo el slug y borra datos de la
organizacion. Los comandos legacy `org-list`, `org-create`, `org-disable`,
`org-enable`, `org-delete` siguen disponibles.

## 6. Tests y verificacion

- `tests/test_multitenant_isolation.py`: dos organizaciones, 404 cruzado,
  prohibicion de SQL/Core en sesion tenant, inmutabilidad de
  `organization_id`, scoping de PK, API keys, enumeracion de rutas, CLI/purge y
  cobertura de tablas tenant.
- `tests/test_migration_parity.py`: modelos vs Alembic en SQLite y PostgreSQL.
  - Suite completa: **355 passed** en SQLite y **355 passed** en PostgreSQL 16
    (runtime real, `psycopg`), incluida la paridad de modelos/migraciones.
- `tests/test_sla_settings.py`: settings/SLA por organizacion y auditoria.
- Suite completa: **355 passed** en SQLite y **355 passed** en PostgreSQL 16
  (runtime real, `psycopg`).
- El deploy de referencia se probo con una imagen Docker, migraciones al
  arrancar y PostgreSQL 16; `/health` respondio 200.

## 7. Limitaciones conocidas

1. **No hay RLS de PostgreSQL.** El aislamiento es de aplicacion (ORM) y
   constraints. Una consulta en sesion `system` puede cruzar organizaciones por
   diseno; un bug en un servicio `system` no lo detiene la base.
2. **No hay defensa en profundidad a nivel DB.** RLS con
   `SET app.current_organization` y politicas por tabla es trabajo futuro.
3. **SQL textual/Core** se rechaza en sesion tenant, pero no se analiza
   semanticamente: la regla es prohibirlo, no reescribirlo.
4. **Sin cifrado por tenant ni claves por organizacion.** Todos los datos viven
   en la misma base; el cifrado en reposo depende de la infraestructura.
5. **Sin super-admin cross-org por API/UI.** La operacion cross-org requiere
   acceso a la CLI/servidor.
6. **Schedulers y rate-limits en un solo proceso.** No hay coordinacion
   multi-instancia; ver `docs/hardening.md`.
7. **Migraciones y backfills** corren en sesion `system` y deben revisarse a
   mano; no estan aislados por tenant.
8. **La organizacion del agente** se deriva de la key; si la key se filtra, el
   atacante puede enviar datos falsos solo a ese agente/organizacion hasta que
   se revoque.

## 8. Como agregar una tabla tenant

1. Heredar de `TenantMixin` (no declarar `organization_id` a mano).
2. Agregar migracion con FK no nula, indice por `organization_id` y uniques que
   incluyan `organization_id`.
3. Usar sesiones tenant en routers/servicios; no usar `SessionLocal()` directo.
4. Agregar el modelo a la lista de cobertura de
   `test_multitenant_isolation.py` y un test de 404 cruzado.
5. Actualizar `test_migration_parity.py` para comparar columnas/FKs.
