# Modelo de amenazas

## 1. Activos a proteger

- Datos de inventario, certificados, scans, discovery y hallazgos de cada
  organizacion.
- Credenciales de usuarios, refresh tokens y API keys de agentes.
- Secretos de infraestructura: `JWT_SECRET`, password de PostgreSQL, claves de
  LLM y `deploy/.env`.
- Integridad de los resultados y del audit log.
- Disponibilidad de la plataforma y de los agentes.
- Red interna del cliente (no debe quedar expuesta por el agente ni por SSRF).

## 2. Supuestos

- El operador controla la plataforma, la base y los backups.
- El cliente controla el host del agente y su archivo `agent.yaml`.
- TLS del deploy se termina en Caddy con un certificado valido.
- La red del cliente permite egress HTTPS al backend, no ingress al agente.
- El LLM externo, si se habilita, es un tercero bajo una decision de privacidad
  del operador/cliente.

## 3. Tabla de amenazas

| # | Amenaza | Mitigacion implementada | Riesgo residual | Evidencia |
|---|---|---|---|---|
| 1 | Un tenant lee datos de otro | `organization_id` no nulo + sesion `tenant` fail-closed, `with_loader_criteria` en ORM, `Session.get/refresh/merge` acotados, 404 cruzado, prohibicion de SQL textual/Core en sesion tenant | Sin RLS: un bug en una sesion `system` o en la logica de aplicacion puede cruzar datos. No hay cifrado por tenant. Un DBA/operador ve todo | `test_multitenant_isolation.py`, `tenancy.py`, `db.py` |
| 2 | SSRF: usar el escaner cloud contra la red interna de la plataforma | Bloqueo de rangos privados/reservados/loopback/link-local/metadatos, resolucion DNS y fijacion a IP, validacion de todas las respuestas y revalidacion antes de conectar; puertos `0`/fuera de rango rechazados; un job cloud sin targets pinned falla cerrado; `CLOUD_SCAN_BLOCK_PRIVATE=true` obligatorio fuera de `dev` | Categorias nuevas de rangos reservados, errores de resolucion o bugs en la fijacion de IP. IPv6 y proxies corporativos requieren revision | `cloud_network.py`, `cloud_guardrails.py`, `discovery_service.py`, tests M2 |
| 3 | Escanear terceros sin autorizacion | Declaracion de autorizacion versionada y auditada, cuotas por organizacion, limite de hosts de discovery, ejecutor cloud solo publico | No se verifica propiedad del dominio ni identidad del solicitante. Un usuario autorizado puede mentir en la declaracion; el control es contractual/auditable, no tecnico | `cloud_guardrails.py`, audit log, tests M2 |
| 4 | Robo de API key de agente | Rol `agent` acotado a ingesta/tareas de su agente, derivacion de organizacion desde la key, rotacion/revocacion inmediata, HTTPS, rate-limit, payload validado | Sin mTLS: quien tenga la key puede enviar datos falsos **solo a su agente/organizacion** y reclamar sus tareas. La key vive en variable de entorno del host | `api/deps.py`, `agent_service.py`, tests agent |
| 5 | Plataforma comprometida ordena al agente escanear redes arbitrarias | Tareas opt-in (`allow_remote_tasks=false` por defecto), allowlists locales de CIDR/puertos, topes por tarea, solo `scan`/`discovery`, validacion y fijacion de IP antes de I/O | Un atacante con control total de la plataforma puede mover datos dentro de lo que el cliente permita y enviar tareas; no hay tareas firmadas ni mTLS. El agente confia en su config local | `agent/remote_tasks.py`, tests M3/E2E |
| 6 | Certificado/banner/finding de agente malicioso manipula al LLM (prompt injection) | Los metadatos de findings del agente se descartan y reconstruyen desde un catalogo server-side; solo se conserva evidencia saneada y las reglas desconocidas se rechazan con `422`. Todo campo no confiable del prompt va delimitado con nonce, hay anonimizacion, salida saneada, cobertura de hallazgos, modo `template` por organizacion y LLM externo solo con `ai_mode=external` | La salida del LLM puede ser imprecisa o manipulada; los findings deterministicos no dependen de ella. La anonimizacion no es perfecta y el texto puede contener patrones identificables | `finding_catalog.py`, `ai_privacy.py`, `ai_recommendations.py`, `test_agent_prompt_injection.py`, tests M6 |
| 7 | DoS por un tenant | Cuotas de agentes/scans/schedules, rate-limit de auth e ingesta, `MAX_CONCURRENT_SCANS`, limite de payload de agente (2 MiB), limite de discovery cloud | Limites en memoria por proceso: no se comparten entre replicas ni sobreviven reinicios. Un scan grande compite con requests en el unico worker. Sin WAF/cola | `cloud_guardrails.py`, `config.py`, tests M2 |
| 8 | Fuga de datos del cliente hacia la nube | `upload_level` (`minimal`/`standard`/`full`), `pseudonymize` (`off`/`internal`/`strict`), `--dry-run`, agente solo egress, NVD sin identidad del host, LLM solo si se habilita | En `full` sale handshake crudo y `rawResult`; metadatos y patrones pueden reidentificar. NVD/LLM son terceros. Sin cifrado adicional extremo a extremo | `agent/minimize.py`, `agent/pseudonymize.py`, `data_flow.md` |
| 9 | Robo de credenciales de usuario | Argon2id, bloqueo por intentos, access token corto, refresh rotativo con revocacion de cadena, rate-limit de auth, auditoria, cookies `Secure` | Sin 2FA/MFA. Phishing, malware en el cliente o reuso de password siguen siendo posibles. Existe cambio de password propio, pero no recuperacion por email | `auth_service.py`, `routers/auth.py`, tests auth |
| 10 | Fuga o perdida de backups/DB | Volumen PostgreSQL persistente, backup manual documentado, DB sin puerto publico | Backups sin cifrado ni retencion automatica; quien acceda al volumen o al dump ve todos los tenants. No hay restore automatico probado en produccion | `deploy/README.md`, `hardening.md` |
| 11 | Secreto `JWT_SECRET` debil o filtrado | La app no arranca fuera de `dev` sin secreto; `.env.example` exige generar uno; `.env` no versionado | Si se filtra, un atacante puede firmar tokens validos hasta rotarlo. No hay rotacion automatica de claves | `config.py`, `deploy/.env.example` |
| 12 | Admin inicial o bootstrap inseguro | Bootstrap solo si no hay usuarios, password fuerte recomendado, se puede quitar tras el primer login | Si se deja `BOOTSTRAP_ADMIN_PASSWORD` en el entorno, queda expuesta en la config del host. No hay forzado de cambio de password | `routers/auth.py`, `deploy/README.md` |
| 13 | Manipulacion del audit log | `audit_logs` solo-insercion desde la app; acciones sensibles auditadas con actor/org/IP | El operador/DB puede alterar la tabla; no hay hash chain ni WORM. No hay exportacion a SIEM | `audit`/modelos, tests |
| 14 | Enumeracion de IDs entre tenants | UUIDs y 404 uniforme en recursos de otra organizacion | IDs secuenciales en algunas tablas internas y diferencias de timing pueden filtrar existencia si se combinan con otros canales | `test_multitenant_isolation.py` |
| 15 | Dependencia/ imagen comprometida | Imagenes pineadas, CI con build y tests, `.gitattributes` LF para scripts | Sin escaneo de vulnerabilidades de imagenes/dependencias ni firma de imagenes en CI. Actualizar requiere rebuild manual | `.github/workflows/ci.yml`, `deploy/` |
| 16 | Enumeracion de emails entre organizaciones | El email es unico global; un duplicado en otra organizacion se rechaza con `409` y mensaje generico, sin revelar la organizacion propietaria | Un admin puede inferir que el email ya existe en la plataforma (no en que organizacion). No se permite reutilizar el mismo email en dos tenants | `user_service.py`, `test_user_email_uniqueness.py` |

## 4. Riesgos residuales prioritarios

1. **Sin RLS de PostgreSQL**: el control principal es de aplicacion. Es el riesgo
   tecnico mas importante para una plataforma compartida.
2. **Sin mTLS para agentes**: una key robada permite datos falsos en el propio
   agente/organizacion.
3. **Un solo proceso**: no hay aislamiento de recursos entre tenants a nivel de
   workers; un tenant puede consumir el scheduler.
4. **Sin 2FA**: el robo de credenciales de un `admin` sigue siendo critico.
5. **Backups sin cifrado/automaticos**: riesgo de fuga masiva y de perdida.
6. **LLM externo**: la anonimizacion reduce pero no elimina el riesgo de
   reidentificacion; requiere aprobacion de privacidad.

## 5. Fuera de alcance / trabajo futuro

- RLS y roles DB separados (migrador vs runtime).
- mTLS, tareas firmadas y enrolamiento con token de un solo uso.
- 2FA/MFA, recuperacion de cuenta y politicas de password.
- Cola de trabajos, scheduler distribuido y rate-limit compartido.
- Cifrado en reposo por tenant y gestion de claves (KMS).
- Backup automatico cifrado y pruebas de restore.
- WAF/limites de request en el proxy, metricas y alertas.
- Verificacion de propiedad de dominio para autorizar escaneos.
- Escaneo de dependencias/imagenes y firma de artefactos en CI.

## 6. Que no afirmar

- No afirmar que el multi-tenant es "imposible de vulnerar": afirmar que hay
  filtro fail-closed, constraints, tests de dos organizaciones y 404 cruzado.
- No afirmar que el agente es "inalcanzable": afirmar que solo inicia conexiones
  salientes y que no abre puertos.
- No afirmar que el LLM "no ve datos del cliente": depende de `upload_level`,
  `pseudonymize` y `ai_mode`; el modo `template` no hace llamadas externas.
- No afirmar que hay alta disponibilidad: hay un solo backend y una sola DB en
  el compose de referencia.
