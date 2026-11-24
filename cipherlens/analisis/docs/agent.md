# Agente on-premise

El agente ejecuta análisis TLS y descubrimiento desde la red donde se instala. Envía los resultados a CryptoGuard mediante conexiones salientes y no escucha en puertos propios.

## Instalación y configuración

Desde `cipherlens/analisis`, con el entorno virtual activo:

```powershell
python -m pip install -e ".[agent,sslyze]"
cryptoguard-agent run --help
```

Usá [agent.yaml](../agent.yaml) como base. Ajustá `server_url` a la URL HTTPS de la plataforma y configurá los objetivos autorizados. Creá el agente desde la sección **Agentes** del frontend y cargá su clave en la variable de entorno `CRYPTOGUARD_AGENT_KEY`. El campo `api_key_env` permite usar otro nombre de variable.

## Comprobación y arranque

```powershell
cryptoguard-agent run --config agent.yaml --once --dry-run
cryptoguard-agent run --config agent.yaml
```

`--dry-run` ejecuta las comprobaciones de los objetivos configurados e imprime los datos que se enviarían. Necesita conectividad a esos objetivos, aunque no requiere una clave ni envía resultados a la plataforma. `--once` limita la ejecución a un ciclo.

Para desarrollo con un backend HTTP en localhost, el CLI admite `--allow-insecure-localhost`. En Docker, configurá una URL de la plataforma accesible desde el contenedor. Su `127.0.0.1` apunta al propio contenedor. El [Compose de ejemplo](../docker-compose.agent.example.yml) monta el YAML y conserva el estado en un volumen.

## Datos y mantenimiento

- `upload_level` admite `minimal`, `standard` y `full`. `standard` es el valor por defecto. `full` incluye el resultado crudo. El [flujo de datos](./data_flow.md) detalla los campos y destinos.
- `pseudonymize` admite `off`, `internal` y `strict`. El YAML del repositorio configura `internal`. Si se omite el campo y la variable `CRYPTOGUARD_PSEUDONYMIZE` está ausente, el código usa `off`.
- El mapeo de seudónimos queda en el estado local. Consultalo con `cryptoguard-agent resolve <seudónimo>` o exportalo con `cryptoguard-agent export-mapping --out mapa.csv`.
- Para usar una CA propia, indicá la ruta del archivo PEM en `ca_bundle` o `CRYPTOGUARD_CA_BUNDLE`.
- Las tareas remotas requieren habilitación local y listas de redes y puertos autorizados. El agente las consulta desde su conexión saliente.
- Si rotás la clave desde la sección **Agentes**, actualizá la variable de entorno del agente y reiniciá el proceso.
