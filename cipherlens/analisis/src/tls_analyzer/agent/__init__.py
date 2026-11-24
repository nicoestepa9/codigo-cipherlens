"""Agente de recoleccion on-premise (Parte 5).

El agente corre dentro de la red del cliente, escanea objetivos y discovery, y
sube **solo** los resultados por HTTPS saliente (nunca abre puertos de escucha).
No depende de FastAPI ni SQLAlchemy: usa solo el nucleo puro ``tls_analyzer``.
"""

from .config import AgentConfig, ConfigError, load_config

__all__ = ["AgentConfig", "load_config", "ConfigError"]
