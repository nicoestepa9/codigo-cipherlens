"""Configuracion del backend CryptoGuard (FastAPI)."""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

# Load .env.local (takes precedence) then .env from project root
_project_root = Path(__file__).resolve().parents[3]
load_dotenv(_project_root / ".env.local", override=False)
load_dotenv(_project_root / ".env", override=False)

logger = logging.getLogger(__name__)


def _bool(name: str, default: str) -> bool:
    return os.getenv(name, default).lower() == "true"


def _csv(name: str, default: str) -> list[str]:
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]


def _jwt_secret(env: str) -> str:
    """JWT_SECRET obligatorio fuera de dev; en dev genera uno efímero."""
    secret = os.getenv("JWT_SECRET", "").strip()
    if secret:
        return secret
    if env != "dev":
        raise SystemExit(
            "Falta JWT_SECRET y ENV != 'dev': la aplicacion no arranca sin un "
            "secreto de firmado. Genera uno con "
            "`python -c \"import secrets; print(secrets.token_urlsafe(48))\"` "
            "y agregalo a .env.local (o setea ENV=dev solo para desarrollo)."
        )
    logger.warning(
        "JWT_SECRET no configurado y ENV=dev: se genera un secreto efimero; "
        "las sesiones se invalidaran en cada reinicio."
    )
    return secrets.token_urlsafe(48)


class Settings:
    """Configuracion por variables de entorno (con defaults para SQLite)."""

    def __init__(self) -> None:
        # --- Base ---
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///cryptoguard.db")
        self.db_pool_size = int(os.getenv("DB_POOL_SIZE", "10"))
        self.db_max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "10"))
        self.db_pool_timeout = int(os.getenv("DB_POOL_TIMEOUT", "30"))
        self.db_pool_recycle = int(os.getenv("DB_POOL_RECYCLE", "1800"))
        if min(self.db_pool_size, self.db_max_overflow, self.db_pool_timeout, self.db_pool_recycle) < 1:
            raise SystemExit("Los parametros del pool de base de datos deben ser mayores que cero.")
        self.env = os.getenv("ENV", "production")
        self.cors_origins = _csv("CORS_ORIGINS", "*")
        # No permitir comodin "*" junto con credenciales (inseguro y rechazado por navegadores).
        self.cors_allow_credentials = "*" not in self.cors_origins
        self.expose_docs = _bool("EXPOSE_DOCS", "false")
        self.disable_api_auth = _bool("DISABLE_API_AUTH", "false")
        if self.disable_api_auth and self.env != "dev":
            raise SystemExit(
                "DISABLE_API_AUTH=true solo se permite con ENV=dev. "
                "El default de ENV es 'production' (modo seguro); en desarrollo "
                "setea ENV=dev explicitamente."
            )
        if self.disable_api_auth:
            logger.warning(
                "DISABLE_API_AUTH=true: autenticacion desactivada en desarrollo; "
                "las requests usan la organizacion por defecto."
            )

        # --- AI ---
        self.ai_provider = os.getenv("AI_PROVIDER", "template")
        self.ai_api_key = (
            os.getenv("AI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
            or os.getenv("GEMINI_API_KEY")
            or ""
        )
        self.ai_model = os.getenv("AI_MODEL", "claude-3-5-sonnet-latest")
        self.ai_api_url = os.getenv("AI_API_URL", "https://api.anthropic.com/v1/messages")
        self.ai_anonymization = os.getenv("AI_ANONYMIZATION", "internal")
        self.ai_internal_domains = _csv("AI_INTERNAL_DOMAINS", "")
        self.ai_field_max_len = int(os.getenv("AI_FIELD_MAX_LEN", "200"))
        self.ai_output_max_chars = int(os.getenv("AI_OUTPUT_MAX_CHARS", "30000"))
        self.ai_link_allowlist = _csv(
            "AI_LINK_ALLOWLIST",
            "nvd.nist.gov,csrc.nist.gov,nvlpubs.nist.gov,datatracker.ietf.org",
        )
        self.ai_log_prompts = _bool("AI_LOG_PROMPTS", "false")

        # --- Alerts ---
        self.alerts_enabled = _bool("ALERTS_ENABLED", "true")
        self.recurring_scans_enabled = _bool(
            "RECURRING_SCANS_ENABLED", str(self.alerts_enabled).lower()
        )
        self.alerts_interval_minutes = int(os.getenv("ALERTS_INTERVAL_MINUTES", "15"))
        self.scan_tick_interval_minutes = int(os.getenv("SCAN_TICK_INTERVAL_MINUTES", "15"))

        # --- Scans ---
        self.max_concurrent_scans = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
        self.scheduled_scan_fail_threshold = int(
            os.getenv("SCHEDULED_SCAN_FAIL_THRESHOLD", "3")
        )
        self.default_timeout = float(os.getenv("SCAN_TIMEOUT", "10.0"))
        self.cloud_scan_block_private = _bool(
            "CLOUD_SCAN_BLOCK_PRIVATE", "true"
        )
        if not self.cloud_scan_block_private and self.env != "dev":
            raise SystemExit(
                "CLOUD_SCAN_BLOCK_PRIVATE=false solo se permite con ENV=dev."
            )
        self.cloud_discovery_max_hosts = int(
            os.getenv("CLOUD_DISCOVERY_MAX_HOSTS", "256")
        )
        if self.cloud_discovery_max_hosts < 1:
            raise SystemExit("CLOUD_DISCOVERY_MAX_HOSTS debe ser mayor que cero.")
        self.default_max_agents = int(os.getenv("DEFAULT_MAX_AGENTS", "10"))
        self.default_max_cloud_scans_per_hour = int(
            os.getenv("DEFAULT_MAX_CLOUD_SCANS_PER_HOUR", "60")
        )
        self.default_max_recurring_scans = int(
            os.getenv("DEFAULT_MAX_RECURRING_SCANS", "10")
        )
        if min(
            self.default_max_agents,
            self.default_max_cloud_scans_per_hour,
            self.default_max_recurring_scans,
        ) < 1:
            raise SystemExit("Los límites por defecto de organización deben ser mayores que cero.")

        # --- Auth (Parte 1) ---
        self.jwt_secret = _jwt_secret(self.env)
        self.access_token_minutes = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
        self.refresh_token_days = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))
        self.cookie_secure = _bool("COOKIE_SECURE", "true")
        self.cookie_domain = os.getenv("COOKIE_DOMAIN")
        self.login_max_failures = int(os.getenv("LOGIN_MAX_FAILURES", "5"))
        self.login_lockout_minutes = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
        self.auth_rate_limit_per_minute = int(
            os.getenv("AUTH_RATE_LIMIT_PER_MINUTE", "10")
        )
        self.bootstrap_admin_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "")
        self.bootstrap_admin_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
        self.argon2_time_cost = int(os.getenv("ARGON2_TIME_COST", "3"))
        self.argon2_memory_cost = int(os.getenv("ARGON2_MEMORY_COST", "65536"))
        self.argon2_parallelism = int(os.getenv("ARGON2_PARALLELISM", "4"))

        # --- Issues / SLA (Parte 2) ---
        self.issue_min_severity = os.getenv("ISSUE_MIN_SEVERITY", "medium")
        self.issue_verify_after_clean_scans = int(
            os.getenv("ISSUE_VERIFY_AFTER_CLEAN_SCANS", "2")
        )
        self.sla_days_critical = int(os.getenv("SLA_DAYS_CRITICAL", "7"))
        self.sla_days_high = int(os.getenv("SLA_DAYS_HIGH", "30"))
        self.sla_days_medium = int(os.getenv("SLA_DAYS_MEDIUM", "90"))
        self.risk_acceptance_max_days = int(
            os.getenv("RISK_ACCEPTANCE_MAX_DAYS", "365")
        )

        # --- Agente on-premise (Parte 5) ---
        self.agent_ingest_max_bytes = int(
            os.getenv("AGENT_INGEST_MAX_BYTES", str(2 * 1024 * 1024))
        )
        self.agent_ingest_rate_per_minute = int(
            os.getenv("AGENT_INGEST_RATE_PER_MINUTE", "60")
        )
        self.agent_heartbeat_seconds = int(os.getenv("AGENT_HEARTBEAT_SECONDS", "60"))
        # Un agente sin heartbeat dentro de esta ventana se considera offline.
        self.agent_offline_seconds = int(
            os.getenv("AGENT_OFFLINE_SECONDS", str(self.agent_heartbeat_seconds * 5))
        )
        self.agent_task_lease_seconds = max(
            30, int(os.getenv("AGENT_TASK_LEASE_SECONDS", "600"))
        )
        self.agent_task_max_attempts = max(
            1, int(os.getenv("AGENT_TASK_MAX_ATTEMPTS", "3"))
        )
        self.agent_task_ttl_seconds = max(
            60, int(os.getenv("AGENT_TASK_TTL_SECONDS", "3600"))
        )
        self.agent_max_findings = int(os.getenv("AGENT_MAX_FINDINGS", "1000"))
        self.agent_max_discovery_results = int(
            os.getenv("AGENT_MAX_DISCOVERY_RESULTS", "5000")
        )
        self.agent_max_discovery_targets = int(
            os.getenv("AGENT_MAX_DISCOVERY_TARGETS", "1024")
        )
        self.agent_max_discovery_ports = int(
            os.getenv("AGENT_MAX_DISCOVERY_PORTS", "256")
        )

        # --- Reportes para Grafana (Parte 6.2) ---
        self.reports_max_range_days = int(os.getenv("REPORTS_MAX_RANGE_DAYS", "366"))
        self.reports_max_buckets = int(os.getenv("REPORTS_MAX_BUCKETS", "400"))


settings = Settings()
