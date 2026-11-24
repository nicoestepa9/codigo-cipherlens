"""Valida los artefactos de `grafana/` (Parte 6.3/6.7): YAML/JSON validos,
uid consistente y ausencia de secretos."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

GRAFANA_DIR = Path(__file__).resolve().parents[2] / "grafana"

DATASOURCE_UID = "cryptoguard-infinity"
# Una ApiKey real es "cg_" + token_urlsafe(32) (~43 chars). El placeholder de
# .env.example es mas corto, por eso exigimos 40+.
SECRET_RE = re.compile(r"cg_[A-Za-z0-9_\-]{40,}")


def _load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from _walk_dicts(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_dicts(v)


def test_expected_files_exist():
    for rel in (
        "docker-compose.yml",
        ".env.example",
        "README.md",
        "provisioning/datasources/cryptoguard.yaml",
        "provisioning/dashboards/dashboards.yaml",
        "dashboards/cryptoguard-overview.json",
    ):
        assert (GRAFANA_DIR / rel).is_file(), f"falta {rel}"


def test_compose_pins_versions():
    compose = _load_yaml(GRAFANA_DIR / "docker-compose.yml")
    grafana = compose["services"]["grafana"]
    assert "grafana/grafana:" in grafana["image"]
    assert not grafana["image"].endswith(":latest")
    plugins = grafana["environment"]["GF_PLUGINS_PREINSTALL"].strip()
    # En Grafana 11.6 la variable es GF_PLUGINS_PREINSTALL (no *_SYNC, que se
    # ignora) con sintaxis oficial <plugin>@<version>@<URL>. Con ";" el plugin
    # no se instala.
    assert plugins.startswith("yesoreyeram-infinity-datasource@")
    assert "@https://" in plugins
    # Version del plugin fijada por URL de release.
    assert "releases/download/v" in plugins
    # Instalacion bloqueante: el datasource debe existir al servir.
    assert grafana["environment"]["GF_PLUGINS_PREINSTALL_ASYNC"] == "false"


def test_datasource_provisioning_valid():
    ds = _load_yaml(GRAFANA_DIR / "provisioning/datasources/cryptoguard.yaml")
    datasources = ds["datasources"]
    assert len(datasources) == 1
    entry = datasources[0]
    assert entry["uid"] == DATASOURCE_UID
    assert entry["type"] == "yesoreyeram-infinity-datasource"
    assert entry["url"] == "${CRYPTOGUARD_URL}"
    assert entry["jsonData"]["auth_method"] == "apiKey"
    assert entry["jsonData"]["apiKeyKey"] == "X-API-Key"
    assert entry["jsonData"]["allowedHosts"] == ["${CRYPTOGUARD_URL}"]
    # El secreto se inyecta por variable de entorno, nunca hardcodeado.
    assert entry["secureJsonData"]["apiKeyValue"] == "${CRYPTOGUARD_API_KEY}"


def test_dashboard_provider_valid():
    prov = _load_yaml(GRAFANA_DIR / "provisioning/dashboards/dashboards.yaml")
    providers = prov["providers"]
    assert providers and providers[0]["options"]["path"] == "/var/lib/grafana/dashboards"


def test_dashboard_uid_matches_datasource_and_is_valid_json():
    dash = json.loads((GRAFANA_DIR / "dashboards/cryptoguard-overview.json").read_text(encoding="utf-8"))
    assert dash["uid"] == "cryptoguard-overview"
    assert dash["title"]
    assert dash["panels"], "el dashboard no tiene paneles"

    # Solo se referencia un datasource, y es el provisionado.
    referenced = {
        d["uid"] for d in _walk_dicts(dash)
        if d.get("uid") == DATASOURCE_UID
    }
    assert referenced == {DATASOURCE_UID}

    # Ningun panel apunta a un datasource distinto del provisionado.
    for panel in dash["panels"]:
        if "datasource" in panel:
            assert panel["datasource"]["uid"] == DATASOURCE_UID
        for target in panel.get("targets", []):
            assert target["datasource"]["uid"] == DATASOURCE_UID

    # Todas las variables vienen de /api/reports/dimensions.
    fields = {
        "agent": ("agents", "agentId", "name"),
        "team": ("teams", "teamId", "name"),
        "service": ("services", "serviceId", "host"),
    }
    for var in dash["templating"]["list"]:
        root, value, label = fields[var["name"]]
        assert var["query"]["queryType"] == "infinity"
        query = var["query"]["infinityQuery"]
        assert query["url"] == "/api/reports/dimensions"
        assert query["root_selector"] == f"$.{root}"
        assert {col["text"]: col["selector"] for col in query["columns"]} == {
            "__value": value,
            "__text": label,
        }


def test_every_panel_targets_a_reports_endpoint():
    dash = json.loads((GRAFANA_DIR / "dashboards/cryptoguard-overview.json").read_text(encoding="utf-8"))
    for panel in dash["panels"]:
        for target in panel.get("targets", []):
            url = target["url"]
            assert url.startswith("/api/reports/"), f"target fuera de /api/reports: {url}"


def test_no_secrets_committed():
    offenders = []
    exts = {".yml", ".yaml", ".json", ".md", ".example"}
    for path in GRAFANA_DIR.rglob("*"):
        if path.is_file() and (path.suffix in exts or path.name == ".env.example"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if SECRET_RE.search(text):
                offenders.append(str(path.relative_to(GRAFANA_DIR)))
    assert not offenders, f"posibles secretos en: {offenders}"

    env_example = (GRAFANA_DIR / ".env.example").read_text(encoding="utf-8")
    assert "CRYPTOGUARD_API_KEY=cg_reemplazar" in env_example
