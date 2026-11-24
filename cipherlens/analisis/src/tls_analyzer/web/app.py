"""Flask web application for TLS Analyzer."""

import json
import time
from io import BytesIO
from flask import Flask, render_template, request, jsonify, send_file

from ..api.config import settings
from ..cloud_network import (
    CLOUD_SCAN_AUTHORIZATION_TEXT,
    CLOUD_SCAN_AUTHORIZATION_VERSION,
    NonPublicTargetError,
    PinnedTarget,
    parse_scan_target,
    resolve_target_addresses,
)
from ..handshake import analyze_handshake
from ..certificate import fetch_certificate_chain
from ..scanner import scan


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    def _render_index(**context):
        return render_template(
            "index.html",
            authorization_version=CLOUD_SCAN_AUTHORIZATION_VERSION,
            authorization_text=CLOUD_SCAN_AUTHORIZATION_TEXT,
            **context,
        )

    def _authorized_target(target: str, accepted: bool, version: str):
        if settings.env != "dev":
            raise PermissionError(
                "El scanner Flask independiente solo está disponible en desarrollo; "
                "use la plataforma autenticada."
            )
        if not accepted or version != CLOUD_SCAN_AUTHORIZATION_VERSION:
            raise PermissionError(
                "Se requiere aceptar la declaración de autorización vigente."
            )
        host, port = parse_scan_target(target)
        addresses = resolve_target_addresses(
            host,
            enforce_public=settings.cloud_scan_block_private,
        )
        return host, port, PinnedTarget(
            addresses[0],
            enforce_public=settings.cloud_scan_block_private,
        )

    @app.route("/")
    def index():
        return _render_index()

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        data = request.get_json(silent=True)
        if not data or "target" not in data:
            return jsonify({"error": "Missing 'target' field"}), 400

        target = data["target"].strip()
        timeout = data.get("timeout", 10.0)

        try:
            host, port, pinned_target = _authorized_target(
                target,
                data.get("authorizationAccepted") is True,
                data.get("authorizationVersion", ""),
            )
            handshake = analyze_handshake(
                host, port, timeout, pinned_target=pinned_target
            )
            cert_chain = fetch_certificate_chain(
                host, port, timeout, pinned_target=pinned_target
            )

            # Fallback: use DER cert from handshake
            if not cert_chain and handshake.peer_cert_der:
                try:
                    from ..certificate import analyze_certificate_from_der
                    cert_chain = [analyze_certificate_from_der(handshake.peer_cert_der)]
                except Exception:
                    pass
            if not cert_chain and handshake.peer_cert_chain_der:
                try:
                    from ..certificate import analyze_certificate_from_der
                    cert_chain = [analyze_certificate_from_der(der) for der in handshake.peer_cert_chain_der]
                except Exception:
                    pass

            scan_result = scan(handshake, cert_chain, host)
            return jsonify(scan_result.to_dict())
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 422
        except NonPublicTargetError as exc:
            return jsonify({"error": str(exc)}), 422
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/scan", methods=["POST"])
    def web_scan():
        target = request.form.get("target", "").strip()
        if not target:
            return _render_index(error="Please enter a target")

        timeout = 10.0

        try:
            host, port, pinned_target = _authorized_target(
                target,
                request.form.get("authorizationAccepted") == "true",
                request.form.get("authorizationVersion", ""),
            )
            handshake = analyze_handshake(
                host, port, timeout, pinned_target=pinned_target
            )
            cert_chain = fetch_certificate_chain(
                host, port, timeout, pinned_target=pinned_target
            )

            # Fallback: use DER cert from handshake
            if not cert_chain and handshake.peer_cert_der:
                try:
                    from ..certificate import analyze_certificate_from_der
                    cert_chain = [analyze_certificate_from_der(handshake.peer_cert_der)]
                except Exception:
                    pass
            if not cert_chain and handshake.peer_cert_chain_der:
                try:
                    from ..certificate import analyze_certificate_from_der
                    cert_chain = [analyze_certificate_from_der(der) for der in handshake.peer_cert_chain_der]
                except Exception:
                    pass

            scan_result = scan(handshake, cert_chain, host)
            return _render_index(result=scan_result, target=target)
        except PermissionError as exc:
            return _render_index(error=str(exc), target=target), 422
        except NonPublicTargetError as exc:
            return _render_index(error=str(exc), target=target), 422
        except Exception as e:
            return _render_index(error=str(e), target=target)

    @app.route("/download", methods=["POST"])
    def download_results():
        """Download scan results as JSON file."""
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        host = data.get("host", "unknown")
        port = data.get("port", 443)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{host}_{port}_{timestamp}.json"

        data["_meta"] = {
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": f"{host}:{port}",
            "tool": "tls-analyzer",
            "version": "1.0.0",
        }

        # Reorder: meta first
        ordered = {"_meta": data.pop("_meta")}
        ordered.update(data)

        json_str = json.dumps(ordered, indent=2, ensure_ascii=False, default=str)
        buffer = BytesIO(json_str.encode("utf-8"))
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype="application/json",
            as_attachment=True,
            download_name=filename,
        )

    return app
