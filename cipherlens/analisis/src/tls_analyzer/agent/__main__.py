"""CLI del agente on-premise: ``python -m tls_analyzer.agent ...`` (Parte 5.5)."""

from __future__ import annotations

import argparse
import logging
import sys

from . import state
from .config import ConfigError, load_config
from .runner import AgentRunner


def _setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


def _cmd_run(args) -> int:
    try:
        config = load_config(
            args.config, allow_insecure_localhost=args.allow_insecure_localhost
        )
    except ConfigError as exc:
        print(f"Error de configuracion: {exc}", file=sys.stderr)
        return 1
    if not args.dry_run and not config.api_key:
        print(
            f"Falta la API key del agente: exporta la variable "
            f"{config.api_key_env}.",
            file=sys.stderr,
        )
        return 1
    runner = AgentRunner(config, dry_run=args.dry_run, once=args.once)
    return runner.run()


def _cmd_resolve(args) -> int:
    real = state.resolve_pseudonym(args.pseudonym)
    if real is None:
        print(f"Seudonimo desconocido: {args.pseudonym}", file=sys.stderr)
        return 1
    print(real)
    return 0


def _cmd_export_mapping(args) -> int:
    count = state.export_mapping_csv(args.out)
    print(f"Exportados {count} mapeo(s) a {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoguard-agent",
        description="Agente de recoleccion on-premise de CryptoGuard.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Ejecuta el agente (bucle o --once).")
    run.add_argument("--config", required=True, help="Ruta al agent.yaml")
    run.add_argument("--once", action="store_true", help="Una sola pasada y salir.")
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="Imprime exactamente qué se enviaría, sin enviarlo.",
    )
    run.add_argument(
        "--allow-insecure-localhost",
        action="store_true",
        help="Permite server_url http:// solo para localhost (desarrollo).",
    )
    run.set_defaults(func=_cmd_run)

    resolve = sub.add_parser("resolve", help="Resuelve un seudonimo a su valor real.")
    resolve.add_argument("pseudonym")
    resolve.set_defaults(func=_cmd_resolve)

    export = sub.add_parser("export-mapping", help="Exporta el mapeo a CSV.")
    export.add_argument("--out", required=True, help="Ruta del CSV de salida.")
    export.set_defaults(func=_cmd_export_mapping)

    return parser


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
