"""CLI interface using Rich."""

import json
import os
import secrets
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, TextColumn

from .handshake import analyze_handshake, HandshakeResult
from .certificate import fetch_certificate_chain, CertificateInfo
from .scanner import scan, ScanResult, build_eval_data
from .report import (
    print_handshake_info_rich,
    print_certificate_rich,
    print_findings_rich,
    print_compliance_report_rich,
)
from . import nist
from . import compliance
from .issues import STANDARD_ORDER

console = Console()

SCANS_DIR = Path(__file__).resolve().parent.parent.parent / "scans"

STANDARD_CHOICES = [*STANDARD_ORDER, "all"]


def _operator_log(action: str, slug: str, *, details: dict | None = None) -> None:
    """Append an operator event outside tenant AuditLog, never including secrets."""
    log_path = Path(
        os.getenv(
            "OPERATOR_LOG_PATH",
            str(Path.home() / ".cryptoguard" / "operator-audit.log"),
        )
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "organization_slug": slug,
        "details": details or {},
    }
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    try:
        log_path.chmod(0o600)
    except OSError:
        # Windows filesystems do not consistently expose POSIX mode bits.
        pass


def _purge_organization(db, organization_id: int) -> dict[str, int]:
    """Delete one tenant's rows in FK-safe order inside the caller's transaction."""
    from .api import models

    # Break the Service <-> Certificate reference cycle before deletion.
    db.query(models.Service).filter(
        models.Service.organization_id == organization_id
    ).update({models.Service.certificate_id: None}, synchronize_session=False)
    db.query(models.Certificate).filter(
        models.Certificate.organization_id == organization_id
    ).update({models.Certificate.service_id: None}, synchronize_session=False)
    ordered_models = (
        # Remote tasks reference scans, discovery jobs, recurring schedules and agents.
        models.AgentTask,
        models.Finding,
        models.IssueHistory,
        models.ScanCveMatch,
        models.DiscoveryResult,
        models.RefreshToken,
        models.AuditLog,
        models.TeamMember,
        models.Alert,
        models.Issue,
        models.Scan,
        models.DiscoveryJob,
        models.RecurringScan,
        models.Certificate,
        models.Service,
        models.Asset,
        models.Agent,
        models.Integration,
        models.AlertThreshold,
        models.ComplianceWindow,
        models.ApiKey,
        models.Team,
        models.User,
    )
    deleted: dict[str, int] = {}
    for model in ordered_models:
        query = db.query(model).filter(model.organization_id == organization_id)
        count = query.count()
        query.delete(synchronize_session=False)
        deleted[model.__tablename__] = count
    organization_query = db.query(models.Organization).filter(
        models.Organization.id == organization_id
    )
    deleted["organizations"] = organization_query.count()
    organization_query.delete(synchronize_session=False)
    return deleted


def _parse_standard_args(raw: list[str] | None) -> list[str] | None:
    """Convierte los valores de --standard en la lista de codigos a evaluar."""
    if not raw:
        return None
    selected: list[str] = []
    for value in raw:
        if value == "all":
            selected.extend(STANDARD_ORDER)
        else:
            selected.append(value)
    return list(dict.fromkeys(selected))


def _parse_evaluation_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise nist.NISTEvaluationError(
            f"Fecha de evaluacion invalida: '{value}'. Use el formato YYYY-MM-DD."
        )


def _parse_target(target: str) -> tuple[str, int]:
    """Parse a target string like 'example.com' or 'example.com:8443'."""
    target = target.strip()
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.rstrip("/")

    port = 443
    if ":" in target:
        parts = target.rsplit(":", 1)
        try:
            port = int(parts[1])
            target = parts[0]
        except ValueError:
            pass

    return target, port


def save_scan_data(data: dict, output_dir: str | Path | None = None) -> Path:
    """Save raw scan data (handshake + certificate_chain) to a JSON file. Returns the file path."""
    if output_dir is None:
        output_dir = SCANS_DIR
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"{data.get('host', 'unknown')}_{data.get('port', 443)}_{timestamp}.json"
    filepath = output_dir / filename

    ordered = {"_meta": {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": f"{data.get('host', 'unknown')}:{data.get('port', 443)}",
        "tool": "tls-analyzer",
        "version": "1.0.0",
    }}
    ordered.update(data)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(ordered, f, indent=2, ensure_ascii=False, default=str)

    return filepath


def save_scan_result(scan_result: ScanResult, output_dir: str | Path | None = None) -> Path:
    """Save scan results to a JSON file. Returns the file path."""
    return save_scan_data(scan_result.to_dict(), output_dir)


def run_scan(target: str, timeout: float = 10.0, save: bool = False, output_dir: str | None = None,
             profile: str = nist.DEFAULT_PROFILE) -> ScanResult:
    """Run a full scan against a target and print results."""
    host, port = _parse_target(target)

    console.print(Panel(
        f"[bold]Target:[/bold] {host}:{port}\n"
        f"[bold]Time:[/bold] {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[bold]Profile:[/bold] {profile}",
        title="TLS Analyzer",
        border_style="blue",
    ))

    # Step 1: Handshake analysis
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Performing TLS handshake...", total=None)
        handshake = analyze_handshake(host, port, timeout)
        progress.update(task, completed=True, description="Handshake complete")

    if handshake.connection_error:
        console.print(f"[red]Connection failed: {handshake.connection_error}[/red]")
        return ScanResult(host=host, port=port, handshake=handshake)

    # Step 2: Certificate chain
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching certificate chain...", total=None)
        cert_chain = fetch_certificate_chain(host, port, timeout)

        # Fallback: use DER cert captured during handshake
        if not cert_chain and handshake and handshake.peer_cert_der:
            try:
                from .certificate import analyze_certificate_from_der
                cert_chain = [analyze_certificate_from_der(handshake.peer_cert_der)]
            except Exception:
                pass

        progress.update(task, completed=True, description=f"Got {len(cert_chain)} certificates")

    # Step 3: Vulnerability scan
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning for vulnerabilities...", total=None)
        scan_result = scan(handshake, cert_chain, host, profile=profile)
        progress.update(task, completed=True, description="Scan complete")

    # Step 4: Display results
    console.print()
    print_handshake_info_rich(console, handshake)
    console.print()
    print_certificate_rich(console, cert_chain)
    console.print()
    print_findings_rich(console, scan_result)

    # Step 5: Save if requested
    if save:
        filepath = save_scan_result(scan_result, output_dir)
        console.print(f"\n[green]Results saved to:[/green] {filepath}")

    return scan_result


def run_json(target: str, timeout: float = 10.0, profile: str = nist.DEFAULT_PROFILE) -> str:
    """Run a scan and return JSON output."""
    host, port = _parse_target(target)
    handshake = analyze_handshake(host, port, timeout)

    if handshake.connection_error:
        import json
        return json.dumps({"error": handshake.connection_error, "host": host, "port": port})

    cert_chain = fetch_certificate_chain(host, port, timeout)

    # Fallback: use DER cert captured during handshake
    if not cert_chain and handshake.peer_cert_der:
        try:
            from .certificate import analyze_certificate_from_der
            cert_chain = [analyze_certificate_from_der(handshake.peer_cert_der)]
        except Exception:
            pass
    if not cert_chain and handshake.peer_cert_chain_der:
        try:
            from .certificate import analyze_certificate_from_der
            cert_chain = [analyze_certificate_from_der(der) for der in handshake.peer_cert_chain_der]
        except Exception:
            pass

    scan_result = scan(handshake, cert_chain, host, profile=profile)
    return scan_result.to_json()


def _nist_input_kind(value: str) -> str:
    """Decide whether a 'nist' argument is a saved scan file or a live target."""
    if value.endswith(".json"):
        return "file"
    if os.path.isfile(value):
        return "file"
    return "target"


def run_nist_live(
    target: str,
    timeout: float,
    profile: str = nist.DEFAULT_PROFILE,
    standards: list[str] | None = None,
    evaluation_date: date | None = None,
) -> tuple[dict, dict]:
    """Scan a target live and evaluate it against the selected NIST standards.

    Returns (report, raw_data) where raw_data is the scan JSON structure
    (handshake + certificate_chain) that a saved scan file would contain.
    """
    host, port = _parse_target(target)
    handshake = analyze_handshake(host, port, timeout)

    if handshake.connection_error:
        raise nist.NISTEvaluationError(
            f"Could not connect to {host}:{port} - {handshake.connection_error}"
        )

    cert_chain = fetch_certificate_chain(host, port, timeout)

    # Fallback: use DER certs captured during handshake
    if not cert_chain and handshake.peer_cert_der:
        try:
            from .certificate import analyze_certificate_from_der
            cert_chain = [analyze_certificate_from_der(handshake.peer_cert_der)]
        except Exception:
            pass
    if not cert_chain and handshake.peer_cert_chain_der:
        try:
            from .certificate import analyze_certificate_from_der
            cert_chain = [analyze_certificate_from_der(der) for der in handshake.peer_cert_chain_der]
        except Exception:
            pass

    data = build_eval_data(handshake, cert_chain)
    report = compliance.evaluate_all(data, profile=profile, standards=standards, evaluation_date=evaluation_date)
    return report, data


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="tls-analyzer",
        description="TLS Handshake Analyzer & Vulnerability Scanner",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a target for TLS vulnerabilities")
    scan_parser.add_argument("target", help="Target host (e.g., example.com or example.com:8443)")
    scan_parser.add_argument("--json", action="store_true", help="Output results as JSON")
    scan_parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds")
    scan_parser.add_argument("--save", action="store_true", help="Save results to JSON file in scans/ directory")
    scan_parser.add_argument("--output", type=str, default=None, help="Directory to save scan results")
    scan_parser.add_argument(
        "--profile",
        choices=[nist.PROFILE_CITIZEN_FACING, nist.PROFILE_GOVERNMENT_ONLY],
        default=nist.DEFAULT_PROFILE,
        help="Application profile for NIST SP 800-52 Rev.2 evaluation",
    )

    # nist command
    nist_parser = subparsers.add_parser(
        "nist",
        help="Evaluate a saved scan JSON or a live target against the NIST standards (SP 800-52, SP 800-57 Part 1, SP 800-131A)",
    )
    nist_parser.add_argument(
        "input",
        help="Path to a saved scan JSON file (scans/*.json) or a target URL/host to scan live (e.g., https://example.com)",
    )
    nist_parser.add_argument(
        "--profile",
        choices=[nist.PROFILE_CITIZEN_FACING, nist.PROFILE_GOVERNMENT_ONLY],
        default=nist.DEFAULT_PROFILE,
        help="Application profile for the evaluation",
    )
    nist_parser.add_argument(
        "--standard",
        nargs="+",
        choices=STANDARD_CHOICES,
        default=None,
        help="Standard(s) to evaluate against (default: all). Valid values: 80052, 80057, 800131a, all",
    )
    nist_parser.add_argument(
        "--evaluation-date",
        type=str,
        default=None,
        help="Date of evaluation in YYYY-MM-DD format (default: scan date of the JSON, or today)",
    )
    nist_parser.add_argument("--json", action="store_true", help="Output the raw report as JSON")
    nist_parser.add_argument("--output", type=str, default=None, help="Save the report JSON to a file")
    nist_parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds (live target scans only)")
    nist_parser.add_argument("--save", action="store_true", help="Save the raw scan JSON to the scans/ directory (live target scans only)")

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Start the web interface")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    serve_parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    serve_parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    # serve-api command
    serve_api_parser = subparsers.add_parser("serve-api", help="Start the FastAPI backend")
    serve_api_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    serve_api_parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    serve_api_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")

    subparsers.add_parser("org-list", help="List organizations")
    p_create = subparsers.add_parser("org-create", help="Create organization")
    p_create.add_argument("name")
    p_create.add_argument("--admin-email", required=True)
    p_create.add_argument("--slug")
    p_create.add_argument(
        "--ai-mode", choices=("external", "template"), default="template"
    )
    p_create.add_argument("--max-agents", type=int, default=0)
    p_create.add_argument("--max-cloud-scans-per-hour", type=int, default=0)
    p_create.add_argument("--max-recurring-scans", type=int, default=0)
    p_disable = subparsers.add_parser("org-disable", help="Disable organization")
    p_disable.add_argument("id", type=int)
    p_enable = subparsers.add_parser("org-enable", help="Enable organization")
    p_enable.add_argument("id", type=int)
    p_del = subparsers.add_parser("org-delete", help="Delete organization")
    p_del.add_argument("id", type=int)
    p_del.add_argument("--purge", action="store_true")

    # Current operator interface. Legacy org-* commands remain available for
    # installations that already use them.
    subparsers.add_parser("list-orgs", help="List organizations")
    p_create_org = subparsers.add_parser(
        "create-org", help="Create an organization and its initial administrator"
    )
    p_create_org.add_argument("--name", required=True)
    p_create_org.add_argument("--admin-email", required=True)
    p_create_org.add_argument("--slug")
    p_create_org.add_argument("--ai-mode", choices=("external", "template"), default="template")
    p_create_org.add_argument("--max-agents", type=int, default=0)
    p_create_org.add_argument("--max-cloud-scans-per-hour", type=int, default=0)
    p_create_org.add_argument("--max-recurring-scans", type=int, default=0)
    p_disable_org = subparsers.add_parser("disable-org", help="Disable an organization")
    p_disable_org.add_argument("--slug", required=True)
    p_enable_org = subparsers.add_parser("enable-org", help="Enable an organization")
    p_enable_org.add_argument("--slug", required=True)
    p_delete_org = subparsers.add_parser("delete-org", help="Purge an organization")
    p_delete_org.add_argument("--slug", required=True)
    p_delete_org.add_argument("--purge", action="store_true")

    args = parser.parse_args()

    if args.command == "scan":
        if args.json:
            json_output = run_json(args.target, args.timeout, profile=args.profile)
            if args.save:
                host, port = _parse_target(args.target)
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                output_dir = Path(args.output) if args.output else SCANS_DIR
                output_dir.mkdir(parents=True, exist_ok=True)
                filepath = output_dir / f"{host}_{port}_{timestamp}.json"
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(json_output)
                console.print(f"[green]Results saved to:[/green] {filepath}")
            else:
                print(json_output)
        else:
            run_scan(args.target, args.timeout, save=args.save, output_dir=args.output, profile=args.profile)

    elif args.command == "nist":
        try:
            standards = _parse_standard_args(args.standard)
            evaluation_date = _parse_evaluation_date(args.evaluation_date)
            if _nist_input_kind(args.input) == "file":
                data = nist.load_scan_file(args.input)
                report = compliance.evaluate_all(
                    data, profile=args.profile, standards=standards, evaluation_date=evaluation_date
                )
            else:
                report, raw_data = run_nist_live(
                    args.input, args.timeout, profile=args.profile,
                    standards=standards, evaluation_date=evaluation_date,
                )
                if args.save:
                    filepath = save_scan_data(raw_data)
                    console.print(f"[green]Raw scan saved to:[/green] {filepath}")
        except nist.NISTEvaluationError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)

        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print_compliance_report_rich(console, report)

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            console.print(f"[green]Report saved to:[/green] {out_path}")

    elif args.command == "serve":
        from .web.app import create_app
        app = create_app()
        console.print(f"[green]Starting web interface at http://{args.host}:{args.port}[/green]")
        app.run(host=args.host, port=args.port, debug=args.debug)

    elif args.command == "serve-api":
        import uvicorn
        console.print(f"[green]Starting CryptoGuard API at http://{args.host}:{args.port}[/green]")
        uvicorn.run(
            "tls_analyzer.api.main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
        )
    elif args.command == "list-orgs":
        from .api.db import SessionLocal
        from .api import models, tenancy

        db = SessionLocal()
        tenancy.set_system_session(db)
        try:
            rows = db.query(models.Organization).order_by(models.Organization.id).all()
            print("id\tslug\tname\tstatus\tai_mode")
            for organization in rows:
                print(
                    f"{organization.id}\t{organization.slug}\t{organization.name}\t"
                    f"{organization.status}\t{organization.ai_mode}"
                )
            _operator_log("list-orgs", "*", details={"count": len(rows)})
        finally:
            db.close()
    elif args.command == "create-org":
        from .api.db import SessionLocal
        from .api import models, tenancy
        from .api.services import user_service
        import re

        db = SessionLocal()
        tenancy.set_system_session(db)
        try:
            base_slug = re.sub(r"[^a-z0-9]+", "-", args.name.lower()).strip("-")
            slug = args.slug or (base_slug or "org")
            if db.query(models.Organization).filter_by(slug=slug).first():
                raise SystemExit(f"Organization slug already exists: {slug}")
            if db.query(models.User).filter_by(email=args.admin_email.lower().strip()).first():
                raise SystemExit("Administrator email is already in use")
            temporary_password = secrets.token_urlsafe(18)
            organization = models.Organization(
                name=args.name,
                slug=slug,
                status="active",
                ai_mode=args.ai_mode,
                max_agents=args.max_agents,
                max_cloud_scans_per_hour=args.max_cloud_scans_per_hour,
                max_recurring_scans=args.max_recurring_scans,
            )
            db.add(organization)
            db.flush()
            administrator = user_service.create_user(
                db,
                email=args.admin_email,
                name=args.admin_email,
                password=temporary_password,
                role="admin",
                organization_id=organization.id,
                must_change_password=True,
            )
            db.commit()
            print(f"Created organization {organization.slug} (id={organization.id})")
            print(f"Initial administrator: {administrator.email}")
            print(f"Temporary password (shown once; change at first login): {temporary_password}")
            _operator_log(
                "create-org",
                organization.slug,
                details={"organization_id": organization.id, "admin_user_id": administrator.id},
            )
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
    elif args.command == "disable-org":
        from .api.db import SessionLocal
        from .api import models, tenancy

        db = SessionLocal()
        tenancy.set_system_session(db)
        try:
            organization = db.query(models.Organization).filter_by(slug=args.slug).first()
            if organization is None:
                raise SystemExit(f"Organization not found: {args.slug}")
            organization.status = "disabled"
            db.commit()
            _operator_log("disable-org", organization.slug, details={"organization_id": organization.id})
            print(f"Disabled organization {organization.slug}")
        finally:
            db.close()
    elif args.command == "enable-org":
        from .api.db import SessionLocal
        from .api import models, tenancy

        db = SessionLocal()
        tenancy.set_system_session(db)
        try:
            organization = db.query(models.Organization).filter_by(slug=args.slug).first()
            if organization is None:
                raise SystemExit(f"Organization not found: {args.slug}")
            organization.status = "active"
            db.commit()
            _operator_log("enable-org", organization.slug, details={"organization_id": organization.id})
            print(f"Enabled organization {organization.slug}")
        finally:
            db.close()
    elif args.command == "delete-org":
        from .api.db import SessionLocal
        from .api import models, tenancy

        if not args.purge:
            raise SystemExit("delete-org requires --purge")
        db = SessionLocal()
        tenancy.set_system_session(db)
        try:
            organization = db.query(models.Organization).filter_by(slug=args.slug).first()
            if organization is None:
                raise SystemExit(f"Organization not found: {args.slug}")
            print("WARNING: this permanently deletes all organization data.")
            print("Create and verify a database backup before proceeding.")
            confirmation = input(f"Type '{organization.slug}' to confirm purge: ")
            if confirmation != organization.slug:
                raise SystemExit("Confirmation did not match; no data was deleted")
            organization_id = organization.id
            deleted = _purge_organization(db, organization_id)
            db.commit()
            _operator_log(
                "delete-org-purge",
                organization.slug,
                details={"organization_id": organization_id, "deleted_rows": deleted},
            )
            for table, count in sorted(deleted.items()):
                print(f"{table}\t{count}")
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
    elif args.command == "org-list":
        from .api.db import SessionLocal
        from .api import models
        from .api import tenancy
        db = SessionLocal()
        tenancy.set_system_session(db)
        try:
            for o in db.query(models.Organization).order_by(models.Organization.id).all():
                print(f"{o.id}\t{o.name}\t{getattr(o,'slug','')}\t{getattr(o,'status','')}\t{getattr(o,'ai_mode','')}")
            _operator_log("org-list", "*")
        finally:
            db.close()
    elif args.command == "org-create":
        from .api.db import SessionLocal
        from .api import models, tenancy
        from .api.services import user_service
        import re

        db = SessionLocal()
        tenancy.set_system_session(db)
        try:
            slug = args.slug or re.sub(r"[^a-z0-9]+", "-", args.name.lower()).strip("-") or "org"
            temporary_password = secrets.token_urlsafe(18)
            org = models.Organization(
                name=args.name,
                slug=slug,
                status="active",
                ai_mode=args.ai_mode,
                max_agents=args.max_agents,
                max_cloud_scans_per_hour=args.max_cloud_scans_per_hour,
                max_recurring_scans=args.max_recurring_scans,
            )
            db.add(org)
            db.flush()
            admin = user_service.create_user(
                db,
                email=args.admin_email,
                name=args.admin_email,
                password=temporary_password,
                role="admin",
                organization_id=org.id,
                must_change_password=True,
            )
            db.commit()
            print(f"Created organization {org.slug} (id={org.id})")
            print(f"Initial administrator: {admin.email}")
            print(f"Temporary password (shown once; change at first login): {temporary_password}")
            _operator_log(
                "org-create",
                org.slug,
                details={"organization_id": org.id, "admin_user_id": admin.id},
            )
        finally:
            db.close()
    elif args.command == "org-disable":
        from .api.db import SessionLocal
        from .api import models
        db = SessionLocal()
        from .api import tenancy

        tenancy.set_system_session(db)
        try:
            o = db.get(models.Organization, args.id)
            if not o:
                print("not found")
                sys.exit(1)
            o.status = "disabled"
            db.commit()
            _operator_log("org-disable", o.slug, details={"organization_id": o.id})
            print("ok")
        finally:
            db.close()
    elif args.command == "org-enable":
        from .api.db import SessionLocal
        from .api import models
        db = SessionLocal()
        from .api import tenancy

        tenancy.set_system_session(db)
        try:
            o = db.get(models.Organization, args.id)
            if not o:
                print("not found")
                sys.exit(1)
            o.status = "active"
            db.commit()
            _operator_log("org-enable", o.slug, details={"organization_id": o.id})
            print("ok")
        finally:
            db.close()
    elif args.command == "org-delete":
        from .api.db import SessionLocal
        from .api import models
        db = SessionLocal()
        from .api import tenancy

        tenancy.set_system_session(db)
        try:
            o = db.get(models.Organization, args.id)
            if not o:
                print("not found")
                sys.exit(1)
            if args.purge:
                print("WARNING: create a verified database backup before purging.")
                if input(f"Type '{o.slug}' to confirm purge: ") != o.slug:
                    raise SystemExit("Confirmation did not match; no data was deleted")
                org_id = o.id
                deleted = _purge_organization(db, org_id)
                db.commit()
                _operator_log(
                    "org-delete-purge",
                    o.slug,
                    details={"organization_id": org_id, "deleted_rows": deleted},
                )
            else:
                o.status = "disabled"
                db.commit()
                _operator_log("org-delete-disable", o.slug, details={"organization_id": o.id})
            print("ok")
        finally:
            db.close()

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
