"""Report formatting for scan results."""

from .scanner import ScanResult, Severity
from .handshake import HandshakeResult
from .certificate import CertificateInfo


def format_score_bar(score: int) -> str:
    """Create a text-based score bar."""
    filled = score // 5
    empty = 20 - filled
    if score >= 80:
        color = "green"
    elif score >= 60:
        color = "yellow"
    elif score >= 40:
        color = "dark_orange"
    else:
        color = "red"
    bar = "#" * filled + "-" * empty
    return f"[{color}]{bar}[/{color}] {score}/100"


def format_severity(severity: Severity) -> str:
    """Format severity with color."""
    colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
        Severity.NOT_EVALUABLE: "bold blue",
    }
    style = colors.get(severity, "")
    return f"[{style}]{severity.value}[/{style}]"


def print_handshake_info_rich(console, result: HandshakeResult):
    """Print handshake info using Rich console."""
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    # Connection info
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Key", style="bold")
    info_table.add_column("Value")
    info_table.add_row("Host", result.host)
    info_table.add_row("Port", str(result.port))
    info_table.add_row("IP", result.ip_address or "N/A")

    if result.connection_error:
        info_table.add_row("Error", f"[red]{result.connection_error}[/red]")
        console.print(Panel(info_table, title="Connection", border_style="red"))
        return

    info_table.add_row("Protocol", result.negotiated_protocol)
    info_table.add_row("Cipher", result.negotiated_cipher)

    if result.extensions:
        for k, v in result.extensions.items():
            info_table.add_row(k, str(v))

    console.print(Panel(info_table, title="TLS Handshake", border_style="blue"))

    # Supported protocols
    if result.supported_protocols:
        proto_text = ", ".join(result.supported_protocols)
        console.print(f"  [bold]Supported Protocols:[/bold] {proto_text}")

    # Cipher suites table
    if result.accepted_cipher_suites:
        cipher_table = Table(title="Accepted Cipher Suites", show_lines=False)
        cipher_table.add_column("#", style="dim", width=4)
        cipher_table.add_column("Cipher Suite", style="green")
        cipher_table.add_column("Protocol")
        cipher_table.add_column("Bits", justify="right")

        for i, c in enumerate(result.accepted_cipher_suites[:50], 1):
            cipher_table.add_row(
                str(i),
                c["name"],
                c.get("protocol", ""),
                str(c.get("bits", "")),
            )

        if len(result.accepted_cipher_suites) > 50:
            cipher_table.add_row("...", f"+{len(result.accepted_cipher_suites) - 50} more", "", "")

        console.print(cipher_table)


def print_certificate_rich(console, chain: list[CertificateInfo]):
    """Print certificate info using Rich console."""
    from rich.table import Table
    from rich.panel import Panel

    if not chain:
        console.print("[yellow]No certificate chain received.[/yellow]")
        return

    for i, cert in enumerate(chain):
        role = "Leaf" if i == 0 else f"Intermediate #{i}"
        if i == len(chain) - 1 and cert.is_self_signed:
            role = "Root CA"

        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column("Key", style="bold")
        info_table.add_column("Value")

        cn = cert.subject.get("CN", "N/A")
        info_table.add_row("Role", role)
        info_table.add_row("Subject CN", cn)

        issuer_cn = cert.issuer.get("CN", "N/A")
        info_table.add_row("Issuer", issuer_cn)

        info_table.add_row("Serial", cert.serial_number)
        info_table.add_row("Valid From", cert.not_before)
        info_table.add_row("Valid Until", cert.not_after)

        if cert.is_expired:
            info_table.add_row("Status", "[bold red]EXPIRED[/bold red]")
        elif cert.days_until_expiry <= 30:
            info_table.add_row("Status", f"[yellow]Expires in {cert.days_until_expiry} days[/yellow]")
        else:
            info_table.add_row("Status", f"[green]Valid ({cert.days_until_expiry} days left)[/green]")

        info_table.add_row("Key Type", cert.key_type)
        info_table.add_row("Key Size", str(cert.key_size))
        info_table.add_row("Signature", cert.signature_algorithm)
        info_table.add_row("Self-Signed", "Yes" if cert.is_self_signed else "No")

        if cert.san:
            info_table.add_row("SAN", ", ".join(cert.san[:5]))
            if len(cert.san) > 5:
                info_table.add_row("", f"+{len(cert.san) - 5} more")

        if cert.key_usage:
            info_table.add_row("Key Usage", ", ".join(cert.key_usage))

        if cert.extended_key_usage:
            info_table.add_row("Ext Key Usage", ", ".join(cert.extended_key_usage))

        info_table.add_row("SHA-256", cert.fingerprint_sha256[:30] + "...")

        border = "red" if cert.is_expired else "green"
        console.print(Panel(info_table, title=f"Certificate: {cn} ({role})", border_style=border))


def print_findings_rich(console, scan_result: ScanResult):
    """Print vulnerability findings using Rich console."""
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    summary = scan_result.summary()

    # Score panel
    score_text = format_score_bar(scan_result.score)
    console.print(Panel(
        f"Security Score: {score_text}\n"
        f"Findings: {summary['total']} total "
        f"([bold red]{summary['critical']} critical[/bold red], "
        f"[red]{summary['high']} high[/red], "
        f"[yellow]{summary['medium']} medium[/yellow], "
        f"[cyan]{summary['low']} low[/cyan], "
        f"[dim]{summary['info']} info[/dim], "
        f"[bold blue]{summary['not_evaluable']} not evaluable[/bold blue])",
        title="Scan Summary",
        border_style="blue" if scan_result.score >= 60 else "red",
    ))

    if not scan_result.findings:
        console.print("[green]No vulnerabilities found![/green]")
        return

    # Findings table
    findings_table = Table(title="Vulnerability Findings", show_lines=True)
    findings_table.add_column("Severity", width=10)
    findings_table.add_column("ID", width=20)
    findings_table.add_column("Title")
    findings_table.add_column("Category", width=15)

    for f in sorted(scan_result.findings, key=lambda x: list(Severity).index(x.severity)):
        findings_table.add_row(
            format_severity(f.severity),
            f.id,
            f.title,
            f.category,
        )

    console.print(findings_table)

    # Detailed findings
    for f in sorted(scan_result.findings, key=lambda x: list(Severity).index(x.severity)):
        border_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }.get(f.severity, "blue")

        details = f"[bold]{f.title}[/bold]\n"
        details += f"{f.description}\n"
        if f.section_reference:
            details += f"\n[bold]NIST Reference:[/bold] {f.section_reference}\n"
        if f.observed_value:
            details += f"\n[bold]Observed:[/bold] {f.observed_value}\n"
        if f.recommendation:
            details += f"\n[bold]Recommendation:[/bold] {f.recommendation}"

        console.print(Panel(
            details,
            title=f"{format_severity(f.severity)} | {f.id}",
            border_style=border_color,
        ))


def print_nist_report_rich(console, report: dict):
    """Print a NIST SP 800-52 Rev.2 compliance report using Rich."""
    from rich.table import Table
    from rich.panel import Panel

    summary = report.get("summary", {})
    console.print(Panel(
        f"[bold]Host:[/bold] {report.get('host')}:{report.get('port')}\n"
        f"[bold]Profile:[/bold] {report.get('profile')}\n"
        f"[bold]Standard:[/bold] {report.get('evaluated_against')}\n"
        f"Findings: "
        f"[bold red]{summary.get('critical', 0)} critical[/bold red], "
        f"[red]{summary.get('high', 0)} high[/red], "
        f"[yellow]{summary.get('medium', 0)} medium[/yellow], "
        f"[dim]{summary.get('info', 0)} info[/dim], "
        f"[bold blue]{summary.get('not_evaluable', 0)} not evaluable[/bold blue]",
        title="NIST SP 800-52 Rev.2 Compliance",
        border_style="blue",
    ))

    findings = report.get("findings", [])
    if not findings:
        console.print("[green]No compliance findings.[/green]")
        return

    for f in findings:
        sev = f.get("severity")
        sev_enum = Severity(sev) if sev in {s.value for s in Severity} else Severity.INFO
        border = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.INFO: "dim",
            Severity.NOT_EVALUABLE: "blue",
        }.get(sev_enum, "blue")

        details = f"[bold]{f.get('title')}[/bold]\n"
        if f.get("citation"):
            details += f"[italic]{f.get('citation')}[/italic]\n"
        if f.get("section_reference"):
            details += f"\n[bold]Reference:[/bold] {f.get('section_reference')}\n"
        if f.get("observed_value"):
            details += f"\n[bold]Observed:[/bold] {f.get('observed_value')}\n"
        if f.get("recommendation"):
            details += f"\n[bold]Recommendation:[/bold] {f.get('recommendation')}"

        console.print(Panel(
            details,
            title=f"{format_severity(sev_enum)} | {f.get('id')}",
            border_style=border,
        ))


def print_compliance_report_rich(console, report: dict):
    """Print a combined compliance report (SP 800-52 + SP 800-57 + SP 800-131A).

    Cada finding muestra su id prefijado con el estandar (maxima trazabilidad).
    """
    from rich.table import Table
    from rich.panel import Panel

    summary = report.get("summary", {})
    eval_date = report.get("evaluation_date", "")
    lines = [
        f"[bold]Host:[/bold] {report.get('host')}:{report.get('port')}",
        f"[bold]Profile:[/bold] {report.get('profile')}",
        f"[bold]Evaluation date:[/bold] {eval_date}",
        f"[bold]Standards:[/bold] {', '.join(report.get('standards', []))}",
    ]
    for r in report.get("reports", []):
        rs = r.get("summary", {})
        lines.append(
            f"[bold]{r.get('name')}:[/bold] "
            f"[bold red]{rs.get('critical', 0)} critical[/bold red], "
            f"[red]{rs.get('high', 0)} high[/red], "
            f"[yellow]{rs.get('medium', 0)} medium[/yellow], "
            f"[dim]{rs.get('info', 0)} info[/dim], "
            f"[bold blue]{rs.get('not_evaluable', 0)} not evaluable[/bold blue]"
        )
    lines.append(
        f"[bold]Total:[/bold] "
        f"[bold red]{summary.get('critical', 0)} critical[/bold red], "
        f"[red]{summary.get('high', 0)} high[/red], "
        f"[yellow]{summary.get('medium', 0)} medium[/yellow], "
        f"[dim]{summary.get('info', 0)} info[/dim], "
        f"[bold blue]{summary.get('not_evaluable', 0)} not evaluable[/bold blue]"
    )
    console.print(Panel("\n".join(lines), title="NIST Compliance (Combined)", border_style="blue"))

    findings = report.get("findings", [])
    if not findings:
        console.print("[green]No compliance findings.[/green]")
        return

    findings_table = Table(title="Compliance Findings", show_lines=False)
    findings_table.add_column("Severity", width=12)
    findings_table.add_column("ID", width=26)
    findings_table.add_column("Standard", width=9)
    findings_table.add_column("Title", width=48, overflow="fold")
    findings_table.add_column("Status", width=14)

    severity_sort = [s.value for s in Severity]
    for f in sorted(findings, key=lambda x: severity_sort.index(x.get("severity", "INFO"))):
        status = f.get("status", f.get("severity", ""))
        findings_table.add_row(
            format_severity(Severity(f["severity"])),
            f.get("id", ""),
            f.get("standard", ""),
            f.get("title", ""),
            status,
        )
    console.print(findings_table)

    for f in sorted(findings, key=lambda x: severity_sort.index(x.get("severity", "INFO"))):
        sev_enum = Severity(f["severity"])
        border = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.INFO: "dim",
            Severity.NOT_EVALUABLE: "blue",
        }.get(sev_enum, "blue")

        details = f"[bold]{f.get('title')}[/bold]\n"
        if f.get("citation"):
            details += f"[italic]{f.get('citation')}[/italic]\n"
        if f.get("section_reference"):
            details += f"\n[bold]Reference:[/bold] {f.get('section_reference')}\n"
        if f.get("observed_value"):
            details += f"\n[bold]Observed:[/bold] {f.get('observed_value')}\n"
        if f.get("recommendation"):
            details += f"\n[bold]Recommendation:[/bold] {f.get('recommendation')}"

        console.print(Panel(
            details,
            title=f"{format_severity(sev_enum)} | {f.get('id')}",
            border_style=border,
        ))
