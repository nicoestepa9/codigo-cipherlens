"""Vulnerability scanner for TLS configurations.

La deteccion de malas configuraciones se basa en tres estandares NIST que se
corren sobre el mismo JSON de escaneo:

- NIST SP 800-52 Rev.2 (``nist``): guia de seleccion, configuracion y uso de
  TLS (agosto 2019).
- NIST SP 800-57 Part 1 Rev.5 (``nist80057``): fuerza de seguridad de claves
  y hashes.
- NIST SP 800-131A Rev.2 (``nist800131a``): transicion de algoritmos y
  tamanos de clave.

Los hallazgos se deduplican por el defecto subyacente (ver ``issues``): un
mismo problema detectado por varios estandares produce un solo finding, cuyo id
es el del estandar mas severo, y los detalles listan todos los estandares y
reglas que lo detectaron. El score descuenta una sola vez por defecto.
"""

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from .handshake import HandshakeResult
from .certificate import CertificateInfo
from . import nist
from . import nist80057, nist800131a, issues


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NOT_EVALUABLE = "NOT_EVALUABLE"


@dataclass
class Finding:
    """A single vulnerability or misconfiguration finding."""

    id: str
    title: str
    description: str
    severity: Severity
    category: str
    recommendation: str = ""
    details: dict = field(default_factory=dict)
    section_reference: str = ""
    citation: str = ""
    observed_value: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Complete scan results for a host."""

    host: str
    port: int
    findings: list[Finding] = field(default_factory=list)
    handshake: Optional[HandshakeResult] = None
    certificate_chain: list[CertificateInfo] = field(default_factory=list)
    score: int = 100  # starts at 100, deductions for findings
    profile: str = nist.DEFAULT_PROFILE

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "profile": self.profile,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "handshake": self.handshake.to_dict() if self.handshake else None,
            "certificate_chain": [c.to_dict() for c in self.certificate_chain],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def summary(self) -> dict:
        return {
            "total": len(self.findings),
            "critical": len(self.get_findings_by_severity(Severity.CRITICAL)),
            "high": len(self.get_findings_by_severity(Severity.HIGH)),
            "medium": len(self.get_findings_by_severity(Severity.MEDIUM)),
            "low": len(self.get_findings_by_severity(Severity.LOW)),
            "info": len(self.get_findings_by_severity(Severity.INFO)),
            "not_evaluable": len(self.get_findings_by_severity(Severity.NOT_EVALUABLE)),
            "score": self.score,
        }


def calculate_score(findings: list[Finding]) -> int:
    """Calculate a security score from 0 to 100 based on findings."""
    score = 100
    deductions = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,
        Severity.NOT_EVALUABLE: 0,
    }
    for f in findings:
        score -= deductions.get(f.severity, 0)
    return max(0, score)


_CATEGORY_FOR_PREFIX = {
    "PROTO": "Protocol",
    "CERT": "Certificate",
    "CIPH": "Cipher Suite",
    "EXT": "Extension",
    "COMP": "Compression",
    "NE": "Not Evaluable",
    "KEY": "Key Management",
    "HASH": "Hash",
    "SCHED": "Key Schedule",
    "COMBO": "Combination",
    "PQC": "Post-Quantum",
    "CRYPTO": "Cryptoperiod",
    "REDUCE": "Strength Reduction",
    "BLK": "Block Cipher",
    "SIG": "Signature",
    "RBG": "Random Bit Generator",
    "DH": "Key Agreement",
    "RSA": "RSA Key Transport",
    "MAC": "MAC",
}

_NIST_MODULES = {
    issues.STANDARD_80052: nist,
    issues.STANDARD_80057: nist80057,
    issues.STANDARD_800131A: nist800131a,
}


def _finding_from_nist(f: dict, standard: str | None = None) -> Finding:
    """Convert a NIST finding dict into a Finding object."""
    rule_id = f.get("id", "")
    prefix = rule_id.split("-")[0] if "-" in rule_id else rule_id
    severity = Severity(f.get("severity", Severity.INFO.value))
    details = {
        "observed_value": f.get("observed_value", ""),
        "section_reference": f.get("section_reference", ""),
        "severity": severity.value,
    }
    if standard is not None:
        details["standard"] = standard
    return Finding(
        id=rule_id,
        title=f.get("title", ""),
        description=f.get("citation", ""),
        severity=severity,
        category=_CATEGORY_FOR_PREFIX.get(prefix, "NIST"),
        recommendation=f.get("recommendation", ""),
        details=details,
        section_reference=f.get("section_reference", ""),
        citation=f.get("citation", ""),
        observed_value=f.get("observed_value", ""),
    )


_SEV_VALUE = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.NOT_EVALUABLE: 5,
}


def _merge_findings(reports: list[dict]) -> list[Finding]:
    """Deduplica los hallazgos de varios estandares por defecto subyacente.

    Para cada defecto se conserva un finding representante: el de mayor
    severidad y, en empate, el del estandar con prioridad mas alta (SP 800-52
    primero). Los detalles del representante listan todos los estandares y
    rule-ids prefijados que detectaron el defecto.
    """
    groups: dict[str, dict] = {}
    order: list[str] = []

    for report in reports:
        standard = report.get("standard")
        for f in report.get("findings", []):
            finding = _finding_from_nist(f, standard)
            canonical = issues.issue_of(standard, finding.id)
            if canonical not in groups:
                groups[canonical] = {"finding": finding, "standards": [], "rule_ids": []}
                order.append(canonical)
            group = groups[canonical]
            if _SEV_VALUE[finding.severity] < _SEV_VALUE[group["finding"].severity]:
                group["finding"] = finding
            if standard not in group["standards"]:
                group["standards"].append(standard)
            group["rule_ids"].append(f"{standard}-{finding.id}")

    merged: list[Finding] = []
    for canonical in order:
        group = groups[canonical]
        finding = group["finding"]
        prefixed = sorted(set(group["rule_ids"]))
        standards = [issues.STANDARD_NAMES[s] for s in issues.STANDARD_ORDER if s in group["standards"]]
        finding.details = {
            **finding.details,
            "standards": standards,
            "rule_ids": prefixed,
        }
        if len(prefixed) > 1:
            finding.description = (finding.description or "").strip() + " " + "[{}]".format(", ".join(prefixed))
        merged.append(finding)

    merged.sort(key=lambda f: _SEV_VALUE.get(f.severity, 6))
    return merged


def build_eval_data(
    handshake: HandshakeResult,
    cert_chain: list[CertificateInfo],
) -> dict:
    """Build the spec JSON structure consumed by the NIST evaluator."""
    return {
        "host": handshake.host,
        "port": handshake.port,
        "handshake": handshake.to_dict(),
        "certificate_chain": [c.to_dict() for c in cert_chain],
    }


def scan(
    handshake: HandshakeResult,
    cert_chain: list[CertificateInfo],
    hostname: str,
    profile: str = nist.DEFAULT_PROFILE,
    standards: list[str] | None = None,
    evaluation_date: Optional = None,
) -> ScanResult:
    """Run the full vulnerability scan against the selected NIST standards.

    ``standards`` es una lista de codigos (default: los tres). Los hallazgos
    de los estandares se deduplican por defecto subyacente y el score
    descuenta una sola vez por defecto.
    """
    result = ScanResult(
        host=handshake.host,
        port=handshake.port,
        handshake=handshake,
        certificate_chain=cert_chain,
        profile=profile,
    )

    if handshake.connection_error:
        result.findings.append(Finding(
            id="CONNECTION_FAILED",
            title="Connection Failed",
            description=f"Could not establish TLS connection: {handshake.connection_error}",
            severity=Severity.CRITICAL,
            category="Connection",
            recommendation="Check that the host and port are correct and the server is running.",
        ))
        result.score = 0
        return result

    data = build_eval_data(handshake, cert_chain)
    selected = standards or list(issues.STANDARD_ORDER)

    reports = []
    for code in issues.STANDARD_ORDER:
        if code not in selected:
            continue
        mod = _NIST_MODULES[code]
        if code == issues.STANDARD_80052:
            report = mod.evaluate(data, profile=profile)
        else:
            report = mod.evaluate(data, profile=profile, evaluation_date=evaluation_date)
        report["standard"] = code
        reports.append(report)

    result.findings = _merge_findings(reports)
    result.score = calculate_score(result.findings)
    return result
