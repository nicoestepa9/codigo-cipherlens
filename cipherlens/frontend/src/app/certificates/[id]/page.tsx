"use client";

import { useMemo } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  BadgeCheck,
  Bug,
  Fingerprint,
  KeyRound,
  Link2,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { CertStatusBadge } from "@/components/shared/cert-status-badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { CardSkeleton } from "@/components/shared/skeletons";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { cn } from "@/lib/utils";
import { formatDate } from "@/lib/format";
import { useAsync } from "@/hooks/use-async";
import { useSettings } from "@/context/settings-context";
import { getCertificateDetail } from "@/services/certificatesService";
import type { CertificateInfo } from "@/types/certificate";

function InfoRow({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className={cn("text-right text-xs text-foreground", mono && "font-mono")}>{value}</span>
    </div>
  );
}

function ChainVisual({ cert }: { cert: CertificateInfo }) {
  return (
    <div className="flex flex-col gap-3">
      {[
        { role: "Root CA", isLeaf: false, isRoot: true, label: cert.issuerName.replace(/[ -].*$/, "") || "Root CA" },
        { role: "Intermediate", isLeaf: false, isRoot: false, label: cert.issuerName },
        { role: "Leaf", isLeaf: true, isRoot: false, label: cert.commonName },
      ].map((node, i) => (
        <div key={i} className="flex items-center gap-3">
          {i > 0 && <div className="ml-4 h-4 w-px bg-border" />}
          <div
            className={cn(
              "flex items-center gap-2 rounded-md border px-3 py-2",
              node.isRoot && "border-violet-500/40 bg-violet-500/10",
              node.isLeaf && "border-emerald-500/40 bg-emerald-500/10",
              !node.isRoot && !node.isLeaf && "border-border bg-background",
            )}
          >
            {node.isRoot ? (
              <ShieldCheck className="h-4 w-4 text-violet-400" />
            ) : node.isLeaf ? (
              <BadgeCheck className="h-4 w-4 text-emerald-400" />
            ) : (
              <Link2 className="h-4 w-4 text-muted-foreground" />
            )}
            <div>
              <p className="font-mono text-xs font-medium text-foreground">{node.label}</p>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{node.role}</p>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function CertificateDetailPage() {
  const params = useParams<{ id: string }>();
  const { settings } = useSettings();
  const { criticalDays, warningDays } = settings.thresholds;
  const { data, loading, error, refetch } = useAsync(() => getCertificateDetail(params.id), [params.id]);

  const remainingBadge = useMemo(() => {
    if (!data) return null;
    const days = data.certificate.daysUntilExpiry;
    const cls =
      days < 0
        ? "border-red-500/40 bg-red-500/10 text-red-400"
        : days <= criticalDays
          ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
          : days <= warningDays
            ? "border-sky-500/40 bg-sky-500/10 text-sky-400"
            : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400";
    return <Badge variant="outline" className={cls}>{days < 0 ? `Expired ${Math.abs(days)}d ago` : `${days} days left`}</Badge>;
  }, [data, criticalDays, warningDays]);

  if (loading) {
    return (
      <div className="space-y-4">
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  if (error) {
    return <ErrorState message="Could not load certificate details." onRetry={refetch} />;
  }

  if (!data) {
    return <EmptyState icon={<ShieldX className="h-6 w-6" />} title="Certificate not found." />;
  }

  const cert = data.certificate;

  return (
    <div>
      <Button variant="ghost" size="sm" asChild className="mb-4 -ml-2 text-muted-foreground">
        <Link href="/certificates">
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back to inventory
        </Link>
      </Button>

      <PageHeader
        title={<span className="font-mono">{cert.domain}</span>}
        subtitle={`${cert.san.length} SANs${cert.serviceName ? ` · used by ${cert.serviceName}` : ""}`}
        actions={
          <>
            <CertStatusBadge status={cert.status} />
            {remainingBadge}
            <Badge variant="outline" className="border-sky-500/40 bg-sky-500/10 text-sky-400">
              {cert.origin === "discovered" ? "Discovered" : "Manual"}
            </Badge>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyRound className="h-4 w-4 text-muted-foreground" />
              Certificate Information
            </CardTitle>
          </CardHeader>
          <CardContent className="divide-y divide-border/60">
            <InfoRow label="Common Name" value={cert.commonName} mono />
            <InfoRow
              label="Subject"
              value={`${cert.subject.CN ?? ""} · ${cert.subject.O ?? ""} · ${cert.subject.C ?? ""}`}
              mono
            />
            <InfoRow label="Issuer" value={cert.issuerName} mono />
            <InfoRow label="Serial Number" value={cert.serialNumber} mono />
            <InfoRow label="Signature Algorithm" value={cert.signatureAlgorithm} />
            <InfoRow label="Key" value={`${cert.keyType} ${cert.keySize} bit`} />
            <InfoRow label="Valid From" value={formatDate(cert.notBefore)} />
            <InfoRow label="Valid To" value={formatDate(cert.notAfter)} />
            <InfoRow label="Self-signed" value={cert.isSelfSigned ? "Yes" : "No"} />
            <InfoRow label="Basic Constraints" value={cert.basicConstraints} mono />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Trust Chain</CardTitle>
            <CardDescription>Chain as observed during the TLS handshake.</CardDescription>
          </CardHeader>
          <CardContent>
            <ChainVisual cert={cert} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Subject Alternative Names</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-1.5">
              {cert.san.map((s) => (
                <Badge key={s} variant="outline" className="font-mono text-xs">{s}</Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Fingerprint className="h-4 w-4 text-muted-foreground" />
              Fingerprints
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="mb-1 text-xs text-muted-foreground">SHA-256</p>
              <p className="break-all font-mono text-[11px] text-foreground">{cert.fingerprintSha256}</p>
            </div>
            <div>
              <p className="mb-1 text-xs text-muted-foreground">SHA-1</p>
              <p className="break-all font-mono text-[11px] text-foreground">{cert.fingerprintSha1}</p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Usage & Distribution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="mb-1.5 text-xs text-muted-foreground">Key Usage</p>
              <div className="flex flex-wrap gap-1.5">
                {cert.keyUsage.map((u) => (
                  <Badge key={u} variant="outline" className="text-xs">{u}</Badge>
                ))}
              </div>
            </div>
            <div>
              <p className="mb-1.5 text-xs text-muted-foreground">Extended Key Usage</p>
              <div className="flex flex-wrap gap-1.5">
                {cert.extendedKeyUsage.map((u) => (
                  <Badge key={u} variant="outline" className="text-xs">{u}</Badge>
                ))}
              </div>
            </div>
            <InfoRow label="OCSP Must-Staple" value={cert.ocspMustStaple ? "Yes" : "No"} />
            <div>
              <p className="mb-1.5 text-xs text-muted-foreground">CRL Distribution Points</p>
              {cert.crlDistributionPoints.map((u) => (
                <p key={u} className="break-all font-mono text-[11px] text-muted-foreground">{u}</p>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Related Services</CardTitle>
            <CardDescription>Services served by this certificate.</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {data.relatedServices.length === 0 ? (
              <p className="px-4 pb-4 text-xs text-muted-foreground">No services linked to this certificate.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Service</TableHead>
                    <TableHead>Endpoint</TableHead>
                    <TableHead>TLS</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.relatedServices.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell>
                        <Link href={`/services/${s.id}`} className="text-sm font-medium hover:underline">
                          {s.name}
                        </Link>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{s.host}:{s.port}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{s.tlsVersion}</TableCell>
                      <TableCell>
                        <StatusBadge status={s.securityStatus as "secure" | "warning" | "critical"} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Bug className="h-4 w-4 text-muted-foreground" />
              Related Findings
            </CardTitle>
            <CardDescription>
              {data.relatedFindings > 0
                ? `${data.relatedFindings} finding(s) associated with this host.`
                : "No findings associated with this host."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" size="sm" asChild>
              <Link href={`/vulnerabilities?host=${encodeURIComponent(cert.domain)}`}>
                <Bug className="mr-2 h-4 w-4" />
                View findings for {cert.domain}
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
