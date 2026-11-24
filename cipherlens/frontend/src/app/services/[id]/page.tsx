"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Bug,
  Fingerprint,
  Globe,
  Lock,
  Server,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { StatusBadge } from "@/components/shared/status-badge";
import { CertStatusBadge } from "@/components/shared/cert-status-badge";
import { CardSkeleton } from "@/components/shared/skeletons";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { formatDateTime } from "@/lib/format";
import { useAsync } from "@/hooks/use-async";
import { getService } from "@/services/servicesService";

function InfoRow({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className={`text-right text-xs text-foreground ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}

export default function ServiceDetailPage() {
  const params = useParams<{ id: string }>();
  const { data: service, loading, error, refetch } = useAsync(() => getService(params.id), [params.id]);

  if (loading) {
    return (
      <div className="space-y-4">
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  if (error) {
    return <ErrorState message="Could not load service details." onRetry={refetch} />;
  }

  if (!service) {
    return <EmptyState icon={<ShieldOff className="h-6 w-6" />} title="Service not found." />;
  }

  return (
    <div>
      <Button variant="ghost" size="sm" asChild className="mb-4 -ml-2 text-muted-foreground">
        <Link href="/services">
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back to services
        </Link>
      </Button>

      <PageHeader
        title={service.name}
        subtitle={`${service.host} · ${service.service}`}
        actions={
          <>
            <StatusBadge status={service.securityStatus} />
            <Badge
              variant="outline"
              className={
                service.scope === "internal"
                  ? "border-sky-500/40 bg-sky-500/10 text-sky-400"
                  : "border-violet-500/40 bg-violet-500/10 text-violet-400"
              }
            >
              {service.scope === "internal" ? "Internal" : "Public"}
            </Badge>
            <Badge variant="outline" className="font-mono text-xs">{service.tlsVersion}</Badge>
            <Button size="sm" asChild>
              <Link href={`/scanner?target=${encodeURIComponent(`${service.host}:${service.port}`)}`}>
                Scan now
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Server className="h-4 w-4 text-muted-foreground" />
              Endpoint
            </CardTitle>
          </CardHeader>
          <CardContent className="divide-y divide-border/60">
            <InfoRow label="Hostname" value={service.host} mono />
            <InfoRow label="IP Address" value={service.ipAddress} mono />
            <InfoRow label="Port" value={String(service.port)} mono />
            <InfoRow label="Protocol" value={service.protocol} />
            <InfoRow label="Service" value={service.service} />
            <InfoRow label="OS Fingerprint" value={service.osFingerprint ?? "—"} mono />
            <InfoRow label="Last Seen" value={formatDateTime(service.lastSeen)} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Lock className="h-4 w-4 text-muted-foreground" />
              TLS Configuration
            </CardTitle>
            <CardDescription>Protocol and cipher negotiated during the last scan.</CardDescription>
          </CardHeader>
          <CardContent className="divide-y divide-border/60">
            <InfoRow label="TLS Version" value={service.tlsVersion} mono />
            <InfoRow label="Cipher Suite" value={service.cipherSuite} mono />
            <InfoRow label="Security Status" value={<StatusBadge status={service.securityStatus} />} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Globe className="h-4 w-4 text-muted-foreground" />
              Certificate
            </CardTitle>
          </CardHeader>
          <CardContent className="divide-y divide-border/60">
            <InfoRow
              label="Domain"
              value={
                <Link href={`/certificates/${service.certificateId}`} className="font-mono hover:underline">
                  {service.certificateDomain}
                </Link>
              }
              mono
            />
            <InfoRow label="Status" value={<CertStatusBadge status={service.certificateStatus as never} />} />
            <InfoRow
              label="Expiration"
              value={
                <span className={service.certificateDaysLeft < 30 ? "text-amber-400" : "text-foreground"}>
                  {service.certificateDaysLeft}d left
                </span>
              }
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Bug className="h-4 w-4 text-muted-foreground" />
              Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent className="divide-y divide-border/60">
            <InfoRow label="Open Findings" value={service.vulnerabilityCount} />
            {service.findingsSeverity && (
              <InfoRow
                label="Worst Severity"
                value={
                  <Badge
                    variant="outline"
                    className={
                      service.findingsSeverity === "critical"
                        ? "border-red-500/40 bg-red-500/10 text-red-400"
                        : "border-amber-500/40 bg-amber-500/10 text-amber-400"
                    }
                  >
                    {service.findingsSeverity}
                  </Badge>
                }
              />
            )}
            <div className="pt-3">
              <Button variant="outline" size="sm" asChild>
                <Link href={`/vulnerabilities?host=${encodeURIComponent(service.host)}`}>
                  <ShieldCheck className="mr-2 h-4 w-4" />
                  View findings
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Fingerprint className="h-4 w-4 text-muted-foreground" />
              Asset
            </CardTitle>
            <CardDescription>Business inventory entry linked to this service.</CardDescription>
          </CardHeader>
          <CardContent className="divide-y divide-border/60">
            <InfoRow label="Asset Name" value={service.asset.name} />
            <InfoRow label="Type" value={service.asset.type} />
            <InfoRow label="Owner" value={service.asset.owner} />
            <InfoRow label="Department" value={service.asset.department} />
            <InfoRow label="Declared" value={service.asset.declared ? "Yes" : "No — Shadow IT"} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
