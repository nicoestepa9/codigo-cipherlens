"use client";

import { ArrowDown, BadgeCheck, ShieldAlert, ShieldX } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CertStatusBadge } from "@/components/shared/cert-status-badge";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ScanResult } from "@/types/scan";

function DetailRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border/60 py-2 last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-right font-mono text-sm text-foreground">{value}</span>
    </div>
  );
}

export function CertificateTab({ scan }: { scan: ScanResult }) {
  const cert = scan.certificate;
  const statusBanner =
    cert.status === "expired"
      ? { cls: "border-red-500/40 bg-red-500/10 text-red-400", icon: ShieldX, text: "EXPIRED", sub: `Expired ${Math.abs(cert.daysUntilExpiry)} days ago` }
      : cert.status === "expiring_soon"
        ? { cls: "border-amber-500/40 bg-amber-500/10 text-amber-400", icon: ShieldAlert, text: "EXPIRING SOON", sub: `Expires in ${cert.daysUntilExpiry} days` }
        : { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400", icon: BadgeCheck, text: "VALID", sub: `Expires in ${cert.daysUntilExpiry} days` };
  const Icon = statusBanner.icon;

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Certificate</CardTitle>
        </CardHeader>
        <CardContent className="p-5 pt-0">
          <div className={cn("mb-4 flex items-center gap-3 rounded-md border p-3", statusBanner.cls)}>
            <Icon className="h-5 w-5" />
            <div>
              <p className="font-mono text-sm font-semibold">{statusBanner.text}</p>
              <p className="text-xs opacity-80">{statusBanner.sub}</p>
            </div>
            <div className="ml-auto">
              <CertStatusBadge status={cert.status} />
            </div>
          </div>
          <DetailRow label="Subject" value={cert.commonName} />
          <DetailRow label="Issuer" value={cert.issuerName} />
          <DetailRow label="Serial Number" value={cert.serialNumber.slice(0, 24)} />
          <DetailRow label="Valid From" value={formatDate(cert.notBefore)} />
          <DetailRow label="Valid Until" value={formatDate(cert.notAfter)} />
          <DetailRow label="Remaining Days" value={cert.daysUntilExpiry} />
          <DetailRow label="Signature Algorithm" value={cert.signatureAlgorithm} />
          <DetailRow label="Public Key Algorithm" value={`${cert.keyType} (${cert.keySize}-bit)`} />
          <DetailRow label="Key Size" value={cert.keySize} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Subject Alternative Names</CardTitle>
        </CardHeader>
        <CardContent className="p-5 pt-0">
          <div className="flex flex-wrap gap-1.5">
            {cert.san.map((san) => (
              <Badge key={san} variant="outline" className="font-mono text-xs">
                {san}
              </Badge>
            ))}
          </div>
          <div className="mt-6">
            <p className="mb-2 text-sm font-medium text-foreground">Certificate Chain</p>
            <div className="flex flex-col items-start gap-0">
              {scan.chain.map((c, i) => {
                const isRoot = c.isSelfSigned;
                const isLeaf = i === scan.chain.length - 1;
                return (
                  <div key={c.id} className="flex items-start gap-2">
                    <div className="flex flex-col items-center">
                      <div
                        className={cn(
                          "rounded-md border px-3 py-2",
                          isRoot
                            ? "border-violet-500/40 bg-violet-500/10"
                            : isLeaf
                              ? "border-emerald-500/40 bg-emerald-500/10"
                              : "border-sky-500/40 bg-sky-500/10",
                        )}
                      >
                        <p className="font-mono text-xs font-medium text-foreground">{c.commonName}</p>
                        <p className="font-mono text-[10px] text-muted-foreground">
                          {isRoot ? "Root CA" : isLeaf ? "Leaf Certificate" : "Intermediate CA"}
                        </p>
                      </div>
                      {i < scan.chain.length - 1 && (
                        <div className="flex h-6 flex-col items-center">
                          <div className="h-3 w-px bg-border" />
                          <ArrowDown className="h-3 w-3 text-muted-foreground" />
                        </div>
                      )}
                    </div>
                    {i < scan.chain.length - 1 && <span className="sr-only">signed by</span>}
                  </div>
                );
              })}
            </div>
            <p className="mt-3 text-xs text-muted-foreground">
              Chain verified for {scan.certificate.commonName}: Root CA → Intermediate → Leaf → Service
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
