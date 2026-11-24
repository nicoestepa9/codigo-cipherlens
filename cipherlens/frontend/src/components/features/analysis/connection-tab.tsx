"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScanSearch, Fingerprint } from "lucide-react";
import { formatDateTime, formatDuration } from "@/lib/format";
import type { ScanResult } from "@/types/scan";
import type { SecurityStatus } from "@/types/severity";

function itemStatus(secure: boolean, critical: boolean): SecurityStatus {
  if (critical) return "critical";
  if (secure) return "secure";
  return "warning";
}

function ItemBadge({ status }: { status: SecurityStatus }) {
  const cls =
    status === "secure"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
      : status === "warning"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
        : "border-red-500/40 bg-red-500/10 text-red-400";
  return (
    <Badge variant="outline" className={cls}>
      {status === "secure" ? "Secure" : status === "warning" ? "Warning" : "Critical"}
    </Badge>
  );
}

function DetailRow({ label, value, status }: { label: string; value: string; status?: SecurityStatus }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border/60 py-2.5 last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="flex items-center gap-2 text-right">
        <span className="font-mono text-sm text-foreground">{value || "Not available"}</span>
        {value && status && <ItemBadge status={status} />}
      </span>
    </div>
  );
}

export function ConnectionTab({ scan }: { scan: ScanResult }) {
  const protoSecure = scan.negotiatedProtocol.includes("1.3") || scan.negotiatedProtocol.includes("1.2");
  const cipherSecure = /GCM|CHACHA|TLS_AES/.test(scan.negotiatedCipher);
  const kexSecure = scan.keyExchange === "X25519" || scan.keyExchange === "ECDHE";
  const sigSecure = /PSS|SHA256|SHA384/i.test(scan.signatureAlgorithm) && !/SHA1/i.test(scan.signatureAlgorithm);

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ScanSearch className="h-4 w-4 text-primary" />
            Connection Information
          </CardTitle>
        </CardHeader>
        <CardContent className="p-5 pt-0">
          <DetailRow label="Host" value={scan.host} />
          <DetailRow label="IP Address" value={scan.ipAddress} />
          <DetailRow label="Port" value={`${scan.port}${scan.portIsAlternate ? " (alternate)" : ""}`} />
          <DetailRow label="Scan date" value={formatDateTime(scan.scanStartedAt)} />
          <DetailRow label="Duration" value={formatDuration(scan.scanDurationMs)} />
          <DetailRow label="Profile" value={scan.profile} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Negotiated TLS</CardTitle>
        </CardHeader>
        <CardContent className="p-5 pt-0">
          <DetailRow
            label="TLS Version"
            value={scan.negotiatedProtocol}
            status={itemStatus(protoSecure, scan.negotiatedProtocol.includes("1.0") || scan.negotiatedProtocol.includes("1.1"))}
          />
          <DetailRow label="Cipher Suite" value={scan.negotiatedCipher} status={itemStatus(cipherSecure, /3DES|RC4|DES/.test(scan.negotiatedCipher))} />
          <DetailRow label="Key Exchange" value={scan.keyExchange} status={itemStatus(kexSecure, scan.keyExchange === "RSA")} />
          <DetailRow label="Signature Algorithm" value={scan.signatureAlgorithm} status={itemStatus(sigSecure, /SHA1/i.test(scan.signatureAlgorithm))} />
          <div className="pt-2">
            <p className="mb-2 text-xs text-muted-foreground">Supported protocols</p>
            <div className="flex flex-wrap gap-1.5">
              {scan.supportedProtocols.map((p) => (
                <Badge key={p} variant="outline" className="font-mono text-xs">
                  {p}
                </Badge>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Fingerprint className="h-4 w-4 text-primary" />
            OS / Service Fingerprint
          </CardTitle>
        </CardHeader>
        <CardContent className="p-5 pt-0">
          {scan.osFingerprint.detected ? (
            <div className="grid gap-4 sm:grid-cols-3">
              <div>
                <p className="text-xs text-muted-foreground">Operating System</p>
                <p className="mt-1 font-mono text-sm">{scan.osFingerprint.os ?? "—"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Service / Banner</p>
                <p className="mt-1 font-mono text-sm">{scan.osFingerprint.service ?? scan.osFingerprint.banner ?? "—"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Confidence</p>
                <p className="mt-1 font-mono text-sm">{scan.osFingerprint.confidence ?? "—"}</p>
              </div>
              {scan.osFingerprint.ja3Hash && (
                <div>
                  <p className="text-xs text-muted-foreground">JA3 Hash</p>
                  <p className="mt-1 font-mono text-sm break-all">{scan.osFingerprint.ja3Hash}</p>
                </div>
              )}
              {scan.osFingerprint.ja3sHash && (
                <div>
                  <p className="text-xs text-muted-foreground">JA3S Hash</p>
                  <p className="mt-1 font-mono text-sm break-all">{scan.osFingerprint.ja3sHash}</p>
                </div>
              )}
              {scan.osFingerprint.method && (
                <div>
                  <p className="text-xs text-muted-foreground">Detection Method</p>
                  <p className="mt-1 font-mono text-sm">{scan.osFingerprint.method}</p>
                </div>
              )}
              <div className="sm:col-span-3">
                <p className="text-xs text-muted-foreground">Note</p>
                <p className="mt-1 text-sm text-foreground">{scan.osFingerprint.note}</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No OS fingerprint could be derived from this handshake.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
