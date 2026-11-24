"use client";

import { PageHeader } from "@/components/shared/page-header";
import { ScannerForm } from "@/components/features/scanner/scanner-form";
import { RecentScans } from "@/components/features/scanner/recent-scans";

export default function ScannerPage() {
  return (
    <div>
      <PageHeader
        title="TLS Scanner"
        subtitle="Perform a point-in-time TLS handshake analysis against any target."
      />
      <div className="grid gap-6">
        <ScannerForm />
        <RecentScans />
      </div>
    </div>
  );
}
