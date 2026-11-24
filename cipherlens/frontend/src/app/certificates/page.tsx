"use client";

import Link from "next/link";
import { Activity, AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { CertificatesTable } from "@/components/features/certificates/certificates-table";

export default function CertificatesPage() {
  return (
    <div>
      <PageHeader
        title="Certificate Inventory"
        subtitle="All TLS certificates discovered in your environment, with expiration monitoring."
        actions={
          <>
            <Button variant="outline" size="sm" asChild>
              <Link href="/certificates/expiration">
                <AlertTriangle className="mr-2 h-4 w-4" />
                Expiration Monitoring
              </Link>
            </Button>
            <Button variant="outline" size="sm" disabled>
              <RefreshCw className="mr-2 h-4 w-4" />
              Rescan
            </Button>
            <Button size="sm" disabled>
              <Activity className="mr-2 h-4 w-4" />
              Import Certificate
            </Button>
          </>
        }
      />
      <CertificatesTable />
    </div>
  );
}
