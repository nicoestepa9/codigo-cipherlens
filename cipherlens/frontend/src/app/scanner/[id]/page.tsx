"use client";

import { useParams } from "next/navigation";
import { FileSearch, Loader2 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ResultHeader } from "@/components/features/analysis/result-header";
import { ConnectionTab } from "@/components/features/analysis/connection-tab";
import { CertificateTab } from "@/components/features/analysis/certificate-tab";
import { CipherSuitesTab } from "@/components/features/analysis/cipher-suites-tab";
import { FindingsTab } from "@/components/features/analysis/findings-tab";
import { AiRecommendationsTab } from "@/components/features/analysis/ai-recommendations-tab";
import { getScanResult } from "@/services/scansService";
import { useAsync } from "@/hooks/use-async";
import { EmptyState } from "@/components/shared/empty-state";
import { Card, CardContent } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export default function ScanResultPage() {
  const params = useParams<{ id: string }>();
  const { data: scan, loading, error } = useAsync(() => getScanResult(params.id), [params.id]);

  if (loading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading analysis result...
        </CardContent>
      </Card>
    );
  }

  if (error || !scan) {
    return (
      <EmptyState
        icon={<FileSearch className="h-6 w-6" />}
        title="Analysis not found"
        description="This analysis may have expired. Run a new scan from the TLS Scanner."
      />
    );
  }

  if (scan.status === "failed" || scan.connectionError) {
    return (
      <>
        <ResultHeader scan={scan} />
        <Alert variant="destructive">
          <AlertTitle>TLS analysis failed</AlertTitle>
          <AlertDescription>{scan.connectionError || "The scan did not collect a TLS result."}</AlertDescription>
        </Alert>
      </>
    );
  }

  return (
    <div>
      <ResultHeader scan={scan} />
      <Tabs defaultValue="connection" className="w-full">
        <TabsList className="flex h-auto w-full flex-wrap justify-start gap-1">
          <TabsTrigger value="connection">Connection</TabsTrigger>
          <TabsTrigger value="certificate">Certificate</TabsTrigger>
          <TabsTrigger value="ciphers">Cipher Suites</TabsTrigger>
          <TabsTrigger value="findings">
            Security Findings ({scan.findings.length})
          </TabsTrigger>
          <TabsTrigger value="ai">AI Recommendations</TabsTrigger>
        </TabsList>
        <TabsContent value="connection">
          <ConnectionTab scan={scan} />
        </TabsContent>
        <TabsContent value="certificate">
          <CertificateTab scan={scan} />
        </TabsContent>
        <TabsContent value="ciphers">
          <CipherSuitesTab scan={scan} />
        </TabsContent>
        <TabsContent value="findings">
          <FindingsTab scan={scan} />
        </TabsContent>
        <TabsContent value="ai">
          <AiRecommendationsTab scan={scan} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
