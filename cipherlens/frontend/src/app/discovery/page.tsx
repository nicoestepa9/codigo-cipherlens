"use client";

import { useState } from "react";
import { PageHeader } from "@/components/shared/page-header";
import { DiscoveryForm } from "@/components/features/discovery/discovery-form";
import { DiscoveryResults } from "@/components/features/discovery/discovery-results";
import type { DiscoveryResult } from "@/types/discovery";

export default function DiscoveryPage() {
  const [results, setResults] = useState<DiscoveryResult[] | null>(null);

  return (
    <div>
      <PageHeader
        title="Network Discovery"
        subtitle="Discover services and certificates across your network, separating declared inventory from Shadow IT."
      />
      <div className="space-y-6">
        <DiscoveryForm onComplete={setResults} />
        {results && <DiscoveryResults results={results} />}
      </div>
    </div>
  );
}
