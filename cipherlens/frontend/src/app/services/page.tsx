"use client";

import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { ServicesTable } from "@/components/features/services/services-table";

export default function ServicesPage() {
  return (
    <div>
      <PageHeader
        title="Services Inventory"
        subtitle="Every service with its TLS posture, certificate binding, and linked business asset."
        actions={
          <Button variant="outline" size="sm" disabled>
            <Plus className="mr-2 h-4 w-4" />
            Add Service
          </Button>
        }
      />
      <ServicesTable />
    </div>
  );
}
