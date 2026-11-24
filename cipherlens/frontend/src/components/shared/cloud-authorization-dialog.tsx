"use client";

import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  CLOUD_AUTHORIZATION_REQUEST_EVENT,
  type CloudAuthorizationRequest,
} from "@/services/cloudAuthorization";

export function CloudAuthorizationDialog() {
  const [request, setRequest] = useState<CloudAuthorizationRequest | null>(null);

  useEffect(() => {
    function handleRequest(event: Event) {
      event.preventDefault();
      setRequest((previous) => {
        previous?.resolve(false);
        return (event as CustomEvent<CloudAuthorizationRequest>).detail;
      });
    }

    window.addEventListener(CLOUD_AUTHORIZATION_REQUEST_EVENT, handleRequest);
    return () => window.removeEventListener(CLOUD_AUTHORIZATION_REQUEST_EVENT, handleRequest);
  }, []);

  function settle(accepted: boolean) {
    request?.resolve(accepted);
    setRequest(null);
  }

  return (
    <Dialog
      open={request !== null}
      onOpenChange={(open) => {
        if (!open) settle(false);
      }}
    >
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            Cloud scan authorization
          </DialogTitle>
          <DialogDescription>
            Cloud scans run from the platform against an external target. Confirm that you are
            authorized to scan it.
          </DialogDescription>
        </DialogHeader>

        <p className="rounded-lg border bg-muted/40 p-3 text-sm">{request?.text}</p>
        <p className="text-xs text-muted-foreground">
          Version {request?.version}. Your acceptance is recorded in the audit log.
        </p>

        <DialogFooter>
          <Button variant="outline" onClick={() => settle(false)}>
            Cancel
          </Button>
          <Button onClick={() => settle(true)}>I confirm authorization</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
