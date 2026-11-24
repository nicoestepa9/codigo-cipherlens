"use client";

import { usePathname } from "next/navigation";
import { SettingsProvider } from "@/context/settings-context";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AppShell } from "@/components/layout/app-shell";
import { AuthProvider } from "@/components/auth/AuthContext";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { CloudAuthorizationDialog } from "@/components/shared/cloud-authorization-dialog";

export function Providers({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isAuthPage = pathname.startsWith("/login");

  return (
    <AuthProvider>
      <SettingsProvider>
        <TooltipProvider>
          {isAuthPage ? (
            children
          ) : (
            <ProtectedRoute>
              <AppShell>{children}</AppShell>
            </ProtectedRoute>
          )}
          <CloudAuthorizationDialog />
        </TooltipProvider>
      </SettingsProvider>
    </AuthProvider>
  );
}
