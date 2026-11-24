"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { useAuth } from "@/components/auth/AuthContext";

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading, isOperator } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const isOperatorRoute = pathname === "/operator" || pathname.startsWith("/operator/");

  useEffect(() => {
    if (loading) return;
    if (!isAuthenticated) {
      const next = pathname && pathname !== "/" ? `?next=${encodeURIComponent(pathname)}` : "";
      router.replace(`/login${next}`);
      return;
    }
    if (isOperator && !isOperatorRoute) {
      router.replace("/operator");
      return;
    }
    if (!isOperator && isOperatorRoute) {
      router.replace("/dashboard");
    }
  }, [loading, isAuthenticated, isOperator, isOperatorRoute, router, pathname]);

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  if (isOperator && !isOperatorRoute) {
    return null;
  }

  if (!isOperator && isOperatorRoute) {
    return null;
  }

  return <>{children}</>;
}
