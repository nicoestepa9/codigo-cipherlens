"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Bell, Building2, Search } from "lucide-react";
import { PAGE_TITLES } from "./nav-items";
import { getUnreadAlertsCount } from "@/services/alertsService";
import { getOrganization } from "@/services/organizationService";
import { useAsync } from "@/hooks/use-async";
import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/components/auth/AuthContext";

export function Topbar({ menu }: { menu: React.ReactNode }) {
  const pathname = usePathname();
  const { isOperator } = useAuth();
  const { data: unread } = useAsync(
    () => (isOperator ? Promise.resolve(0) : getUnreadAlertsCount()),
    [isOperator],
  );
  const { data: organization } = useAsync(
    () => (isOperator ? Promise.resolve(null) : getOrganization()),
    [isOperator],
  );
  const [searchOpen, setSearchOpen] = useState(false);
  const [search, setSearch] = useState("");

  const meta = PAGE_TITLES[pathname];

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b px-4">
      <div className="flex min-w-0 items-center gap-3">
        {menu}
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            {meta?.section ?? "CipherLens"}
          </p>
          <h2 className="truncate text-sm font-medium text-foreground">{meta?.title ?? "Security Platform"}</h2>
        </div>
      </div>

      <div className="flex items-center gap-1.5">
        {!isOperator && organization && (
          <div className="hidden max-w-48 items-center gap-1.5 rounded-md border px-2 py-1 text-xs text-muted-foreground lg:flex">
            <Building2 className="h-3.5 w-3.5 shrink-0" />
            <span className="truncate">{organization.name}</span>
          </div>
        )}
        {!isOperator && (
          <>
            <div className={searchOpen ? "relative hidden sm:block" : "relative hidden md:block"}>
              <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search assets, certs..."
                className="h-8 w-48 pl-8 text-sm"
              />
            </div>
            <Button
              variant="ghost"
              size="icon"
              className="sm:hidden"
              onClick={() => setSearchOpen((v) => !v)}
              aria-label="Search"
            >
              <Search className="h-4 w-4" />
            </Button>
          </>
        )}
        {!isOperator && (
          <Button variant="ghost" size="icon" asChild className="relative" aria-label="Alerts">
            <Link href="/alerts">
              <Bell className="h-4 w-4" />
              {!!unread && (
                <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-semibold text-white">
                  {unread}
                </span>
              )}
            </Link>
          </Button>
        )}
      </div>
    </header>
  );
}
