"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LogOut, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { NAV_SECTIONS } from "./nav-items";
import { cn } from "@/lib/utils";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useAuth } from "@/components/auth/AuthContext";
import cipherLensLogo from "../../../public/cipherlens-logo.png";

export function Sidebar({
  collapsed = false,
  onToggle,
  onNavigate,
  className,
}: {
  collapsed?: boolean;
  onToggle?: () => void;
  onNavigate?: () => void;
  className?: string;
}) {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  const sections = NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter(
      (item) => !item.roles || (user?.role ? item.roles.includes(user.role) : false),
    ),
  })).filter((section) => section.items.length > 0);

  const initials = user?.name
    ? user.name.split(" ").map((n) => n[0]).join("").slice(0, 2).toUpperCase()
    : "SO";

  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col border-r bg-sidebar transition-[width] duration-200 motion-reduce:transition-none",
        collapsed ? "w-[76px]" : "w-[264px]",
        className,
      )}
    >
      <div className={cn("flex h-16 shrink-0 items-center border-b px-3", collapsed ? "justify-center" : "justify-between")}>
        <div className={cn("flex items-center gap-2.5 overflow-hidden", collapsed && "justify-center")}>
          <div className="brand-mark size-[38px]">
            <Image src={cipherLensLogo} alt="" width={36} height={24} />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold leading-tight text-sidebar-foreground">CipherLens</p>
              <p className="truncate text-[10.5px] font-semibold tracking-widest uppercase text-muted-foreground">Safe Cryptography</p>
            </div>
          )}
        </div>
        {!collapsed && onToggle && (
          <button
            onClick={onToggle}
            className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground"
            aria-label="Collapse sidebar"
          >
            <PanelLeftClose className="h-4 w-4" />
          </button>
        )}
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-4">
        {sections.map((section) => (
          <div key={section.label}>
            {!collapsed && (
              <p className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                {section.label}
              </p>
            )}
            <div className="space-y-[3px]">
              {section.items.map((item) => {
                const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
                const Icon = item.icon;
                const link = (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={onNavigate}
                    aria-label={collapsed ? item.label : undefined}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "relative flex items-center gap-[11px] px-[11px] py-[9px] text-[13.5px] transition-colors",
                      collapsed && "justify-center px-0",
                      active
                        ? "bg-sidebar-accent font-semibold text-sidebar-accent-foreground before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:bg-primary"
                        : "text-sidebar-foreground hover:bg-muted hover:text-foreground",
                    )}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                  </Link>
                );
                return collapsed ? (
                  <Tooltip key={item.href}>
                    <TooltipTrigger asChild>{link}</TooltipTrigger>
                    <TooltipContent side="right">{item.label}</TooltipContent>
                  </Tooltip>
                ) : (
                  link
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t p-3">
        {collapsed ? (
          <div className="flex justify-center">
            <Avatar className="h-8 w-8">
              <AvatarFallback className="border border-white/25 bg-linear-to-br from-[#1e5a91] to-[#123b66] text-xs font-bold">{initials}</AvatarFallback>
            </Avatar>
          </div>
        ) : (
          <div className="flex items-center justify-between">
            <div className="flex min-w-0 items-center gap-2.5">
              <Avatar className="h-8 w-8">
                <AvatarFallback className="border border-white/25 bg-linear-to-br from-[#1e5a91] to-[#123b66] text-xs font-bold">{initials}</AvatarFallback>
              </Avatar>
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-sidebar-foreground">{user?.name ?? "Security Ops"}</p>
                <p className="truncate text-[11px] text-muted-foreground capitalize">{user?.role ?? "Company Corp"}</p>
              </div>
            </div>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => void logout()}
                  aria-label="Logout"
                  className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                >
                  <LogOut className="h-4 w-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent>Logout</TooltipContent>
            </Tooltip>
          </div>
        )}
        {collapsed && (
          <div className="mt-2 flex justify-center">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={onToggle}
                  aria-label="Expand sidebar"
                  className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                >
                  <PanelLeftOpen className="h-4 w-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="right">Expand sidebar</TooltipContent>
            </Tooltip>
          </div>
        )}
      </div>
    </aside>
  );
}
