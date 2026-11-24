"use client";

import { useEffect, useState } from "react";
import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";
import { ForcePasswordChange } from "@/components/auth/force-password-change";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const desktop = window.matchMedia("(min-width: 901px)");
    const closeDesktopMenu = (event: MediaQueryListEvent) => {
      if (event.matches) setMenuOpen(false);
    };
    desktop.addEventListener("change", closeDesktopMenu);
    return () => desktop.removeEventListener("change", closeDesktopMenu);
  }, []);

  return (
    <div className="flex h-dvh overflow-hidden">
      <Sidebar className="hidden min-[901px]:flex" collapsed={collapsed} onToggle={() => setCollapsed((v) => !v)} />
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <Topbar menu={
          <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" className="min-[901px]:hidden" aria-label="Open navigation">
                <Menu />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="gap-0 data-[side=left]:w-[min(290px,84vw)] min-[901px]:hidden" aria-describedby={undefined}>
              <SheetTitle className="sr-only">Navigation</SheetTitle>
              <Sidebar className="min-h-0 w-full flex-1 border-r-0" onNavigate={() => setMenuOpen(false)} />
            </SheetContent>
          </Sheet>
        } />
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1240px] px-[clamp(18px,4vw,44px)] pt-[30px] pb-12">{children}</div>
        </main>
      </div>
      <ForcePasswordChange />
    </div>
  );
}
