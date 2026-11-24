import {
  Bell,
  Bug,
  Building2,
  CalendarClock,
  Cpu,
  Flag,
  History,
  LayoutDashboard,
  ListChecks,
  Plug,
  Radar,
  ScanSearch,
  Server,
  Settings,
  ShieldCheck,
  Users,
  UsersRound,
  type LucideIcon,
} from "lucide-react";
import type { Role } from "@/types/auth";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  badge?: number;
  roles?: Role[];
}

export interface NavSection {
  label: string;
  items: NavItem[];
}

export const NAV_SECTIONS: NavSection[] = [
  {
    label: "Operator",
    items: [{ href: "/operator", label: "Organizations", icon: Building2, roles: ["operator"] }],
  },
  {
    label: "Overview",
    items: [{ href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, roles: ["user", "lead", "admin", "viewer"] }],
  },
  {
    label: "Analysis",
    items: [
      { href: "/scanner", label: "TLS Scanner", icon: ScanSearch, roles: ["user", "lead", "admin"] },
      { href: "/crypto-ml", label: "SAST", icon: Cpu, roles: ["user", "lead", "admin"] },
      { href: "/discovery", label: "Network Discovery", icon: Radar, roles: ["user", "lead", "admin"] },
      { href: "/recurring-scans", label: "Recurring Scans", icon: CalendarClock, roles: ["user", "lead", "admin"] },
      { href: "/history", label: "Analysis History", icon: History, roles: ["user", "lead", "admin"] },
    ],
  },
  {
    label: "Inventory",
    items: [
      { href: "/certificates", label: "Certificates", icon: ShieldCheck, roles: ["user", "lead", "admin"] },
      { href: "/services", label: "Services", icon: Server, roles: ["user", "lead", "admin"] },
      { href: "/assets", label: "Assets", icon: ListChecks, roles: ["user", "lead", "admin"] },
    ],
  },
  {
    label: "Security",
    items: [
      { href: "/vulnerabilities", label: "Vulnerabilities", icon: Bug, roles: ["user", "lead", "admin"] },
      { href: "/alerts", label: "Alerts", icon: Bell, roles: ["user", "lead", "admin"] },
    ],
  },
  {
    label: "Administration",
    items: [
      { href: "/users", label: "Users", icon: Users, roles: ["admin"] },
      { href: "/teams", label: "Teams", icon: UsersRound, roles: ["admin", "lead"] },
      { href: "/issues", label: "Issues", icon: Flag, roles: ["admin", "lead"] },
      { href: "/agents", label: "Agents", icon: Cpu, roles: ["admin", "lead"] },
      { href: "/agent-tasks", label: "Agent Tasks", icon: ListChecks, roles: ["admin", "lead"] },
    ],
  },
  {
    label: "My Work",
    items: [{ href: "/my-issues", label: "My Issues", icon: Flag, roles: ["user", "lead", "admin"] }],
  },
  {
    label: "Platform",
    items: [
      { href: "/integrations", label: "Integrations / API", icon: Plug, roles: ["admin"] },
      { href: "/settings", label: "Settings", icon: Settings, roles: ["viewer", "user", "lead", "admin"] },
    ],
  },
];

export const PAGE_TITLES: Record<string, { title: string; section: string }> = {
  "/operator": { title: "Organizations", section: "Platform" },
  "/dashboard": { title: "Security Overview", section: "Dashboard" },
  "/scanner": { title: "TLS Scanner", section: "Analysis" },
  "/crypto-ml": { title: "SAST", section: "Analysis" },
  "/discovery": { title: "Network Discovery", section: "Analysis" },
  "/recurring-scans": { title: "Recurring Scans", section: "Analysis" },
  "/history": { title: "Analysis History", section: "Analysis" },
  "/certificates": { title: "Certificate Inventory", section: "Inventory" },
  "/certificates/expiration": { title: "Expiration Monitoring", section: "Inventory" },
  "/services": { title: "Services Inventory", section: "Inventory" },
  "/assets": { title: "Asset Inventory", section: "Inventory" },
  "/vulnerabilities": { title: "Vulnerabilities", section: "Security" },
  "/alerts": { title: "Security Alerts", section: "Security" },
  "/integrations": { title: "Integrations / API", section: "Platform" },
  "/settings": { title: "Settings", section: "Platform" },
  "/users": { title: "User Management", section: "Administration" },
  "/teams": { title: "Team Management", section: "Administration" },
  "/issues": { title: "Issue Tracking", section: "Administration" },
  "/agents": { title: "On-prem Agents", section: "Administration" },
  "/agent-tasks": { title: "Agent Tasks", section: "Administration" },
  "/my-issues": { title: "My Issues", section: "My Work" },
};
