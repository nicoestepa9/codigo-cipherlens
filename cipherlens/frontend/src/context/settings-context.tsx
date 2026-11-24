"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { Settings } from "@/types/settings";
import { isMock } from "@/services/config";
import { getThresholds } from "@/services/organizationService";
import { useAuth } from "@/components/auth/AuthContext";

const STORAGE_KEY = "cipherlens-settings";
const LEGACY_STORAGE_KEY = "cryptoguard-settings";

export const DEFAULT_SETTINGS: Settings = {
  thresholds: {
    criticalDays: 7,
    warningDays: 30,
  },
  scanDefaults: {
    timeout: 15,
    profile: "citizen-facing",
    alternatePorts: [8080, 8000, 4443, 8443],
    sni: true,
  },
  organization: "Company Corp",
  email: "security@company.com",
};

interface SettingsContextValue {
  settings: Settings;
  updateSettings: (patch: Partial<Settings>) => void;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

function loadSettings(): Settings {
  if (typeof window === "undefined") return DEFAULT_SETTINGS;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY) ?? window.localStorage.getItem(LEGACY_STORAGE_KEY);
    if (!raw) return DEFAULT_SETTINGS;
    return { ...DEFAULT_SETTINGS, ...(JSON.parse(raw) as Settings) };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const { token, user, isOperator } = useAuth();
  const organizationId = user?.organization_id ?? null;
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);

  useEffect(() => {
    setSettings(loadSettings());
  }, []);

  const updateSettings = useCallback((patch: Partial<Settings>) => {
    setSettings((prev) => {
      const next = {
        ...prev,
        ...patch,
        thresholds: { ...prev.thresholds, ...patch.thresholds },
        scanDefaults: { ...prev.scanDefaults, ...patch.scanDefaults },
      };
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        // storage unavailable
      }
      return next;
    });
  }, []);

  useEffect(() => {
    if (isOperator || !organizationId) return;
    if (!isMock() && !token) return;
    let cancelled = false;
    getThresholds()
      .then((thresholds) => {
        if (cancelled) return;
        updateSettings({
          thresholds: {
            criticalDays: thresholds.criticalDays,
            warningDays: thresholds.warningDays,
          },
        });
      })
      .catch(() => {
        // Keep local thresholds when the backend is unavailable.
      });
    return () => {
      cancelled = true;
    };
  }, [token, isOperator, organizationId, updateSettings]);

  return (
    <SettingsContext.Provider value={{ settings, updateSettings }}>
      {children}
    </SettingsContext.Provider>
  );
}

export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error("useSettings must be used within SettingsProvider");
  return ctx;
}
