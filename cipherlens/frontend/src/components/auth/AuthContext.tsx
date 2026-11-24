"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { setAccessToken } from "@/services/apiClient";
import * as authService from "@/services/authService";
import type { AuthUser, Role } from "@/types/auth";

interface AuthContextValue {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  isOperator: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(async () => {
    try {
      await authService.logoutRequest();
    } catch {
      // ignore
    }
    setAccessToken(null);
    setToken(null);
    setUser(null);
    localStorage.removeItem('authToken');
    router.push("/login");
  }, [router]);

  const loadUser = useCallback(async () => {
    try {
      const me = await authService.fetchMe();
      setUser(me);
    } catch {
      setUser(null);
      setAccessToken(null);
      setToken(null);
      localStorage.removeItem("authToken");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const storedToken = localStorage.getItem("authToken");
    if (storedToken) {
      setAccessToken(storedToken);
      setToken(storedToken);
      void loadUser();
    } else {
      setLoading(false);
    }
  }, [loadUser]);

const login = useCallback(
    async (email: string, password: string) => {
      const response = await authService.login(email, password);
      if (response.accessToken) {
        setAccessToken(response.accessToken);
        setToken(response.accessToken);
        localStorage.setItem('authToken', response.accessToken);
      }
      const me = await authService.fetchMe();
      setUser(me);
    },
    [],
  );

  const refreshUser = useCallback(async () => {
    await loadUser();
  }, [loadUser]);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      token,
      loading,
      isAuthenticated: !!token,
      isAdmin: user?.role === "admin",
      isOperator: user?.role === "operator",
      login,
      logout,
      refreshUser,
    }),
    [user, token, loading, login, logout, refreshUser],
  );

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export function useRole(): {
  role: Role | null;
  isAdmin: boolean;
  isLead: boolean;
  canAssign: boolean;
} {
  const { user } = useAuth();
  const role = user?.role ?? null;
  return {
    role,
    isAdmin: role === "admin",
    isLead: role === "lead",
    canAssign: role === "admin" || role === "lead",
  };
}
