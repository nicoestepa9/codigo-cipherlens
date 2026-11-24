"use client";

import { Suspense, useEffect, useState } from "react";
import Image from "next/image";
import { useRouter, useSearchParams } from "next/navigation";
import { FileCode2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/components/auth/AuthContext";
import cipherLensLogo from "../../../public/cipherlens-logo.png";

function LoginForm() {
  const { login, isAuthenticated, loading } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!loading && isAuthenticated) {
      const next = searchParams.get("next");
      router.replace(next && next.startsWith("/") ? next : "/dashboard");
    }
  }, [loading, isAuthenticated, router, searchParams]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "No se pudo iniciar sesión");
      setSubmitting(false);
    }
  }

  return (
    <section lang="es" className="grid w-full max-w-[1000px] border border-[var(--border-strong)] bg-card shadow-2xl min-[821px]:grid-cols-[1.05fr_1fr]">
      <div className="login-brand hidden flex-col gap-8 border-r p-10 min-[821px]:flex">
        <div className="flex items-center gap-3">
          <div className="brand-mark size-[52px] rounded-[14px]">
            <Image src={cipherLensLogo} alt="" width={48} height={32} />
          </div>
          <div>
            <p className="text-[21px] font-bold">CipherLens</p>
            <p className="text-[10.5px] font-semibold tracking-widest uppercase text-muted-foreground">Safe Cryptography</p>
          </div>
        </div>
        <p className="max-w-[20ch] text-[27px] leading-tight font-bold">Seguridad criptográfica en una sola consola</p>
        <ul className="grid gap-3 text-secondary-foreground">
          <li className="flex items-center gap-3"><ShieldCheck className="size-4 text-[var(--accent-bright)]" /> Monitoreo TLS y de certificados</li>
          <li className="flex items-center gap-3"><FileCode2 className="size-4 text-[var(--accent-bright)]" /> Análisis SAST de código Java</li>
        </ul>
      </div>
      <div className="flex flex-col justify-center gap-5 p-6 sm:p-10">
        <div>
          <div className="mb-3 flex items-center gap-2 font-bold min-[821px]:hidden">
            <div className="brand-mark size-[38px]">
              <Image src={cipherLensLogo} alt="" width={36} height={24} />
            </div>
            CipherLens
          </div>
          <h1 className="text-[27px] leading-tight font-bold">Iniciar sesión</h1>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@cipherlens.local"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="password">Contraseña</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />
          </div>
          {error && (
            <p role="alert" className="border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {error}
            </p>
          )}
          <Button type="submit" className="h-10 w-full" disabled={submitting}>
            {submitting ? "Ingresando..." : "Iniciar sesión"}
          </Button>
        </form>
      </div>
    </section>
  );
}

export default function LoginPage() {
  return (
    <div className="flex min-h-dvh items-center justify-center p-4">
      <Suspense>
        <LoginForm />
      </Suspense>
    </div>
  );
}
