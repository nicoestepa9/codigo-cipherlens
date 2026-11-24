"use client";

import { useState, useEffect } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { PageHeader } from "@/components/shared/page-header";
import { useSettings } from "@/context/settings-context";
import { isMock, setMockMode } from "@/services/config";
import { changeMyPassword, deleteMyAccount } from "@/services/authService";
import { useAuth } from "@/components/auth/AuthContext";
import { Loader2, CheckCircle2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useAsync } from "@/hooks/use-async";
import { api } from "@/services/apiClient";
import {
  getComplianceWindows,
  getOrganization,
  getThresholds,
  replaceComplianceWindows,
  setAiMode,
  updateSlaSettings,
  updateThresholds,
} from "@/services/organizationService";
import type { ComplianceWindowInput } from "@/types/organization";
import { Plus, Trash2 } from "lucide-react";

interface AiStatus {
  provider: string;
  anonymization: string;
  externalLlm: boolean;
}

export default function SettingsPage() {
  const { settings, updateSettings } = useSettings();
  const { logout, user } = useAuth();
  const [mockMode, setMockModeState] = useState(isMock());

  const [criticalDays, setCriticalDays] = useState(String(settings.thresholds.criticalDays));
  const [warningDays, setWarningDays] = useState(String(settings.thresholds.warningDays));
  const [timeout, setTimeoutSec] = useState(String(settings.scanDefaults.timeout));
  const [profile, setProfile] = useState<"citizen-facing" | "government-only">(settings.scanDefaults.profile);
  const [alternatePorts, setAlternatePorts] = useState(settings.scanDefaults.alternatePorts.join(", "));
  const [sni, setSni] = useState(settings.scanDefaults.sni);
  const [email, setEmail] = useState(settings.email);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [windows, setWindows] = useState<ComplianceWindowInput[]>([]);
  const [windowsBusy, setWindowsBusy] = useState(false);
  const [windowsMessage, setWindowsMessage] = useState("");
  const [aiMode, setAiModeState] = useState<"external" | "template">("template");
  const [aiModeBusy, setAiModeBusy] = useState(false);
  const [aiModeMessage, setAiModeMessage] = useState("");
  const [slaCritical, setSlaCritical] = useState("7");
  const [slaHigh, setSlaHigh] = useState("14");
  const [slaMedium, setSlaMedium] = useState("30");
  const [slaBusy, setSlaBusy] = useState(false);
  const [slaMessage, setSlaMessage] = useState("");
  const [thresholdsBusy, setThresholdsBusy] = useState(false);
  const [thresholdsMessage, setThresholdsMessage] = useState("");

  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwMsg, setPwMsg] = useState("");
  const [pwBusy, setPwBusy] = useState(false);

  const [delBusy, setDelBusy] = useState(false);

  const { data: aiStatus } = useAsync<AiStatus>(() => api.get<AiStatus>("/settings/ai-status"), []);
  const { data: organization } = useAsync(getOrganization, []);
  const { data: backendThresholds } = useAsync(getThresholds, []);
  const { data: complianceWindows } = useAsync(getComplianceWindows, []);

  useEffect(() => {
    if (!backendThresholds) return;
    setCriticalDays(String(backendThresholds.criticalDays));
    setWarningDays(String(backendThresholds.warningDays));
  }, [backendThresholds]);

  useEffect(() => {
    if (!organization) return;
    setAiModeState(organization.aiMode);
    setSlaCritical(String(organization.slaDaysCritical));
    setSlaHigh(String(organization.slaDaysHigh));
    setSlaMedium(String(organization.slaDaysMedium));
  }, [organization]);

  useEffect(() => {
    if (!complianceWindows) return;
    setWindows(
      complianceWindows.map(({ name, framework, auditDate, scopeFilter }) => ({
        name,
        framework,
        auditDate,
        scopeFilter,
      })),
    );
  }, [complianceWindows]);

  function handleMockToggle(value: boolean) {
    setMockMode(value);
    setMockModeState(value);
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  }

  function handleSave() {
    const ports = alternatePorts
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean)
      .map(Number)
      .filter((n) => !Number.isNaN(n) && n > 0 && n <= 65535);

    setSaveError("");
    updateSettings({
      scanDefaults: {
        timeout: Math.max(5, Math.min(120, Number(timeout) || 15)),
        profile,
        alternatePorts: ports.length > 0 ? ports : [8080, 8000, 4443, 8443],
        sni,
      },
      email: email.trim(),
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  }

  async function handleSaveThresholds() {
    if (user?.role !== "admin") return;
    const critical = Math.max(1, Number(criticalDays) || 7);
    const warning = Math.max(critical + 1, Number(warningDays) || 30);

    setThresholdsBusy(true);
    setThresholdsMessage("");
    try {
      const savedThresholds = await updateThresholds({
        daysBeforeExpiry: backendThresholds?.daysBeforeExpiry ?? [warning, critical],
        notifyOnCriticalFinding: backendThresholds?.notifyOnCriticalFinding ?? true,
        notifyOnCompliance: backendThresholds?.notifyOnCompliance ?? true,
        criticalDays: critical,
        warningDays: warning,
      });
      setCriticalDays(String(savedThresholds.criticalDays));
      setWarningDays(String(savedThresholds.warningDays));
      updateSettings({
        thresholds: {
          criticalDays: savedThresholds.criticalDays,
          warningDays: savedThresholds.warningDays,
        },
      });
      setThresholdsMessage("Expiration thresholds updated.");
      setTimeout(() => setThresholdsMessage(""), 3000);
    } catch (err) {
      setThresholdsMessage(err instanceof Error ? err.message : "Could not save the thresholds.");
      setTimeout(() => setThresholdsMessage(""), 3000);
    } finally {
      setThresholdsBusy(false);
    }
  }

  async function handleAiModeChange(mode: "external" | "template") {
    setAiModeBusy(true);
    setAiModeMessage("");
    try {
      await setAiMode(mode);
      setAiModeState(mode);
      setAiModeMessage("AI mode updated.");
    } catch (err) {
      setAiModeMessage(err instanceof Error ? err.message : "Could not update the AI mode.");
    } finally {
      setAiModeBusy(false);
    }
  }

  async function handleSaveSla() {
    const criticalDays = Math.max(1, Math.min(365, Number(slaCritical) || 7));
    const highDays = Math.max(1, Math.min(365, Number(slaHigh) || 14));
    const mediumDays = Math.max(1, Math.min(365, Number(slaMedium) || 30));
    setSlaCritical(String(criticalDays));
    setSlaHigh(String(highDays));
    setSlaMedium(String(mediumDays));
    setSlaBusy(true);
    setSlaMessage("");
    try {
      const saved = await updateSlaSettings({ criticalDays, highDays, mediumDays });
      setSlaCritical(String(saved.slaDaysCritical));
      setSlaHigh(String(saved.slaDaysHigh));
      setSlaMedium(String(saved.slaDaysMedium));
      setSlaMessage("SLA targets updated.");
    } catch (err) {
      setSlaMessage(err instanceof Error ? err.message : "Could not update SLA targets.");
    } finally {
      setSlaBusy(false);
    }
  }

  function updateWindow(index: number, patch: Partial<ComplianceWindowInput>) {
    setWindows((prev) => prev.map((window, i) => (i === index ? { ...window, ...patch } : window)));
  }

  async function handleSaveWindows() {
    setWindowsBusy(true);
    setWindowsMessage("");
    try {
      const savedWindows = await replaceComplianceWindows(
        windows
          .filter((window) => window.name.trim() && window.auditDate)
          .map((window) => ({
            ...window,
            name: window.name.trim(),
            scopeFilter: window.scopeFilter.map((scope) => scope.trim()).filter(Boolean),
          })),
      );
      setWindowsMessage(`${savedWindows.length} compliance window(s) saved.`);
    } catch (err) {
      setWindowsMessage(err instanceof Error ? err.message : "Could not save compliance windows.");
    } finally {
      setWindowsBusy(false);
    }
  }

  async function handleChangePw() {
    setPwMsg("");
    if (newPw !== confirmPw) {
      setPwMsg("Las contraseñas no coinciden");
      return;
    }
    setPwBusy(true);
    try {
      await changeMyPassword(currentPw, newPw);
      setPwMsg("Contraseña actualizada");
      setCurrentPw("");
      setNewPw("");
      setConfirmPw("");
    } catch (err) {
      setPwMsg(err instanceof Error ? err.message : "Error al cambiar contraseña");
    } finally {
      setPwBusy(false);
    }
  }

  async function handleDeleteAccount() {
    if (!confirm("¿Estás seguro de eliminar tu cuenta? Esta acción es irreversible.")) return;
    setDelBusy(true);
    try {
      await deleteMyAccount();
      await logout();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al eliminar cuenta");
    } finally {
      setDelBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Settings"
        subtitle="Configuración, seguridad y modo de IA."
        actions={<Button onClick={handleSave}>Save changes</Button>}
      />

      {saved && (
        <Alert className="mb-4 border-emerald-500/40 bg-emerald-500/10">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          <AlertTitle>Saved</AlertTitle>
          <AlertDescription>Settings updated.</AlertDescription>
        </Alert>
      )}

      {saveError && (
        <Alert variant="destructive" className="mb-4">
          <AlertTitle>Could not save</AlertTitle>
          <AlertDescription>{saveError}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        {user?.role === "admin" && (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-base">Data Source</CardTitle>
              <CardDescription>Usar mock o backend real</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <Label htmlFor="use-mock">Use mock data</Label>
                  <p className="text-[11px] text-muted-foreground">
                    Off: backend /api. On: datos de ejemplo.
                  </p>
                </div>
                <Switch id="use-mock" checked={mockMode} onCheckedChange={handleMockToggle} />
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle className="text-base">AI Status</CardTitle>
            <CardDescription>Estado del modo IA configurado</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span>Proveedor</span>
              <Badge variant="outline">{aiStatus?.provider ?? "—"}</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span>Anonymization</span>
              <Badge variant="outline">{aiStatus?.anonymization ?? "—"}</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span>External LLM</span>
              <Badge variant={aiStatus?.externalLlm ? "secondary" : "outline"}>
                {aiStatus?.externalLlm ? "true" : "false"}
              </Badge>
            </div>
            {user?.role === "admin" && (
              <div className="space-y-2 border-t pt-3">
                <Label htmlFor="ai-mode">Organization AI mode</Label>
                <Select
                  value={aiMode}
                  onValueChange={(value) => void handleAiModeChange(value as "external" | "template")}
                  disabled={aiModeBusy}
                >
                  <SelectTrigger id="ai-mode">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="template">Template only (no external LLM)</SelectItem>
                    <SelectItem value="external">Allow external LLM</SelectItem>
                  </SelectContent>
                </Select>
                {aiModeMessage && <p className="text-xs text-muted-foreground">{aiModeMessage}</p>}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Seguridad</CardTitle>
            <CardDescription>Cambiar contraseña / eliminar cuenta</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-2">
              <Input
                type="password"
                placeholder="Contraseña actual"
                value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
              />
              <Input
                type="password"
                placeholder="Nueva contraseña"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
              />
              <Input
                type="password"
                placeholder="Confirmar nueva contraseña"
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
              />
              <Button onClick={handleChangePw} disabled={pwBusy} size="sm">
                {pwBusy && <Loader2 className="mr-2 h-3 w-3 animate-spin" />}
                Cambiar contraseña
              </Button>
              {pwMsg && <p className="text-xs text-muted-foreground">{pwMsg}</p>}
            </div>
            <div className="pt-2">
              <Button
                variant="destructive"
                size="sm"
                onClick={handleDeleteAccount}
                disabled={delBusy}
              >
                Eliminar mi cuenta
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Expiration Thresholds</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="critical-days">Critical (days)</Label>
                <Input
                  id="critical-days"
                  type="number"
                  min={1}
                  value={criticalDays}
                  onChange={(e) => setCriticalDays(e.target.value)}
                  disabled={user?.role !== "admin"}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="warning-days">Warning (days)</Label>
                <Input
                  id="warning-days"
                  type="number"
                  min={2}
                  value={warningDays}
                  onChange={(e) => setWarningDays(e.target.value)}
                  disabled={user?.role !== "admin"}
                />
              </div>
            </div>
            {user?.role === "admin" && (
              <Button size="sm" onClick={() => void handleSaveThresholds()} disabled={thresholdsBusy}>
                {thresholdsBusy && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
                Save expiration threshold
              </Button>
            )}
            {thresholdsMessage && (
              <p className="text-xs text-muted-foreground">{thresholdsMessage}</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Issue SLA targets</CardTitle>
            <CardDescription>Days to remediate issues by severity for this organization.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="sla-critical">Critical (days)</Label>
                <Input
                  id="sla-critical"
                  type="number"
                  min={1}
                  max={365}
                  value={slaCritical}
                  onChange={(e) => setSlaCritical(e.target.value)}
                  disabled={user?.role !== "admin" || slaBusy}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sla-high">High (days)</Label>
                <Input
                  id="sla-high"
                  type="number"
                  min={1}
                  max={365}
                  value={slaHigh}
                  onChange={(e) => setSlaHigh(e.target.value)}
                  disabled={user?.role !== "admin" || slaBusy}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sla-medium">Medium (days)</Label>
                <Input
                  id="sla-medium"
                  type="number"
                  min={1}
                  max={365}
                  value={slaMedium}
                  onChange={(e) => setSlaMedium(e.target.value)}
                  disabled={user?.role !== "admin" || slaBusy}
                />
              </div>
            </div>
            {user?.role === "admin" && (
              <Button size="sm" onClick={() => void handleSaveSla()} disabled={slaBusy}>
                {slaBusy && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
                Save SLA targets
              </Button>
            )}
            {slaMessage && <p className="text-xs text-muted-foreground">{slaMessage}</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Scan Defaults</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="scan-timeout">Handshake timeout (s)</Label>
                <Input
                  id="scan-timeout"
                  type="number"
                  min={5}
                  max={120}
                  value={timeout}
                  onChange={(e) => setTimeoutSec(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label>Profile</Label>
                <Select value={profile} onValueChange={(v) => setProfile(v as typeof profile)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="citizen-facing">Citizen-facing</SelectItem>
                    <SelectItem value="government-only">Government-only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="alt-ports">Alternate TLS ports</Label>
              <Input
                id="alt-ports"
                value={alternatePorts}
                onChange={(e) => setAlternatePorts(e.target.value)}
                placeholder="8080, 8000, 4443, 8443"
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="sni">Use SNI</Label>
              </div>
              <Switch id="sni" checked={sni} onCheckedChange={setSni} />
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Organization</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="org-name">Organization</Label>
                <Input id="org-name" value={organization?.name ?? settings.organization} readOnly />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="org-email">Security contact email</Label>
                <Input id="org-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant="outline">slug: {organization?.slug ?? "—"}</Badge>
              <Badge variant="outline">status: {organization?.status ?? "—"}</Badge>
              <Badge variant="outline">AI: {organization?.aiMode ?? "—"}</Badge>
              <Badge variant="outline">max agents: {organization?.maxAgents ?? 0}</Badge>
              <Badge variant="outline">cloud scans/h: {organization?.maxCloudScansPerHour ?? 0}</Badge>
              <Badge variant="outline">recurring scans: {organization?.maxRecurringScans ?? 0}</Badge>
            </div>
            <p className="text-xs text-muted-foreground">
              Organization name and limits are managed by the platform operator.
            </p>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="text-base">Compliance windows</CardTitle>
              <CardDescription>
                Audit dates and scope used to flag compliance findings for this organization.
              </CardDescription>
            </div>
            {user?.role === "admin" && (
              <Button
                variant="outline"
                size="sm"
                className="gap-2"
                onClick={() =>
                  setWindows((prev) => [
                    ...prev,
                    { name: "", framework: "PCI-DSS", auditDate: "", scopeFilter: [] },
                  ])
                }
              >
                <Plus className="h-3.5 w-3.5" />
                Add window
              </Button>
            )}
          </CardHeader>
          <CardContent className="space-y-3">
            {windows.length === 0 && (
              <p className="text-sm text-muted-foreground">No compliance windows configured.</p>
            )}
            {windows.map((window, index) => (
              <div key={index} className="grid gap-2 sm:grid-cols-[1fr_140px_150px_1fr_auto]">
                <Input
                  aria-label="Window name"
                  placeholder="Q4 PCI audit"
                  value={window.name}
                  onChange={(event) => updateWindow(index, { name: event.target.value })}
                  disabled={user?.role !== "admin"}
                />
                <Input
                  aria-label="Framework"
                  value={window.framework}
                  onChange={(event) => updateWindow(index, { framework: event.target.value })}
                  disabled={user?.role !== "admin"}
                />
                <Input
                  aria-label="Audit date"
                  type="date"
                  value={window.auditDate}
                  onChange={(event) => updateWindow(index, { auditDate: event.target.value })}
                  disabled={user?.role !== "admin"}
                />
                <Input
                  aria-label="Scope filter"
                  placeholder="payments.example.com, 10.0.0.0/24"
                  value={window.scopeFilter.join(", ")}
                  onChange={(event) =>
                    updateWindow(index, {
                      scopeFilter: event.target.value.split(",").map((value) => value.trim()),
                    })
                  }
                  disabled={user?.role !== "admin"}
                />
                {user?.role === "admin" && (
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Remove window"
                    onClick={() => setWindows((prev) => prev.filter((_, i) => i !== index))}
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                )}
              </div>
            ))}
            {windowsMessage && <p className="text-xs text-muted-foreground">{windowsMessage}</p>}
            {user?.role === "admin" && (
              <Button size="sm" onClick={() => void handleSaveWindows()} disabled={windowsBusy}>
                {windowsBusy && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
                Save compliance windows
              </Button>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
