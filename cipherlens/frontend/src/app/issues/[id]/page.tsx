"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, Check, Clock, FileCode } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { IssueSeverityBadge, IssueStatusBadge } from "@/components/shared/issue-badges";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { CardSkeleton } from "@/components/shared/skeletons";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { useAsync } from "@/hooks/use-async";
import { useAuth, useRole } from "@/components/auth/AuthContext";
import { getIssue, updateIssue, addIssueComment } from "@/services/issuesService";
import { listTeamMembers, listTeams } from "@/services/teamsService";
import { statusLabel, eventTypeLabel } from "@/types/issue";
import type { Issue, IssueStatus } from "@/types/issue";
import type { Team, TeamMember } from "@/types/team";
import { formatDateTime } from "@/lib/format";

const UI_TRANSITIONS: Record<string, IssueStatus[]> = {
  open: ["assigned", "in_progress", "resolved", "risk_accepted", "false_positive"],
  assigned: ["in_progress", "resolved", "risk_accepted", "false_positive"],
  in_progress: ["resolved", "risk_accepted", "false_positive"],
  resolved: ["verified", "risk_accepted", "false_positive"],
  verified: [],
  risk_accepted: ["in_progress", "resolved", "false_positive"],
  false_positive: [],
};

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className="text-right text-xs text-foreground">{value}</span>
    </div>
  );
}

export default function IssueDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const { user } = useAuth();
const orgId = user?.organization_id;
  const { isAdmin, isLead, canAssign } = useRole();

  const {
    data: issue,
    loading,
    error,
    refetch,
  } = useAsync<Issue | null>(() => getIssue(params.id), [params.id]);

  const { data: directory } = useAsync<TeamMember[]>(() => listTeamMembers(), []);
  const { data: teams } = useAsync<Team[]>(() => listTeams(), []);

  const [ownerType, setOwnerType] = useState<"user" | "team">("user");
  const [ownerId, setOwnerId] = useState("");
  const [comment, setComment] = useState("");
  const [riskReason, setRiskReason] = useState("");
  const [riskUntil, setRiskUntil] = useState("");
  const [busy, setBusy] = useState(false);
  const [pendingRisk, setPendingRisk] = useState(false);

  if (loading) {
    return (
      <div className="space-y-4">
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  if (error) {
    return <ErrorState message="No se pudo cargar el issue." onRetry={refetch} />;
  }

  if (!issue) {
    return <EmptyState title="Issue no encontrado." />;
  }

  const dir = directory ?? [];
  const filteredDirectory = orgId
  ? dir.filter((m) => m.organization_id === orgId)
  : dir;
  const members = filteredDirectory;
  const teamList = teams ?? [];

  const ledMemberIds = new Set<string>();
  if (isLead && user) {
    for (const t of teamList) {
      if ((t.leadIds ?? []).includes(user.id)) {
        for (const mid of t.memberIds ?? []) ledMemberIds.add(mid);
      }
    }
  }
  const assignableMembers = isAdmin ? members : members.filter((m) => ledMemberIds.has(m.id));
  const assignableTeams = isAdmin ? teamList : [];
  const canWork =
    canAssign || (!!user && (issue.ownerUserId === user.id || !!issue.ownerTeamId));
  const canComment = canWork;

  const doUpdate = async (payload: Parameters<typeof updateIssue>[1]) => {
    setBusy(true);
    try {
      await updateIssue(issue.id, payload);
      await refetch();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al actualizar el issue");
    } finally {
      setBusy(false);
    }
  };

  const applyOwner = () => {
    if (!ownerId) return;
    void doUpdate(
      ownerType === "user"
        ? { ownerUserId: ownerId, ownerTeamId: null }
        : { ownerUserId: null, ownerTeamId: ownerId },
    );
  };

  const clearOwner = async () => {
    setBusy(true);
    try {
      await updateIssue(issue.id, { ownerUserId: null, ownerTeamId: null });
      if (isAdmin) {
        await refetch();
      } else {
        router.push("/issues");
      }
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al actualizar el issue");
    } finally {
      setBusy(false);
    }
  };

  const changeStatus = (status: IssueStatus) => {
    if (status === "risk_accepted") {
      setPendingRisk(true);
      return;
    }
    void doUpdate({ status });
  };

  const confirmRisk = () => {
    if (!riskReason.trim()) {
      alert("Debes indicar un motivo para aceptar el riesgo.");
      return;
    }
    setPendingRisk(false);
    void doUpdate({
      status: "risk_accepted",
      reason: riskReason.trim(),
      riskAcceptedUntil: riskUntil ? new Date(riskUntil).toISOString() : undefined,
    });
  };

  const submitComment = async () => {
    if (!comment.trim()) return;
    setBusy(true);
    try {
      await addIssueComment(issue.id, comment.trim());
      setComment("");
      await refetch();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al agregar comentario");
    } finally {
      setBusy(false);
    }
  };

  const transitions = UI_TRANSITIONS[issue.status] ?? [];
  const canReopen = issue.status === "resolved" || issue.status === "verified";
  const history = issue.history ?? [];

  return (
    <div>
      <Button
        variant="ghost"
        size="sm"
        asChild
        className="mb-4 -ml-2 text-muted-foreground"
      >
        <Link href="/issues">
          <ArrowLeft className="mr-1 h-4 w-4" />
          Volver a issues
        </Link>
      </Button>

      <PageHeader
        title={issue.title}
        subtitle={
          <span className="font-mono text-xs">
            {issue.sourceDocument ?? "—"} · {issue.ruleId}
          </span>
        }
        actions={
          <>
            <IssueSeverityBadge severity={issue.severity} />
            <IssueStatusBadge status={issue.status} />
            {issue.isOverdue && <Badge variant="destructive">Vencido</Badge>}
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Detalle</CardTitle>
            </CardHeader>
            <CardContent>
              <InfoRow
                label="Servicio"
                value={
                  issue.serviceId ? (
                    <Link
                      href={`/services/${issue.serviceId}`}
                      className="text-sky-500 underline-offset-2 hover:underline"
                    >
                      {issue.serviceHost
                        ? `${issue.serviceHost}${issue.servicePort ? `:${issue.servicePort}` : ""}`
                        : issue.serviceId}
                    </Link>
                  ) : (
                    "—"
                  )
                }
              />
              <InfoRow
                label="Regla"
                value={<span className="font-mono">{issue.ruleId}</span>}
              />
              <InfoRow
                label="Documento fuente"
                value={
                  <span className="inline-flex items-center gap-1">
                    <FileCode className="h-3.5 w-3.5" />
                    {issue.sourceDocument ?? "—"}
                  </span>
                }
              />
              <InfoRow
                label="Owner"
                value={
                  issue.ownerName ? (
                    issue.ownerName
                  ) : (
                    <span className="text-muted-foreground">Sin asignar</span>
                  )
                }
              />
              <InfoRow label="Primera detección" value={formatDateTime(issue.firstSeenAt)} />
              <InfoRow label="Última detección" value={formatDateTime(issue.lastSeenAt)} />
              <InfoRow
                label="Vence"
                value={
                  <span className={issue.isOverdue ? "text-red-500" : ""}>
                    {formatDateTime(issue.dueAt)}
                    {issue.isOverdue ? " (vencido)" : ""}
                  </span>
                }
              />
              {issue.resolvedAt && (
                <InfoRow label="Resuelto" value={formatDateTime(issue.resolvedAt)} />
              )}
              {issue.verifiedAt && (
                <InfoRow label="Verificado" value={formatDateTime(issue.verifiedAt)} />
              )}
              {issue.reopenedCount > 0 && (
                <InfoRow label="Reaperturas" value={issue.reopenedCount} />
              )}
              {issue.riskAcceptanceReason && (
                <InfoRow label="Motivo de riesgo" value={issue.riskAcceptanceReason} />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Asignación</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-2 text-xs">
                <span className="text-muted-foreground">Asignado a:</span>
                {issue.ownerName ? (
                  <span className="font-medium">
                    {issue.ownerName}
                    {issue.ownerTeamId ? " (equipo)" : " (usuario)"}
                  </span>
                ) : (
                  <span className="text-muted-foreground">Sin asignar</span>
                )}
              </div>
              <div className="flex flex-col gap-2 sm:flex-row">
                <Select
                  value={ownerType}
                  onValueChange={(v) => {
                    setOwnerType(v as "user" | "team");
                    setOwnerId("");
                  }}
                  disabled={!canAssign}
                >
                  <SelectTrigger className="sm:w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user">Usuario</SelectItem>
                    {isAdmin && <SelectItem value="team">Equipo</SelectItem>}
                  </SelectContent>
                </Select>
                <Select value={ownerId} onValueChange={setOwnerId} disabled={!canAssign}>
                  <SelectTrigger className="flex-1">
                    <SelectValue
                      placeholder={
                        ownerType === "user"
                          ? "Seleccionar usuario"
                          : "Seleccionar equipo"
                      }
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {ownerType === "user"
                      ? assignableMembers.map((m) => (
                          <SelectItem key={m.id} value={m.id}>
                            {m.name} ({m.email})
                          </SelectItem>
                        ))
                      : assignableTeams.map((t) => (
                          <SelectItem key={t.id} value={t.id}>
                            {t.name}
                          </SelectItem>
                        ))}
                  </SelectContent>
                </Select>
                <Button onClick={applyOwner} disabled={busy || !ownerId || !canAssign}>
                  Asignar
                </Button>
                {(issue.ownerUserId || issue.ownerTeamId) && (
                  <Button
                    variant="outline"
                    onClick={clearOwner}
                    disabled={busy || !canAssign}
                  >
                    Quitar
                  </Button>
                )}
              </div>
              <p className="text-[11px] text-muted-foreground">
                {canAssign
                  ? "Al asignar un owner, si el issue estaba abierto pasa a \"Asignado\" y aparece en My Issues de esa persona o de los miembros del equipo."
                  : "Solo un administrador o el líder del equipo puede reasignar este issue."}
              </p>
            </CardContent>
          </Card>

          {canComment && (
            <Card>
              <CardHeader>
                <CardTitle>Comentario</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Textarea
                  placeholder="Agregar un comentario..."
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  rows={3}
                />
                <Button
                  size="sm"
                  onClick={() => void submitComment()}
                  disabled={busy || !comment.trim()}
                >
                  <Check className="mr-1 h-4 w-4" />
                  Comentar
                </Button>
              </CardContent>
            </Card>
          )}
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Estado</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <IssueStatusBadge status={issue.status} />

              {pendingRisk ? (
                <div className="space-y-2 rounded-md border p-3">
                  <p className="text-xs font-medium">Aceptar riesgo</p>
                  <Textarea
                    placeholder="Motivo (obligatorio)"
                    value={riskReason}
                    onChange={(e) => setRiskReason(e.target.value)}
                    rows={2}
                  />
                  <Input
                    type="date"
                    value={riskUntil}
                    onChange={(e) => setRiskUntil(e.target.value)}
                  />
                  <div className="flex gap-2">
                    <Button size="sm" onClick={confirmRisk} disabled={busy}>
                      Confirmar
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setPendingRisk(false)}
                    >
                      Cancelar
                    </Button>
                  </div>
                </div>
              ) : canWork ? (
                <div className="flex flex-col gap-2">
                  {transitions.map((s) => (
                    <Button
                      key={s}
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => changeStatus(s)}
                    >
                      {statusLabel(s)}
                    </Button>
                  ))}
                  {canReopen && (
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={busy}
                      onClick={() => void doUpdate({ status: "reopened" })}
                    >
                      Reabrir
                    </Button>
                  )}
                  {transitions.length === 0 && !canReopen && (
                    <p className="text-xs text-muted-foreground">
                      Estado terminal.
                    </p>
                  )}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">
                  Solo lectura para tu rol.
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Historial</CardTitle>
            </CardHeader>
            <CardContent>
              {history.length === 0 ? (
                <p className="text-sm text-muted-foreground">Sin eventos.</p>
              ) : (
                <ul className="space-y-3">
                  {history.map((h) => (
                    <li key={h.id} className="flex gap-2">
                      <Clock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                      <div className="space-y-0.5">
                        <p className="text-xs font-medium">
                          {eventTypeLabel(h.eventType)}
                          {h.fromValue && h.toValue && (
                            <span className="font-normal text-muted-foreground">
                              {" "}
                              · {statusLabel(h.fromValue)} → {statusLabel(h.toValue)}
                            </span>
                          )}
                        </p>
                        {h.comment && (
                          <p className="text-xs text-muted-foreground">{h.comment}</p>
                        )}
                        <p className="text-[11px] text-muted-foreground">
                          {formatDateTime(h.ts)}
                          {h.actorType === "system" ? " · sistema" : " · usuario"}
                        </p>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
