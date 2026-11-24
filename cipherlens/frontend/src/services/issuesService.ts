import { isMock } from "./config";
import { api } from "./apiClient";
import { getMockCurrentUser } from "./authService";
import type { Issue, IssueSummary } from "@/types/issue";
import type { Paged } from "@/types/settings";
import { mocked } from "./mock/utils";
import { mockIssues, mockHistoryFor, mockUsers, mockTeams } from "./mock/store";

export interface IssueFilter {
  status?: string;
  severity?: string;
  ownerUserId?: string;
  ownerTeamId?: string;
  serviceId?: string;
  overdue?: boolean;
  unassigned?: boolean;
  mine?: boolean;
  q?: string;
  page?: number;
  pageSize?: number;
}

export interface IssueUpdateInput {
  ownerUserId?: string | null;
  ownerTeamId?: string | null;
  status?: string;
  comment?: string;
  reason?: string;
  riskAcceptedUntil?: string;
}

function buildQuery(filter: IssueFilter): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filter)) {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

function applyMockFilter(filter: IssueFilter): Issue[] {
  let items = [...mockIssues];
  if (filter.status) items = items.filter((i) => i.status === filter.status);
  if (filter.severity) items = items.filter((i) => i.severity === filter.severity);
  if (filter.ownerUserId) items = items.filter((i) => i.ownerUserId === filter.ownerUserId);
  if (filter.ownerTeamId) items = items.filter((i) => i.ownerTeamId === filter.ownerTeamId);
  if (filter.serviceId) items = items.filter((i) => i.serviceId === filter.serviceId);
  if (filter.overdue) items = items.filter((i) => i.isOverdue);
  if (filter.unassigned) items = items.filter((i) => !i.ownerUserId && !i.ownerTeamId);
  if (filter.mine) {
    const me = getMockCurrentUser();
    const myTeamIds = new Set(
      mockTeams
        .filter((team) => (team.memberIds ?? []).includes(me.id))
        .map((team) => team.id),
    );
    items = items.filter(
      (i) =>
        i.ownerUserId === me.id ||
        (i.ownerTeamId !== null && myTeamIds.has(i.ownerTeamId)),
    );
  }
  if (filter.q) {
    const q = filter.q.toLowerCase();
    items = items.filter(
      (i) => i.title.toLowerCase().includes(q) || i.ruleId.toLowerCase().includes(q),
    );
  }
  return items;
}

export async function listIssues(filter: IssueFilter = {}): Promise<Paged<Issue>> {
  if (isMock()) {
    const page = filter.page ?? 1;
    const pageSize = filter.pageSize ?? 25;
    const all = applyMockFilter(filter);
    const start = (page - 1) * pageSize;
    return mocked({
      items: all.slice(start, start + pageSize),
      total: all.length,
      page,
      pageSize,
    });
  }
  return api.get<Paged<Issue>>(`/issues${buildQuery(filter)}`);
}

export async function getIssue(id: string): Promise<Issue | null> {
  if (isMock()) {
    const issue = mockIssues.find((i) => i.id === id);
    if (!issue) return mocked(null);
    return mocked({ ...issue, history: mockHistoryFor(issue) });
  }
  return api.get<Issue>(`/issues/${id}`);
}

export async function updateIssue(id: string, input: IssueUpdateInput): Promise<Issue> {
  if (isMock()) {
    const issue = mockIssues.find((i) => i.id === id);
    if (!issue) throw new Error("Issue no encontrado");
    if (input.ownerUserId !== undefined) issue.ownerUserId = input.ownerUserId;
    if (input.ownerTeamId !== undefined) issue.ownerTeamId = input.ownerTeamId;
    if (input.status !== undefined) issue.status = input.status;
    if (input.riskAcceptedUntil !== undefined) issue.riskAcceptedUntil = input.riskAcceptedUntil;
    if (input.reason !== undefined) issue.riskAcceptanceReason = input.reason;
    issue.effectiveOwnerUserId = issue.ownerUserId;
    issue.effectiveOwnerTeamId = issue.ownerTeamId;
    issue.ownerName = issue.ownerUserId
      ? (mockUsers.find((u) => u.id === issue.ownerUserId)?.name ?? null)
      : issue.ownerTeamId
        ? (mockTeams.find((t) => t.id === issue.ownerTeamId)?.name ?? null)
        : null;
    if ((issue.ownerUserId || issue.ownerTeamId) && issue.status === "open") {
      issue.status = "assigned";
    }
    return mocked({ ...issue });
  }
  return api.patch<Issue>(`/issues/${id}`, { body: input });
}

export async function addIssueComment(id: string, comment: string): Promise<void> {
  if (isMock()) return mocked(undefined);
  await api.post(`/issues/${id}/comment`, { body: { comment } });
}

export async function getIssueSummary(): Promise<IssueSummary> {
  if (isMock()) {
    const byStatus: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    for (const i of mockIssues) {
      byStatus[i.status] = (byStatus[i.status] ?? 0) + 1;
      bySeverity[i.severity] = (bySeverity[i.severity] ?? 0) + 1;
    }
    return mocked({
      byStatus,
      bySeverity,
      overdue: mockIssues.filter((i) => i.isOverdue).length,
      unassigned: mockIssues.filter((i) => !i.ownerUserId && !i.ownerTeamId).length,
      total: mockIssues.length,
    });
  }
  return api.get<IssueSummary>("/issues/summary");
}
