import { isMock } from "./config";
import { api } from "./apiClient";
import type { Alert, AlertStatus } from "@/types/alert";
import { getMockAlerts, setAlertStatus } from "./mock/alerts";
import { mocked } from "./mock/utils";

export async function getAlerts(): Promise<Alert[]> {
  if (isMock()) return mocked(getMockAlerts());
  return api.get<Alert[]>("/alerts");
}

export async function getUnreadAlertsCount(): Promise<number> {
  if (isMock()) {
    const alerts = getMockAlerts();
    return mocked(alerts.filter((a) => a.status === "unread").length, 60, 150);
  }
  const alerts = await api.get<Alert[]>("/alerts");
  return alerts.filter((a) => a.status === "unread").length;
}

export async function setAlertStatusService(id: string, status: AlertStatus): Promise<void> {
  if (isMock()) {
    setAlertStatus(id, status);
    return mocked(undefined, 80, 200);
  }
  await api.put(`/alerts/${id}/status`, { body: { status } });
}
