export interface AlertThresholds {
  criticalDays: number;
  warningDays: number;
}

export interface ScanDefaults {
  timeout: number;
  profile: "citizen-facing" | "government-only";
  alternatePorts: number[];
  sni: boolean;
}

export interface Settings {
  thresholds: AlertThresholds;
  scanDefaults: ScanDefaults;
  organization: string;
  email: string;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}
