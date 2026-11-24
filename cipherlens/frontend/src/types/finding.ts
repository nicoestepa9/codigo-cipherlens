import type { Severity } from "./severity";

export interface CveReference {
  cveId: string;
  name?: string;
  cvssV3Score?: number;
  matchType: "static_mapping" | "cpe" | "keyword";
  referenceUrl?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
  reference?: string;
  severity: Severity;
  category: string;
  affectedHost: string;
  affectedService?: string;
  detectionDate: string;
  relatedCves?: CveReference[];
}
