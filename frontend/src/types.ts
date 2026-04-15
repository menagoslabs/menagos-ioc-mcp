// Mirrors app/schema.py. Keep in sync if the backend schema changes.

export type IndicatorType =
  | "ip"
  | "domain"
  | "url"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256";

export type Classification = "benign" | "suspicious" | "malicious" | "unknown";

export type Confidence = "low" | "medium" | "high";

export type SourceStatus =
  | "ok"
  | "not_found"
  | "unsupported"
  | "error"
  | "timeout"
  | "rate_limited";

export interface Indicator {
  value: string;
  type: IndicatorType;
  normalized_value: string;
}

export interface SourceReport {
  provider: string;
  status: SourceStatus;
  reputation_score: number | null;
  classification: Classification | null;
  raw_signals: Record<string, unknown>;
  reference_url: string | null;
  latency_ms: number;
  fetched_at: string;
  error_message: string | null;
}

export interface Verdict {
  classification: Classification;
  reputation_score: number;
  confidence: Confidence;
  summary: string;
}

export interface ErrorEntry {
  provider: string;
  error_type: string;
  message: string;
}

export interface Meta {
  server_version: string;
  query_id: string;
  duration_ms: number;
  providers_queried: string[];
  providers_skipped: string[];
}

export interface LookupResponse {
  indicator: Indicator;
  verdict: Verdict;
  sources: SourceReport[];
  errors: ErrorEntry[];
  meta: Meta;
}

export interface ApiError {
  error: string;
  message: string;
}

export function isApiError(x: unknown): x is ApiError {
  return (
    typeof x === "object" &&
    x !== null &&
    "error" in x &&
    typeof (x as ApiError).error === "string"
  );
}
