import type { ApiError, LookupResponse } from "./types";
import { isApiError } from "./types";

/**
 * Resolve the backend base URL. In dev, Vite proxies /api to localhost:8765.
 * In a built/preview scenario, set VITE_API_BASE to override.
 */
const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export class LookupClientError extends Error {
  constructor(
    public readonly kind: string,
    message: string,
  ) {
    super(message);
    this.name = "LookupClientError";
  }
}

export async function lookupIndicator(
  indicator: string,
  signal?: AbortSignal,
): Promise<LookupResponse> {
  const url = `${API_BASE}/api/lookup?indicator=${encodeURIComponent(indicator)}`;

  let resp: Response;
  try {
    resp = await fetch(url, { signal });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new LookupClientError(
      "network",
      `Could not reach the MCP server at ${API_BASE || "localhost:8765"}. Is it running?`,
    );
  }

  let body: unknown;
  try {
    body = await resp.json();
  } catch {
    throw new LookupClientError(
      "parse",
      `Server returned a non-JSON response (HTTP ${resp.status}).`,
    );
  }

  if (!resp.ok || isApiError(body)) {
    const err = body as ApiError;
    throw new LookupClientError(err.error ?? "unknown", err.message ?? "Unknown error");
  }

  return body as LookupResponse;
}

export async function getHealth(): Promise<{ status: string; version: string }> {
  const resp = await fetch(`${API_BASE}/api/health`);
  if (!resp.ok) throw new Error(`health check failed: ${resp.status}`);
  return resp.json();
}
