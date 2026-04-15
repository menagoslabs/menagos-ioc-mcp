import type { Classification, SourceStatus } from "./types";

export function classificationStyles(c: Classification | null): {
  ring: string;
  bg: string;
  text: string;
  dot: string;
  glow: string;
  label: string;
} {
  switch (c) {
    case "benign":
      return {
        ring: "ring-emerald-400/30",
        bg: "bg-emerald-500/10",
        text: "text-emerald-300",
        dot: "bg-emerald-400",
        glow: "shadow-[0_0_60px_-10px_rgba(16,185,129,0.45)]",
        label: "Benign",
      };
    case "suspicious":
      return {
        ring: "ring-amber-400/30",
        bg: "bg-amber-500/10",
        text: "text-amber-300",
        dot: "bg-amber-400",
        glow: "shadow-[0_0_60px_-10px_rgba(245,158,11,0.45)]",
        label: "Suspicious",
      };
    case "malicious":
      return {
        ring: "ring-rose-400/30",
        bg: "bg-rose-500/10",
        text: "text-rose-300",
        dot: "bg-rose-400",
        glow: "shadow-[0_0_60px_-10px_rgba(244,63,94,0.45)]",
        label: "Malicious",
      };
    default:
      return {
        ring: "ring-slate-400/30",
        bg: "bg-slate-500/10",
        text: "text-slate-300",
        dot: "bg-slate-400",
        glow: "shadow-[0_0_60px_-10px_rgba(148,163,184,0.25)]",
        label: "Unknown",
      };
  }
}

export function statusStyles(s: SourceStatus): { ring: string; bg: string; text: string; label: string } {
  switch (s) {
    case "ok":
      return { ring: "ring-emerald-400/30", bg: "bg-emerald-500/10", text: "text-emerald-300", label: "ok" };
    case "not_found":
      return { ring: "ring-slate-400/30", bg: "bg-slate-500/10", text: "text-slate-300", label: "not found" };
    case "unsupported":
      return { ring: "ring-slate-400/20", bg: "bg-slate-500/5", text: "text-slate-400", label: "unsupported" };
    case "error":
      return { ring: "ring-rose-400/30", bg: "bg-rose-500/10", text: "text-rose-300", label: "error" };
    case "timeout":
      return { ring: "ring-amber-400/30", bg: "bg-amber-500/10", text: "text-amber-300", label: "timeout" };
    case "rate_limited":
      return { ring: "ring-amber-400/30", bg: "bg-amber-500/10", text: "text-amber-300", label: "rate limited" };
  }
}

export function providerLabel(id: string): string {
  const map: Record<string, string> = {
    virustotal: "VirusTotal",
    greynoise: "GreyNoise",
    abuseipdb: "AbuseIPDB",
  };
  return map[id] ?? id;
}

export function indicatorTypeLabel(t: string): string {
  const map: Record<string, string> = {
    ip: "IP address",
    domain: "Domain",
    url: "URL",
    hash_md5: "MD5 hash",
    hash_sha1: "SHA-1 hash",
    hash_sha256: "SHA-256 hash",
  };
  return map[t] ?? t;
}

export function formatScore(score: number | null): string {
  if (score === null || score === undefined) return "-";
  return score.toFixed(2);
}

export function formatLatency(ms: number): string {
  if (ms < 1) return "<1ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}
