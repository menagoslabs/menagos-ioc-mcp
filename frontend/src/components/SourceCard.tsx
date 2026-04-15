import { useState } from "react";
import type { SourceReport } from "../types";
import {
  classificationStyles,
  formatLatency,
  formatScore,
  providerLabel,
  statusStyles,
} from "../utils";

interface Props {
  source: SourceReport;
}

export function SourceCard({ source }: Props) {
  const [expanded, setExpanded] = useState(false);
  const cls = classificationStyles(source.classification);
  const st = statusStyles(source.status);
  const scorePercent =
    source.reputation_score !== null ? Math.round(source.reputation_score * 100) : 0;
  const isOk = source.status === "ok";
  const isDegraded = source.status !== "ok" && source.status !== "unsupported";

  return (
    <div
      className={`card p-5 transition-colors duration-200 ${
        isDegraded ? "opacity-80 hover:opacity-100" : ""
      }`}
    >
      <div className="mb-4 flex items-start justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-300">
            {providerLabel(source.provider)}
          </h3>
          <div className="mt-1 text-[10px] uppercase tracking-wider text-slate-600">
            {formatLatency(source.latency_ms)}
          </div>
        </div>
        <span className={`pill ${st.bg} ${st.ring} ${st.text}`}>{st.label}</span>
      </div>

      {isOk && source.classification && (
        <>
          <div className="mb-4">
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <span className={`font-semibold uppercase tracking-wide ${cls.text}`}>
                {cls.label}
              </span>
              <span className="font-mono text-slate-400">
                {formatScore(source.reputation_score)}
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
              <div
                className={`h-full ${cls.dot} transition-all duration-500 ease-out`}
                style={{ width: `${Math.max(scorePercent, 2)}%` }}
              />
            </div>
          </div>
          <RawSignals
            signals={source.raw_signals}
            expanded={expanded}
            onToggle={() => setExpanded((s) => !s)}
          />
        </>
      )}

      {!isOk && (
        <div className="text-xs text-slate-500">
          {source.error_message || "No data."}
        </div>
      )}

      {source.reference_url && (
        <a
          href={source.reference_url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-4 inline-flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-slate-500 transition-colors hover:text-brand-400"
        >
          View on {providerLabel(source.provider)}
          <ExternalIcon />
        </a>
      )}
    </div>
  );
}

function RawSignals({
  signals,
  expanded,
  onToggle,
}: {
  signals: Record<string, unknown>;
  expanded: boolean;
  onToggle: () => void;
}) {
  const keys = Object.keys(signals);
  if (keys.length === 0) return null;

  return (
    <div className="rounded-lg border border-slate-800/60 bg-slate-950/40">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between px-3 py-2 text-[10px] uppercase tracking-wider text-slate-500 transition-colors hover:text-slate-300"
      >
        <span>Raw signals ({keys.length})</span>
        <ChevronIcon open={expanded} />
      </button>
      {expanded && (
        <dl className="border-t border-slate-800/60 px-3 py-2 text-xs">
          {keys.map((k) => (
            <div
              key={k}
              className="flex items-start justify-between gap-3 border-b border-slate-900 py-1 last:border-b-0"
            >
              <dt className="font-mono text-[11px] text-slate-500">{k}</dt>
              <dd className="truncate text-right font-mono text-[11px] text-slate-300">
                {formatValue(signals[k])}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "-";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number" || typeof v === "string") return String(v);
  return JSON.stringify(v);
}

function ExternalIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className="h-3 w-3"
      stroke="currentColor"
      strokeWidth={2.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M7 17 17 7M7 7h10v10" />
    </svg>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className={`h-3 w-3 transition-transform duration-200 ${open ? "rotate-180" : ""}`}
      stroke="currentColor"
      strokeWidth={2.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}
