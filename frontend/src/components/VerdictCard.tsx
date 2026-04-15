import type { LookupResponse } from "../types";
import { classificationStyles, indicatorTypeLabel } from "../utils";

interface Props {
  data: LookupResponse;
}

export function VerdictCard({ data }: Props) {
  const { indicator, verdict } = data;
  const styles = classificationStyles(verdict.classification);
  const scorePercent = Math.round(verdict.reputation_score * 100);

  return (
    <div className={`card ${styles.glow} overflow-hidden`}>
      <div className="flex flex-col gap-6 p-8 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0 flex-1">
          <div className="mb-1 flex items-center gap-2 text-xs uppercase tracking-wider text-slate-500">
            <span>{indicatorTypeLabel(indicator.type)}</span>
            <span className="text-slate-700">•</span>
            <span>{data.meta.providers_queried.length} sources queried</span>
          </div>
          <h2 className="truncate font-mono text-2xl font-semibold text-slate-100 md:text-3xl">
            {indicator.normalized_value}
          </h2>
          <p className="mt-2 text-sm text-slate-400">{verdict.summary}</p>
        </div>

        <div className="flex-shrink-0">
          <VerdictBadge classification={verdict.classification} confidence={verdict.confidence} />
        </div>
      </div>

      <div className="border-t border-slate-800/60 bg-slate-950/40 px-8 py-5">
        <div className="mb-2 flex items-center justify-between text-xs">
          <span className="text-slate-500">Reputation score</span>
          <span className="font-mono text-slate-300">
            {verdict.reputation_score.toFixed(3)} / 1.000
          </span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
          <div
            className={`h-full ${styles.dot} transition-all duration-700 ease-out`}
            style={{ width: `${Math.max(scorePercent, 2)}%` }}
          />
        </div>
        <div className="mt-2 flex justify-between text-[10px] uppercase tracking-wider text-slate-600">
          <span>Clean</span>
          <span>Malicious</span>
        </div>
      </div>
    </div>
  );
}

function VerdictBadge({
  classification,
  confidence,
}: {
  classification: LookupResponse["verdict"]["classification"];
  confidence: LookupResponse["verdict"]["confidence"];
}) {
  const styles = classificationStyles(classification);
  return (
    <div className={`rounded-2xl ${styles.bg} px-6 py-5 ring-1 ring-inset ${styles.ring}`}>
      <div className="flex items-center gap-3">
        <div className={`h-3 w-3 rounded-full ${styles.dot} animate-pulse-slow`} />
        <div className={`text-3xl font-bold uppercase tracking-tight ${styles.text}`}>
          {styles.label}
        </div>
      </div>
      <div className="mt-2 text-right text-[10px] uppercase tracking-wider text-slate-500">
        Confidence:{" "}
        <span className="font-semibold text-slate-300">{confidence}</span>
      </div>
    </div>
  );
}
