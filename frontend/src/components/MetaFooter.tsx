import type { Meta } from "../types";
import { formatLatency, providerLabel } from "../utils";

interface Props {
  meta: Meta;
}

export function MetaFooter({ meta }: Props) {
  return (
    <div className="mt-6 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t border-slate-800/60 pt-4 text-[11px] uppercase tracking-wider text-slate-600">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span>
          Duration: <span className="font-mono text-slate-400">{formatLatency(meta.duration_ms)}</span>
        </span>
        <span>
          Query ID: <span className="font-mono text-slate-400">{meta.query_id}</span>
        </span>
        <span>
          Server: <span className="font-mono text-slate-400">v{meta.server_version}</span>
        </span>
      </div>
      {meta.providers_skipped.length > 0 && (
        <span className="text-slate-600">
          Skipped:{" "}
          <span className="font-mono text-slate-500">
            {meta.providers_skipped.map(providerLabel).join(", ")}
          </span>
        </span>
      )}
    </div>
  );
}
