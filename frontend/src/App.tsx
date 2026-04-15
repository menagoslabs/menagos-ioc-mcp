import { useCallback, useRef, useState } from "react";
import { SearchBar } from "./components/SearchBar";
import { VerdictCard } from "./components/VerdictCard";
import { SourceCard } from "./components/SourceCard";
import { MetaFooter } from "./components/MetaFooter";
import { lookupIndicator, LookupClientError } from "./api";
import type { LookupResponse } from "./types";

type State =
  | { kind: "idle" }
  | { kind: "loading"; indicator: string }
  | { kind: "success"; data: LookupResponse }
  | { kind: "error"; indicator: string; title: string; message: string };

export default function App() {
  const [state, setState] = useState<State>({ kind: "idle" });
  const abortRef = useRef<AbortController | null>(null);

  const handleLookup = useCallback(async (indicator: string) => {
    // Cancel any in-flight request.
    if (abortRef.current) abortRef.current.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    setState({ kind: "loading", indicator });
    try {
      const data = await lookupIndicator(indicator, ctrl.signal);
      if (ctrl.signal.aborted) return;
      setState({ kind: "success", data });
    } catch (e) {
      if ((e as Error).name === "AbortError") return;
      const err = e as LookupClientError;
      const title =
        err.kind === "invalid_indicator"
          ? "Not a valid indicator"
          : err.kind === "network"
          ? "Cannot reach the server"
          : "Lookup failed";
      setState({
        kind: "error",
        indicator,
        title,
        message: err.message || "Unexpected error",
      });
    }
  }, []);

  return (
    <div className="min-h-screen">
      <Header />
      <main className="mx-auto max-w-6xl px-5 pb-20 pt-10 md:pt-16">
        <div className="mx-auto max-w-3xl text-center">
          <h1 className="bg-gradient-to-b from-slate-100 to-slate-400 bg-clip-text text-4xl font-bold tracking-tight text-transparent md:text-5xl">
            Indicator of compromise, triaged.
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-balance text-sm text-slate-400 md:text-base">
            Paste an IP, domain, or file hash. We fan out to{" "}
            <span className="text-slate-300">VirusTotal</span>,{" "}
            <span className="text-slate-300">GreyNoise</span>, and{" "}
            <span className="text-slate-300">AbuseIPDB</span> and return a normalized verdict with
            per-source attribution.
          </p>
        </div>

        <div className="mx-auto mt-10 max-w-3xl">
          <SearchBar onSubmit={handleLookup} loading={state.kind === "loading"} />
        </div>

        <div className="mt-12">
          {state.kind === "idle" && <EmptyState />}

          {state.kind === "loading" && <LoadingState indicator={state.indicator} />}

          {state.kind === "error" && (
            <ErrorPanel title={state.title} message={state.message} indicator={state.indicator} />
          )}

          {state.kind === "success" && (
            <div className="space-y-6">
              <VerdictCard data={state.data} />

              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                {state.data.sources.map((s) => (
                  <SourceCard key={s.provider} source={s} />
                ))}
              </div>

              {state.data.errors.length > 0 && (
                <div className="card p-4 text-xs text-slate-400">
                  <h4 className="mb-2 text-[11px] uppercase tracking-wider text-slate-500">
                    Provider errors ({state.data.errors.length})
                  </h4>
                  <ul className="space-y-1 font-mono">
                    {state.data.errors.map((e, i) => (
                      <li key={i}>
                        <span className="text-slate-500">{e.provider}:</span>{" "}
                        <span className="text-slate-400">{e.error_type}</span>, {e.message}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <MetaFooter meta={state.data.meta} />
            </div>
          )}
        </div>
      </main>
      <Footer />
    </div>
  );
}

function Header() {
  return (
    <header className="border-b border-slate-900/60">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-5 py-4">
        <div className="flex items-center gap-3">
          <LogoMark />
          <div>
            <div className="text-sm font-semibold text-slate-200">menagos-ioc-mcp</div>
            <div className="text-[10px] uppercase tracking-wider text-slate-600">
              MCP · Threat Intelligence · Menagos Labs
            </div>
          </div>
        </div>
        <a
          href="https://github.com/menagoslabs/menagos-ioc-mcp"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-400 transition-colors hover:border-slate-700 hover:text-slate-200"
        >
          <GithubIcon /> GitHub
        </a>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="border-t border-slate-900/60">
      <div className="mx-auto max-w-6xl px-5 py-6 text-[11px] text-slate-600">
        MIT · © 2026 Menagos LLC · Source:{" "}
        <a
          href="https://github.com/menagoslabs/menagos-ioc-mcp"
          target="_blank"
          rel="noopener noreferrer"
          className="text-slate-500 underline underline-offset-2 hover:text-brand-400"
        >
          github.com/menagoslabs/menagos-ioc-mcp
        </a>
      </div>
    </footer>
  );
}

function EmptyState() {
  return (
    <div className="card mx-auto max-w-3xl p-10 text-center">
      <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-brand-500/10 ring-1 ring-inset ring-brand-500/20">
        <SparkIcon />
      </div>
      <p className="text-sm text-slate-400">
        Results appear here. Try one of the example indicators above, or paste your own.
      </p>
    </div>
  );
}

function LoadingState({ indicator }: { indicator: string }) {
  return (
    <div className="card mx-auto max-w-3xl p-10 text-center">
      <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-brand-500/10 ring-1 ring-inset ring-brand-500/20">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-brand-400 border-t-transparent" />
      </div>
      <div className="font-mono text-sm text-slate-300">{indicator}</div>
      <div className="mt-2 text-xs text-slate-500">Querying 3 providers in parallel…</div>
    </div>
  );
}

function ErrorPanel({
  title,
  message,
  indicator,
}: {
  title: string;
  message: string;
  indicator: string;
}) {
  return (
    <div className="card mx-auto max-w-3xl border-rose-500/30 bg-rose-950/20 p-8">
      <div className="flex items-start gap-4">
        <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-rose-500/10 ring-1 ring-inset ring-rose-500/30">
          <AlertIcon />
        </div>
        <div className="min-w-0">
          <h3 className="font-semibold text-rose-300">{title}</h3>
          <p className="mt-1 text-sm text-slate-400">{message}</p>
          <div className="mt-2 font-mono text-[11px] text-slate-600">Input: {indicator}</div>
        </div>
      </div>
    </div>
  );
}

function LogoMark() {
  return (
    <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-slate-900 ring-1 ring-inset ring-slate-800">
      <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-brand-500/20 to-transparent" />
      <svg viewBox="0 0 24 24" className="relative h-5 w-5" fill="none">
        <circle cx="12" cy="12" r="6" stroke="#38bdf8" strokeWidth="1.5" />
        <circle cx="12" cy="12" r="1.5" fill="#38bdf8" />
        <line x1="12" y1="3" x2="12" y2="5.5" stroke="#38bdf8" strokeWidth="1.5" strokeLinecap="round" />
        <line x1="12" y1="18.5" x2="12" y2="21" stroke="#38bdf8" strokeWidth="1.5" strokeLinecap="round" />
        <line x1="3" y1="12" x2="5.5" y2="12" stroke="#38bdf8" strokeWidth="1.5" strokeLinecap="round" />
        <line x1="18.5" y1="12" x2="21" y2="12" stroke="#38bdf8" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    </div>
  );
}

function SparkIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-6 w-6 text-brand-400" fill="none">
      <path
        d="M12 3v18M3 12h18M5.6 5.6l12.8 12.8M5.6 18.4l12.8-12.8"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeOpacity="0.4"
      />
      <circle cx="12" cy="12" r="3" fill="currentColor" />
    </svg>
  );
}

function AlertIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-5 w-5 text-rose-400" fill="none">
      <path
        d="M12 8v5m0 3.5v.5M10.3 3.9 2.5 17.1a2 2 0 0 0 1.7 3h15.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function GithubIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="currentColor">
      <path d="M12 .5C5.73.5.67 5.56.67 11.83c0 5.01 3.24 9.26 7.75 10.77.57.1.78-.25.78-.55v-1.94c-3.15.68-3.82-1.52-3.82-1.52-.52-1.32-1.26-1.67-1.26-1.67-1.03-.7.08-.69.08-.69 1.14.08 1.74 1.17 1.74 1.17 1.01 1.73 2.65 1.23 3.3.94.1-.73.39-1.23.72-1.51-2.51-.29-5.15-1.26-5.15-5.6 0-1.24.44-2.25 1.17-3.05-.12-.29-.51-1.44.11-3 0 0 .95-.31 3.12 1.17a10.84 10.84 0 0 1 5.68 0c2.17-1.48 3.12-1.17 3.12-1.17.62 1.56.23 2.71.11 3 .73.8 1.17 1.81 1.17 3.05 0 4.35-2.64 5.3-5.16 5.59.4.35.76 1.04.76 2.09v3.1c0 .3.2.66.79.55 4.5-1.5 7.74-5.76 7.74-10.76C23.33 5.56 18.27.5 12 .5Z" />
    </svg>
  );
}
