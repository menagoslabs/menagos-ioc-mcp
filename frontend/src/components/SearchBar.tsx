import { useState, type FormEvent, type KeyboardEvent } from "react";

interface Props {
  onSubmit: (indicator: string) => void;
  loading: boolean;
  initialValue?: string;
}

const EXAMPLES = [
  "8.8.8.8",
  "example.com",
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
];

export function SearchBar({ onSubmit, loading, initialValue = "" }: Props) {
  const [value, setValue] = useState(initialValue);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const v = value.trim();
    if (!v) return;
    onSubmit(v);
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e as unknown as FormEvent);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="relative group">
        <div className="pointer-events-none absolute -inset-0.5 rounded-2xl bg-gradient-to-r from-brand-500/30 via-cyan-500/30 to-brand-500/30 opacity-0 blur-xl transition-opacity duration-500 group-focus-within:opacity-100"></div>
        <div className="relative flex items-center gap-3 rounded-2xl border border-slate-800 bg-slate-900/80 px-5 py-4 shadow-xl backdrop-blur-sm transition-colors duration-200 focus-within:border-brand-500/50">
          <SearchIcon />
          <input
            type="text"
            autoFocus
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Enter an IP, domain, or file hash…"
            className="flex-1 bg-transparent text-lg text-slate-100 placeholder-slate-500 outline-none font-mono"
          />
          <button
            type="submit"
            disabled={loading || !value.trim()}
            className="relative inline-flex items-center gap-2 rounded-xl bg-brand-500 px-5 py-2.5 text-sm font-semibold text-slate-950 shadow-lg transition-all duration-200 hover:bg-brand-400 hover:shadow-glow disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-brand-500"
          >
            {loading ? (
              <>
                <Spinner /> Looking up…
              </>
            ) : (
              <>Look up</>
            )}
          </button>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
        <span className="mr-1">Try:</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            type="button"
            onClick={() => setValue(ex)}
            className="rounded-full border border-slate-800 bg-slate-900/60 px-3 py-1 font-mono text-[11px] text-slate-400 transition-colors hover:border-brand-500/50 hover:text-brand-300"
          >
            {ex.length > 20 ? `${ex.slice(0, 10)}…${ex.slice(-6)}` : ex}
          </button>
        ))}
      </div>
    </form>
  );
}

function SearchIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className="h-5 w-5 flex-shrink-0 text-slate-500"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="11" cy="11" r="7" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  );
}

function Spinner() {
  return (
    <svg
      className="h-4 w-4 animate-spin"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeOpacity="0.3" strokeWidth="3" />
      <path
        d="M22 12a10 10 0 0 1-10 10"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  );
}
