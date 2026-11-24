import { CloudOff, KeyRound, RefreshCw, SearchX } from "lucide-react";
import { useState } from "react";
import type { RunListItem } from "../api/types";

/** Shell-shaped placeholder shown while a run loads. */
export function BootSkeleton() {
  return (
    <div className="skel-app" role="status" aria-label="Loading the run">
      <div className="skel-top">
        <div className="skel" style={{ width: 120, height: 20 }} />
        <div className="skel" style={{ width: 240, height: 32 }} />
      </div>
      <div className="skel-rail">
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className="skel" style={{ height: 34 }} />
        ))}
      </div>
      <div className="skel-main">
        <div className="skel" style={{ height: 44, width: "60%" }} />
        <div className="skel" style={{ height: 96 }} />
        <div className="skel-grid">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i} className="skel" style={{ height: 112 }} />
          ))}
        </div>
        <div className="skel" style={{ height: 220 }} />
      </div>
    </div>
  );
}

export function BootError({
  message, runs, onRetry, onPick,
}: { message: string; runs: RunListItem[]; onRetry: () => void; onPick: (id: string) => void }) {
  const notFound = /^404/.test(message);
  return (
    <div className="boot">
      {notFound ? <SearchX size={32} className="boot-ico" aria-hidden /> : <CloudOff size={32} className="boot-ico" aria-hidden />}
      <p className="boot-title">{notFound ? "We could not find that scan" : "Guardian cannot reach its data"}</p>
      {notFound ? (
        <p>The scan in the address does not exist (or has been removed). Pick one of the scans that are available instead.</p>
      ) : (
        <p>
          The Guardian service is not answering. Start it with <code>guardian api</code>, or open the built-in sample with{" "}
          <code>?source=sample</code> in the address.
        </p>
      )}
      <div className="boot-actions">
        {runs.slice(0, 6).map((r) => (
          <button key={r.id} type="button" className="btn" onClick={() => onPick(r.id)}>
            {r.target} <span className="faint mono">{r.id.replace(/^run_/, "")}</span>
          </button>
        ))}
        <button type="button" className="btn" onClick={onRetry}>
          <RefreshCw size={16} aria-hidden /> Try again
        </button>
        {!runs.length && (
          <a className="btn" href="?source=sample">
            Open the sample scan
          </a>
        )}
      </div>
      <p className="boot-detail">{message}</p>
    </div>
  );
}

export function SignIn({ bad, onSubmit }: { bad: boolean; onSubmit: (t: string) => void }) {
  const [t, setT] = useState("");
  return (
    <div className="boot">
      <KeyRound size={32} className="boot-ico" aria-hidden />
      <p className="boot-title">Sign in to Guardian</p>
      <p>This Guardian service asks for an access token. Paste the one you were given. It is kept only for this browser tab and is forgotten when you close it.</p>
      <form
        className="signin"
        onSubmit={(e) => {
          e.preventDefault();
          if (t.trim()) onSubmit(t.trim());
        }}
      >
        <label className={`field${bad ? " invalid" : ""}`}>
          <span>Access token</span>
          <input type="password" autoComplete="off" autoFocus value={t} onChange={(e) => setT(e.target.value)} />
          {bad && <span className="field-err" role="alert">That token was not accepted. Check it and try again.</span>}
        </label>
        <button type="submit" className="btn primary lg" disabled={!t.trim()}>Sign in</button>
      </form>
    </div>
  );
}
