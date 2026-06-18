import { useMemo, useState } from "react";
import FileDropzone from "./components/FileDropzone";
import FindingsPanel from "./components/FindingsPanel";
import LadderTimeline from "./components/LadderTimeline";
import SummaryBanner from "./components/SummaryBanner";
import { AnalysisReport } from "./types";

const API_BASE = "http://localhost:8009";

export default function App() {
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [anonymize, setAnonymize] = useState(false);
  const [psk, setPsk] = useState("");

  const title = useMemo(
    () => (report ? `Tunnel ${report.summary.status}` : "FortiGate IPsec PCAP Analyzer"),
    [report]
  );

  const submitFile = async (file: File) => {
    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("anonymize", String(anonymize));
      if (psk.trim()) formData.append("psk", psk.trim());

      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({ detail: "Unknown API error" }));
        throw new Error(payload.detail || "Failed to analyze capture");
      }

      const data: AnalysisReport = await response.json();
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unexpected error");
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen px-4 py-8 md:px-8">
      <main className="mx-auto max-w-6xl space-y-6">
        <header className="animate-rise rounded-2xl border border-edge bg-panel p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-ink/65">FortiGate diagnostics</p>
          <h1 className="mt-2 font-display text-3xl font-bold text-ink md:text-4xl">{title}</h1>
          <p className="mt-2 max-w-3xl text-sm text-ink/75">
            Upload a capture and inspect exactly where IKE/IPsec negotiation failed, with remediation and generated FortiOS debug commands.
          </p>
        </header>

        <section className="grid gap-4 rounded-2xl border border-edge bg-panel p-4 shadow-panel md:grid-cols-3">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={anonymize}
              onChange={(event) => setAnonymize(event.target.checked)}
              className="h-4 w-4"
            />
            Mask public IP addresses in report
          </label>

          <label className="md:col-span-2">
            <span className="text-sm">Optional IKE PSK for deeper decode</span>
            <input
              type="password"
              value={psk}
              onChange={(event) => setPsk(event.target.value)}
              className="mt-1 w-full rounded-lg border border-edge bg-canvas/90 px-3 py-2 text-sm outline-none focus:border-accent"
              placeholder="Enter PSK only when needed"
            />
          </label>
        </section>

        <FileDropzone loading={loading} onFilePicked={submitFile} />

        {error && (
          <div className="rounded-xl border border-bad/40 bg-bad/10 p-4 text-sm text-bad">{error}</div>
        )}

        {report && (
          <>
            <SummaryBanner summary={report.summary} />
            <div className="grid gap-6 xl:grid-cols-[1.1fr,0.9fr]">
              <LadderTimeline timeline={report.timeline} />
              <FindingsPanel report={report} />
            </div>
          </>
        )}
      </main>
    </div>
  );
}
