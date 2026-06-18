import { AnalysisReport } from "../types";

interface Props {
  report: AnalysisReport;
}

export default function FindingsPanel({ report }: Props) {
  return (
    <section className="animate-rise rounded-2xl border border-edge bg-panel p-5 shadow-panel">
      <h2 className="font-display text-xl font-bold text-ink">Root Cause Analysis</h2>
      <p className="mt-2 text-sm text-ink/80">{report.root_cause}</p>

      <h3 className="mt-5 text-sm font-semibold uppercase tracking-wider text-ink/70">Remediation</h3>
      <ul className="mt-2 space-y-2">
        {report.remediation_steps.map((step) => (
          <li key={step} className="rounded-lg border border-edge/70 bg-canvas/80 p-3 text-sm text-ink/90">{step}</li>
        ))}
      </ul>

      <h3 className="mt-5 text-sm font-semibold uppercase tracking-wider text-ink/70">FortiGate Debug CLI</h3>
      <pre className="mt-2 overflow-x-auto rounded-lg border border-edge/70 bg-[#0b2426] p-3 font-mono text-xs text-[#d8f2ef]">
{report.fortigate_debug_cli.join("\n")}
      </pre>
    </section>
  );
}
