import { Summary } from "../types";

interface Props {
  summary: Summary;
}

const statusColor: Record<string, string> = {
  SUCCESS: "bg-ok/15 text-ok border-ok/40",
  FAILURE: "bg-bad/15 text-bad border-bad/40",
  FLAPPING: "bg-warn/20 text-warn border-warn/50",
  UNKNOWN: "bg-ink/10 text-ink border-edge",
};

export default function SummaryBanner({ summary }: Props) {
  return (
    <section className="animate-rise rounded-2xl border border-edge bg-panel p-5 shadow-panel">
      <div className="flex flex-wrap items-center gap-3">
        <div className={`rounded-full border px-4 py-1 text-sm font-semibold ${statusColor[summary.status] || statusColor.UNKNOWN}`}>
          {summary.status}
        </div>
        <p className="font-mono text-xs uppercase tracking-wider text-ink/60">IKE {summary.ike_version}</p>
      </div>

      <div className="mt-4 grid gap-2 text-sm md:grid-cols-2">
        <p><span className="font-semibold">Initiator:</span> {summary.initiator_ip ?? "n/a"}</p>
        <p><span className="font-semibold">Responder:</span> {summary.responder_ip ?? "n/a"}</p>
      </div>

      {summary.peer_ids.length > 0 && (
        <div className="mt-3">
          <p className="text-sm font-semibold">Peer IDs</p>
          <div className="mt-1 flex flex-wrap gap-2">
            {summary.peer_ids.map((id) => (
              <span key={id} className="rounded-md bg-accent/10 px-2 py-1 font-mono text-xs text-ink">{id}</span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
