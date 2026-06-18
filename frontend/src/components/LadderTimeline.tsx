import { TimelineEvent } from "../types";

interface Props {
  timeline: TimelineEvent[];
}

function colorForSeverity(severity: string): string {
  if (severity === "high") return "bg-bad";
  if (severity === "warning") return "bg-warn";
  return "bg-accent";
}

export default function LadderTimeline({ timeline }: Props) {
  return (
    <section className="animate-rise rounded-2xl border border-edge bg-panel p-5 shadow-panel">
      <h2 className="font-display text-xl font-bold text-ink">Ladder Timeline</h2>
      <p className="mt-1 text-sm text-ink/70">Chronological view of IKE and ESP message flow.</p>

      <div className="mt-4 space-y-3">
        {timeline.slice(0, 200).map((event) => (
          <div key={`${event.frame_number}-${event.ts}`} className="grid grid-cols-[20px,1fr] items-start gap-3">
            <div className={`mt-1 h-3 w-3 rounded-full ${colorForSeverity(event.severity)}`} />
            <div className="rounded-lg border border-edge/70 bg-canvas/80 p-3">
              <p className="font-mono text-xs text-ink/60">Frame #{event.frame_number} | {event.ts}</p>
              <p className="mt-1 text-sm font-semibold text-ink">{event.src} {"->"} {event.dst}</p>
              <p className="text-sm text-ink/80">{event.protocol} | {event.phase} | {event.step}</p>
              <p className="mt-1 text-sm text-ink/70">{event.details}</p>
            </div>
          </div>
        ))}

        {timeline.length === 0 && <p className="text-sm text-ink/70">No timeline data yet.</p>}
      </div>
    </section>
  );
}
