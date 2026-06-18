export type TunnelStatus = "SUCCESS" | "FAILURE" | "FLAPPING" | "UNKNOWN";

export interface Summary {
  status: TunnelStatus;
  ike_version: string;
  initiator_ip: string | null;
  responder_ip: string | null;
  peer_ids: string[];
}

export interface TimelineEvent {
  ts: string;
  frame_number: number;
  src: string;
  dst: string;
  protocol: string;
  phase: string;
  step: string;
  severity: "info" | "warning" | "high" | string;
  details: string;
}

export interface Finding {
  severity: string;
  category: string;
  title: string;
  detail: string;
  frame_number: number | null;
}

export interface AnalysisReport {
  summary: Summary;
  timeline: TimelineEvent[];
  findings: Finding[];
  root_cause: string;
  remediation_steps: string[];
  fortigate_debug_cli: string[];
  metadata: Record<string, unknown>;
  upload?: {
    retention_seconds: number;
    auto_delete_scheduled: boolean;
  };
}
