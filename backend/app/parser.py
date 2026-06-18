from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import re
from typing import Any

import pyshark


IKE_FAILURE_NOTIFIES = {
    "NO_PROPOSAL_CHOSEN",
    "AUTHENTICATION_FAILED",
    "INVALID_ID_INFORMATION",
    "SINGLE_PAIR_REQUIRED",
    "TS_UNACCEPTABLE",
    "INVALID_SELECTORS",
}

EXCHANGE_CODE_MAP = {
    "34": "IKE_SA_INIT",
    "35": "IKE_AUTH",
    "36": "CREATE_CHILD_SA",
    "37": "INFORMATIONAL",
}


@dataclass
class TimelineEvent:
    ts: str
    frame_number: int
    src: str
    dst: str
    protocol: str
    phase: str
    step: str
    severity: str
    details: str


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    frame_number: int | None = None


@dataclass
class TunnelSummary:
    status: str = "UNKNOWN"
    ike_version: str = "unknown"
    initiator_ip: str | None = None
    responder_ip: str | None = None
    peer_ids: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    summary: TunnelSummary
    timeline: list[TimelineEvent]
    findings: list[Finding]
    root_cause: str
    remediation_steps: list[str]
    fortigate_debug_cli: list[str]
    metadata: dict[str, Any]


class FortiIPsecAnalyzer:
    def __init__(self, pcap_path: str, anonymize: bool = False, psk: str | None = None) -> None:
        self.pcap_path = pcap_path
        self.anonymize = anonymize
        self.psk = psk

        self.timeline: list[TimelineEvent] = []
        self.findings: list[Finding] = []
        self.peer_counter: Counter[tuple[str, str]] = Counter()
        self.ike_version_counter: Counter[str] = Counter()

        self.phase1_started = False
        self.phase1_completed = False
        self.udp500_seen = False
        self.udp4500_seen = False
        self.nat_t_detected = False

        self.esp_flows: Counter[str] = Counter()
        self.dpd_requests = 0
        self.dpd_acks = 0
        self.notify_hits: list[tuple[str, int]] = []

        self.proposals: dict[str, set[str]] = defaultdict(set)
        self.fragmentation_frames: list[int] = []
        self.peer_ids: list[str] = []
        self.traffic_selectors: list[str] = []

        self.decryption_attempted = bool(psk)
        self.decryption_enabled = False
        self.decryption_error: str | None = None

    def analyze(self) -> AnalysisResult:
        capture = self._open_capture()
        try:
            for packet in capture:
                self._process_packet(packet)
        finally:
            capture.close()

        summary = self._build_summary()
        root_cause, remediation_steps = self._derive_rca(summary)
        return AnalysisResult(
            summary=summary,
            timeline=self.timeline,
            findings=self.findings,
            root_cause=root_cause,
            remediation_steps=remediation_steps,
            fortigate_debug_cli=self._build_fortigate_debug_cli(summary),
            metadata={
                "packet_count": len(self.timeline),
                "udp500_seen": self.udp500_seen,
                "udp4500_seen": self.udp4500_seen,
                "nat_t_detected": self.nat_t_detected,
                "dpd_requests": self.dpd_requests,
                "dpd_acks": self.dpd_acks,
                "notify_hits": [{"notify": n, "frame": f} for n, f in self.notify_hits],
                "proposals": {k: sorted(v) for k, v in self.proposals.items()},
                "traffic_selectors": self.traffic_selectors,
                "fragmentation_frames": self.fragmentation_frames,
                "decryption_attempted": self.decryption_attempted,
                "decryption_enabled": self.decryption_enabled,
                "decryption_error": self.decryption_error,
            },
        )

    def _open_capture(self) -> pyshark.FileCapture:
        params = ["-n"]
        if self.psk:
            params.extend(["-o", f"isakmp.key:{self.psk}"])

        try:
            return pyshark.FileCapture(
                input_file=self.pcap_path,
                keep_packets=False,
                use_json=True,
                include_raw=False,
                custom_parameters=params,
                display_filter="udp.port == 500 or udp.port == 4500 or isakmp or ikev2 or esp",
            )
        except Exception as exc:
            if self.psk:
                self.decryption_error = f"PSK decryption preference failed: {exc}"
                return pyshark.FileCapture(
                    input_file=self.pcap_path,
                    keep_packets=False,
                    use_json=True,
                    include_raw=False,
                    custom_parameters=["-n"],
                    display_filter="udp.port == 500 or udp.port == 4500 or isakmp or ikev2 or esp",
                )
            raise

    def _process_packet(self, packet: Any) -> None:
        if not hasattr(packet, "ip"):
            return

        src = self._sanitize_ip(str(getattr(packet.ip, "src", "")))
        dst = self._sanitize_ip(str(getattr(packet.ip, "dst", "")))
        if not src or not dst:
            return

        frame = self._safe_int(getattr(packet, "number", None)) or 0
        ts = self._packet_ts(packet)
        self.peer_counter[(src, dst)] += 1

        if hasattr(packet, "udp"):
            self._process_udp(packet, ts, frame, src, dst)

        if self._is_esp(packet):
            self._process_esp(packet, ts, frame, src, dst)

    def _process_udp(self, packet: Any, ts: str, frame: int, src: str, dst: str) -> None:
        sport = self._safe_int(getattr(packet.udp, "srcport", None))
        dport = self._safe_int(getattr(packet.udp, "dstport", None))

        if sport == 500 or dport == 500:
            self.udp500_seen = True
        if sport == 4500 or dport == 4500:
            self.udp4500_seen = True
            if self.udp500_seen:
                self.nat_t_detected = True

        if hasattr(packet, "isakmp") or hasattr(packet, "ikev2"):
            self._process_ike(packet, ts, frame, src, dst, sport, dport)

    def _process_ike(
        self,
        packet: Any,
        ts: str,
        frame: int,
        src: str,
        dst: str,
        sport: int | None,
        dport: int | None,
    ) -> None:
        layer = getattr(packet, "ikev2", None) or getattr(packet, "isakmp", None)
        if layer is None:
            return

        ike_version = self._detect_ike_version(packet)
        self.ike_version_counter[ike_version] += 1

        exchange = self._extract_exchange(layer)
        phase = "phase1" if exchange in {"IKE_SA_INIT", "IKE_AUTH", "MAIN_MODE", "AGGRESSIVE_MODE"} else "phase2"

        if exchange in {"IKE_SA_INIT", "MAIN_MODE", "AGGRESSIVE_MODE"}:
            self.phase1_started = True
        if exchange == "IKE_AUTH":
            self.phase1_completed = True

        notifies = self._extract_notifies(packet)

        self.timeline.append(
            TimelineEvent(
                ts=ts,
                frame_number=frame,
                src=src,
                dst=dst,
                protocol="IKE",
                phase=phase,
                step=exchange,
                severity="warning" if notifies else "info",
                details=f"IKE {ike_version} {exchange} UDP {sport}->{dport}" + (f" | notify={','.join(notifies)}" if notifies else ""),
            )
        )

        for notify in notifies:
            if notify in IKE_FAILURE_NOTIFIES:
                self.notify_hits.append((notify, frame))
                self._add_finding("high", "ike-notify", f"IKE notify error: {notify}", "Critical IKE notify from remote peer.", frame)
            if "DPD" in notify or "R_U_THERE" in notify:
                self.dpd_requests += 1
            if "R_U_THERE_ACK" in notify or "DPD_ACK" in notify:
                self.dpd_acks += 1

        self._extract_proposals(packet)
        self._extract_peer_ids(packet)
        self._extract_traffic_selectors(packet)
        self._detect_fragmentation(packet, frame)

    def _process_esp(self, packet: Any, ts: str, frame: int, src: str, dst: str) -> None:
        self.esp_flows[f"{src}->{dst}"] += 1
        natt = hasattr(packet, "udp") and (
            self._safe_int(getattr(packet.udp, "srcport", None)) == 4500
            or self._safe_int(getattr(packet.udp, "dstport", None)) == 4500
        )

        self.timeline.append(
            TimelineEvent(
                ts=ts,
                frame_number=frame,
                src=src,
                dst=dst,
                protocol="ESP",
                phase="phase2",
                step="ESP_DATA",
                severity="info",
                details="ESP packet observed (UDP-encap)" if natt else "ESP packet observed (proto 50)",
            )
        )

    def _build_summary(self) -> TunnelSummary:
        summary = TunnelSummary()

        if self.ike_version_counter:
            summary.ike_version = self.ike_version_counter.most_common(1)[0][0]

        if self.peer_counter:
            (src, dst), _ = self.peer_counter.most_common(1)[0]
            summary.initiator_ip = src
            summary.responder_ip = dst

        summary.peer_ids = sorted(set(self.peer_ids))

        if any(f.severity == "high" for f in self.findings):
            summary.status = "FAILURE"
        elif self._is_flapping():
            summary.status = "FLAPPING"
        elif self.phase1_started and self.phase1_completed and self._esp_bidirectional():
            summary.status = "SUCCESS"
        elif self.phase1_started and not self.phase1_completed:
            summary.status = "FAILURE"
            self._add_finding("high", "phase1", "Phase 1 did not progress to IKE_AUTH", "Negotiation started but no authentication completion was observed.", None)
        else:
            summary.status = "FLAPPING"

        if self.udp500_seen and not self.udp4500_seen:
            self._add_finding("medium", "nat-t", "NAT-T transition not observed", "Capture stayed on UDP 500. If NAT exists in path, UDP 4500 should be used.", None)

        if self.dpd_requests > 0 and self.dpd_acks == 0:
            self._add_finding("high", "dpd", "DPD probes not acknowledged", "Dead Peer Detection probes were not answered.", None)

        if self._esp_one_way():
            self._add_finding("high", "phase2", "Asymmetric/one-way ESP traffic", "ESP packets are observed in one direction only.", None)

        return summary

    def _derive_rca(self, summary: TunnelSummary) -> tuple[str, list[str]]:
        notify_codes = {n for n, _ in self.notify_hits}

        if "NO_PROPOSAL_CHOSEN" in notify_codes:
            return (
                "Phase 1 failed because IKE proposals are mismatched between peers.",
                [
                    "Align Phase 1 encryption, hash, and DH group on both peers.",
                    "Start from AES256/SHA256/DH14 and adjust as needed.",
                    "Ensure both peers use the same IKE version.",
                ],
            )

        if "AUTHENTICATION_FAILED" in notify_codes:
            return (
                "Phase 1 authentication failed due to PSK/certificate/ID mismatch.",
                [
                    "Verify PSK/certificate configuration on both peers.",
                    "Validate local/peer IDs and ID types.",
                    "Re-test with full IKE debug logs enabled.",
                ],
            )

        if "INVALID_ID_INFORMATION" in notify_codes:
            return (
                "Remote peer rejected IKE identity information.",
                [
                    "Verify localid and peerid values and expected identity type.",
                    "Check NAT influence on identity presentation.",
                    "Capture both sides and compare ID payloads.",
                ],
            )

        if "SINGLE_PAIR_REQUIRED" in notify_codes or "TS_UNACCEPTABLE" in notify_codes or "INVALID_SELECTORS" in notify_codes:
            return (
                "Phase 2 failed due to traffic selector mismatch.",
                [
                    "Match local/remote subnets exactly for Phase 2 selectors.",
                    "If required, use one subnet pair per Phase 2 definition.",
                    "Ensure policies route interesting traffic into the tunnel.",
                ],
            )

        if self._esp_one_way():
            return (
                "Phase 2 data path is asymmetric: no return ESP traffic from peer.",
                [
                    "Check return routing and firewall/NAT policy on both sides.",
                    "Allow ESP or UDP 4500 bidirectionally across all middleboxes.",
                    "Run simultaneous endpoint captures to isolate the drop point.",
                ],
            )

        if self.dpd_requests > 0 and self.dpd_acks == 0:
            return (
                "Tunnel likely dropped due to unacknowledged DPD keep-alives.",
                [
                    "Tune DPD intervals/retries on both peers.",
                    "Validate NAT UDP timeout behavior.",
                    "Inspect packet loss/jitter on WAN path.",
                ],
            )

        if summary.status == "SUCCESS":
            return (
                "No critical tunnel fault detected in the analyzed capture.",
                [
                    "No immediate remediation required.",
                    "If issue persists, capture a longer outage window.",
                ],
            )

        return (
            "Tunnel negotiation did not complete cleanly; likely policy mismatch or transport filtering.",
            [
                "Validate Phase 1/2 settings and peer IDs.",
                "Confirm UDP 500/4500 and ESP are allowed end-to-end.",
                "Capture packets from both tunnel endpoints.",
            ],
        )

    def _build_fortigate_debug_cli(self, summary: TunnelSummary) -> list[str]:
        peer = summary.responder_ip or "<peer-ip>"
        commands = [
            "diagnose vpn ike log-filter clear",
            f"diagnose vpn ike log-filter dst-addr4 {peer}",
            "diagnose debug reset",
            "diagnose debug console timestamp enable",
            "diagnose debug application ike -1",
            "diagnose debug enable",
            "# Reproduce issue, then disable debug:",
            "diagnose debug disable",
        ]

        if any(f.category == "phase2" for f in self.findings):
            commands.extend(
                [
                    "diagnose vpn tunnel list",
                    f"diagnose sniffer packet any 'host {peer} and (udp port 500 or udp port 4500 or esp)' 4 0 a",
                ]
            )

        if any(f.category == "dpd" for f in self.findings):
            commands.extend(
                [
                    "diagnose vpn ike gateway list",
                    "# Check DPD and keylife parameters in phase1-interface config.",
                ]
            )

        if self.fragmentation_frames:
            commands.extend(
                [
                    f"diagnose sniffer packet any 'host {peer} and udp port 4500' 6 0 a",
                    "# Validate MTU/MSS behavior for IKE fragmentation.",
                ]
            )

        return commands

    def _extract_exchange(self, layer: Any) -> str:
        raw = self._first_attr(layer, ["exchange_type", "exchangetype", "ikev2_exchange_type", "msg_type"])
        if raw is None:
            return "UNKNOWN"

        text = str(raw).upper()
        if text in EXCHANGE_CODE_MAP:
            return EXCHANGE_CODE_MAP[text]

        for code, name in EXCHANGE_CODE_MAP.items():
            if code in text:
                return name

        if "IKE_SA_INIT" in text:
            return "IKE_SA_INIT"
        if "IKE_AUTH" in text:
            return "IKE_AUTH"
        if "INFORMATIONAL" in text:
            return "INFORMATIONAL"
        if "AGGRESSIVE" in text:
            return "AGGRESSIVE_MODE"
        if "MAIN" in text:
            return "MAIN_MODE"

        return text or "UNKNOWN"

    def _extract_notifies(self, packet: Any) -> list[str]:
        blobs: list[str] = []
        for name in ["ikev2", "isakmp"]:
            layer = getattr(packet, name, None)
            if layer is None:
                continue
            if hasattr(layer, "_all_fields") and isinstance(layer._all_fields, dict):
                blobs.append(" ".join(str(v) for v in layer._all_fields.values()))
            else:
                blobs.append(str(layer))

        text = " ".join(blobs).upper()
        tokens: list[str] = []

        for code in IKE_FAILURE_NOTIFIES:
            if code in text:
                tokens.append(code)

        if "R_U_THERE_ACK" in text:
            tokens.append("R_U_THERE_ACK")
        if "R_U_THERE" in text:
            tokens.append("R_U_THERE")
        if "DPD" in text and "R_U_THERE" not in text:
            tokens.append("DPD")

        dedup: list[str] = []
        seen = set()
        for token in tokens:
            if token not in seen:
                dedup.append(token)
                seen.add(token)

        return dedup

    def _extract_proposals(self, packet: Any) -> None:
        text = ""
        for name in ["ikev2", "isakmp"]:
            layer = getattr(packet, name, None)
            if layer is not None:
                text += " " + str(layer).lower()

        for match in re.findall(r"aes(?:_|-|\s)?(gcm|cbc)", text):
            self.proposals["enc"].add(f"aes_{match}")

        for match in re.findall(r"sha(?:-|\s)?(1|256|384|512)", text):
            self.proposals["hash"].add(f"sha{match}")

        for pair in re.findall(r"group\s?(\d{1,2})|dh\s?(\d{1,2})", text):
            group = next((v for v in pair if v), None)
            if group:
                self.proposals["dh"].add(group)

    def _extract_peer_ids(self, packet: Any) -> None:
        text = ""
        for name in ["ikev2", "isakmp"]:
            layer = getattr(packet, name, None)
            if layer is not None:
                text += "\n" + str(layer)

        for item in re.findall(r"ID[^\n:]*:\s*([^\n]+)", text, flags=re.IGNORECASE):
            val = item.strip()
            if val and val not in self.peer_ids:
                self.peer_ids.append(val)

    def _extract_traffic_selectors(self, packet: Any) -> None:
        text = ""
        for name in ["ikev2", "isakmp"]:
            layer = getattr(packet, name, None)
            if layer is not None:
                text += "\n" + str(layer)

        for sel in re.findall(r"traffic selector[^\n]*", text, flags=re.IGNORECASE):
            clean = sel.strip()
            if clean and clean not in self.traffic_selectors:
                self.traffic_selectors.append(clean)

        upper = text.upper()
        if self.psk and ("TRAFFIC SELECTOR" in upper or "TSI" in upper or "TSR" in upper):
            self.decryption_enabled = True

    def _detect_fragmentation(self, packet: Any, frame: int) -> None:
        if not hasattr(packet, "ip"):
            return

        flags = str(getattr(packet.ip, "flags", "")).lower()
        frag_offset = self._safe_int(getattr(packet.ip, "frag_offset", None))
        ip_len = self._safe_int(getattr(packet.ip, "len", None))

        fragmented = "mf" in flags or (frag_offset is not None and frag_offset > 0)
        oversized = ip_len is not None and ip_len > 1300 and (hasattr(packet, "isakmp") or hasattr(packet, "ikev2"))

        if fragmented or oversized:
            self.fragmentation_frames.append(frame)

    def _is_esp(self, packet: Any) -> bool:
        if hasattr(packet, "esp"):
            return True
        if hasattr(packet, "ip") and str(getattr(packet.ip, "proto", "")) == "50":
            return True
        if hasattr(packet, "udp"):
            sport = self._safe_int(getattr(packet.udp, "srcport", None))
            dport = self._safe_int(getattr(packet.udp, "dstport", None))
            if sport == 4500 and dport == 4500:
                return True
        return False

    def _esp_bidirectional(self) -> bool:
        for flow, count in self.esp_flows.items():
            if count <= 0:
                continue
            src, dst = flow.split("->", 1)
            if self.esp_flows.get(f"{dst}->{src}", 0) > 0:
                return True
        return False

    def _esp_one_way(self) -> bool:
        if not self.esp_flows:
            return False
        return not self._esp_bidirectional()

    def _is_flapping(self) -> bool:
        setup = sum(1 for event in self.timeline if event.step in {"IKE_SA_INIT", "IKE_AUTH"})
        informational = sum(1 for event in self.timeline if event.step == "INFORMATIONAL")
        return setup >= 4 and informational >= 2

    def _detect_ike_version(self, packet: Any) -> str:
        if hasattr(packet, "ikev2"):
            return "v2"

        layer = getattr(packet, "isakmp", None)
        if layer is None:
            return "unknown"

        raw = self._first_attr(layer, ["version", "ike_version", "isakmp_version"])
        if raw is not None:
            txt = str(raw)
            if "2" in txt:
                return "v2"
            if "1" in txt:
                return "v1"

        return "unknown"

    def _packet_ts(self, packet: Any) -> str:
        ts = getattr(packet, "sniff_time", None)
        if isinstance(ts, datetime):
            return ts.isoformat()
        if ts is not None:
            return str(ts)
        return "unknown"

    def _sanitize_ip(self, value: str) -> str:
        if not self.anonymize:
            return value

        try:
            ip_obj = ipaddress.ip_address(value)
        except ValueError:
            return value

        if ip_obj.version == 4:
            if ip_obj.is_private:
                return value
            octets = value.split(".")
            return f"{octets[0]}.{octets[1]}.x.x"

        if ip_obj.is_private:
            return value
        parts = value.split(":")
        return ":".join(parts[:2] + ["xxxx", "xxxx"])

    def _first_attr(self, obj: Any, names: list[str]) -> Any:
        for name in names:
            if hasattr(obj, name):
                val = getattr(obj, name)
                if val not in (None, ""):
                    return val
        return None

    def _safe_int(self, value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _add_finding(self, severity: str, category: str, title: str, detail: str, frame_number: int | None) -> None:
        for existing in self.findings:
            if existing.title == title and existing.frame_number == frame_number:
                return

        self.findings.append(
            Finding(
                severity=severity,
                category=category,
                title=title,
                detail=detail,
                frame_number=frame_number,
            )
        )


def analyze_pcap(pcap_path: str, anonymize: bool = False, psk: str | None = None) -> dict[str, Any]:
    analyzer = FortiIPsecAnalyzer(pcap_path=pcap_path, anonymize=anonymize, psk=psk)
    result = analyzer.analyze()

    return {
        "summary": {
            "status": result.summary.status,
            "ike_version": result.summary.ike_version,
            "initiator_ip": result.summary.initiator_ip,
            "responder_ip": result.summary.responder_ip,
            "peer_ids": result.summary.peer_ids,
        },
        "timeline": [
            {
                "ts": event.ts,
                "frame_number": event.frame_number,
                "src": event.src,
                "dst": event.dst,
                "protocol": event.protocol,
                "phase": event.phase,
                "step": event.step,
                "severity": event.severity,
                "details": event.details,
            }
            for event in result.timeline
        ],
        "findings": [
            {
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "detail": finding.detail,
                "frame_number": finding.frame_number,
            }
            for finding in result.findings
        ],
        "root_cause": result.root_cause,
        "remediation_steps": result.remediation_steps,
        "fortigate_debug_cli": result.fortigate_debug_cli,
        "metadata": result.metadata,
    }
