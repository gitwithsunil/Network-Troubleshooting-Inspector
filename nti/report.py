"""Human-readable report + JSON export."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .analyzer import Analysis
from .integration import rate_limiter_signal

_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}


def to_markdown(a: Analysis, source: str = "capture.pcap") -> str:
    s = a.summary
    out = [f"# Network Troubleshooting Report",
           f"_Source: `{source}` · generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}_", "",
           "## Capture overview",
           f"- Packets: **{s.get('packets', 0)}** over **{s.get('duration_s', 0)} s** "
           f"({s.get('bytes', 0)} bytes)",
           f"- TCP flows: {s.get('tcp_flows', 0)} · DNS packets: {s.get('dns_packets', 0)} · "
           f"ICMP: {s.get('icmp_packets', 0)}", "", "## Findings"]
    for i, f in enumerate(a.findings, 1):
        out += [f"### {i}. {_ICON[f.severity]} [{f.severity.upper()}] {f.title}  _({f.category})_",
                "**Observed evidence**"] + [f"- {e}" for e in f.evidence]
        if f.possible_causes:
            out += ["", "**Possible causes**"] + [f"- {c}" for c in f.possible_causes]
        if f.next_steps:
            out += ["", "**Areas to investigate**"] + [f"- {n}" for n in f.next_steps]
        if f.packet_numbers:
            out += ["", "Wireshark filter: `frame.number in {" + " ".join(map(str, f.packet_numbers[:20])) + "}`"]
        out.append("")
    out += ["---", "_Findings are heuristic indicators from a single capture point; "
            "confirm with captures at both endpoints before acting._"]
    return "\n".join(out)


def to_json(a: Analysis) -> str:
    return json.dumps({"summary": a.summary, "metrics": a.metrics,
                       "findings": a.findings_dicts(),
                       "rate_limiter_signal": rate_limiter_signal(a)}, indent=2, default=str)
