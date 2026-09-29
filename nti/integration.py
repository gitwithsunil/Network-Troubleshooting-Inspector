"""Bridge between NTI and an adaptive / self-evolving API rate limiter.

NTI turns a PCAP into a compact "network health signal". Your rate limiter can
poll this (JSON file, function call, or HTTP) and use it as an extra input to
its adaptation loop: when the network path is degrading, back off *before*
requests start timing out.
"""
from __future__ import annotations

from .analyzer import Analysis


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def rate_limiter_signal(a: Analysis) -> dict:
    """Return a JSON-serialisable health signal.

    `limit_multiplier` is a heuristic in [0.25, 1.0] that the limiter can multiply
    into its current allowed rate. Treat the weights as a starting point and let
    your limiter's learning loop tune them.
    """
    m = a.metrics
    if not m:
        return {"health_score": None, "limit_multiplier": 1.0, "reasons": ["no data"], "metrics": {}}

    penalty, reasons = 0.0, []

    def add(cond, pts, why):
        nonlocal penalty
        if cond:
            penalty += pts
            reasons.append(why)

    add(m["retrans_rate_pct"] > 1, min(30, m["retrans_rate_pct"] * 3), f"retransmissions {m['retrans_rate_pct']}%")
    add(m["rst_flow_pct"] > 5, min(20, m["rst_flow_pct"]), f"resets on {m['rst_flow_pct']}% of flows")
    add(m["dns_fail_rate_pct"] > 2, min(20, m["dns_fail_rate_pct"]), f"DNS failures {m['dns_fail_rate_pct']}%")
    add(m.get("rtt_p95_ms", 0) > 200, min(25, m.get("rtt_p95_ms", 0) / 20), f"RTT p95 {m.get('rtt_p95_ms')} ms")
    add(m["zero_window_count"] > 0, 5, "zero-window advertisements")
    add(m["failed_connection_count"] >= 5, 10, f"{m['failed_connection_count']} failed connection attempts")

    score = round(_clamp(100 - penalty, 0, 100), 1)
    multiplier = round(_clamp(0.25 + 0.75 * score / 100, 0.25, 1.0), 2)
    return {
        "health_score": score,
        "limit_multiplier": multiplier,
        "congestion_suspected": m["retrans_rate_pct"] > 2 or m.get("rtt_p95_ms", 0) > 300,
        "reasons": reasons or ["healthy"],
        "metrics": m,
        "duration_s": a.summary.get("duration_s"),
        "window_start_epoch": a.summary.get("start_epoch"),
    }
