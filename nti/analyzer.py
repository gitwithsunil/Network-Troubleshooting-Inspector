"""PCAP parsing + detection engine for Network Troubleshooting Inspector."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional

import pandas as pd
from scapy.all import DNS, ICMP, IP, IPv6, TCP, UDP, PcapReader

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

COLUMNS = ["no", "time", "src", "dst", "proto", "sport", "dport", "length", "tflags",
           "seq", "ack", "win", "payload", "dns_id", "dns_qr", "dns_rcode",
           "dns_qname", "icmp_type"]


@dataclass
class Finding:
    severity: str            # high | medium | low | info
    category: str            # e.g. "TCP", "DNS", "Latency", "Traffic"
    title: str
    evidence: list[str]      # what was observed in the capture
    possible_causes: list[str]
    next_steps: list[str]
    count: int = 0
    packet_numbers: list[int] = field(default_factory=list)  # Wireshark frame numbers (capped)


@dataclass
class Analysis:
    summary: dict
    metrics: dict
    findings: list[Finding]
    tables: dict[str, pd.DataFrame]
    packets: pd.DataFrame

    def findings_dicts(self) -> list[dict]:
        return [asdict(f) for f in self.findings]


# --------------------------------------------------------------------------- parsing
def _parse(pkt, no: int) -> Optional[dict]:
    if pkt.haslayer(IP):
        l3 = pkt[IP]
        l4len = l3.len - l3.ihl * 4
    elif pkt.haslayer(IPv6):
        l3 = pkt[IPv6]
        l4len = l3.plen
    else:
        return None

    row = dict.fromkeys(COLUMNS)
    row.update(no=no, time=float(pkt.time), src=l3.src, dst=l3.dst,
               length=len(pkt), proto="OTHER", tflags=0, payload=0)

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        row.update(proto="TCP", sport=t.sport, dport=t.dport, tflags=int(t.flags),
                   seq=int(t.seq), ack=int(t.ack), win=int(t.window),
                   payload=max(int(l4len) - t.dataofs * 4, 0))
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        row.update(proto="UDP", sport=u.sport, dport=u.dport,
                   payload=max(int(l4len) - 8, 0))
        if pkt.haslayer(DNS):
            d = pkt[DNS]
            qd = d.qd
            if isinstance(qd, list):
                qd = qd[0] if qd else None
            name = None
            if qd is not None and hasattr(qd, "qname"):
                name = qd.qname.decode(errors="replace") if isinstance(qd.qname, bytes) else str(qd.qname)
                name = name.rstrip(".")
            row.update(proto="DNS", dns_id=int(d.id), dns_qr=int(d.qr),
                       dns_rcode=int(d.rcode) if d.qr else None, dns_qname=name)
    elif pkt.haslayer(ICMP):
        row.update(proto="ICMP", icmp_type=int(pkt[ICMP].type))
    return row


def load_pcap(path: str, max_packets: Optional[int] = None) -> pd.DataFrame:
    """Stream a .pcap / .pcapng file into a DataFrame (one row per IP packet)."""
    rows = []
    with PcapReader(path) as reader:
        for i, pkt in enumerate(reader):
            if max_packets and i >= max_packets:
                break
            row = _parse(pkt, i + 1)
            if row:
                rows.append(row)
    df = pd.DataFrame(rows, columns=COLUMNS)
    for col in ("sport", "dport", "seq", "ack", "win", "dns_id", "dns_qr", "dns_rcode", "icmp_type"):
        df[col] = df[col].astype("Int64")   # keep ports/seq numbers as integers despite missing values
    if not df.empty:
        df["rel_time"] = df["time"] - df["time"].min()
    else:
        df["rel_time"] = []
    return df


# --------------------------------------------------------------------------- helpers
def _flow(r) -> str:
    return f"{r.src}:{r.sport} → {r.dst}:{r.dport}"


def _cap(nums, n=50):
    return [int(x) for x in list(nums)[:n]]


def _pct(a, b) -> float:
    return round(100.0 * a / b, 2) if b else 0.0


# --------------------------------------------------------------------------- detectors
def detect_retransmissions(tcp: pd.DataFrame):
    seen, hits = set(), []
    data = tcp[(tcp.payload > 0) | ((tcp.tflags & SYN) > 0)]
    for r in data.itertuples():
        key = (r.src, r.sport, r.dst, r.dport, r.seq, r.payload, r.tflags & (SYN | FIN | ACK))
        if key in seen:
            hits.append(r)
        else:
            seen.add(key)
    n_data = int((tcp.payload > 0).sum())
    df = pd.DataFrame([{"frame": r.no, "time": round(r.rel_time, 4), "flow": _flow(r),
                        "seq": r.seq, "syn": bool(r.tflags & SYN)} for r in hits])
    return df, n_data


def detect_dup_acks(tcp: pd.DataFrame):
    last, run, max_run, hits = {}, defaultdict(int), defaultdict(int), []
    pure = tcp[((tcp.tflags & (SYN | FIN | RST)) == 0) & ((tcp.tflags & ACK) > 0) & (tcp.payload == 0)]
    for r in pure.itertuples():
        key = (r.src, r.sport, r.dst, r.dport)
        sig = (r.ack, r.win)
        if last.get(key) == sig:
            run[key] += 1
            max_run[key] = max(max_run[key], run[key])
            hits.append({"frame": r.no, "time": round(r.rel_time, 4), "flow": _flow(r),
                         "ack": r.ack, "dup_count": run[key]})
        else:
            run[key] = 0
        last[key] = sig
    return pd.DataFrame(hits), dict(max_run)


def detect_handshake_rtt(tcp: pd.DataFrame) -> pd.DataFrame:
    syns = {}
    out = []
    for r in tcp[(tcp.tflags & (SYN | ACK)) > 0].itertuples():
        f = r.tflags & (SYN | ACK)
        if f == SYN:
            syns.setdefault((r.src, r.sport, r.dst, r.dport, r.seq), r.rel_time)
        elif f == (SYN | ACK):
            key = (r.dst, r.dport, r.src, r.sport, (r.ack - 1) & 0xFFFFFFFF)
            if key in syns:
                out.append({"frame": r.no, "flow": f"{r.dst}:{r.dport} → {r.src}:{r.sport}",
                            "rtt_ms": round((r.rel_time - syns.pop(key)) * 1000, 3)})
    return pd.DataFrame(out, columns=["frame", "flow", "rtt_ms"])


def analyze_dns(df: pd.DataFrame):
    dns = df[df.proto == "DNS"]
    queries = dns[dns.dns_qr == 0]
    responses = dns[dns.dns_qr == 1]
    pending = {}
    for r in queries.itertuples():
        pending.setdefault((r.src, r.dns_id, r.dns_qname), []).append(r)
    matched = []
    for r in responses.itertuples():
        key = (r.dst, r.dns_id, r.dns_qname)
        if pending.get(key):
            q = pending[key].pop(0)
            matched.append({"frame": r.no, "qname": r.dns_qname,
                            "rcode": DNS_RCODES.get(int(r.dns_rcode), str(r.dns_rcode)),
                            "latency_ms": round((r.rel_time - q.rel_time) * 1000, 3)})
    unanswered = [{"frame": q.no, "qname": q.dns_qname, "client": q.src}
                  for lst in pending.values() for q in lst]
    return (pd.DataFrame(matched, columns=["frame", "qname", "rcode", "latency_ms"]),
            pd.DataFrame(unanswered, columns=["frame", "qname", "client"]),
            len(queries), len(responses))


def detect_scans(tcp: pd.DataFrame) -> pd.DataFrame:
    syn_only = tcp[(tcp.tflags & (SYN | ACK)) == SYN]
    if syn_only.empty:
        return pd.DataFrame(columns=["src", "targets", "ports", "syn_packets"])
    g = syn_only.groupby("src").agg(targets=("dst", "nunique"), ports=("dport", "nunique"),
                                    syn_packets=("no", "count")).reset_index()
    return g[(g.ports >= 20) | (g.targets >= 20)].sort_values("syn_packets", ascending=False)


# --------------------------------------------------------------------------- main entry
def analyze(df: pd.DataFrame) -> Analysis:
    findings: list[Finding] = []
    tables: dict[str, pd.DataFrame] = {}

    if df.empty:
        return Analysis({"packets": 0}, {}, [Finding("info", "Capture", "No IP packets found",
                        ["The file contained no parseable IPv4/IPv6 packets."], [],
                        ["Check the capture filter / interface used in Wireshark."])], {}, df)

    tcp = df[df.proto == "TCP"].copy()
    for col in ("sport", "dport", "seq", "ack", "win"):
        tcp[col] = tcp[col].astype("int64")
    duration = float(df.rel_time.max())
    summary = {
        "packets": len(df), "bytes": int(df.length.sum()), "duration_s": round(duration, 3),
        "tcp_packets": len(tcp), "udp_packets": int((df.proto == "UDP").sum()),
        "dns_packets": int((df.proto == "DNS").sum()), "icmp_packets": int((df.proto == "ICMP").sum()),
        "tcp_flows": int(tcp.groupby(["src", "sport", "dst", "dport"]).ngroups) if len(tcp) else 0,
        "start_epoch": float(df.time.min()),
    }

    # ---- TCP retransmissions
    retr, n_data = detect_retransmissions(tcp)
    retr_rate = _pct(len(retr), n_data)
    tables["retransmissions"] = retr
    if len(retr):
        sev = "high" if retr_rate > 5 else "medium" if retr_rate > 1 else "low"
        top = retr.flow.value_counts().head(3)
        findings.append(Finding(
            sev, "TCP", "TCP retransmissions detected",
            [f"{len(retr)} retransmitted segments out of {n_data} data segments ({retr_rate}%)."]
            + [f"{flow}: {c} retransmissions" for flow, c in top.items()],
            ["Packet loss on the path (congested link, faulty cable/NIC, Wi-Fi interference)",
             "Overloaded or slow receiver not ACKing in time",
             "Middlebox (firewall/IPS/load balancer) dropping packets",
             "MTU / fragmentation problems"],
            ["Capture at both endpoints to see where packets disappear",
             "Check interface error/drop counters on switches and hosts",
             "Compare against a path test (ping/mtr) to the affected server"],
            len(retr), _cap(retr.frame)))

    # ---- Duplicate ACKs
    dups, max_run = detect_dup_acks(tcp)
    tables["duplicate_acks"] = dups
    fast_retx_flows = sum(1 for v in max_run.values() if v >= 3)
    if len(dups):
        sev = "medium" if fast_retx_flows else "low"
        findings.append(Finding(
            sev, "TCP", "Duplicate ACKs observed",
            [f"{len(dups)} duplicate ACKs; {fast_retx_flows} flow(s) reached 3+ duplicates "
             "(fast-retransmit trigger)."],
            ["A segment was lost or reordered and the receiver keeps re-acknowledging the gap",
             "Out-of-order delivery due to multipath / load balancing"],
            ["Look for the retransmitted segment following the dup-ACK burst",
             "Check for asymmetric routing or ECMP reordering"],
            len(dups), _cap(dups.frame)))

    # ---- TCP resets
    rst = tcp[(tcp.tflags & RST) > 0]
    rst_rate = _pct(len(rst), summary["tcp_flows"] or 1)
    tables["resets"] = pd.DataFrame([{"frame": r.no, "time": round(r.rel_time, 4), "flow": _flow(r)}
                                     for r in rst.itertuples()])
    if len(rst):
        sev = "high" if rst_rate > 20 else "medium" if rst_rate > 5 else "low"
        top = tables["resets"].flow.value_counts().head(3)
        findings.append(Finding(
            sev, "TCP", "TCP resets (RST) observed",
            [f"{len(rst)} RST packets across {summary['tcp_flows']} flows."]
            + [f"{flow}: {c} RST(s)" for flow, c in top.items()],
            ["Service not listening on the port (RST in reply to SYN)",
             "Firewall / IPS actively rejecting or terminating sessions",
             "Application crashed or closed abruptly with unread data",
             "Idle-timeout on a NAT/firewall then late packets rejected"],
            ["Check who sent the RST (client vs server vs middlebox) and the TTL of the RST",
             "Verify the listening service and firewall rules for the affected ports"],
            len(rst), _cap(rst.no)))

    # ---- Zero window
    zw = tcp[(tcp.win == 0) & ((tcp.tflags & (SYN | RST | FIN)) == 0)]
    if len(zw):
        findings.append(Finding(
            "medium", "TCP", "TCP zero-window advertisements",
            [f"{len(zw)} packets advertised a receive window of 0."],
            ["Receiving application not reading from its socket fast enough",
             "Receiver CPU/memory/disk bottleneck"],
            ["Investigate the receiving host's resource usage and app read loop"],
            len(zw), _cap(zw.no)))

    # ---- Handshake latency
    rtt = detect_handshake_rtt(tcp)
    tables["handshake_rtt"] = rtt
    metrics_rtt = {}
    if len(rtt):
        metrics_rtt = {"rtt_avg_ms": round(rtt.rtt_ms.mean(), 2),
                       "rtt_p95_ms": round(rtt.rtt_ms.quantile(0.95), 2),
                       "rtt_max_ms": round(rtt.rtt_ms.max(), 2)}
        p95 = metrics_rtt["rtt_p95_ms"]
        if p95 > 200:
            sev = "high" if p95 > 500 else "medium"
            slow = rtt.sort_values("rtt_ms", ascending=False).head(3)
            findings.append(Finding(
                sev, "Latency", "High TCP handshake latency",
                [f"{len(rtt)} handshakes measured; avg {metrics_rtt['rtt_avg_ms']} ms, "
                 f"p95 {p95} ms, max {metrics_rtt['rtt_max_ms']} ms."]
                + [f"{r.flow}: {r.rtt_ms} ms" for r in slow.itertuples()],
                ["Long-distance / congested WAN or VPN path", "Bufferbloat on a saturated link",
                 "Overloaded server slow to accept connections"],
                ["Run traceroute/mtr to isolate the slow hop", "Compare handshake RTT vs. app response time"],
                len(rtt), _cap(rtt.frame)))

    # ---- DNS
    dns_ok, dns_unans, n_q, n_r = analyze_dns(df)
    tables["dns"] = dns_ok
    tables["dns_unanswered"] = dns_unans
    dns_fail = dns_ok[dns_ok.rcode != "NOERROR"] if len(dns_ok) else dns_ok
    dns_fail_rate = _pct(len(dns_fail) + len(dns_unans), n_q)
    if len(dns_fail):
        by = dns_fail.rcode.value_counts().to_dict()
        findings.append(Finding(
            "high" if dns_fail_rate > 20 else "medium", "DNS", "DNS error responses",
            [f"{len(dns_fail)} failed responses: " + ", ".join(f"{k}={v}" for k, v in by.items())]
            + [f"{n}: {c} failure(s)" for n, c in dns_fail.qname.value_counts().head(3).items()],
            ["NXDOMAIN: typo, stale config, or missing record / split-horizon DNS issue",
             "SERVFAIL: upstream resolver or DNSSEC problem", "REFUSED: resolver ACL / policy"],
            ["Query the failing names directly with dig/nslookup against each resolver",
             "Check the client's configured DNS servers and search domains"],
            len(dns_fail), _cap(dns_fail.frame)))
    if len(dns_unans):
        findings.append(Finding(
            "high" if len(dns_unans) >= 3 else "medium", "DNS", "Unanswered DNS queries",
            [f"{len(dns_unans)} of {n_q} queries never received a response."]
            + [f"{n}: {c} unanswered" for n, c in dns_unans.qname.value_counts().head(3).items()],
            ["DNS server unreachable or overloaded", "Firewall blocking UDP/TCP 53",
             "Packet loss on the path to the resolver",
             "Capture started/ended mid-exchange (response outside the capture window)"],
            ["Test the resolver directly (dig @server) and check connectivity on port 53",
             "Check for a secondary resolver failover delay"],
            len(dns_unans), _cap(dns_unans.frame)))
    dns_p95 = 0.0
    if len(dns_ok):
        dns_p95 = round(dns_ok.latency_ms.quantile(0.95), 2)
        if dns_p95 > 200:
            findings.append(Finding(
                "medium", "DNS", "Slow DNS responses",
                [f"p95 DNS response time {dns_p95} ms over {len(dns_ok)} answered queries."],
                ["Slow/overloaded resolver", "Recursive lookups to distant authoritative servers"],
                ["Compare against a nearby caching resolver"], len(dns_ok)))

    # ---- Unusual traffic
    scans = detect_scans(tcp)
    tables["scan_suspects"] = scans
    for r in scans.itertuples():
        findings.append(Finding(
            "high", "Traffic", f"Possible port scan / SYN sweep from {r.src}",
            [f"{r.syn_packets} SYN-only packets to {r.targets} host(s) and {r.ports} distinct port(s)."],
            ["Reconnaissance / port scanning", "Misbehaving monitoring or discovery tool",
             "Malware attempting lateral movement"],
            ["Identify the source device and confirm it is authorised", "Review firewall/IDS logs for this source"],
            int(r.syn_packets)))

    unreach = df[(df.proto == "ICMP") & (df.icmp_type == 3)]
    if len(unreach):
        findings.append(Finding(
            "low", "Traffic", "ICMP destination unreachable messages",
            [f"{len(unreach)} ICMP type-3 messages seen."],
            ["Closed UDP port / no route to host", "Firewall reject rule", "MTU issue (fragmentation needed)"],
            ["Inspect the ICMP code and the embedded original packet"], len(unreach), _cap(unreach.no)))

    # SYNs that never got a SYN/ACK
    syn_only = tcp[(tcp.tflags & (SYN | ACK)) == SYN]
    synack = tcp[(tcp.tflags & (SYN | ACK)) == (SYN | ACK)]
    answered = {(r.dst, r.dport, r.src, r.sport) for r in synack.itertuples()}
    refused = {(r.dst, r.dport, r.src, r.sport) for r in tcp[(tcp.tflags & RST) > 0].itertuples()}
    scan_srcs = set(scans.src) if len(scans) else set()
    unanswered_syn = syn_only[[(r.src, r.sport, r.dst, r.dport) not in answered
                               and (r.src, r.sport, r.dst, r.dport) not in refused
                               and r.src not in scan_srcs for r in syn_only.itertuples()]]
    unanswered_syn = unanswered_syn.drop_duplicates(["src", "sport", "dst", "dport"])
    tables["failed_connections"] = unanswered_syn[["no", "src", "sport", "dst", "dport"]]
    if len(unanswered_syn):
        top = unanswered_syn.groupby(["dst", "dport"]).size().sort_values(ascending=False).head(3)
        findings.append(Finding(
            "medium" if len(unanswered_syn) >= 5 else "low", "TCP", "Connection attempts with no SYN/ACK",
            [f"{len(unanswered_syn)} connection attempts got no SYN/ACK."]
            + [f"{d}:{p}: {c} attempt(s)" for (d, p), c in top.items()],
            ["Destination host down or unreachable", "Firewall silently dropping the SYN",
             "Capture point is after the drop"],
            ["Verify reachability/routes to the destination", "Check ACLs and security groups"],
            len(unanswered_syn), _cap(unanswered_syn.no)))

    # ---- Top talkers (informational)
    talkers = (df.groupby("src").agg(packets=("no", "count"), bytes=("length", "sum"))
               .sort_values("bytes", ascending=False).head(10).reset_index())
    tables["top_talkers"] = talkers
    tables["protocols"] = df.proto.value_counts().rename_axis("proto").reset_index(name="packets")

    if not findings:
        findings.append(Finding("info", "Capture", "No significant issues detected",
                                ["None of the built-in indicators exceeded their thresholds."], [],
                                ["If the problem is intermittent, capture during a failure window."]))

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])

    metrics = {
        "retrans_rate_pct": retr_rate, "dupack_count": len(dups), "rst_count": len(rst),
        "rst_flow_pct": rst_rate, "zero_window_count": len(zw),
        "dns_fail_rate_pct": dns_fail_rate, "dns_p95_ms": dns_p95,
        "failed_connection_count": len(unanswered_syn), "scan_sources": len(scans), **metrics_rtt,
    }
    return Analysis(summary, metrics, findings, tables, df)
