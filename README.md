# Network Troubleshooting Inspector (NTI)

NTI is a PCAP-based network analysis tool that turns raw packet captures into a readable troubleshooting report. Give it a capture taken with Wireshark and it reports what it observed, what could be causing it, and where to look next.

Manually scrolling through thousands of packets to find out why an application is slow or a connection keeps dropping is tedious and error-prone. NTI automates the first pass of that investigation by checking the capture for the usual indicators of trouble: TCP retransmissions, duplicate ACKs, resets, high latency, DNS failures, and unusual traffic patterns.

**Tech stack:** Python, Scapy, Pandas, Plotly, Streamlit (captures are recorded with Wireshark).

## Features

- Parses `.pcap` and `.pcapng` files (IPv4 and IPv6) into a Pandas DataFrame.
- Detects TCP, DNS, latency and traffic anomalies (see the table below).
- Every finding contains three parts: observed evidence, possible causes, and areas to investigate.
- Each finding includes a Wireshark display filter (`frame.number in {...}`) so you can jump straight to the relevant packets.
- Streamlit dashboard with summary metrics, charts, detail tables and report downloads.
- Command-line interface for scripted or headless use.
- Exports a compact JSON "health signal" that other systems, such as an adaptive API rate limiter, can consume.

## What NTI detects

| Indicator | How it is detected | Severity rule |
|---|---|---|
| TCP retransmissions | The same data or SYN segment (flow, sequence number, length) seen more than once | Over 5% of data segments: high. Over 1%: medium. Otherwise low |
| Duplicate ACKs | Repeated pure ACKs with the same acknowledgement and window values on a flow | Medium if any flow reaches 3 or more (the fast-retransmit trigger), otherwise low |
| TCP resets | Packets with the RST flag, grouped by flow | Based on the percentage of flows with a reset: over 20% high, over 5% medium, otherwise low |
| Zero window | Non-handshake packets that advertise a receive window of 0 | Medium |
| Handshake latency | Time between a SYN and its matching SYN/ACK | p95 over 200 ms: medium. Over 500 ms: high |
| DNS errors | Responses with a return code other than NOERROR (NXDOMAIN, SERVFAIL, REFUSED and so on) | Over 20% of queries: high, otherwise medium |
| Unanswered DNS queries | Queries with no matching response (matched on client, transaction ID and name) | 3 or more: high, otherwise medium |
| Slow DNS | p95 query-to-response time over 200 ms | Medium |
| Port scan or SYN sweep | One source sending SYN-only packets to 20 or more ports or hosts | High |
| Failed connection attempts | SYNs that received neither a SYN/ACK nor a RST | 5 or more: medium, otherwise low |
| ICMP unreachable | ICMP type 3 messages | Low |

The thresholds are defined in `nti/analyzer.py` and are easy to adjust for your environment.

## Installation

Requirements: Python 3.10 or newer.

```bash
git clone <your-repository-url>
cd nti

python -m venv venv
# Windows:      venv\Scripts\activate
# macOS/Linux:  source venv/bin/activate

pip install -r requirements.txt
```

Wireshark is only needed to record new captures. Reading existing capture files does not require Wireshark or Npcap.

## Usage

### 1. Record a capture

In Wireshark, capture traffic while the problem is happening, then use **File > Save As** and save it as `.pcap` or `.pcapng`. Captures that include the failure window give the most useful results.

### 2. Dashboard

```bash
streamlit run app.py
```

Open `http://localhost:8501`, upload your capture from the sidebar, and review the results. Run this command from the project root (the folder containing `app.py`).

The dashboard has four tabs:

- **Findings:** each detected issue, ordered by severity, with evidence, possible causes, next steps and a Wireshark filter.
- **Charts:** packets over time, protocol mix, handshake RTT distribution, top talkers, and TCP problem events over time.
- **Tables:** the underlying data for each detector (retransmissions, resets, DNS results, scan suspects and more) and the raw packet table.
- **Export / Integration:** downloads for the Markdown report, full JSON results and the rate-limiter signal.

The "Max packets" setting in the sidebar limits how many packets are parsed. Scapy is pure Python, so a cap keeps very large files responsive.

### 3. Command line

```bash
python cli.py capture.pcap                      # print the report
python cli.py capture.pcap --md report.md       # save a Markdown report
python cli.py capture.pcap --json results.json  # save full results
python cli.py capture.pcap --signal signal.json # save the health signal
```

### 4. Try it without a real capture

```bash
python samples/make_sample_pcap.py
python cli.py samples/sample.pcap
```

This generates a small synthetic capture that contains every issue type NTI detects, which is useful for testing changes to the detectors.

## Reading the results

- **Retransmission rate:** the share of TCP data segments that were sent again. Persistent values above 1% usually point to packet loss or congestion.
- **Resets:** the number of RST packets. Look at who sent them (client, server or a middlebox) before drawing conclusions.
- **RTT p95:** 95% of TCP handshakes completed within this time. It reflects the path latency that most users experience.
- **Health score:** a number from 0 to 100 that combines the metrics above into a single penalty-based score. Lower is worse.

Findings are indicators, not verdicts. A "port scan" finding, for example, can also be triggered by a health checker or service-discovery tool, so confirm what the source device is before acting on it.

## Rate limiter integration

NTI can produce a compact signal describing the health of the network path, intended as an extra input for an adaptive (self-evolving) API rate limiter. When the path degrades, the limiter can back off before requests begin to time out.

```python
from nti import load_pcap, analyze, rate_limiter_signal

signal = rate_limiter_signal(analyze(load_pcap("window.pcap")))
```

Example output:

```json
{
  "health_score": 29.7,
  "limit_multiplier": 0.47,
  "congestion_suspected": true,
  "reasons": ["retransmissions 33.33%", "DNS failures 80.0%", "RTT p95 306.0 ms"],
  "metrics": { "retrans_rate_pct": 33.33, "rtt_p95_ms": 306.0 },
  "duration_s": 6.4
}
```

- `health_score` is 100 minus penalties for retransmissions, resets, DNS failures, high RTT, zero-window events and failed connections.
- `limit_multiplier` is a value between 0.25 and 1.0 calculated from the score. The limiter can multiply its current allowed rate by this value.
- `metrics` exposes the raw measurements so a learning component can use them as features.

The penalty weights are heuristic starting points. In a self-evolving limiter they are intended to be tuned by its own feedback loop.

For near-real-time use, capture in short windows and analyze each one:

```bash
tshark -i <interface> -a duration:30 -w window.pcap
python cli.py window.pcap --signal signal.json
```

The rate limiter can then poll `signal.json`.

## Project structure

```
nti/
  app.py                       Streamlit dashboard
  cli.py                       Command-line interface
  requirements.txt
  nti/
    __init__.py
    analyzer.py                Packet parsing and all detectors
    report.py                  Markdown and JSON report generation
    integration.py             Rate-limiter health signal
  samples/
    make_sample_pcap.py        Generates a synthetic test capture
```

## How it works

1. `load_pcap` streams the file with Scapy and extracts one row per IP packet: addresses, ports, TCP flags, sequence and acknowledgement numbers, window size, payload length, and DNS or ICMP fields where relevant.
2. `analyze` runs each detector over the resulting DataFrame and collects the results as `Finding` objects along with summary metrics and detail tables.
3. `report.py` and the dashboard present those findings, and `integration.py` condenses the metrics into the health signal.

## Limitations

- Analysis is based on a single capture point. Confirming where packets are lost usually requires captures at both endpoints.
- Sequence-number wraparound, TCP options such as SACK, and TCP stream reassembly are not modelled.
- Retransmission detection is exact-match based, so retransmissions with changed segment boundaries may be missed.
- DNS analysis covers UDP DNS only.
- Scapy parses in pure Python, so very large captures are slow. Use the packet cap or pre-filter with Wireshark or `tshark`.

## Possible extensions

- Rolling-window live analysis with a small HTTP endpoint that serves the health signal.
- SACK-aware loss analysis and TCP stream reassembly.
- DNS over TCP, DNS over HTTPS and TLS handshake analysis.
- Configurable thresholds through a settings file.

## License

OPEN SOURCE / WAITING FOR COLLABORATORS FOR RE-DEVLOPEMENT 