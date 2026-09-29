# Network Troubleshooting Inspector (NTI)

PCAP → evidence, possible causes, and next steps. Python + Scapy + Pandas + Streamlit + Plotly.

## Run
```bash
pip install -r requirements.txt
python samples/make_sample_pcap.py          # synthetic capture with every issue type
streamlit run app.py                        # dashboard
python cli.py samples/sample.pcap --md report.md --signal signal.json   # headless
```

## What it detects
| Indicator | How |
|---|---|
| Retransmissions | repeated (flow, seq, len) data/SYN segments |
| Duplicate ACKs | repeated pure-ACK with same ack+window; 3+ = fast-retransmit trigger |
| Resets | RST packets, grouped by flow |
| Zero window | window=0 advertisements |
| Latency | SYN → SYN/ACK handshake RTT (avg / p95 / max) |
| DNS | NXDOMAIN/SERVFAIL/REFUSED, unanswered queries, slow responses |
| Unusual traffic | SYN sweeps/port scans, ICMP unreachable, SYNs with no reply |

Wireshark workflow: capture → *File → Save As* `.pcap`/`.pcapng` → upload. Each finding gives a
`frame.number in {...}` filter to jump back to the packets in Wireshark.

## Rate-limiter integration
`nti.rate_limiter_signal(analysis)` returns:
```json
{"health_score": 19.7, "limit_multiplier": 0.4, "congestion_suspected": true,
 "reasons": ["retransmissions 33.33%", "..."], "metrics": {"...": "..."}}
```
Use it as an extra input to the limiter's adaptation loop (multiply the current limit by
`limit_multiplier`, or feed `metrics` as features to the learning component). For live use,
run NTI on rolling capture windows (e.g. `tshark -a duration:30 -w win.pcap` in a loop) and write
`signal.json` for the limiter to poll.

## Limits
Single-vantage-point heuristics; sequence-number wraparound and TCP options (SACK) are not modelled.
Scapy is pure Python, so use the max-packets cap for very large files.
