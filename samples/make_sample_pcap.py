"""Generate a synthetic capture containing every issue NTI detects (for testing)."""
from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP, wrpcap

pkts = []
C, S = "10.0.0.5", "203.0.113.10"


def tcp(src, dst, sp, dp, flags, seq, ack, t, payload=b"", win=8192):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack, window=win)
    if payload:
        p = p / Raw(payload)
    p.time = 1700000000 + t
    pkts.append(p)


# 1) healthy flow, 40 ms RTT
tcp(C, S, 40000, 443, "S", 100, 0, 0.000)
tcp(S, C, 443, 40000, "SA", 500, 101, 0.040)
tcp(C, S, 40000, 443, "A", 101, 501, 0.041)
tcp(C, S, 40000, 443, "PA", 101, 501, 0.042, b"x" * 200)
tcp(S, C, 443, 40000, "A", 501, 301, 0.085)

# 2) lossy flow: retransmissions + dup ACKs, slow 320 ms handshake
tcp(C, S, 40001, 443, "S", 900, 0, 1.0)
tcp(S, C, 443, 40001, "SA", 700, 901, 1.32)
tcp(C, S, 40001, 443, "A", 901, 701, 1.321)
for i in range(3):
    tcp(C, S, 40001, 443, "PA", 901 + i * 100, 701, 1.4 + i * 0.01, b"y" * 100)
for k in range(4):
    tcp(S, C, 443, 40001, "A", 701, 901, 1.5 + k * 0.001)  # dup ACKs
tcp(C, S, 40001, 443, "PA", 901, 701, 1.8, b"y" * 100)      # retransmission
tcp(C, S, 40001, 443, "PA", 901, 701, 2.6, b"y" * 100)      # retransmission again
tcp(S, C, 443, 40001, "A", 701, 1001, 2.7, win=0)           # zero window

# 3) reset after handshake + connection refused
tcp(C, S, 40002, 8080, "S", 10, 0, 3.0)
tcp(S, C, 8080, 40002, "R", 0, 11, 3.02)

# 4) DNS: ok, NXDOMAIN, unanswered x3
def dns_q(id_, name, t):
    p = Ether() / IP(src=C, dst="10.0.0.1") / UDP(sport=5000 + id_, dport=53) / DNS(id=id_, rd=1, qd=DNSQR(qname=name))
    p.time = 1700000000 + t
    pkts.append(p)


def dns_r(id_, name, t, rcode):
    p = Ether() / IP(src="10.0.0.1", dst=C) / UDP(sport=53, dport=5000 + id_) / DNS(id=id_, qr=1, rcode=rcode, qd=DNSQR(qname=name))
    p.time = 1700000000 + t
    pkts.append(p)


dns_q(1, "example.com", 4.0); dns_r(1, "example.com", 4.02, 0)
dns_q(2, "intranet.corp.local", 4.1); dns_r(2, "intranet.corp.local", 4.15, 3)
for i in range(3, 6):
    dns_q(i, "api.slow-resolver.net", 4.2 + i * 0.5)

# 5) port scan from 10.0.0.66
for port in range(1, 41):
    tcp("10.0.0.66", "10.0.0.20", 55555, port, "S", 1, 0, 6.0 + port * 0.01)

wrpcap("samples/sample.pcap", pkts)
print(f"wrote samples/sample.pcap with {len(pkts)} packets")
