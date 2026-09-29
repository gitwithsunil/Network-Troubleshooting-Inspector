"""Network Troubleshooting Inspector — Streamlit dashboard.  Run: streamlit run app.py"""
import json
import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

from nti import analyze, load_pcap, rate_limiter_signal, to_json, to_markdown

st.set_page_config(page_title="Network Troubleshooting Inspector", page_icon="🛰️", layout="wide")
st.title("🛰️ Network Troubleshooting Inspector")
st.caption("Upload a Wireshark capture → get evidence, possible causes and next steps.")

SEV = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}

with st.sidebar:
    st.header("Input")
    up = st.file_uploader("PCAP / PCAPNG", type=["pcap", "pcapng", "cap"])
    max_pk = st.number_input("Max packets (0 = all)", min_value=0, value=200_000, step=50_000,
                             help="Scapy parses in pure Python; cap large files for speed.")
    if st.button("Use bundled sample", disabled=not os.path.exists("samples/sample.pcap")):
        st.session_state["sample"] = True


@st.cache_data(show_spinner="Parsing packets…")
def run(raw: bytes, limit: int):
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(raw)
        path = tmp.name
    try:
        a = analyze(load_pcap(path, limit or None))
    finally:
        os.unlink(path)
    return a


raw, name = None, "capture.pcap"
if up is not None:
    raw, name = up.getvalue(), up.name
elif st.session_state.get("sample"):
    raw, name = open("samples/sample.pcap", "rb").read(), "sample.pcap"

if raw is None:
    st.info("Upload a capture in the sidebar to begin (or generate one with "
            "`python samples/make_sample_pcap.py`).")
    st.stop()

a = run(raw, int(max_pk))
pk, m, s = a.packets, a.metrics, a.summary
if pk.empty:
    st.error("No IP packets found in this capture.")
    st.stop()

sig = rate_limiter_signal(a)

c = st.columns(6)
c[0].metric("Packets", f"{s['packets']:,}")
c[1].metric("Duration", f"{s['duration_s']} s")
c[2].metric("Retransmissions", f"{m['retrans_rate_pct']}%")
c[3].metric("Resets", m["rst_count"])
c[4].metric("RTT p95", f"{m.get('rtt_p95_ms', '—')} ms")
c[5].metric("Health score", sig["health_score"])

tab_find, tab_charts, tab_tables, tab_export = st.tabs(["🔎 Findings", "📈 Charts", "📋 Tables", "⬇️ Export / Integration"])

with tab_find:
    counts = pd.Series([f.severity for f in a.findings]).value_counts()
    st.write("  ".join(f"{SEV[k]} {k}: **{v}**" for k, v in counts.items()))
    for f in a.findings:
        with st.expander(f"{SEV[f.severity]} {f.title}  ·  {f.category}", expanded=f.severity == "high"):
            st.markdown("**Observed evidence**\n" + "\n".join(f"- {e}" for e in f.evidence))
            if f.possible_causes:
                st.markdown("**Possible causes**\n" + "\n".join(f"- {x}" for x in f.possible_causes))
            if f.next_steps:
                st.markdown("**Areas to investigate**\n" + "\n".join(f"- {x}" for x in f.next_steps))
            if f.packet_numbers:
                st.code("frame.number in {" + " ".join(map(str, f.packet_numbers[:30])) + "}", language="text")
                st.caption("Paste into Wireshark's display filter bar.")

with tab_charts:
    l, r = st.columns(2)
    bucket = max(s["duration_s"] / 60, 0.001)
    tl = pk.assign(bin=(pk.rel_time // bucket) * bucket).groupby(["bin", "proto"]).size().reset_index(name="packets")
    l.plotly_chart(px.area(tl, x="bin", y="packets", color="proto", title="Packets over time (s)"),
                   use_container_width=True)
    r.plotly_chart(px.pie(a.tables["protocols"], names="proto", values="packets", title="Protocol mix"),
                   use_container_width=True)
    l, r = st.columns(2)
    rtt = a.tables["handshake_rtt"]
    if len(rtt):
        l.plotly_chart(px.histogram(rtt, x="rtt_ms", nbins=30, title="TCP handshake RTT (ms)"),
                       use_container_width=True)
    else:
        l.info("No complete TCP handshakes in this capture.")
    tt = a.tables["top_talkers"]
    r.plotly_chart(px.bar(tt, x="src", y="bytes", title="Top talkers (bytes)"), use_container_width=True)
    ev = pd.concat([
        a.tables["retransmissions"].assign(kind="retransmission")[["time", "kind"]] if len(a.tables["retransmissions"]) else None,
        a.tables["duplicate_acks"].assign(kind="dup ACK")[["time", "kind"]] if len(a.tables["duplicate_acks"]) else None,
        a.tables["resets"].assign(kind="RST")[["time", "kind"]] if len(a.tables["resets"]) else None,
    ])
    if ev is not None and len(ev):
        st.plotly_chart(px.histogram(ev, x="time", color="kind", nbins=60, title="TCP problem events over time (s)"),
                        use_container_width=True)

with tab_tables:
    labels = {k: k.replace("_", " ").title() for k in a.tables}
    pick = st.selectbox("Table", list(a.tables), format_func=lambda k: labels[k])
    st.dataframe(a.tables[pick], use_container_width=True)
    with st.expander("Raw packet table (first 5,000 rows)"):
        st.dataframe(pk.head(5000), use_container_width=True)

with tab_export:
    st.download_button("Download Markdown report", to_markdown(a, name), "nti_report.md", "text/markdown")
    st.download_button("Download full JSON", to_json(a), "nti_results.json", "application/json")
    st.subheader("Rate-limiter health signal")
    st.caption("Feed this into the adaptive rate limiter: scale allowed request rate by `limit_multiplier`.")
    st.json(sig)
    st.download_button("Download signal.json", json.dumps(sig, indent=2), "signal.json", "application/json")
