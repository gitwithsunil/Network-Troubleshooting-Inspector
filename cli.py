"""Usage: python cli.py capture.pcap [--md report.md] [--json out.json] [--signal signal.json]"""
import argparse
import json

from nti import analyze, load_pcap, rate_limiter_signal, to_json, to_markdown


def main():
    ap = argparse.ArgumentParser(description="Network Troubleshooting Inspector")
    ap.add_argument("pcap")
    ap.add_argument("--md", help="write markdown report")
    ap.add_argument("--json", help="write full JSON results")
    ap.add_argument("--signal", help="write compact rate-limiter health signal JSON")
    ap.add_argument("--max-packets", type=int)
    args = ap.parse_args()

    a = analyze(load_pcap(args.pcap, args.max_packets))
    md = to_markdown(a, args.pcap)
    if args.md:
        open(args.md, "w", encoding="utf-8").write(md)
    else:
        print(md)
    if args.json:
        open(args.json, "w", encoding="utf-8").write(to_json(a))
    if args.signal:
        json.dump(rate_limiter_signal(a), open(args.signal, "w"), indent=2)


if __name__ == "__main__":
    main()
