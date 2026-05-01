"""CLI for Clearwing."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from clearwing.scanner import ActiveScanner
from clearwing.swarm import PentestSwarm


def main() -> None:
    parser = argparse.ArgumentParser(description="Clearwing — Autonomous AI Pentesting")
    sub = parser.add_subparsers(dest="cmd")

    # scan
    scan_parser = sub.add_parser("scan", help="Quick active scan")
    scan_parser.add_argument("target", help="Target URL")
    scan_parser.add_argument("--depth", type=int, default=2)
    scan_parser.add_argument("--output", "-o", default="./pentest-report")

    # pentest
    pentest_parser = sub.add_parser("pentest", help="Full swarm pentest")
    pentest_parser.add_argument("target", help="Target URL")
    pentest_parser.add_argument("--scope", choices=["quick", "full"], default="full")
    pentest_parser.add_argument("--model", default="llama3.1")
    pentest_parser.add_argument("--memory", default="./clearwing-memory.json")
    pentest_parser.add_argument("--output", "-o", default="./pentest-reports")

    args = parser.parse_args()

    if args.cmd == "scan":
        scanner = ActiveScanner(args.target, max_depth=args.depth)
        results = scanner.run()
        print(f"\n🔍 Scan complete: {len(results)} findings")
        for r in results:
            print(f"  [{r.confidence:.0%}] {r.finding}")
            print(f"    → {r.curl_repro}")
        return

    if args.cmd == "pentest":
        swarm = PentestSwarm(
            model=args.model,
            memory_path=args.memory,
            output_dir=args.output,
        )
        manifest = swarm.run(args.target, scope=args.scope)
        print(f"\n✅ Pentest complete")
        print(f"  Findings: {manifest['findings']}")
        print(f"  Report: {manifest['report']}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
