#!/usr/bin/env python3
"""
Simple CLI for CrackTime Analyzer.

Usage:
  python -m cracktime_analyzer.cli "P@ssw0rd!" --preset mid_gpu --output-prefix myreport
"""
import argparse
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

from .core import analyze_password, estimate_crack_time_from_guesses, CRACK_SPEED_PRESETS
from .report import save_json_report, save_csv_report


def human_meta() -> Dict[str, Any]:
    return {
        "tool": "CrackTime Analyzer",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def main(argv: List[str] = None):
    parser = argparse.ArgumentParser(description="CrackTime Analyzer - password audit CLI")
    parser.add_argument("passwords", nargs="+", help="Password(s) to analyze (quote if special chars present)")
    parser.add_argument("--preset", choices=list(CRACK_SPEED_PRESETS.keys()), default="mid_gpu",
                        help="Attacker speed preset for crack-time estimate")
    parser.add_argument("--custom-speed", type=float, default=None,
                        help="Provide custom guesses/sec (overrides preset)")

    parser.add_argument("--output-prefix", type=str, default=None,
                        help="Prefix for JSON/CSV output files (optional). If not provided, no files are written.")
    args = parser.parse_args(argv)

    results: List[Dict[str, Any]] = []
    for pw in args.passwords:
        r = analyze_password(pw)
        # Use guesses from analysis
        guesses = r.get("guesses", 1)
        speed = args.custom_speed if args.custom_speed and args.custom_speed > 0 else CRACK_SPEED_PRESETS.get(args.preset, 1e3)
        timeinfo = estimate_crack_time_from_guesses(float(guesses), float(speed))
        r["crack_time_seconds"] = timeinfo["seconds"]
        r["crack_time_human"] = timeinfo["human_readable"]
        r["assumptions"] = {"preset": args.preset, "guesses_per_second": timeinfo["guesses_per_second"]}
        results.append(r)

    # CLI output (pretty)
    for i, r in enumerate(results, start=1):
        print(f"--- Password #{i} ---")
        print(f"Masked: {r['password_masked']}")
        print(f"Length: {r['length']}")
        print(f"Entropy (bits): {r['entropy_bits']}")
        print(f"Estimated guesses: {r['guesses']:,}")
        print(f"Score (0-4): {r['score']}")
        print(f"Estimated crack time ({r['assumptions']['preset']} @ {r['assumptions']['guesses_per_second']:,} guesses/sec): {r['crack_time_human']}")
        if r.get("notes"):
            print("Notes:", " | ".join(r.get("notes", [])))
        print()

    # Save files if requested
    if args.output_prefix:
        meta = human_meta()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_file = f"{args.output_prefix}_{timestamp}.json"
        csv_file = f"{args.output_prefix}_{timestamp}.csv"
        save_json_report(meta, results, json_file)
        save_csv_report(meta, results, csv_file)
        print(f"Reports saved: {json_file}, {csv_file}")


if __name__ == "__main__":
    main()
