"""Utilities to save JSON and CSV reports for CrackTime Analyzer"""

import json
import csv
from typing import List, Dict, Any


def save_json_report(meta: Dict[str, Any], results: List[Dict[str, Any]], filename: str):
    payload = {"meta": meta, "results": results}
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def save_csv_report(meta: Dict[str, Any], results: List[Dict[str, Any]], filename: str):
    # flatten results and write CSV; meta is not written to CSV but you can extend as needed
    if not results:
        # write header only
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["password_id", "password_masked", "length", "entropy_bits", "guesses", "score", "notes"])
        return

    fieldnames = ["password_id", "password_masked", "length", "entropy_bits", "guesses", "score", "notes"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, r in enumerate(results, start=1):
            writer.writerow({
                "password_id": f"p{i}",
                "password_masked": r.get("password_masked", ""),
                "length": r.get("length", ""),
                "entropy_bits": r.get("entropy_bits", ""),
                "guesses": r.get("guesses", ""),
                "score": r.get("score", ""),
                "notes": " | ".join(r.get("notes", [])) if r.get("notes") else ""
            })
