from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .scoring import ScoredItem


def save_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def save_text(path: Path, summary: Dict[str, Any], items: List[ScoredItem]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append(f"FINAL SCORE: {summary['final_score']} ({summary['level']})")
    lines.append("")
    lines.append("SUMMARY:")
    for k, v in summary["summary"].items():
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("TOP REASONS:")
    for tr in summary["top_reasons"]:
        lines.append(f"- {tr['reason']} (x{tr['count']})")
    lines.append("")
    lines.append("SAMPLE SCANS (first 10):")
    for it in items[:10]:
        lines.append(f"* {it.score:>3} | {it.url}")
        for r in it.reasons:
            lines.append(f"    - {r}")
    lines.append("")

    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
