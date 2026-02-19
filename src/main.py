from __future__ import annotations

import argparse
from pathlib import Path

from parser import load_history
from features import extract_features
from scoring import score_one, aggregate_scores
from report import save_json, save_text


def main():
    ap = argparse.ArgumentParser(description="Human Web Negligence Risk Scoring Tool")
    ap.add_argument("--input", required=True, help="Input .csv (timestamp,url,...) atau .txt (1 url per baris)")
    ap.add_argument("--probe", action="store_true", help="Aktifkan HTTP probe (GET) untuk cek redirect/status")
    ap.add_argument("--outdir", default="output", help="Folder output report")
    ap.add_argument("--limit", type=int, default=0, help="Batasi jumlah URL diproses (0 = semua)")
    args = ap.parse_args()

    visits = load_history(args.input)
    if args.limit and args.limit > 0:
        visits = visits[: args.limit]

    scored_items = []
    for v in visits:
        feats = extract_features(v.url, do_probe=args.probe)
        feats["original_url"] = v.url
        scored_items.append(score_one(feats))

    summary = aggregate_scores(scored_items)

    outdir = Path(args.outdir)
    json_path = outdir / "report.json"
    txt_path = outdir / "report.txt"

    payload = {
        "input": args.input,
        "probe_enabled": args.probe,
        "result": summary,
        "items_first_50": [
            {"url": it.url, "score": it.score, "reasons": it.reasons, "fatal": it.is_fatal}
            for it in scored_items[:50]
        ],
    }

    save_json(json_path, payload)
    save_text(txt_path, summary, scored_items)

    print(f"✅ Final score: {summary['final_score']} ({summary['level']})")
    print(f"📄 Report JSON: {json_path}")
    print(f"📄 Report TXT : {txt_path}")


if __name__ == "__main__":
    main()
