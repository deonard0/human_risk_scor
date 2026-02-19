import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


def chrome_time_to_utc_string(microseconds_since_1601: int) -> str:
    """
    Chrome/Windows WebKit time:
    microseconds since 1601-01-01 00:00:00 UTC.

    Convert to "YYYY-MM-DD HH:MM:SS" in UTC.
    """
  
    EPOCH_DIFF_SECONDS = 11644473600

    seconds = microseconds_since_1601 / 1_000_000
    unix_seconds = seconds - EPOCH_DIFF_SECONDS
    dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def load_takeout_history(json_path: Path) -> pd.DataFrame:
    """
    Google Takeout Chrome history file usually contains:
    {
      "Browser History": [
         { "time_usec": "...", "url": "...", "title": "...", "page_transition": "...", ... },
         ...
      ]
    }
    Sometimes keys may differ slightly. We handle common variants.
    """
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    possible_keys = ["Browser History", "BrowserHistory", "history", "History"]
    items = None
    for k in possible_keys:
        if k in data and isinstance(data[k], list):
            items = data[k]
            break

    if items is None:
        if isinstance(data, list):
            items = data
        else:
            raise ValueError(
                "Tidak menemukan list history di JSON. "
                "Pastikan file yang dipakai adalah Takeout/Chrome/BrowserHistory.json"
            )

    rows = []
    for it in items:
        url = it.get("url") or it.get("URL")
        if not url:
            continue

        time_usec = it.get("time_usec") or it.get("timeUsec") or it.get("time")
        if time_usec is None:
            ts = ""
        else:
            try:
                ts = chrome_time_to_utc_string(int(time_usec))
            except Exception:
                ts = ""

        title = it.get("title", "")
        visit_count = it.get("visit_count") or it.get("visitCount") or 1

        rows.append(
            {
                "timestamp": ts,
                "url": url,
                "title": title,
                "visit_count": int(visit_count) if str(visit_count).isdigit() else 1,
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        raise ValueError("History kosong setelah diproses. Coba cek file JSON-nya.")
    return df


def main():
    ap = argparse.ArgumentParser(
        description="Convert Google Takeout Chrome BrowserHistory.json -> CSV standar"
    )
    ap.add_argument(
        "--input",
        required=True,
        help="Path ke BrowserHistory.json (contoh: data/BrowserHistory.json)",
    )
    ap.add_argument(
        "--output",
        required=True,
        help="Path output CSV (contoh: output/history.csv)",
    )
    ap.add_argument(
        "--dedup",
        action="store_true",
        help="Jika diaktifkan, hapus duplikat berdasarkan (timestamp,url)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Batasi jumlah baris (0 = tidak dibatasi)",
    )
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    df = load_takeout_history(in_path)

    # Optional: limit
    if args.limit and args.limit > 0:
        df = df.head(args.limit)

    # Optional: dedup
    if args.dedup:
        df = df.drop_duplicates(subset=["timestamp", "url"], keep="first")

    # Sort by time if available
    if "timestamp" in df.columns:
        # empty timestamp will be last
        df["_ts_empty"] = df["timestamp"].eq("")
        df = df.sort_values(by=["_ts_empty", "timestamp"]).drop(columns=["_ts_empty"])

    df.to_csv(out_path, index=False, encoding="utf-8")
    print(f"✅ Sukses: {len(df)} baris disimpan ke: {out_path}")


if __name__ == "__main__":
    main()
