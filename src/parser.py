from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Literal

import pandas as pd


@dataclass
class Visit:
    timestamp: str
    url: str
    title: str = ""
    visit_count: int = 1


def load_from_csv(path: Path) -> List[Visit]:
    df = pd.read_csv(path)
    # Minimal kolom wajib: url
    if "url" not in df.columns:
        raise ValueError("CSV harus punya kolom 'url'.")

    # Kolom opsional
    if "timestamp" not in df.columns:
        df["timestamp"] = ""
    if "title" not in df.columns:
        df["title"] = ""
    if "visit_count" not in df.columns:
        df["visit_count"] = 1

    visits = []
    for _, row in df.iterrows():
        url = str(row["url"]).strip()
        if not url:
            continue
        visits.append(
            Visit(
                timestamp=str(row["timestamp"]).strip(),
                url=url,
                title=str(row["title"]).strip(),
                visit_count=int(row["visit_count"]) if str(row["visit_count"]).isdigit() else 1,
            )
        )
    return visits


def load_from_txt(path: Path) -> List[Visit]:
    visits = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            visits.append(Visit(timestamp="", url=url))
    return visits


def load_history(path_str: str) -> List[Visit]:
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {path}")

    suffix = path.suffix.lower()
    if suffix == ".csv":
        return load_from_csv(path)
    if suffix in [".txt", ".log"]:
        return load_from_txt(path)

    raise ValueError("Format input harus .csv atau .txt/.log")
