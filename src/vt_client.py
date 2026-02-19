# =========================
# src/vt_client.py
# =========================
import base64
import os
import time
from typing import Any, Dict, Optional, Tuple

import requests


VT_BASE = "https://www.virustotal.com/api/v3"


def _headers(api_key: str) -> Dict[str, str]:
    return {"x-apikey": api_key, "Accept": "application/json"}


def _url_id(url: str) -> str:
    # VirusTotal v3 URL identifier: base64 urlsafe, tanpa padding '='
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


def _parse_verdict_from_stats(stats: Dict[str, Any]) -> Tuple[str, int, int]:
    """
    Return (verdict, malicious, suspicious)
    verdict: safe / suspicious / unsafe
    """
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)

    if malicious > 0:
        return "unsafe", malicious, suspicious
    if suspicious > 0:
        return "suspicious", malicious, suspicious
    return "safe", malicious, suspicious


def check_url(
    url: str,
    api_key: Optional[str] = None,
    submit_if_missing: bool = False,
    submit_wait_seconds: float = 2.0,
    max_retries: int = 2,
    sleep_between_retries: float = 1.0,
) -> Dict[str, Any]:
    """
    Cek URL ke VirusTotal:
    - default: lookup report /urls/{id}
    - jika submit_if_missing=True dan belum ada report, akan POST /urls untuk submit scan,
      lalu coba lookup lagi.

    Return dict ringkas:
    {
      "ok": bool,
      "verdict": "safe|suspicious|unsafe|unknown|error",
      "malicious": int,
      "suspicious": int,
      "error": str|None
    }
    """
    api_key = api_key or os.getenv("VT_API_KEY", "")
    if not api_key:
        return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "VT_API_KEY kosong"}

    urlid = _url_id(url)
    url_lookup = f"{VT_BASE}/urls/{urlid}"

    def _lookup() -> Tuple[bool, Optional[requests.Response]]:
        try:
            r = requests.get(url_lookup, headers=_headers(api_key), timeout=10)
            return True, r
        except Exception:
            return False, None

    for attempt in range(max_retries + 1):
        ok, resp = _lookup()
        if not ok or resp is None:
            if attempt < max_retries:
                time.sleep(sleep_between_retries)
                continue
            return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "Network error"}

        # Unauthorized / forbidden
        if resp.status_code in (401, 403):
            return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "API key tidak valid/akses ditolak"}

        # Rate limit
        if resp.status_code == 429:
            return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": "Rate limited (429)"}

        # Not found: belum ada report / id tidak dikenal
        if resp.status_code == 404:
            if not submit_if_missing:
                return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": "No report (404)"}

            # Submit URL untuk scan
            try:
                sr = requests.post(
                    f"{VT_BASE}/urls",
                    headers=_headers(api_key),
                    data={"url": url},
                    timeout=10,
                )
            except Exception:
                return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "Submit failed (network)"}

            if sr.status_code == 429:
                return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": "Rate limited (429) saat submit"}

            if sr.status_code not in (200, 202):
                return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": f"Submit failed ({sr.status_code})"}

            # tunggu sebentar, lalu lookup lagi
            time.sleep(submit_wait_seconds)
            continue

        # OK
        if resp.status_code == 200:
            try:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {}) or {}
                stats = attrs.get("last_analysis_stats", {}) or {}
                verdict, mal, susp = _parse_verdict_from_stats(stats)
                return {"ok": True, "verdict": verdict, "malicious": mal, "suspicious": susp, "error": None}
            except Exception:
                return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "Bad JSON"}

        # Other errors
        if attempt < max_retries:
            time.sleep(sleep_between_retries)
            continue
        return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": f"HTTP {resp.status_code}"}

    return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": "Unknown"}


def check_ip(
    ip: str,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Cek IP address di VirusTotal: GET /ip_addresses/{ip}
    Return format sama seperti check_url()
    """
    api_key = api_key or os.getenv("VT_API_KEY", "")
    if not api_key:
        return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "VT_API_KEY kosong"}

    try:
        r = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=_headers(api_key), timeout=10)
    except Exception:
        return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "Network error"}

    if r.status_code in (401, 403):
        return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "API key tidak valid/akses ditolak"}
    if r.status_code == 429:
        return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": "Rate limited (429)"}
    if r.status_code == 404:
        return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": "No report (404)"}
    if r.status_code != 200:
        return {"ok": False, "verdict": "unknown", "malicious": 0, "suspicious": 0, "error": f"HTTP {r.status_code}"}

    try:
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        verdict, mal, susp = _parse_verdict_from_stats(stats)
        return {"ok": True, "verdict": verdict, "malicious": mal, "suspicious": susp, "error": None}
    except Exception:
        return {"ok": False, "verdict": "error", "malicious": 0, "suspicious": 0, "error": "Bad JSON"}
