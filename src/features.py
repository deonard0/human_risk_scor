from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import tldextract
import requests


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"
}

TRACKING_KEYS_PREFIX = ("utm_",)
TRACKING_KEYS_EXACT = {"ref", "fbclid", "gclid", "yclid"}


LOGIN_KEYWORDS = ("login", "signin", "sign-in", "verify", "reset", "password", "account")


def is_ip_address(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def extract_domain_parts(url: str) -> Tuple[str, str, str]:
    ext = tldextract.extract(url)
    return ext.subdomain, ext.domain, ext.suffix


def looks_like_typosquatting(domain: str) -> bool:
    """
    Heuristik ringan:
    - Banyak angka mengganti huruf (0,1,3,5,7)
    - Banyak repeated char
    (Tidak mengklaim "jahat", hanya indikator 'mirip-mirip')
    """
    if re.search(r"[01357]", domain):
        return True
    if re.search(r"(.)\1\1", domain):  # 3 char sama berturut-turut
        return True
    return False


def suspicious_char_score(url: str) -> int:
    score = 0
    if "@" in url:
        score += 2
    if "%" in url:
        score += 1
    if url.count("-") >= 5:
        score += 1
    if len(url) >= 120:
        score += 2
    return score


@dataclass
class ProbeResult:
    ok: bool
    final_url: str = ""
    status_code: int = 0
    redirect_count: int = 0
    error: str = ""


def http_probe(url: str, timeout: float = 3.0) -> ProbeResult:
    """
    Optional: network call untuk cek status & redirect.
    Aman karena hanya request ke URL yang user input.
    """
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "RiskScoringTool/1.0"})
        return ProbeResult(
            ok=True,
            final_url=str(resp.url),
            status_code=int(resp.status_code),
            redirect_count=len(resp.history),
        )
    except Exception as e:
        return ProbeResult(ok=False, error=str(e))


def extract_features(url: str, do_probe: bool = False) -> Dict[str, Any]:
    """
    Return fitur-fitur yang akan dipakai scoring.
    """
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = parse_qs(parsed.query)

    sub, dom, suf = extract_domain_parts(url)
    reg_domain = f"{dom}.{suf}" if dom and suf else host

    # Tracking keys count
    q_keys = set(k.lower() for k in query.keys())
    tracking_count = 0
    for k in q_keys:
        if k.startswith(TRACKING_KEYS_PREFIX) or k in TRACKING_KEYS_EXACT:
            tracking_count += 1

    has_login_kw = any(k in path or k in parsed.query.lower() for k in LOGIN_KEYWORDS)

    feats: Dict[str, Any] = {
        "scheme": scheme,
        "is_https": scheme == "https",
        "host": host,
        "reg_domain": reg_domain,
        "is_ip_host": is_ip_address(host) if host else False,
        "is_shortener": reg_domain in SHORTENERS,
        "url_len": len(url),
        "tracking_params": tracking_count,
        "many_subdomains": sub.count(".") >= 2 if sub else False,
        "has_login_keywords": has_login_kw,
        "typo_like": looks_like_typosquatting(dom),
        "suspicious_char_score": suspicious_char_score(url),
    }

    if do_probe:
        probe = http_probe(url)
        feats["probe_ok"] = probe.ok
        feats["status_code"] = probe.status_code
        feats["redirect_count"] = probe.redirect_count
        feats["final_url"] = probe.final_url
    else:
        feats["probe_ok"] = None
        feats["status_code"] = None
        feats["redirect_count"] = None
        feats["final_url"] = None

    return feats
