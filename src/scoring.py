from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, List, Tuple


# Bobot aturan
WEIGHTS = {
    "http_not_https": 15,
    "http_login": 25,
    "ip_host": 20,
    "shortener": 10,
    "redirect_many": 10,
    "tracking_params": 3,      
    "many_subdomains": 5,
    "typo_like": 10,
    "suspicious_chars": 5,       # if suspicious_char_score >= 2
    "very_long_url": 5,          # if url_len >= 160
}

FATAL_EVENTS = {"http_login", "ip_host"}  # event yang dianggap berat


@dataclass
class ScoredItem:
    url: str
    score: int
    reasons: List[str]
    is_fatal: bool


def score_one(features: Dict[str, Any]) -> ScoredItem:
    url = features.get("original_url", "")
    reasons: List[str] = []
    score = 0
    fatal = False

    # 1) HTTPS
    if not features["is_https"]:
        score += WEIGHTS["http_not_https"]
        reasons.append(f"HTTP (tanpa HTTPS) +{WEIGHTS['http_not_https']}")

        if features["has_login_keywords"]:
            score += WEIGHTS["http_login"]
            reasons.append(f"HTTP pada halaman login/verify +{WEIGHTS['http_login']}")
            fatal = True

    # 2) IP host
    if features["is_ip_host"]:
        score += WEIGHTS["ip_host"]
        reasons.append(f"Akses host berupa IP +{WEIGHTS['ip_host']}")
        fatal = True

    # 3) Shortener
    if features["is_shortener"]:
        score += WEIGHTS["shortener"]
        reasons.append(f"URL shortener +{WEIGHTS['shortener']}")

    # 4) Redirect chain (jika probe aktif)
    rc = features.get("redirect_count")
    if isinstance(rc, int) and rc > 2:
        score += WEIGHTS["redirect_many"]
        reasons.append(f"Redirect >2 ({rc}) +{WEIGHTS['redirect_many']}")

    # 5) Tracking params
    tp = int(features.get("tracking_params") or 0)
    if tp > 0:
        add = tp * WEIGHTS["tracking_params"]
        score += add
        reasons.append(f"Tracking params ({tp}) +{add}")

    # 6) Many subdomains
    if features.get("many_subdomains"):
        score += WEIGHTS["many_subdomains"]
        reasons.append(f"Subdomain berlapis +{WEIGHTS['many_subdomains']}")

    # 7) Typosquatting-like
    if features.get("typo_like"):
        score += WEIGHTS["typo_like"]
        reasons.append(f"Pola domain mirip/typo-like +{WEIGHTS['typo_like']}")

    # 8) Suspicious chars
    scs = int(features.get("suspicious_char_score") or 0)
    if scs >= 2:
        score += WEIGHTS["suspicious_chars"]
        reasons.append(f"Karakter/struktur URL mencurigakan +{WEIGHTS['suspicious_chars']}")

    # 9) Very long URL
    if int(features.get("url_len") or 0) >= 160:
        score += WEIGHTS["very_long_url"]
        reasons.append(f"URL sangat panjang +{WEIGHTS['very_long_url']}")

    # cap per-url score
    score = min(100, score)

    return ScoredItem(url=url, score=score, reasons=reasons, is_fatal=fatal)


def aggregate_scores(items: List[ScoredItem]) -> Dict[str, Any]:
    if not items:
        return {"final_score": 0, "level": "Low", "summary": {}, "top_reasons": []}

    avg_url_risk = sum(i.score for i in items) / len(items)
    fatal_count = sum(1 for i in items if i.is_fatal)

    # Habit risk
    shortener_count = sum(1 for i in items if any("shortener" in r.lower() for r in i.reasons))
    http_count = sum(1 for i in items if any(r.startswith("HTTP") for r in i.reasons))

    shortener_rate = shortener_count / len(items)
    http_rate = http_count / len(items)

    habit_risk = min(100, (shortener_rate * 40) + (http_rate * 40) + (fatal_count * 10))

    final = 0.6 * avg_url_risk + 0.4 * habit_risk
    final = max(0, min(100, int(round(final))))

    if final < 25:
        level = "Low"
    elif final < 50:
        level = "Medium"
    elif final < 75:
        level = "High"
    else:
        level = "Critical"

    # Top reasons overall: hitung kontribusi rules dari teks reason
    reason_counter: Dict[str, int] = {}
    for i in items:
        for r in i.reasons:
            reason_counter[r] = reason_counter.get(r, 0) + 1

    top_reasons = sorted(reason_counter.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "final_score": final,
        "level": level,
        "summary": {
            "total_urls": len(items),
            "avg_url_risk": round(avg_url_risk, 2),
            "habit_risk": round(habit_risk, 2),
            "fatal_events": fatal_count,
            "http_count": http_count,
            "shortener_count": shortener_count,
        },
        "top_reasons": [{"reason": r, "count": c} for r, c in top_reasons],
    }
