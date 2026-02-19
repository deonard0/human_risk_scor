# =========================
# app.py (FULL) - NEW VERSION
# =========================
import io
import json
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import pandas as pd
import streamlit as st

import socket
import re
import tldextract
import requests

# VirusTotal client
from src.vt_client import check_url as vt_check_url
from src.vt_client import check_ip as vt_check_ip

# Whitelist (separate file)
from src.whitelist import WHITELIST_DOMAINS_DEFAULT


# -----------------------------
# Helpers: time & input parsing
# -----------------------------
def chrome_time_to_utc_string(microseconds_since_1601: int) -> str:
    EPOCH_DIFF_SECONDS = 11644473600
    seconds = microseconds_since_1601 / 1_000_000
    unix_seconds = seconds - EPOCH_DIFF_SECONDS
    dt = datetime.utcfromtimestamp(unix_seconds)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def takeout_json_to_df(file_bytes: bytes) -> pd.DataFrame:
    data = json.loads(file_bytes.decode("utf-8", errors="ignore"))

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
            raise ValueError("Format JSON tidak dikenali. Pastikan BrowserHistory.json dari Google Takeout.")

    rows = []
    for it in items:
        url = it.get("url") or it.get("URL")
        if not url:
            continue

        time_usec = it.get("time_usec") or it.get("timeUsec") or it.get("time")
        ts = ""
        if time_usec is not None:
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
        raise ValueError("Data history kosong.")
    return df


def txt_to_df(file_bytes: bytes) -> pd.DataFrame:
    text = file_bytes.decode("utf-8", errors="ignore")
    urls = []
    for line in text.splitlines():
        u = line.strip()
        if not u or u.startswith("#"):
            continue
        urls.append(u)
    return pd.DataFrame(
        {"timestamp": ["" for _ in urls], "url": urls, "title": ["" for _ in urls], "visit_count": [1 for _ in urls]}
    )


# -----------------------------
# Feature extraction (heuristic)
# -----------------------------
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
LOGIN_KEYWORDS = ("login", "signin", "sign-in", "verify", "reset", "password", "account")
TRACKING_KEYS_EXACT = {"ref", "fbclid", "gclid", "yclid"}


def is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def looks_typo(domain: str) -> bool:
    if re.search(r"[01357]", domain):
        return True
    if re.search(r"(.)\1\1", domain):
        return True
    return False


def normalize_root_domain(url: str) -> str:
    """
    Ambil registered/root domain (contoh: sub.a.google.com -> google.com)
    """
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass

    # fallback
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        return (p.hostname or "").lower()
    except Exception:
        return ""


def extract_features(url: str, do_probe: bool) -> dict:
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    q = parse_qs(parsed.query)
    qkeys = set(k.lower() for k in q.keys())

    ext = tldextract.extract(url)
    reg_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
    root_domain = normalize_root_domain(url)

    tracking = 0
    for k in qkeys:
        if k.startswith("utm_") or k in TRACKING_KEYS_EXACT:
            tracking += 1

    has_login = any(k in path or k in (parsed.query or "").lower() for k in LOGIN_KEYWORDS)

    feats = {
        "url": url,
        "host": host,
        "reg_domain": (reg_domain or "").lower(),
        "root_domain": (root_domain or "").lower(),
        "is_https": scheme == "https",
        "is_ip_host": is_ip(host) if host else False,
        "is_shortener": (reg_domain or "").lower() in SHORTENERS,
        "tracking_params": tracking,
        "typo_like": looks_typo(ext.domain),
        "url_len": len(url),
        "has_login_keywords": has_login,
        "redirect_count": None,
    }

    if do_probe:
        try:
            r = requests.get(url, timeout=3, allow_redirects=True, headers={"User-Agent": "RiskScoringTool/1.0"})
            feats["redirect_count"] = len(r.history)
        except Exception:
            feats["redirect_count"] = None

    return feats


# -----------------------------
# Scoring
# -----------------------------
WEIGHTS = {
    "http_not_https": 15,
    "http_login": 25,
    "ip_host": 20,
    "shortener": 10,
    "redirect_many": 10,
    "tracking_params": 3,
    "typo_like": 10,
    "very_long_url": 5,

    # VirusTotal tambahan
    "vt_url_unsafe": 40,
    "vt_url_suspicious": 20,
    "vt_ip_unsafe": 30,
    "vt_ip_suspicious": 15,
}


def score_one(feats: dict) -> tuple[int, list[str], bool, int]:
    """
    Return: (score, reasons, fatal, vt_score_added)
    """
    s = 0
    reasons = []
    fatal = False
    vt_added = 0

    # --- Heuristik ---
    if not feats["is_https"]:
        s += WEIGHTS["http_not_https"]
        reasons.append(f"HTTP tanpa HTTPS (+{WEIGHTS['http_not_https']})")
        if feats["has_login_keywords"]:
            s += WEIGHTS["http_login"]
            reasons.append(f"HTTP pada halaman login/verify (+{WEIGHTS['http_login']})")
            fatal = True

    if feats["is_ip_host"]:
        s += WEIGHTS["ip_host"]
        reasons.append(f"Host berupa IP (+{WEIGHTS['ip_host']})")
        fatal = True

    if feats["is_shortener"]:
        s += WEIGHTS["shortener"]
        reasons.append(f"URL shortener (+{WEIGHTS['shortener']})")

    rc = feats["redirect_count"]
    if isinstance(rc, int) and rc > 2:
        s += WEIGHTS["redirect_many"]
        reasons.append(f"Redirect >2 ({rc}) (+{WEIGHTS['redirect_many']})")

    tp = int(feats["tracking_params"] or 0)
    if tp > 0:
        add = tp * WEIGHTS["tracking_params"]
        s += add
        reasons.append(f"Tracking params {tp} (+{add})")

    if feats["typo_like"]:
        s += WEIGHTS["typo_like"]
        reasons.append(f"Domain typo-like (+{WEIGHTS['typo_like']})")

    if feats["url_len"] >= 160:
        s += WEIGHTS["very_long_url"]
        reasons.append(f"URL sangat panjang (+{WEIGHTS['very_long_url']})")

    # --- VirusTotal rules ---
    vt_url_verdict = feats.get("vt_url_verdict")
    vt_url_mal = int(feats.get("vt_url_malicious") or 0)
    vt_url_susp = int(feats.get("vt_url_suspicious") or 0)

    if vt_url_verdict == "unsafe" or vt_url_mal > 0:
        s += WEIGHTS["vt_url_unsafe"]
        vt_added += WEIGHTS["vt_url_unsafe"]
        reasons.append(f"VirusTotal URL: malicious={vt_url_mal} (+{WEIGHTS['vt_url_unsafe']})")
        fatal = True
    elif vt_url_verdict == "suspicious" or vt_url_susp > 0:
        s += WEIGHTS["vt_url_suspicious"]
        vt_added += WEIGHTS["vt_url_suspicious"]
        reasons.append(f"VirusTotal URL: suspicious={vt_url_susp} (+{WEIGHTS['vt_url_suspicious']})")
    elif vt_url_verdict == "safe":
        reasons.append("VirusTotal URL: safe (+0)")
    elif vt_url_verdict in ("unknown", "error") and vt_url_verdict is not None:
        reasons.append(f"VirusTotal URL: {vt_url_verdict} (+0)")

    vt_ip_verdict = feats.get("vt_ip_verdict")
    vt_ip_mal = int(feats.get("vt_ip_malicious") or 0)
    vt_ip_susp = int(feats.get("vt_ip_suspicious") or 0)

    if vt_ip_verdict == "unsafe" or vt_ip_mal > 0:
        s += WEIGHTS["vt_ip_unsafe"]
        vt_added += WEIGHTS["vt_ip_unsafe"]
        reasons.append(f"VirusTotal IP: malicious={vt_ip_mal} (+{WEIGHTS['vt_ip_unsafe']})")
        fatal = True
    elif vt_ip_verdict == "suspicious" or vt_ip_susp > 0:
        s += WEIGHTS["vt_ip_suspicious"]
        vt_added += WEIGHTS["vt_ip_suspicious"]
        reasons.append(f"VirusTotal IP: suspicious={vt_ip_susp} (+{WEIGHTS['vt_ip_suspicious']})")
    elif vt_ip_verdict == "safe":
        reasons.append("VirusTotal IP: safe (+0)")
    elif vt_ip_verdict in ("unknown", "error") and vt_ip_verdict is not None:
        reasons.append(f"VirusTotal IP: {vt_ip_verdict} (+0)")

    s = min(100, s)
    return s, reasons, fatal, vt_added


# -----------------------------
# Action Recommendation
# -----------------------------
def build_recommendations(summary: dict, top_reasons: list[dict]) -> list[str]:
    recs = []

    total = max(1, int(summary.get("total_urls") or 1))
    fatal = int(summary.get("fatal_events") or 0)
    http_count = int(summary.get("http_count") or 0)
    shortener_count = int(summary.get("shortener_count") or 0)

    if fatal > 0:
        recs.append("Periksa ulang URL fatal, lakukan edukasi phishing & kebiasaan verifikasi link.")

    if http_count / total >= 0.10:
        recs.append("Aktifkan HTTPS-only mode dan hindari akses situs HTTP.")

    if shortener_count / total >= 0.05:
        recs.append("Kurangi klik URL shortener; gunakan preview/expand link sebelum membuka.")

    # jika ada alasan VT malicious
    for tr in top_reasons:
        r = (tr.get("reason") or "").lower()
        if "virustotal url: malicious" in r or "virustotal ip: malicious" in r:
            recs.append("Lakukan pemindaian perangkat (antivirus/EDR) karena ada indikasi URL berbahaya.")

    if not recs:
        recs.append("Kebiasaan browsing relatif aman. Pertahankan praktik keamanan digital yang baik.")

    # dedup
    out = []
    for x in recs:
        if x not in out:
            out.append(x)
    return out


# -----------------------------
# Analyze
# -----------------------------
def analyze(
    df: pd.DataFrame,
    do_probe: bool,
    limit: int,
    enable_vt: bool,
    vt_api_key: str,
    vt_submit_missing: bool,
    vt_check_ip_host: bool,
    whitelist_domains: set[str],
) -> dict:
    if limit > 0:
        df = df.head(limit)

    urls = df["url"].astype(str).tolist()

    # --- VT scanning (dedup + cache) ---
    url_vt_map = {}
    ip_vt_map = {}

    if enable_vt:
        if "vt_url_cache" not in st.session_state:
            st.session_state.vt_url_cache = {}
        if "vt_ip_cache" not in st.session_state:
            st.session_state.vt_ip_cache = {}

        uniq_urls = list(dict.fromkeys(urls))
        progress = st.progress(0, text="VirusTotal: mulai scan URL unik...")

        total = max(1, len(uniq_urls))
        done = 0

        for u in uniq_urls:
            if u in st.session_state.vt_url_cache:
                url_vt_map[u] = st.session_state.vt_url_cache[u]
            else:
                res = vt_check_url(u, api_key=vt_api_key, submit_if_missing=vt_submit_missing)
                st.session_state.vt_url_cache[u] = res
                url_vt_map[u] = res

            done += 1
            progress.progress(int(done / total * 100), text=f"VirusTotal: scan URL {done}/{total}")

        progress.empty()

        if vt_check_ip_host:
            ip_hosts = []
            for u in uniq_urls:
                try:
                    p = urlparse(u if "://" in u else "http://" + u)
                    h = (p.hostname or "").strip()
                    if h and is_ip(h):
                        ip_hosts.append(h)
                except Exception:
                    continue

            ip_hosts = list(dict.fromkeys(ip_hosts))
            if ip_hosts:
                progress2 = st.progress(0, text="VirusTotal: mulai scan IP host...")
                total2 = max(1, len(ip_hosts))
                done2 = 0

                for ip in ip_hosts:
                    if ip in st.session_state.vt_ip_cache:
                        ip_vt_map[ip] = st.session_state.vt_ip_cache[ip]
                    else:
                        res = vt_check_ip(ip, api_key=vt_api_key)
                        st.session_state.vt_ip_cache[ip] = res
                        ip_vt_map[ip] = res

                    done2 += 1
                    progress2.progress(int(done2 / total2 * 100), text=f"VirusTotal: scan IP {done2}/{total2}")

                progress2.empty()

    # --- Scoring per URL ---
    items = []
    for url in urls:
        feats = extract_features(url, do_probe=do_probe)

        # whitelist?
        feats["is_whitelisted"] = feats.get("root_domain") in whitelist_domains

        # inject VT URL result
        if enable_vt:
            ures = url_vt_map.get(url)
            if ures:
                feats["vt_url_verdict"] = ures.get("verdict")
                feats["vt_url_malicious"] = ures.get("malicious", 0)
                feats["vt_url_suspicious"] = ures.get("suspicious", 0)
            else:
                feats["vt_url_verdict"] = "unknown"

            # inject VT IP result jika host adalah IP dan opsi aktif
            if vt_check_ip_host and feats.get("is_ip_host") and feats.get("host"):
                ires = ip_vt_map.get(feats["host"])
                if ires:
                    feats["vt_ip_verdict"] = ires.get("verdict")
                    feats["vt_ip_malicious"] = ires.get("malicious", 0)
                    feats["vt_ip_suspicious"] = ires.get("suspicious", 0)
                else:
                    feats["vt_ip_verdict"] = "unknown"

        score, reasons, fatal, vt_added = score_one(feats)

        # Jika whitelisted: kurangi bias (skor turun 80%, fatal dinonaktifkan)
        if feats["is_whitelisted"]:
            score = int(round(score * 0.2))
            reasons.append("Whitelisted domain (score dikurangi 80%) (+0)")
            fatal = False

        items.append(
            {
                "url": url,
                "domain": feats.get("root_domain"),
                "score": score,
                "fatal": fatal,
                "whitelisted": feats["is_whitelisted"],
                "vt_url_verdict": feats.get("vt_url_verdict") if enable_vt else None,
                "vt_url_malicious": int(feats.get("vt_url_malicious") or 0) if enable_vt else None,
                "vt_url_suspicious": int(feats.get("vt_url_suspicious") or 0) if enable_vt else None,
                "vt_ip_verdict": feats.get("vt_ip_verdict") if enable_vt and vt_check_ip_host else None,
                "vt_ip_malicious": int(feats.get("vt_ip_malicious") or 0) if enable_vt and vt_check_ip_host else None,
                "vt_ip_suspicious": int(feats.get("vt_ip_suspicious") or 0) if enable_vt and vt_check_ip_host else None,
                "vt_score_added": vt_added if enable_vt else 0,
                "reasons": reasons,
            }
        )

    avg_url = sum(i["score"] for i in items) / max(1, len(items))
    fatal_count = sum(1 for i in items if i["fatal"])

    http_count = sum(1 for i in items if any("HTTP" in r for r in i["reasons"]))
    shortener_count = sum(1 for i in items if any("shortener" in r.lower() for r in i["reasons"]))

    habit_risk = min(100, (shortener_count / len(items)) * 40 + (http_count / len(items)) * 40 + fatal_count * 10)
    final = int(round(min(100, max(0, 0.6 * avg_url + 0.4 * habit_risk))))
    level = "Low" if final < 25 else "Medium" if final < 50 else "High" if final < 75 else "Critical"

    # Top reasons
    reason_count = {}
    for i in items:
        for r in i["reasons"]:
            reason_count[r] = reason_count.get(r, 0) + 1
    top = sorted(reason_count.items(), key=lambda x: x[1], reverse=True)[:5]
    top_reasons = [{"reason": r, "count": c} for r, c in top]

    # Recommendations
    recommendations = build_recommendations(
        summary={
            "total_urls": len(items),
            "fatal_events": fatal_count,
            "http_count": http_count,
            "shortener_count": shortener_count,
        },
        top_reasons=top_reasons,
    )

    return {
        "final_score": final,
        "level": level,
        "summary": {
            "total_urls": len(items),
            "avg_url_risk": round(avg_url, 2),
            "habit_risk": round(habit_risk, 2),
            "fatal_events": fatal_count,
            "http_count": http_count,
            "shortener_count": shortener_count,
            "vt_enabled": bool(enable_vt),
            "whitelist_domains_count": len(whitelist_domains),
        },
        "recommendations": recommendations,
        "top_reasons": top_reasons,
        "items": items,
    }


# -----------------------------
# Streamlit UI (session_state)
# -----------------------------
st.set_page_config(page_title="Human Risk Scoring", layout="wide")
st.title("Human Risk Scoring Tool")
st.write("Upload history Chrome (Google Takeout **BrowserHistory.json**) atau **CSV/TXT**, lalu tool akan menghitung skor kelalaian 0–100.")

# state untuk mencegah hasil hilang saat widget berubah (rerun)
if "df" not in st.session_state:
    st.session_state.df = None
if "result" not in st.session_state:
    st.session_state.result = None
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
if "file_name" not in st.session_state:
    st.session_state.file_name = None

with st.sidebar:
    st.header("Pengaturan")

    st.subheader("Profil Pengguna")
    person_name = st.text_input("Nama pengguna", value="User 1", key="person_name")

    st.divider()

    do_probe = st.checkbox("Aktifkan HTTP probe (cek redirect)", value=False, key="do_probe")
    limit = st.number_input("Limit URL diproses (0 = semua)", min_value=0, max_value=20000, value=500, step=100, key="limit")

    st.divider()

    # Whitelist read-only
    st.subheader("Whitelist Domain Aman (Read-only)")
    st.caption("Whitelist digunakan otomatis untuk mengurangi bias scoring. Pengguna tidak dapat mengubah daftar ini.")
    whitelist_domains = set(d.strip().lower() for d in WHITELIST_DOMAINS_DEFAULT if d.strip())
    st.code("\n".join(sorted(whitelist_domains)))

    st.divider()

    st.subheader("VirusTotal")
    enable_vt = st.checkbox("Aktifkan VirusTotal saat Analyze", value=False, key="enable_vt")
    vt_submit_missing = st.checkbox("Submit scan jika belum ada report (lebih lambat/boros)", value=False, key="vt_submit_missing")
    vt_check_ip_host = st.checkbox("Cek IP host jika URL memakai IP", value=False, key="vt_check_ip_host")

    default_key = os.getenv("VT_API_KEY", "")
    vt_api_key = st.text_input("VT API Key (kosong = pakai env VT_API_KEY)", value="", type="password", key="vt_api_key_input")
    vt_api_key_effective = vt_api_key.strip() if vt_api_key.strip() else default_key

    st.divider()
    if st.button("Reset", key="reset_btn"):
        st.session_state.df = None
        st.session_state.result = None
        st.session_state.analyzed = False
        st.session_state.file_name = None
        if "vt_url_cache" in st.session_state:
            del st.session_state["vt_url_cache"]
        if "vt_ip_cache" in st.session_state:
            del st.session_state["vt_ip_cache"]
        st.rerun()

uploaded = st.file_uploader("Upload file history (BrowserHistory.json / CSV / TXT)", type=["json", "csv", "txt", "log"])

# load df ketika upload baru
if uploaded is not None:
    if st.session_state.file_name != uploaded.name:
        st.session_state.file_name = uploaded.name
        st.session_state.result = None
        st.session_state.analyzed = False

        try:
            file_bytes = uploaded.getvalue()
            if uploaded.name.lower().endswith(".json"):
                df = takeout_json_to_df(file_bytes)
            elif uploaded.name.lower().endswith(".csv"):
                df = pd.read_csv(io.BytesIO(file_bytes))
                if "url" not in df.columns:
                    st.error("CSV harus punya kolom 'url'.")
                    st.stop()
                for col, default in [("timestamp", ""), ("title", ""), ("visit_count", 1)]:
                    if col not in df.columns:
                        df[col] = default
            else:
                df = txt_to_df(file_bytes)

            st.session_state.df = df
        except Exception as e:
            st.error(f"Gagal memproses file: {e}")
            st.stop()

if st.session_state.df is None:
    st.info("Silakan upload file untuk mulai analisis.")
    st.stop()

st.subheader("Preview Data")
st.dataframe(st.session_state.df.head(20), use_container_width=True)

if st.button("Analyze", key="analyze_btn"):
    if enable_vt and not vt_api_key_effective:
        st.error("VirusTotal aktif, tapi API key kosong. Isi VT_API_KEY (env) atau input di sidebar.")
    else:
        with st.spinner("Menganalisis URL... (termasuk VirusTotal jika aktif)"):
            st.session_state.result = analyze(
                st.session_state.df,
                do_probe=do_probe,
                limit=int(limit),
                enable_vt=enable_vt,
                vt_api_key=vt_api_key_effective,
                vt_submit_missing=vt_submit_missing,
                vt_check_ip_host=vt_check_ip_host,
                whitelist_domains=whitelist_domains,
            )
            st.session_state.analyzed = True

if st.session_state.analyzed and st.session_state.result is not None:
    result = st.session_state.result

    st.subheader("Profil Risiko Pengguna")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Nama", person_name)
    c2.metric("Final Score", result["final_score"])
    c3.metric("Level", result["level"])
    c4.metric("Fatal Events", result["summary"]["fatal_events"])

    st.subheader("Ringkasan")
    st.json(result["summary"])

    st.subheader("Action Recommendations")
    for rec in result.get("recommendations", []):
        st.write(f"✅ {rec}")

    st.subheader("Top Reasons")
    st.table(result["top_reasons"])

    st.subheader("Hasil Analisis URL")
    results_df = pd.DataFrame(result["items"])

    # =========================
    # FILTER + FATAL ONLY
    # =========================
    st.markdown("### Filter")
    f1, f2, f3 = st.columns(3)

    with f1:
        fatal_only = st.checkbox("Fatal Only", value=False, key="fatal_only")
    with f2:
        min_score = st.slider("Min Score", min_value=0, max_value=100, value=0, step=5, key="min_score")
    with f3:
        hide_whitelist = st.checkbox("Sembunyikan Whitelist", value=True, key="hide_whitelist")

    filtered_df = results_df.copy()
    if fatal_only:
        filtered_df = filtered_df[filtered_df["fatal"] == True]
    if min_score > 0:
        filtered_df = filtered_df[filtered_df["score"] >= min_score]
    if hide_whitelist:
        filtered_df = filtered_df[filtered_df["whitelisted"] == False]

    st.caption(f"Menampilkan {len(filtered_df)} dari {len(results_df)} URL setelah filter.")

    view_mode = st.radio("Tampilkan:", ["Sampel 50", "Semua", "Custom", "Pagination"], horizontal=True, key="view_mode")

    if view_mode == "Sampel 50":
        st.dataframe(filtered_df.head(50), use_container_width=True, height=600)
    elif view_mode == "Semua":
        st.dataframe(filtered_df, use_container_width=True, height=600)
    elif view_mode == "Custom":
        max_rows = len(filtered_df)
        if max_rows == 0:
            st.info("Tidak ada data setelah filter.")
        else:
            n = st.number_input("Jumlah baris ditampilkan", min_value=1, max_value=max_rows, value=min(200, max_rows), step=50, key="custom_n")
            st.dataframe(filtered_df.head(int(n)), use_container_width=True, height=600)
    else:
        page_size = st.selectbox("Baris per halaman", [50, 100, 200, 500], index=1, key="page_size")
        total_rows = len(filtered_df)
        total_pages = max(1, (total_rows + page_size - 1) // page_size)
        page = st.number_input("Halaman", min_value=1, max_value=total_pages, value=1, key="page")
        start = (page - 1) * page_size
        end = start + page_size
        st.caption(f"Menampilkan baris {start + 1}–{min(end, total_rows)} dari {total_rows} (Hal {page}/{total_pages})")
        st.dataframe(filtered_df.iloc[start:end], use_container_width=True, height=600)

    # Download CSV + JSON (download hasil terfilter)
    csv_bytes = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button("Download hasil terfilter (CSV)", data=csv_bytes, file_name="url_results_filtered.csv", mime="text/csv", key="dl_csv")

    report_out = dict(result)
    report_out["person_name"] = person_name
    report_json = json.dumps(report_out, ensure_ascii=False, indent=2).encode("utf-8")
    st.download_button("Download Report JSON", data=report_json, file_name="report.json", mime="application/json", key="dl_json")

else:
    st.info("Klik **Analyze** untuk melihat hasil.")
