# -*- coding: utf-8 -*-
"""
Tera News Watcher — Sade CRON sürümü
- Haber taraması SADECE /cron endpoint'iyle tetiklenir (cron-job.org tarafından).
- İçeride schedule/poll yok; her tetiklemede tek sefer job() çalışır.
"""

import os
import time
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus, urlparse

import requests
from flask import Flask, jsonify, request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

import feedparser
import yaml

# =========================
# Ortam değişkenleri
# =========================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# Sadece log / saat hesabı için (Türkiye = 3)
TZ_OFFSET_HOURS = int(os.getenv("TZ_OFFSET_HOURS", "3"))

# /cron ve /restart için ortak token
RESTART_TOKEN = os.getenv("RESTART_TOKEN", "").strip()

# *** Domain filtresini kapatmak istersen: DISABLE_DOMAIN_FILTER=true ***
DISABLE_DOMAIN_FILTER = os.getenv("DISABLE_DOMAIN_FILTER", "false").lower() == "true"

# =========================
# Dosyalar
# =========================
SEEN_FILE   = "seen_ids.txt"
INIT_FILE   = ".initialized"
MAX_SEEN_IDS = 50000  # maksimum satır sayısı

# =========================
# Anahtar kelimeler & Şirket eşleşmesi
# =========================
KEYWORDS = [
    "tera", "tera yatırım", "tera yatirim",
    "tehol", "trhol", "tly", "tera şirketleri",
]

COMPANY_TOKENS = [
    # Holding / ana
    "tera yatırım", "tera yatırım menkul değerler", "tera yatırım menkul degerler",
    "tera yatırım menkul değerler a.ş", "tera yatırım menkul degerler a.s",
    # Finans
    "tera bank", "tera finans faktoring", "tera portföy", "tera girişim sermayesi",
    "kointra", "tera finansal yatırımlar holding",
    # Teknoloji
    "tera yatırım teknoloji holding", "barikat grup", "barikat",
    "tra bilişim", "tra bilisim",
    # Tarım / Su
    "viva terra hayvancılık", "viva terra su",
    # Hizmet
    "tera özel güvenlik",
    # Fon/ürün
    "tly fonu", "tera ly", "tera ly fonu",
]

BASE_KEYWORDS = [
    "tera", "tera yatirim", "tera yatırım", "tera yatırım menkul",
    "tera yatırım menkul değerler", "tera yatırım teknoloji holding",
    "tera finansal yatırımlar holding", "barikat", "tra bilisim",
    "tra bilişim", "viva terra",
]

# Domain beyaz liste (config.yaml ile birleşecek)
DEFAULT_ALLOWED_DOMAINS = [
    # büyük haber
    "hurriyet.com.tr", "milliyet.com.tr", "cnnturk.com", "ntv.com.tr",
    "bbc.com", "reuters.com", "bloomberg.com", "bloomberght.com",
    "aa.com.tr", "trthaber.com", "aljazeera.com",
    # ekonomi/finans
    "dunya.com", "ekonomim.com", "foreks.com", "investing.com",
    "ekoturk.com", "haberturk.com", "sozcu.com.tr", "sabah.com.tr",
    "t24.com.tr", "patronlardunyasi.com", "borsagundem.com.tr",
    "finansgundem.com", "bigpara.hurriyet.com.tr", "tr.investing.com",
    # resmi/kurumsal
    "kap.org.tr", "kamuyuaydinlatma.com",
]

# =========================
# Global durum
# =========================
LAST_JOB_TIME   = None
LAST_ERROR_TIME = None
ERROR_COOLDOWN_MIN = 30

JOB_LOCK = threading.Lock()

app = Flask(__name__)

# =========================
# Yardımcılar
# =========================

def debug(*a):
    print(*a, flush=True)

def normalize_text(s: str) -> str:
    table = str.maketrans("ÇçĞğİIıÖöŞşÜü", "ccggiiioossuu")
    return (s or "").translate(table).lower()

def matches_company(item: dict) -> bool:
    text = normalize_text((item.get("title","") + " " + item.get("desc","")))
    tokens = [normalize_text(k) for k in (COMPANY_TOKENS + BASE_KEYWORDS)]
    return any(tok in text for tok in tokens)

def send_telegram(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        debug("⚠️ TELEGRAM_BOT_TOKEN/CHAT_ID yok; mesaj atılmadı.")
        return
    try:
        u = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        r = requests.post(
            u,
            data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=15,
        )
        debug("Telegram status:", r.status_code)
    except Exception as e:
        debug("Telegram error:", e)

def notify_error(msg: str):
    global LAST_ERROR_TIME
    now = datetime.now(timezone.utc)
    if LAST_ERROR_TIME is None or (now - LAST_ERROR_TIME).total_seconds() > ERROR_COOLDOWN_MIN*60:
        send_telegram(f"⚠️ Hata uyarısı:\n{msg}")
        LAST_ERROR_TIME = now
    debug("ERROR:", msg)

def load_config() -> dict:
    try:
        with open("config.yaml", "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

CFG = load_config()
ALLOWED_DOMAINS = list(dict.fromkeys(DEFAULT_ALLOWED_DOMAINS + [
    *(CFG.get("domains_allow") or [])
]))

def domain_allowed(link: str) -> bool:
    if DISABLE_DOMAIN_FILTER:
        return True
    try:
        netloc = urlparse(link).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return any(netloc.endswith(d) for d in ALLOWED_DOMAINS)
    except Exception:
        return False

# =============== seen (sıralı + hızlı) ===============
def load_seen():
    if not os.path.exists(SEEN_FILE):
        return [], set()
    with open(SEEN_FILE, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    return lines, set(lines)

def save_seen(seen_list):
    if len(seen_list) > MAX_SEEN_IDS:
        seen_list = seen_list[-MAX_SEEN_IDS:]
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(seen_list))

# =============== RSS (Google News) ===============
def google_news_rss(query: str) -> str:
    q = quote_plus(query + " site:tr OR site:.com OR site:.com.tr")
    u = f"https://news.google.com/rss/search?q={q}&hl=tr&gl=TR&ceid=TR:tr"
    r = requests.get(u, timeout=30)
    r.raise_for_status()
    return r.text

def parse_rss(xml_text: str):
    root = ET.fromstring(xml_text)
    items = []
    for it in root.findall(".//item"):
        title = (it.findtext("title") or "").strip()
        link  = (it.findtext("link") or "").strip()
        guid  = (it.findtext("guid") or link or title).strip()
        pub   = (it.findtext("pubDate") or "").strip()
        desc  = (it.findtext("description") or "").strip()

        pub_dt = None
        if pub:
            try:
                dt = parsedate_to_datetime(pub)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
                pub_dt = dt
            except Exception:
                pub_dt = None

        items.append({
            "id": guid or link or title,
            "title": title,
            "link": link,
            "pub": pub,
            "pub_dt": pub_dt,
            "desc": desc,
        })
    return items

# =============== EXTRA SOURCES (config.yaml) ===============
def fetch_google_news_feed(query, lang="tr", region="TR", weight=0):
    params = {"q": query, "hl": lang, "gl": region, "ceid": f"{region}:{lang}"}
    url = "https://news.google.com/rss/search?" + requests.compat.urlencode(params)
    feed = feedparser.parse(url)
    out = []
    for e in feed.entries:
        ts = getattr(e, "published_parsed", None)
        published = datetime.fromtimestamp(time.mktime(ts), tz=timezone.utc) if ts else None
        out.append({
            "id": e.get("id") or e.get("link") or e.get("title"),
            "title": e.get("title", ""),
            "link": e.get("link", ""),
            "pub_dt": published,
            "desc": "",
            "weight": int(weight),
            "source": "google_news",
        })
    return out

def nitter_to_x(url: str) -> str:
    return url.replace("https://nitter.net/", "https://x.com/")

def fetch_x_user(users, nitter_base="https://nitter.net", weight=0):
    all_items = []
    headers = {"User-Agent": "Mozilla/5.0"}
    for u in users or []:
        rss = f"{nitter_base.rstrip('/')}/{u}/rss"
        try:
            r = requests.get(rss, timeout=15, headers=headers)
            r.raise_for_status()
            feed = feedparser.parse(r.text)
        except Exception:
            continue
        for e in feed.entries:
            ts = getattr(e, "published_parsed", None)
            published = datetime.fromtimestamp(time.mktime(ts), tz=timezone.utc) if ts else None
            all_items.append({
                "id": e.get("id") or e.get("link") or e.get("title"),
                "title": e.get("title", ""),
                "link": nitter_to_x(e.get("link", "")),
                "pub_dt": published,
                "desc": "",
                "weight": int(weight),
                "source": "x_user",
            })
    return all_items

def gather_extra_sources():
    items = []
    for src in (CFG.get("sources") or []):
        t = src.get("type")
        if t == "google_news":
            items.extend(fetch_google_news_feed(
                query  = src.get("query", "TERA YATIRIM"),
                lang   = src.get("lang", "tr"),
                region = src.get("region", "TR"),
                weight = src.get("weight", 0),
            ))
        elif t == "x_user":
            items.extend(fetch_x_user(
                users       = src.get("users", []),
                nitter_base = src.get("nitter_base", "https://nitter.net"),
                weight      = src.get("weight", 0),
            ))
    return items

# =============== Bootstrap ===============
def bootstrap():
    """İlk çalıştırmada seen_ids dosyasını doldurur."""
    seen_list, _ = load_seen()
    added = 0

    for kw in KEYWORDS:
        try:
            xml = google_news_rss(kw)
            for it in parse_rss(xml):
                if it["id"] not in seen_list:
                    seen_list.append(it["id"])
                    added += 1
        except Exception as e:
            debug("bootstrap err (kw):", kw, e)

    try:
        for it in gather_extra_sources():
            if it["id"] not in seen_list:
                seen_list.append(it["id"])
                added += 1
    except Exception as e:
        debug("bootstrap err (extra):", e)

    save_seen(seen_list)
    with open(INIT_FILE, "w", encoding="utf-8") as f:
        f.write(datetime.now(timezone.utc).isoformat())
    debug(f"✅ İlk kurulum tamam: {added} mevcut haber işaretlendi.")

# =============== JOB ===============
def job():
    """Tek seferlik haber taraması. /cron tarafından çağrılır."""
    global LAST_JOB_TIME

    with JOB_LOCK:
        now_utc   = datetime.now(timezone.utc)
        local_time = now_utc + timedelta(hours=TZ_OFFSET_HOURS)
        today_utc = now_utc.date()

        debug("===== JOB BAŞLANGIÇ =====", now_utc.isoformat(), "local:", local_time.isoformat())

        seen_list, seen_set = load_seen()
        new_items = []

        # 1) Google News (kelime bazlı)
        for kw in KEYWORDS:
            try:
                debug(f"[{kw}] Google News RSS çekiliyor...")
                xml = google_news_rss(kw)
                items = parse_rss(xml)
                debug(f"[{kw}] RSS item sayısı:", len(items))
                for it in items:
                    if it["id"] in seen_set:
                        continue

                    # Sadece BUGÜN'ün haberleri
                    if it["pub_dt"] and it["pub_dt"].date() != today_utc:
                        continue

                    if not domain_allowed(it["link"]):
                        continue
                    if not matches_company(it):
                        continue
                    new_items.append(("KW", kw, it))
                    seen_set.add(it["id"])
                    seen_list.append(it["id"])
            except Exception as e:
                notify_error(f"{kw!r} kelimesi taranırken hata: {e}")

        # 2) Extra sources (config.yaml)
        try:
            extra = gather_extra_sources()
            for it in extra:
                try:
                    if it["id"] in seen_set:
                        continue
                    if it.get("pub_dt") and it["pub_dt"].date() != today_utc:
                        continue
                    if it.get("link") and not domain_allowed(it["link"]):
                        continue
                    if not matches_company(it):
                        continue
                    new_items.append((it.get("source", "EXT"), "", it))
                    seen_set.add(it["id"])
                    seen_list.append(it["id"])
                except Exception as ee:
                    notify_error(f"extra item error: {ee}")
        except Exception as e:
            notify_error(f"extra sources error: {e}")

        # Sonuç
        LAST_JOB_TIME = datetime.now(timezone.utc)

        if new_items:
            for src, kw, it in new_items:
                head = kw.upper() if kw else src.upper()
                pub_str = it.get("pub") or (it.get("pub_dt").isoformat() if it.get("pub_dt") else "")
                msg = f"📰 <b>{head}</b>\n{it.get('title','')}\n{it.get('link','')}\n{pub_str}"
                send_telegram(msg)

            save_seen(seen_list)
            debug(LAST_JOB_TIME, "-", len(new_items), "haber gönderildi.")
        else:
            debug(LAST_JOB_TIME, "- Yeni haber yok.")

            # Hafta içi 08:00–18:00 arası saat başı "haber yok"
            weekday = local_time.weekday()   # 0 = Pazartesi
            hour    = local_time.hour
            minute  = local_time.minute

            if (0 <= weekday <= 4) and (8 <= hour <= 18) and (minute == 0):
                today_local = local_time.date().isoformat()
                send_telegram(f"🟡 Bugün ({today_local}) TERA ile ilgili yeni haber yok.")

        debug("===== JOB BİTTİ =====")

# =============== Flask endpoints ===============
@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    now = datetime.now(timezone.utc)
    if LAST_JOB_TIME is None:
        ago = None
        last_iso = None
    else:
        ago = (now - LAST_JOB_TIME).total_seconds()
        last_iso = LAST_JOB_TIME.isoformat()
    return jsonify(ok=True, time=now.isoformat(), last_job=last_iso, last_job_ago_seconds=ago), 200

@app.get("/test")
def test_notification():
    send_telegram("🧪 Test bildirimi: TERA News Watcher çalışıyor gibi görünüyor.")
    return "Test bildirimi gönderildi.", 200

@app.get("/cron")
def cron_trigger():
    """Cron-job.org burayı çağıracak."""
    if RESTART_TOKEN and (request.args.get("token", "").strip() != RESTART_TOKEN):
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    debug("[CRON] çağrı alındı; job() arka planda çalıştırılacak.")
    threading.Thread(target=job, daemon=True).start()
    return jsonify({"ok": True, "message": "job triggered"}), 200

@app.get("/restart")
def restart():
    if RESTART_TOKEN and (request.args.get("token", "").strip() != RESTART_TOKEN):
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    debug("♻️ Self-restart istendi; 2 sn sonra çıkılacak…")
    def _do_exit():
        time.sleep(2)
        debug("Self-restart: process sonlandırılıyor.")
        os._exit(0)
    threading.Thread(target=_do_exit, daemon=True).start()
    return jsonify({"ok": True, "message": "restart scheduled"}), 200

# =============== Entry ===============
def main():
    if not os.path.exists(INIT_FILE):
        bootstrap()
    else:
        debug("INIT_FILE mevcut, bootstrap atlandı.")

    port = int(os.environ.get("PORT", "10000"))
    debug(f"🌐 Flask başlıyor, port={port}")
    app.run(host="0.0.0.0", port=port)

if __name__ == "__main__":
    main()
