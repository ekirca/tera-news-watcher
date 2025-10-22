# -*- coding: utf-8 -*-
"""
Tera News Watcher — Telegram bildirim botu
- Google News RSS'ten anahtar kelimelere göre haber çeker
- Filtreler: tekrar, zaman, domain beyaz liste, şirket eşleşmesi
- Yeni bulunanları Telegram kanalına yollar
- /, /health ve /debug endpointleri (uptime + teşhis)
"""
import os
import time
import threading
import requests
import schedule
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus, urlparse
from flask import Flask, jsonify
from email.utils import parsedate_to_datetime

# =========================
# AYARLAR / ENV
# =========================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "").strip()
POLL_INTERVAL_MIN  = int(os.getenv("POLL_INTERVAL_MIN", "10"))

# İlk çalıştırmada ve her taramada "eski haber" eşiği
# İstersen hızlı testte 6 saat yapabilirsin.
START_TIME = datetime.now(timezone.utc) - timedelta(hours=24)

# Geçici teşhis için domain filtresini devre dışı bırakmak istersen True yap
DISABLE_DOMAIN_FILTER = True

# Log detay seviyesi (teşhis için True)
DEBUG_VERBOSE = True

# Dosyalar
SEEN_FILE = "seen_ids.txt"
INIT_FILE = ".initialized"

# Anahtar kelimeler
KEYWORDS = ["tera", "tehol", "trhol", "tly", "tera şirketleri"]

# Eşleşme için şirket anahtarları
COMPANY_TOKENS = [
    # Finans
    "tera yatırım", "tera bank", "tera finans faktoring", "tera portföy",
    "tera girişim sermayesi", "kointra", "tera finansal yatırımlar holding",
    # Teknoloji
    "tera yatırım teknoloji holding", "barikat grup", "barikat", "tra bilişim",
    # Tarım / Su
    "viva terra hayvancılık", "viva terra su",
    # Hizmet
    "tera özel güvenlik",
    # Fon
    "tly fonu", "tera ly", "tera ly fonu"
]

# Domain beyaz liste (sondan eşleşir)
ALLOWED_DOMAINS = [
    # Büyük portallar
    "hurriyet.com.tr", "milliyet.com.tr", "cnnturk.com", "ntv.com.tr",
    "bbc.com", "reuters.com", "bloomberg.com", "bloomberght.com",
    "aa.com.tr", "anadoluajansi.com.tr", "trthaber.com", "aljazeera.com",
    # Ekonomi / teknoloji
    "dunya.com", "ekonomim.com", "foreks.com", "investing.com", "ekoturk.com",
    "webrazzi.com", "haberturk.com", "sozcu.com.tr", "sabah.com.tr",
    "t24.com.tr", "patronlardunyasi.com", "borsagundem.com.tr",
    "finansgundem.com", "bigpara.hurriyet.com.tr", "tr.investing.com",
    # Resmi
    "kap.org.tr", "kamuyuaydinlatma.com",
]

# =========================
# FLASK ÖNCE TANIMLANIR!
# =========================
app = Flask(__name__)

# /, /health, /debug endpoint'leri
@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    return jsonify(ok=True, time=datetime.now(timezone.utc).isoformat()), 200

_last_stats = {}  # /debug için son tarama istatistikleri

@app.get("/debug")
def debug_view():
    return jsonify(_last_stats), 200


# =========================
# YARDIMCI FONKSİYONLAR
# =========================
def _strip_html(s: str) -> str:
    if not s:
        return ""
    # basit HTML tag temizleme
    return re.sub(r"<[^>]+>", " ", s)

def _to_utc_naive(dt):
    if dt is None:
        return None
    # timezone aware ise UTC'ye çevirip tzinfo'yu kaldır
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt

def domain_allowed(link: str) -> bool:
    if DISABLE_DOMAIN_FILTER:
        return True
    try:
        netloc = urlparse(link).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        for d in ALLOWED_DOMAINS:
            if netloc.endswith(d):
                return True
        return False
    except Exception:
        return False

def matches_company(it) -> bool:
    # başlık + açıklama + link içinde arama (küçük harf)
    text = (it.get("title","") + " " + it.get("desc","") + " " + it.get("link","")).lower()
    tokens = [t.lower() for t in COMPANY_TOKENS] + ["tera", "tehol", "trhol", "tly", "tera yatırım"]
    return any(tok in text for tok in tokens)

def send_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
    try:
        r = requests.post(url, data=data, timeout=15)
        print("Telegram gönderildi:", r.status_code)
    except Exception as e:
        print("Telegram hata:", e)

def google_news_rss(query: str) -> str:
    # Türkçe sonuç + TR kaynaklarını da gör
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
        desc  = _strip_html(it.findtext("description") or "").strip()

        pub_dt = None
        if pub:
            try:
                pub_dt = _to_utc_naive(parsedate_to_datetime(pub))
            except Exception:
                pub_dt = None

        items.append({
            "id": guid or link or title,
            "title": title,
            "link": link,
            "pub": pub,
            "pub_dt": pub_dt,   # naive UTC
            "desc": desc,
        })
    return items

def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()
    with open(SEEN_FILE, "r", encoding="utf-8") as f:
        return set(l.strip() for l in f if l.strip())

def save_seen(seen: set):
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(seen))

def bootstrap():
    """İlk çalıştırmada mevcutları işaretler (bildirim yok)."""
    seen = load_seen()
    added = 0
    for kw in KEYWORDS:
        try:
            for it in parse_rss(google_news_rss(kw)):
                if it["id"] not in seen:
                    seen.add(it["id"]); added += 1
        except Exception as e:
            print("Bootstrap hata:", kw, e)
    save_seen(seen)
    with open(INIT_FILE, "w", encoding="utf-8") as f:
        f.write(datetime.now(timezone.utc).isoformat())
    print(f"✅ İlk kurulum tamam: {added} mevcut haber işaretlendi (bildirim yok).")


# =========================
# ANA İŞ — PERİYODİK TARAMA
# =========================
def job():
    global _last_stats
    seen = load_seen()
    new = []
    all_stats = {"run_utc": datetime.now(timezone.utc).isoformat(), "keywords": {}}

    for kw in KEYWORDS:
        stat = {
            "fetched": 0, "dup": 0, "time_drop": 0,
            "domain_drop": 0, "company_drop": 0, "accepted": 0,
            "samples_dropped": []
        }
        try:
            items = parse_rss(google_news_rss(kw))
            stat["fetched"] = len(items)

            for it in items:
                title = it["title"]; link = it["link"]; pubdt = it.get("pub_dt")

                # 1) tekrar
                if it["id"] in seen:
                    stat["dup"] += 1
                    continue

                # 2) zaman
                if pubdt is not None and pubdt < START_TIME.replace(tzinfo=None):
                    stat["time_drop"] += 1
                    if len(stat["samples_dropped"]) < 3:
                        stat["samples_dropped"].append({"why":"time", "t":title, "p":str(pubdt)})
                    continue

                # 3) domain
                if not domain_allowed(link):
                    stat["domain_drop"] += 1
                    if len(stat["samples_dropped"]) < 3:
                        stat["samples_dropped"].append({"why":"domain", "t":title, "link":link})
                    continue

                # 4) şirket eşleşmesi
                if not matches_company(it):
                    stat["company_drop"] += 1
                    if len(stat["samples_dropped"]) < 3:
                        stat["samples_dropped"].append({"why":"company", "t":title})
                    continue

                # kabul
                stat["accepted"] += 1
                new.append((kw, it))
                seen.add(it["id"])

        except Exception as e:
            print("Hata:", kw, e)

        all_stats["keywords"][kw] = stat

        if DEBUG_VERBOSE:
            print(f"[{kw}] fetched={stat['fetched']} dup={stat['dup']} "
                  f"time_drop={stat['time_drop']} domain_drop={stat['domain_drop']} "
                  f"company_drop={stat['company_drop']} accepted={stat['accepted']}")
            if stat["samples_dropped"]:
                print("  örnek redler:", stat["samples_dropped"])

    _last_stats = all_stats

    if new:
        for kw, it in new:
            msg = (
                f"📰 <b>{kw.upper()}</b>\n"
                f"{it['title']}\n{it['link']}\n{it.get('pub') or ''}"
            )
            send_telegram(msg)
        save_seen(seen)
        print(datetime.now(timezone.utc), "-", len(new), "haber gönderildi.")
    else:
        print(datetime.now(timezone.utc), "- Yeni haber yok.")


def scheduler_thread():
    booted_now = False
    if not os.path.exists(INIT_FILE):
        bootstrap()
        booted_now = True

    if booted_now:
        print("⏳ Başlangıç sessiz modu: ilk döngüde bildirim yok.")
        schedule.every(POLL_INTERVAL_MIN).minutes.do(job)
    else:
        job()
        schedule.every(POLL_INTERVAL_MIN).minutes.do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)

def main():
    # tarayıcı thread
    threading.Thread(target=scheduler_thread, daemon=True).start()
    # health server
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))

if __name__ == "__main__":
    main()
