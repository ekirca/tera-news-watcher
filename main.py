# -*- coding: utf-8 -*-
"""
Tera News Watcher — Telegram bildirim botu (Render-friendly)
- Google News RSS: anahtar kelimelere göre çek
- Filtreler: tekrar, zaman, domain whitelist, şirket eşleşmesi
- Yeni haberleri Telegram'a gönder
- / ve /health endpointleri (Uptime/monitoring)
- KEEPALIVE: Render free instance uykuya geçmesin diye periyodik self-ping
"""

import os
import time
import threading
import requests
import schedule
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib.parse import quote_plus, urlparse
from email.utils import parsedate_to_datetime
from flask import Flask, jsonify


# ========= Ayarlar / Env =========
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "").strip()
POLL_INTERVAL_MIN  = int(os.getenv("POLL_INTERVAL_MIN", "10"))  # tarama periyodu (dk)

# Render servis URL'ini KENDİ servisinle GÜNCELLE:
KEEPALIVE_URL = os.getenv("KEEPALIVE_URL", "https://tera-news-watcher.onrender.com/health")

# İlk çalıştırmada eski haberleri görmemek için zaman eşiği
START_TIME = datetime.utcnow() - timedelta(hours=24)

# Geliştirirken domain filtresini kapatmak istersen True yap
DISABLE_DOMAIN_FILTER = False

# Anahtar kelimeler
KEYWORDS = ["tera", "tehol", "trhol", "tly", "tera şirketleri"]

# Şirket eşleşmesi için tokenlar (küçük harf aranır)
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

SEEN_FILE = "seen_ids.txt"
INIT_FILE = ".initialized"

# Domain beyaz liste (netloc sondan eşleşir)
ALLOWED_DOMAINS = [
    # Büyük portallar
    "hurriyet.com.tr", "milliyet.com.tr", "cnnturk.com", "ntv.com.tr",
    "bbc.com", "reuters.com", "bloomberg.com", "bloomberght.com",
    "aa.com.tr", "trthaber.com", "aljazeera.com",
    # Ekonomi/teknoloji
    "dunya.com", "ekonomim.com", "foreks.com", "investing.com", "ekoturk.com",
    "webrazzi.com", "haberturk.com", "sozcu.com.tr", "sabah.com.tr", "t24.com.tr",
    "patronlardunyasi.com", "borsagundem.com.tr", "finansgundem.com",
    "bigpara.hurriyet.com.tr", "tr.investing.com",
    # Resmi
    "kap.org.tr", "kamuyuaydinlatma.com",
]

# ========= Yardımcılar =========
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

def matches_company(it: dict) -> bool:
    text = (it.get("title", "") + " " + it.get("desc", "")).lower()
    return any(tok in text for tok in COMPANY_TOKENS)

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
        link  = (it.findtext("link")  or "").strip()
        guid  = (it.findtext("guid")  or link).strip()
        pub   = (it.findtext("pubDate") or "").strip()
        desc  = (it.findtext("description") or "").strip()

        pub_dt = None
        if pub:
            try:
                pub_dt = parsedate_to_datetime(pub)
                pub_dt = (pub_dt if pub_dt.tzinfo is None
                          else pub_dt.astimezone(tz=None)).replace(tzinfo=None)
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

def load_seen() -> set:
    if not os.path.exists(SEEN_FILE):
        return set()
    with open(SEEN_FILE, "r", encoding="utf-8") as f:
        return set(l.strip() for l in f if l.strip())

def save_seen(seen: set):
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(seen))

def bootstrap():
    seen, added = load_seen(), 0
    for kw in KEYWORDS:
        try:
            xml = google_news_rss(kw)
            for it in parse_rss(xml):
                if it["id"] not in seen:
                    seen.add(it["id"]); added += 1
        except Exception as e:
            print("Bootstrap hata:", kw, e)
    save_seen(seen)
    with open(INIT_FILE, "w", encoding="utf-8") as f:
        f.write(datetime.utcnow().isoformat())
    print(f"✅ İlk kurulum tamam: {added} mevcut haber işaretlendi (bildirim yok).")

# ========= Ana iş (periyodik tarama) =========
def job():
    seen = load_seen()
    new  = []

    for kw in KEYWORDS:
        try:
            items = parse_rss(google_news_rss(kw))
            for it in items:
                if it["id"] in seen:
                    continue
                if it["pub_dt"] is not None and it["pub_dt"] < START_TIME:
                    continue
                if not domain_allowed(it["link"]):
                    continue
                if not matches_company(it):
                    continue
                new.append((kw, it))
                seen.add(it["id"])
        except Exception as e:
            print("Hata:", kw, e)

    if new:
        for kw, it in new:
            msg = f"📰 <b>{kw.upper()}</b>\n{it['title']}\n{it['link']}\n{it.get('pub') or ''}"
            send_telegram(msg)
        save_seen(seen)
        print(datetime.utcnow(), "-", len(new), "haber gönderildi.")
    else:
        print(datetime.utcnow(), "- Yeni haber yok.")

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

# ========= Keepalive (Render free uykuya karşı) =========
import requests, time

URL = "https://tera-news-watcher.onrender.com/health"

while True:
    try:
        r = requests.get(URL, timeout=30)
        print(f"{time.strftime('%H:%M:%S')} - {r.status_code}")
    except Exception as e:
        print(f"Hata: {e}")
    time.sleep(600)  # her 10 dakikada bir GET isteği


# ========= Flask (health/monitoring) =========
app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    return jsonify(ok=True, time=datetime.utcnow().isoformat()), 200


@app.route("/test", methods=["GET"])
def test_notification():
    message = "🧪 Test bildirimi: TERA test haberi bulundu!"
    send_telegram(message)   # <- burası önemli
    return "Test bildirimi gönderildi (Telegram’a bak 👀)", 200


# ========= Entry =========
# ========= Entry =========
def main():
    # İş planlayıcı (haber tarayıcı)
    threading.Thread(target=scheduler_thread, daemon=True).start()
    # Keepalive (isteğe bağlı, cron-job.org kullanıyorsak bile dursun)
    threading.Thread(target=keepalive, daemon=True).start()
    # Web (health + test endpointleri)
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

if __name__ == "__main__":
    main()

