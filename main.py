import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus
import requests
from flask import Flask, jsonify, request
import feedparser

# ===============================
# Ortam değişkenleri
# ===============================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

TZ_OFFSET_HOURS = int(os.getenv("TZ_OFFSET_HOURS", "3"))
LOCAL_TZ = timezone(timedelta(hours=TZ_OFFSET_HOURS))

SEEN_FILE = "seen_ids.txt"

# ===============================
# RSS Aramaları (7 adet)
# ===============================
SEARCH_TERMS = [
    "Tera Yatırım",
    "Tera Yatirim",
    "Tera Yatırım Menkul",
    "TERA",
    "TRY",
    "FSU",
    "tehol OR trhol OR tly"   # Tera şirketleri
]

BASE_URL = "https://news.google.com/rss/search?q={}&hl=tr&gl=TR&ceid=TR:tr"

# ===============================
# Telegram Gönderimi
# ===============================
def send_telegram(msg):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": msg, "disable_web_page_preview": False}
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print("Telegram Error:", e)

# ===============================
# seen_ids yükle/kaydet
# ===============================
def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()
    with open(SEEN_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f.readlines())

def save_seen(seen):
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        for s in seen:
            f.write(s + "\n")

# ===============================
# RSS Tarih Okuyucu (her formatı çözer)
# ===============================
def parse_date(entry):
    possible_fields = ["published", "pubDate", "updated", "dc:date"]

    for field in possible_fields:
        if field in entry:
            try:
                return datetime(*entry.parsed[field]).astimezone(LOCAL_TZ).date()
            except:
                try:
                    return datetime.fromisoformat(entry[field]).astimezone(LOCAL_TZ).date()
                except:
                    pass

    # feedparser'ın built-in parsed date
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        return datetime(*entry.published_parsed).astimezone(LOCAL_TZ).date()

    return None  # tarih bulunamazsa

# ===============================
# JOB: haberleri çek ve filtrele
# ===============================
def job():
    print("JOB BAŞLADI ====================")

    today = datetime.now(LOCAL_TZ).date()
    seen = load_seen()
    new_count = 0

    for term in SEARCH_TERMS:
        url = BASE_URL.format(quote_plus(term))
        print("RSS çekiliyor:", url)

        try:
            feed = feedparser.parse(url)
        except:
            continue

        for entry in feed.entries:

            link = entry.get("link")
            if not link or link in seen:
                continue

            # HABER TARİHİNİ OKU
            pub_date = parse_date(entry)
            if pub_date is None:
                continue

            # SADECE BUGÜN
            if pub_date != today:
                continue

            # NEW → Telegram
            title = entry.get("title", "")
            msg = f"🟡 {title}\n{link}\n({pub_date})"
            send_telegram(msg)

            seen.add(link)
            new_count += 1

    save_seen(seen)

    print("JOB BİTTİ — Yeni haber:", new_count)
    return new_count

# ===============================
# Flask server
# ===============================
app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    return "OK", 200

@app.get("/cron")
def cron():
    job()
    return jsonify({"status": "job executed"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
