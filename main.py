import os
import time
import threading
import requests
import feedparser

from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request

# ============================================================
# Ortam değişkenleri
# ============================================================

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
TZ_OFFSET_HOURS = int(os.getenv("TZ_OFFSET_HOURS", "3"))

CRON_TOKEN = os.getenv("CRON_TOKEN", "")
POLL_INTERVAL_MIN = int(os.getenv("POLL_INTERVAL_MIN", "5"))

# ============================================================
# Dosyalar
# ============================================================

SEEN_FILE = "seen_ids.txt"
INIT_FILE = "_initialized"
MAX_SEEN_IDS = 50000

# ============================================================
# Anahtar kelimeler
# ============================================================

KEYWORDS = [
    "tera", "tera yatırım", "tera yatırim",
    "tehol", "thlol", "tly", "tera şirketleri"
]

RSS_FEEDS = [
    "https://news.google.com/rss/search?q=tera+yat%C4%B1r%C4%B1m&hl=tr&gl=TR&ceid=TR:tr",
    "https://news.google.com/rss/search?q=tehol&hl=tr&gl=TR&ceid=TR:tr",
    "https://news.google.com/rss/search?q=tly&hl=tr&gl=TR&ceid=TR:tr"
]

# ============================================================
# Yardımcı fonksiyonlar
# ============================================================

def debug(*msg):
    print(*msg, flush=True)

def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()
    with open(SEEN_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f.readlines())

def save_seen(seen_set):
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        for item in list(seen_set)[-MAX_SEEN_IDS:]:
            f.write(item + "\n")

def send_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        debug("[Telegram] Token/ChatID eksik")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        r = requests.post(url, data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        }, timeout=15)
        debug("Telegram Status:", r.status_code)
    except Exception as e:
        debug("Telegram HATA:", e)

def is_match(text):
    t = text.lower()
    return any(k in t for k in KEYWORDS)

def parse_rss():
    items = []
    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            for e in feed.entries:
                title = e.get("title", "")
                link = e.get("link", "")
                pub = e.get("published", "")
                if title and is_match(title):
                    items.append({
                        "id": link or title,
                        "title": title,
                        "link": link,
                        "pub": pub
                    })
        except:
            pass
    return items

# ============================================================
# Haber kontrol işlevi
# ============================================================

def job():
    debug("===== JOB BAŞLADI =====")

    seen = load_seen()
    new_items = []

    items = parse_rss()

    for it in items:
        if it["id"] not in seen:
            seen.add(it["id"])
            new_items.append(it)

    if new_items:
        for it in new_items:
            msg = f"🟡 <b>{it['title']}</b>\n{it['link']}"
            send_telegram(msg)

        save_seen(seen)
        debug(f"{len(new_items)} yeni haber gönderildi.")
        debug("===== JOB BİTTİ =====")
        return len(new_items)

    # Hiç yeni haber yok → saat başı mesaj (08:00–18:00)
    now_tr = datetime.utcnow() + timedelta(hours=TZ_OFFSET_HOURS)
    if 8 <= now_tr.hour <= 18 and now_tr.minute == 0:
        today = now_tr.date().isoformat()
        send_telegram(f"🟡 Bugün ({today}) TERA ile ilgili yeni haber yok.")

    debug("Yeni haber yok.")
    debug("===== JOB BİTTİ =====")
    return 0


# ============================================================
# Flask Uygulaması
# ============================================================

app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    return "OK", 200

@app.get("/cron")
def cron_trigger():
    token = request.args.get("token", "")
    if CRON_TOKEN and token != CRON_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    debug("[cron] çağrıldı → arka planda job çalışacak...")
    threading.Thread(target=job, daemon=True).start()

    return jsonify({"ok": True, "message": "job started"}), 200


# ============================================================
# Uygulama başlatma
# ============================================================

if __name__ == "__main__":
    if not os.path.exists(INIT_FILE):
        with open(INIT_FILE, "w") as f:
            f.write("initialized")
        debug("İlk kurulum tamam – mevcut haberler işaretlendi.")

    port = int(os.getenv("PORT", "10000"))
    debug(f"Flask başlıyor, port={port}")
    app.run(host="0.0.0.0", port=port)
