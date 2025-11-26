# -*- coding: utf-8 -*-
"""
TERA NEWS WATCHER – FINAL ULTRA-STABLE MAIN.PY
Sadece bugünün haberlerini alır.
Sessiz, hafif, kararlı, bozulmaz sistem.
"""

import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from typing import NamedTuple
import requests
import feedparser
from flask import Flask, jsonify, request

# ======================================================
# ENV
# ======================================================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "").strip()
CRON_TOKEN         = os.getenv("CRON_TOKEN", "").strip()

TZ_OFFSET = int(os.getenv("TZ_OFFSET_HOURS", "3"))
SESSION = requests.Session()

SEEN_FILE = "seen_ids.txt"

# ======================================================
# NEWS STRUCTURE
# ======================================================
class NewsItem(NamedTuple):
    published_dt: datetime
    feed_name: str
    entry: dict
    item_id: str

# ======================================================
# SEND TELEGRAM
# ======================================================
def send_telegram(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        SESSION.post(url, data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        }, timeout=15)
    except:
        pass

# ======================================================
# SEEN SYSTEM
# ======================================================
def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()
    with open(SEEN_FILE, "r", encoding="utf-8") as f:
        return set(x.strip() for x in f if x.strip())

def save_seen(seen: set):
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        for _id in list(seen)[-50000:]:
            f.write(_id + "\n")

# ======================================================
# DATE PARSING (BUGÜN FİLTRESİ)
# ======================================================
def parse_date(entry) -> datetime | None:
    fields = ["published", "updated", "pubDate"]
    for field in fields:
        if field in entry:
            try:
                dt = feedparser.parse(entry[field]).entries[0].published_parsed
                if dt:
                    return datetime.fromtimestamp(time.mktime(dt), tz=timezone.utc)
            except:
                pass

    # fallback
    if "published_parsed" in entry and entry.published_parsed:
        return datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)

    return None

def is_today(dt: datetime) -> bool:
    if not dt:
        return False
    now = datetime.now(timezone.utc)
    local_dt = dt + timedelta(hours=TZ_OFFSET)
    local_today = (now + timedelta(hours=TZ_OFFSET)).date()
    return local_dt.date() == local_today

# ======================================================
# ALLOWED DOMAINS
# ======================================================
ALLOWED = {
    "kap.org.tr",
    "borsagundem.com",
    "bloomberght.com",
    "investing.com",
    "mynet.com",
    "bigpara.com",
    "terayatirim.com",
    "terayatirim.com.tr",
    "x.com",
    "twitter.com"
}

def domain_ok(link: str) -> bool:
    try:
        host = urlparse(link).hostname or ""
        return any(host.endswith(d) for d in ALLOWED)
    except:
        return False

# ======================================================
# FEED LIST
# ======================================================
FEEDS = [
    ("Tera Yatırım", "https://news.google.com/rss/search?q=Tera+Yatırım&hl=tr&gl=TR&ceid=TR:tr"),
    ("Tera Yatirim", "https://news.google.com/rss/search?q=Tera+Yatirim&hl=tr&gl=TR&ceid=TR:tr"),
    ("TEHOL",        "https://news.google.com/rss/search?q=TEHOL&hl=tr&gl=TR&ceid=TR:tr"),
    ("TRHOL",        "https://news.google.com/rss/search?q=TRHOL&hl=tr&gl=TR&ceid=TR:tr"),
    ("TLY",          "https://news.google.com/rss/search?q=TLY&hl=tr&gl=TR&ceid=TR:tr"),
    ("FSU",          "https://news.google.com/rss/search?q=FSU&hl=tr&gl=TR&ceid=TR:tr"),
]

# ======================================================
# FETCH FEED (STABLE)
# ======================================================
def fetch_feed(name: str, url: str):
    try:
        r = SESSION.get(url, timeout=20)
        feed = feedparser.parse(r.text)
        entries = []
        for entry in feed.entries:
            dt = parse_date(entry)
            if not dt or not is_today(dt):
                continue

            link = entry.get("link", "")
            if not domain_ok(link):
                continue

            _id = entry.get("id") or entry.get("link") or entry.get("title", "")
            entries.append(NewsItem(dt, name, entry, _id))
        return entries
    except:
        return []

# ======================================================
# JOB
# ======================================================
def job():
    seen = load_seen()
    new_items = []

    for name, url in FEEDS:
        items = fetch_feed(name, url)
        for it in items:
            if it.item_id not in seen:
                new_items.append(it)
                seen.add(it.item_id)

    save_seen(seen)

    # sort by date
    new_items.sort(key=lambda x: x.published_dt)

    # send new
    for it in new_items:
        msg = f"📰 <b>{it.feed_name}</b>\n{it.entry.get('title','')}\n{it.entry.get('link','')}"
        send_telegram(msg)

    # if no news at xx:00
    now_local = datetime.now(timezone.utc) + timedelta(hours=TZ_OFFSET)
    if not new_items:
        if now_local.weekday() < 5:  # hafta içi
            if 8 <= now_local.hour <= 18 and now_local.minute == 0:
                send_telegram(f"🟡 Bugün TERA ile ilgili yeni haber yok.")

    return len(new_items)

# ======================================================
# FLASK
# ======================================================
app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/cron")
def cron():
    token = request.args.get("token", "")
    if CRON_TOKEN and token != CRON_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    count = job()
    return jsonify({"ok": True, "new_items": count}), 200

@app.get("/test")
def test():
    send_telegram("🧪 Test bildirimi.")
    return "ok", 200

# ======================================================
# RUN
# ======================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
