# -*- coding: utf-8 -*-
"""
TERA NEWS WATCHER – FINAL ULTRA-STABLE MAIN.PY (DATE ENGINE + NO-NEWS TAG)
Sadece bugünün haberlerini çeker, eski haberi asla göndermez.
'Haber yok' mesajını saat içinde sadece bir kere yazar.
"""

import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from typing import NamedTuple, Optional

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
LAST_NO_NEWS_FILE = "last_no_news_tag.txt"

# ======================================================
# NEWS STRUCT
# ======================================================
class NewsItem(NamedTuple):
    published_dt: datetime
    feed_name: str
    entry: dict
    item_id: str

# ======================================================
# TELEGRAM
# ======================================================
def send_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        SESSION.post(
            url,
            data={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
            },
            timeout=15,
        )
    except Exception:
        # Telegram hatasına takılıp job çökmesin
        pass

# ======================================================
# SEEN SYSTEM
# ======================================================
def load_seen() -> set:
    if not os.path.exists(SEEN_FILE):
        return set()
    try:
        with open(SEEN_FILE, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception:
        return set()

def save_seen(seen: set) -> None:
    try:
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            for _id in list(seen)[-50000:]:
                f.write(_id + "\n")
    except Exception:
        pass

# ======================================================
# NO-NEWS TAG (sadece saat başına bir kez)
# ======================================================
def load_last_no_news_tag() -> Optional[str]:
    if not os.path.exists(LAST_NO_NEWS_FILE):
        return None
    try:
        with open(LAST_NO_NEWS_FILE, "r", encoding="utf-8") as f:
            tag = f.read().strip()
            return tag or None
    except Exception:
        return None

def save_last_no_news_tag(tag: str) -> None:
    try:
        with open(LAST_NO_NEWS_FILE, "w", encoding="utf-8") as f:
            f.write(tag)
    except Exception:
        pass

def maybe_send_no_news(now_local: datetime) -> None:
    """
    Hafta içi 08:00–18:00 arası, saat başladıktan sonra ilk 10 dakika içinde
    sadece bir kez 'Bugün yeni haber yok' mesajı gönderir.
    Cron 09:00, 09:01, 09:05 fark etmez; o saat için bir kez çalışması yeter.
    """
    # Hafta içi mi?
    if now_local.weekday() > 4:
        return

    # Saat aralığı 08–18 arası mı?
    if not (8 <= now_local.hour <= 18):
        return

    # Saat başına 10 dakikalık tolerans penceresi:
    if now_local.minute > 10:
        return

    tag = now_local.strftime("%Y-%m-%d %H")  # örn: "2025-11-26 09"
    last_tag = load_last_no_news_tag()

    if last_tag == tag:
        # Bu saat için daha önce mesaj atılmış
        return

    # Mesajı gönder ve tag'i kaydet
    msg = f"🟡 Bugün ({now_local.date()}) TERA ile ilgili yeni haber yok."
    send_telegram(msg)
    save_last_no_news_tag(tag)

# ======================================================
# ⭐ ADVANCED DATE PARSER
# ======================================================
def parse_date(entry) -> Optional[datetime]:
    """En güvenilir → en zayıf sırayla 4 katmanlı tarih çözümü."""

    # 1) published_parsed
    if getattr(entry, "published_parsed", None):
        try:
            return datetime.fromtimestamp(
                time.mktime(entry.published_parsed),
                tz=timezone.utc,
            )
        except Exception:
            pass

    # 2) updated_parsed
    if getattr(entry, "updated_parsed", None):
        try:
            return datetime.fromtimestamp(
                time.mktime(entry.updated_parsed),
                tz=timezone.utc,
            )
        except Exception:
            pass

    # 3) published / updated / pubDate string alanlarından parse etme
    for field in ["published", "updated", "pubDate"]:
        if field in entry:
            try:
                fake = feedparser.parse(entry[field])
                if fake.entries and getattr(fake.entries[0], "published_parsed", None):
                    return datetime.fromtimestamp(
                        time.mktime(fake.entries[0].published_parsed),
                        tz=timezone.utc,
                    )
            except Exception:
                pass

    # 4) hiçbir şey yok → tarihsiz haber → reddet
    return None

def is_today(dt: datetime) -> bool:
    if not dt:
        return False
    now_utc = datetime.now(timezone.utc)
    local_dt = dt + timedelta(hours=TZ_OFFSET)
    today_local = (now_utc + timedelta(hours=TZ_OFFSET)).date()
    return local_dt.date() == today_local

# ======================================================
# DOMAIN FILTER
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
    "twitter.com",
}

def domain_ok(link: str) -> bool:
    try:
        host = urlparse(link).hostname or ""
        return any(host.endswith(d) for d in ALLOWED)
    except Exception:
        return False

# ======================================================
# FEEDS
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
# FEED FETCHER
# ======================================================
def fetch_feed(name: str, url: str) -> list[NewsItem]:
    try:
        r = SESSION.get(url, timeout=20)
        feed = feedparser.parse(r.text)
        out: list[NewsItem] = []

        for entry in feed.entries:
            dt = parse_date(entry)
            if not dt:
                continue
            if not is_today(dt):
                continue

            link = entry.get("link", "")
            if not domain_ok(link):
                continue

            _id = entry.get("id") or entry.get("link") or entry.get("title", "")
            out.append(NewsItem(dt, name, entry, _id))

        return out
    except Exception:
        return []

# ======================================================
# JOB
# ======================================================
def job() -> int:
    seen = load_seen()
    new_items: list[NewsItem] = []

    for name, url in FEEDS:
        items = fetch_feed(name, url)
        for it in items:
            if it.item_id not in seen:
                new_items.append(it)
                seen.add(it.item_id)

    save_seen(seen)
    new_items.sort(key=lambda x: x.published_dt)

    # Yeni haberleri gönder
    for it in new_items:
        msg = f"📰 <b>{it.feed_name}</b>\n{it.entry.get('title','')}\n{it.entry.get('link','')}"
        send_telegram(msg)

    # Eğer haber yoksa → no-news mekanizmasına bırak
    now_local = datetime.now(timezone.utc) + timedelta(hours=TZ_OFFSET)
    if not new_items:
        maybe_send_no_news(now_local)

    return len(new_items)

# ======================================================
# FLASK
# ======================================================
app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    # UptimeRobot ve Render bu endpoint'i kontrol ediyor
    # Sadece 200 OK dönmesi yeterli
    return "ok", 200


@app.get("/cron")
def cron():
    t = request.args.get("token", "")
    if CRON_TOKEN and t != CRON_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    count = job()
    return jsonify({"ok": True, "new_items": count}), 200

@app.get("/test")
def test():
    send_telegram("🧪 Test bildirimi.")
    return "ok", 200

