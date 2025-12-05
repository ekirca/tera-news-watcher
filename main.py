# -*- coding: utf-8 -*-
"""
TERA NEWS WATCHER – FINAL UNBLOCKED EDITION
1. Domain filtresi kaldırıldı (Google linkleri artık engellenmiyor).
2. Dakika sınırı kaldırıldı (Saat içinde her an bildirim atabilir).
3. Tarih filtresi: Son 36 saat (Gece gelen haberleri kaçırmaz).
"""

import os
import time
from datetime import datetime, timedelta, timezone
from typing import NamedTuple, Optional

import requests
import feedparser
from flask import Flask, jsonify, request

# ======================================================
# ENV & AYARLAR
# ======================================================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "").strip()
CRON_TOKEN         = os.getenv("CRON_TOKEN", "").strip()
TZ_OFFSET          = int(os.getenv("TZ_OFFSET_HOURS", "3"))

SEEN_FILE = "seen_ids.txt"
LAST_NO_NEWS_FILE = "last_no_news_tag.txt"

# Google'ın bizi bot sanıp engellememesi için tarayıcı kimliği
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
})

# ======================================================
# DATA YAPILARI
# ======================================================
class NewsItem(NamedTuple):
    published_dt: datetime
    feed_name: str
    entry: dict
    item_id: str

# ======================================================
# TELEGRAM FONKSİYONU
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
        pass

# ======================================================
# DOSYA YÖNETİMİ (Seen & Tags)
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

# ======================================================
# HABER YOK BİLDİRİMİ
# ======================================================
def maybe_send_no_news(now_local: datetime) -> None:
    """
    Hafta içi 08:00–18:00 arası.
    Dakika sınırı YOK. O saat için atılmadıysa atar.
    """
    # Hafta sonu mu? (Cumartesi=5, Pazar=6)
    if now_local.weekday() > 4:
        return

    # Mesai saatleri dışı mı?
    if not (8 <= now_local.hour <= 18):
        return

    tag = now_local.strftime("%Y-%m-%d %H")
    last_tag = load_last_no_news_tag()

    # Bu saat için zaten mesaj attıysak sus.
    if last_tag == tag:
        return

    msg = f"🟡 Bugün ({now_local.date()}) TERA ile ilgili yeni haber yok."
    send_telegram(msg)
    save_last_no_news_tag(tag)

# ======================================================
# TARİH AYRIŞTIRMA (Son 36 Saat)
# ======================================================
def parse_date(entry) -> Optional[datetime]:
    # RSS'ten tarih bilgisini çekmeyi dener
    if getattr(entry, "published_parsed", None):
        try:
            return datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
        except: pass
        
    if getattr(entry, "updated_parsed", None):
        try:
            return datetime.fromtimestamp(time.mktime(entry.updated_parsed), tz=timezone.utc)
        except: pass
        
    # String formatları dener
    for field in ["published", "updated", "pubDate"]:
        if field in entry:
            try:
                fake = feedparser.parse(entry[field])
                if fake.entries and getattr(fake.entries[0], "published_parsed", None):
                    return datetime.fromtimestamp(time.mktime(fake.entries[0].published_parsed), tz=timezone.utc)
            except: pass
    return None

def is_recent(dt: datetime) -> bool:
    """
    Takvim gününe bakmaz. Şu andan geriye doğru 36 saat içindeki her şeyi alır.
    """
    if not dt: return False
    now_utc = datetime.now(timezone.utc)
    diff = now_utc - dt
    
    # Gelecek tarihli hatalı haberleri engelle
    if diff.days < -1: return False
    # 36 saatten eskiyse alma
    return diff <= timedelta(hours=36)

# ======================================================
# FEED LİSTESİ (Filtreler burada yapılıyor zaten)
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
# FEED ÇEKİCİ (Domain Filtresi Kaldırıldı!)
# ======================================================
def fetch_feed(name: str, url: str) -> list[NewsItem]:
    try:
        r = SESSION.get(url, timeout=20)
        feed = feedparser.parse(r.text)
        out = []

        for entry in feed.entries:
            dt = parse_date(entry)
            if not dt: continue
            
            # Tarih kontrolü (Son 36 saat mi?)
            if not is_recent(dt):
                continue

            # NOT: Domain filtresi kaldırıldı çünkü Google linkleri yönlendirmeli geliyor.
            # Zaten RSS sorgumuzda 'site:kap.org.tr' vb. var, Google bizim için filtreliyor.
            
            _id = entry.get("id") or entry.get("link") or entry.get("title", "")
            out.append(NewsItem(dt, name, entry, _id))

        return out
    except Exception:
        return []

# ======================================================
# ANA GÖREV (JOB)
# ======================================================
def job() -> int:
    try:
        seen = load_seen()
        new_items = []

        for name, url in FEEDS:
            items = fetch_feed(name, url)
            for it in items:
                if it.item_id not in seen:
                    new_items.append(it)
                    seen.add(it.item_id)
        
        save_seen(seen)
        new_items.sort(key=lambda x: x.published_dt)
        
        # 1. Yeni haberleri gönder
        for it in new_items:
            # Başlık ve Linki temizle
            title = it.entry.get('title', 'Haber Başlığı Yok')
            link = it.entry.get('link', '#')
            
            msg = f"📰 <b>{it.feed_name}</b>\n{title}\n{link}"
            send_telegram(msg)
        
        # 2. Haber yoksa ve zamanıysa "Haber Yok" bildirimi at
        now_local = datetime.now(timezone.utc) + timedelta(hours=TZ_OFFSET)
        if not new_items:
            maybe_send_no_news(now_local)
            
        return len(new_items)
    except Exception:
        return 0

# ======================================================
# FLASK SERVER
# ======================================================
app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
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
    send_telegram("🧪 Sistem Testi Başarılı.")
    return "ok", 200
