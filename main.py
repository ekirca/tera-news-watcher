import os
from datetime import datetime, timedelta, timezone

import requests
import feedparser
from email.utils import parsedate_to_datetime
from flask import Flask, jsonify, request

# ==========================
# Ortam değişkenleri
# ==========================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# Türkiye saati için UTC+3 (Render UTC çalışıyor)
TZ_OFFSET_HOURS = int(os.getenv("TZ_OFFSET_HOURS", "3"))
LOCAL_TZ = timezone(timedelta(hours=TZ_OFFSET_HOURS))

# Cron güvenlik token'i (cron-job.org URL'inde ?token=TERA1234 kullanıyorsun)
CRON_TOKEN = os.getenv("RESTART_TOKEN", "").strip()

# Seen ID dosyası (aynı haberi tekrar yollamamak için)
SEEN_FILE = "seen_ids.txt"

# Hata spam'ini engellemek için
LAST_ERROR_TIME = None
ERROR_COOLDOWN_MIN = 30

# "Bugün haber yok" mesajını saat başı en fazla 1 kez atmak için
LAST_NO_NEWS_TAG = None

# ==========================
# RSS kaynakları
# ==========================
RSS_FEEDS = [
    {
        "name": "Tera",
        "url": "https://news.google.com/rss/search?q=%22Tera%20Yat%C4%B1r%C4%B1m%22&hl=tr&gl=TR&ceid=TR:tr",
    },
    {
        "name": "Tera Yatırım",
        "url": "https://news.google.com/rss/search?q=Tera%20Yat%C4%B1r%C4%B1m&hl=tr&gl=TR&ceid=TR:tr",
    },
    {
        "name": "TEHOL",
        "url": "https://news.google.com/rss/search?q=TEHOL&hl=tr&gl=TR&ceid=TR:tr",
    },
    {
        "name": "TLY",
        "url": "https://news.google.com/rss/search?q=TLY&hl=tr&gl=TR&ceid=TR:tr",
    },
    {
        "name": "Tera Şirketleri",
        "url": "https://news.google.com/rss/search?q=%22Tera%20Yat%C4%B1r%C4%B1m%20Menkul%22&hl=tr&gl=TR&ceid=TR:tr",
    },
    {
        "name": "FSU",
        "url": "https://news.google.com/rss/search?q=FSU&hl=tr&gl=TR&ceid=TR:tr",
    },
]

# ==========================
# Yardımcı fonksiyonlar
# ==========================


def debug(*args):
    print(*args, flush=True)


def parse_date(date_str: str, tz: timezone) -> datetime:
    """
    Google News'ten gelen pubDate/published alanlarını sağlam bir şekilde
    datetime'e çevir. Hata olursa şu anki zamanı döner.
    """
    if not date_str:
        return datetime.now(tz)

    # 1) email.utils parser
    try:
        dt = parsedate_to_datetime(date_str)
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(tz)
    except Exception:
        pass

    # 2) Farklı olası format denemeleri
    formats = [
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(tz)
        except Exception:
            continue

    # 3) En son çare
    return datetime.now(tz)


def load_seen_ids() -> set:
    try:
        with open(SEEN_FILE, "r", encoding="utf-8") as f:
            ids = {line.strip() for line in f if line.strip()}
        return ids
    except FileNotFoundError:
        return set()
    except Exception as e:
        debug("Seen dosyası okunamadı:", e)
        return set()


def save_seen_ids(ids: set) -> None:
    try:
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            for _id in ids:
                f.write(_id + "\n")
    except Exception as e:
        debug("Seen dosyası yazılamadı:", e)


def make_item_id(feed_name: str, entry) -> str:
    title = (entry.get("title") or "").strip()
    link = (entry.get("link") or "").strip()
    return f"{feed_name}|{title}|{link}"


def send_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        debug("TELEGRAM_BOT_TOKEN veya TELEGRAM_CHAT_ID yok, mesaj atılmadı.")
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
        }
        r = requests.post(url, data=data, timeout=20)
        debug("Telegram status:", r.status_code)
    except Exception as e:
        debug("Telegram error:", e)


def notify_error(msg: str) -> None:
    global LAST_ERROR_TIME
    now_utc = datetime.now(timezone.utc)
    if LAST_ERROR_TIME is not None:
        diff = (now_utc - LAST_ERROR_TIME).total_seconds()
        if diff < ERROR_COOLDOWN_MIN * 60:
            debug("ERROR (susturuldu):", msg)
            return
    LAST_ERROR_TIME = now_utc
    debug("ERROR:", msg)
    send_telegram(f"⚠️ Hata uyarısı:\n{msg}")


def send_no_news_if_needed(now_local: datetime) -> None:
    """
    Hafta içi 08:00–18:00 arasında, saat başı en fazla 1 kez
    'Bugün yeni haber yok' mesajı at.
    """
    global LAST_NO_NEWS_TAG

    weekday = now_local.weekday()  # 0 = Pazartesi
    hour = now_local.hour
    if weekday > 4:
        return
    if not (8 <= hour < 18):
        return

    tag = now_local.strftime("%Y-%m-%d %H")
    if LAST_NO_NEWS_TAG == tag:
        return

    text = f"📢 Bugün ({now_local.date()}) TERA ile ilgili yeni haber yok."
    send_telegram(text)
    LAST_NO_NEWS_TAG = tag


def fetch_feed_entries(url: str):
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        parsed = feedparser.parse(r.text)
        return parsed.entries
    except Exception as e:
        notify_error(f"RSS okunamadı: {url} -> {e}")
        return []


# ==========================
# Ana iş (job)
# ==========================


def job() -> int:
    """
    - RSS'leri çeker
    - Sadece bugünün haberlerini süzer
    - Daha önce gönderilmemiş olanları Telegram'a yollar
    - Yeni haber yoksa gerekli saatlerde 'haber yok' bildirimi atar
    """
    debug("===== JOB BAŞLADI =====")
    now_local = datetime.now(LOCAL_TZ)
    today = now_local.date()

    seen_ids = load_seen_ids()
    new_items = []

    for feed in RSS_FEEDS:
        name = feed["name"]
        url = feed["url"]
        entries = fetch_feed_entries(url)
        debug(f"[{name}] RSS item sayısı: {len(entries)}")

        for entry in entries:
            pub_raw = (
                entry.get("published")
                or entry.get("pubDate")
                or entry.get("updated")
                or ""
            )
            pub_dt = parse_date(pub_raw, LOCAL_TZ)
            if pub_dt.date() != today:
                continue

            _id = make_item_id(name, entry)
            if _id in seen_ids:
                continue

            new_items.append((pub_dt, name, entry, _id))

    # Tarihe göre sırala (eski → yeni)
    new_items.sort(key=lambda x: x[0])

    sent_count = 0
    for pub_dt, name, entry, _id in new_items:
        title = (entry.get("title") or "").strip()
        link = (entry.get("link") or "").strip()
        msg = (
            f"📰 <b>{name}</b>\n"
            f"{title}\n"
            f"{link}\n"
            f"({pub_dt.strftime('%Y-%m-%d %H:%M')})"
        )
        send_telegram(msg)
        seen_ids.add(_id)
        sent_count += 1

    if sent_count > 0:
        save_seen_ids(seen_ids)
        debug("Yeni haber sayısı:", sent_count)
    else:
        debug("Yeni haber yok.")
        send_no_news_if_needed(now_local)

    debug("===== JOB BİTTİ =====")
    return sent_count


# ==========================
# Flask endpoints
# ==========================

app = Flask(__name__)


@app.get("/")
def home():
    return "Alive", 200


@app.get("/health")
def health():
    now_utc = datetime.utcnow().isoformat()
    return jsonify({"ok": True, "time_utc": now_utc}), 200


@app.get("/cron")
def cron():
    token = request.args.get("token", "").strip()
    if CRON_TOKEN and token != CRON_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    try:
        cnt = job()
        return jsonify({"ok": True, "new_items": cnt}), 200
    except Exception as e:
        notify_error(f"/cron çalışırken hata: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/test")
def test_notification():
    send_telegram("✅ Test bildirimi: Sistem çalışıyor. (/test)")
    return jsonify({"ok": True}), 200


# ==========================
# Local çalıştırma
# ==========================

if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    debug(f"Flask başlıyor, port={port}")
    app.run(host="0.0.0.0", port=port)
