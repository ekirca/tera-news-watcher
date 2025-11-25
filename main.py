import os
import time
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus

import requests
import feedparser
from email.utils import parsedate_to_datetime
from flask import Flask, jsonify, request

# ============================================================
# Ortam değişkenleri
# ============================================================

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# Türkiye saati için (UTC+3)
TZ_OFFSET_HOURS = int(os.getenv("TZ_OFFSET_HOURS", "3"))

# Cron güvenlik token'ı (cron-job.org linkinde kullandığın ile aynı olmalı)
CRON_TOKEN = os.getenv("CRON_TOKEN", "TERA1234").strip()

# Restart endpoint'i için token (cron-job.org 07:00 / 17:00 restart işlerinde kullanabilirsin)
RESTART_TOKEN = os.getenv("RESTART_TOKEN", "").strip()

# Hatalar için minimum tekrar süresi (dakika)
ERROR_COOLDOWN_MIN = int(os.getenv("ERROR_COOLDOWN_MIN", "5"))

# ============================================================
# Dosyalar ve global durum
# ============================================================

SEEN_FILE = "seen_ids.txt"
INIT_FILE = ".initialized"
MAX_SEEN_IDS = 50000

LAST_JOB_TIME = None
LAST_JOB_ITEMS = 0
LAST_JOB_ERROR = None
LAST_ERROR_TIME = datetime.min.replace(tzinfo=timezone.utc)

# ============================================================
# Arama anahtar kelimeleri
# ============================================================

KEYWORDS = [
    "tera yatırım",
    "Tera Yatırım",
    "TERA YATIRIM",
    "tera",
    "\"Tera Yatırım Menkul\"",
]

# ============================================================
# Yardımcı fonksiyonlar
# ============================================================


def debug(*args):
    """Log yazdır (Render loglarında görünsün diye)."""
    ts = datetime.now(timezone.utc).isoformat()
    print(ts, "-", *args, flush=True)


def get_local_now():
    """UTC + TZ_OFFSET_HOURS zamanını döner."""
    return datetime.now(timezone.utc) + timedelta(hours=TZ_OFFSET_HOURS)


def load_seen_ids():
    """Daha önce gönderilmiş haber ID'lerini dosyadan oku."""
    seen = set()
    if os.path.exists(SEEN_FILE):
        try:
            with open(SEEN_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        seen.add(line)
        except Exception as e:
            debug("SEEN_FILE okunurken hata:", e)
    return seen


def save_seen_ids(seen_ids):
    """Güncel görülen ID listesini dosyaya yaz."""
    try:
        # Çok büyümesin diye son MAX_SEEN_IDS kadarını saklayalım
        if len(seen_ids) > MAX_SEEN_IDS:
            seen_ids = set(list(seen_ids)[-MAX_SEEN_IDS:])
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            for sid in seen_ids:
                f.write(sid + "\n")
    except Exception as e:
        debug("SEEN_FILE yazılırken hata:", e)


def send_telegram(text: str):
    """Telegram'a mesaj gönder."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        debug("⚠ TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID yok; mesaj gönderilmedi.")
        return

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        r = requests.post(
            url,
            data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=20,
        )
        debug("Telegram status:", r.status_code)
    except Exception as e:
        debug("Telegram error:", e)


def notify_error(msg: str):
    """Hataları gereksiz yere spam yapmadan Telegram'a yolla."""
    global LAST_ERROR_TIME
    now = datetime.now(timezone.utc)
    if (now - LAST_ERROR_TIME).total_seconds() < ERROR_COOLDOWN_MIN * 60:
        # Çok sık hata geliyorsa, sustur
        debug("ERROR (susturulmuş):", msg)
        return
    LAST_ERROR_TIME = now
    debug("ERROR:", msg)
    send_telegram(f"⚠ Hata uyarısı:\n{msg}")


def google_news_rss(keyword: str):
    """Verilen kelime için Google News RSS URL'si."""
    q = quote_plus(keyword)
    # TR için feed
    return f"https://news.google.com/rss/search?q={q}&hl=tr&gl=TR&ceid=TR:tr"

def parse_pub_datetime(entry):
    """RSS entry içindeki tarihi (published/updated) yerel zamana (UTC+TZ_OFFSET_HOURS) çevirir."""
    try:
        if hasattr(entry, "published") and entry.published:
            dt = parsedate_to_datetime(entry.published)
        elif hasattr(entry, "updated") and entry.updated:
            dt = parsedate_to_datetime(entry.updated)
        else:
            return None

        # timezone yoksa UTC varsay
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        # Türkiye saatine çevir
        dt_local = dt + timedelta(hours=TZ_OFFSET_HOURS)
        return dt_local
    except Exception as e:
        debug("Tarih parse edilemedi:", e, getattr(entry, "published", ""))
        return None


def fetch_news():
    """Tüm anahtar kelimeler için, SADECE BUGÜN'e ait Google News RSS sonuçlarını döner."""
    items = []

    # Bugünün tarihi (Türkiye saatiyle)
    today_local = get_local_now().date()

    for kw in KEYWORDS:
        url = google_news_rss(kw)
        debug(f"[{kw}] Google News RSS çekiliyor:", url)
        try:
            d = feedparser.parse(url)
            for entry in d.entries:
                # Yayın tarihini oku ve yerel zamana çevir
                pub_dt_local = parse_pub_datetime(entry)
                if not pub_dt_local:
                    # Tarihi çözemiyorsak bu haberi atla (eski kalabalık gelmesin)
                    continue

                # SADECE bugünün haberleri
                if pub_dt_local.date() != today_local:
                    continue

                # ID yoksa linki ID olarak kullan
                item_id = getattr(entry, "id", None) or getattr(entry, "link", "")
                link = getattr(entry, "link", "")
                title = getattr(entry, "title", "").strip()

                # Publisher bilgisi bazı feed'lerde farklı oluyor
                source = ""
                if "source" in entry and getattr(entry.source, "title", None):
                    source = entry.source.title

                # Tarihi okunabilir string yapalım
                pub_str = pub_dt_local.strftime("%Y-%m-%d %H:%M")

                items.append(
                    {
                        "id": item_id,
                        "title": title,
                        "link": link,
                        "pub": pub_str,
                        "src": source,
                        "kw": kw,
                    }
                )
        except Exception as e:
            notify_error(f"RSS çekilirken hata ({kw}): {e}")
    return items


# ============================================================
# Ana iş (job)
# ============================================================


def job():
    """Tüm haber taraması + Telegram gönderimi."""

    global LAST_JOB_TIME, LAST_JOB_ITEMS, LAST_JOB_ERROR

    debug("===== JOB BAŞLANGIÇ =====")

    LAST_JOB_ERROR = None
    LAST_JOB_ITEMS = 0

    try:
        seen_ids = load_seen_ids()
        debug("Mevcut seen_ids sayısı:", len(seen_ids))

        all_items = fetch_news()

        new_items = []
        for it in all_items:
            item_id = it["id"]
            if not item_id:
                # ID yoksa linki kullan
                item_id = it["link"]
            if not item_id:
                continue

            if item_id in seen_ids:
                continue

            # Yeni haber
            seen_ids.add(item_id)
            new_items.append(it)

        # Önce yeni haberleri gönder
        for it in new_items:
            head = it["src"] or it["kw"]
            msg_lines = [
                f"<b>{head.upper()}</b>",
                "",
                it["title"],
                "",
            ]
            if it["link"]:
                msg_lines.append(it["link"])
            if it["pub"]:
                msg_lines.append(f"({it['pub']})")

            text = "\n".join(msg_lines)
            send_telegram(text)
            time.sleep(1)  # Çok hızlı peş peşe göndermesin

        LAST_JOB_ITEMS = len(new_items)
        debug("Yeni haber sayısı:", LAST_JOB_ITEMS)

        # HABER YOK mesajı (hafta içi 08:00–18:00 arası, saat başı)
        local_time = get_local_now()
        weekday = local_time.weekday()  # 0 = Pazartesi
        hour = local_time.hour
        minute = local_time.minute

        if LAST_JOB_ITEMS == 0:
            if 0 <= weekday <= 4 and 8 <= hour <= 18 and minute == 0:
                today_str = local_time.date().isoformat()
                send_telegram(f"🟡 Bugün ({today_str}) TERA ile ilgili yeni haber yok.")
                debug("HABER YOK mesajı gönderildi.")

        # seen_ids dosyasını güncelle
        save_seen_ids(seen_ids)

        LAST_JOB_TIME = datetime.now(timezone.utc)
        debug("===== JOB BİTTİ =====")
        return LAST_JOB_ITEMS

    except Exception as e:
        LAST_JOB_ERROR = str(e)
        notify_error(f"job() içinde hata: {e}")
        debug("===== JOB HATA İLE BİTTİ =====")
        return 0


# ============================================================
# Flask uygulaması ve endpoint'ler
# ============================================================

app = Flask(__name__)


@app.get("/")
def home():
    return "Alive", 200


@app.get("/health")
def health():
    """UptimeRobot / Render health check."""
    if LAST_JOB_TIME:
        age_sec = (datetime.now(timezone.utc) - LAST_JOB_TIME).total_seconds()
        last_job_iso = LAST_JOB_TIME.isoformat()
    else:
        age_sec = None
        last_job_iso = None

    data = {
        "ok": True,
        "last_job_time": last_job_iso,
        "last_job_age_sec": age_sec,
        "last_job_items": LAST_JOB_ITEMS,
        "last_job_error": LAST_JOB_ERROR,
    }
    return jsonify(data), 200


@app.get("/cron")
def cron_runner():
    """cron-job.org'un saat başı çağıracağı endpoint.

    - İstek hemen 200 OK döner
    - job() arka planda ayrı thread'de çalışır
    """
    token = request.args.get("token", "").strip()
    if CRON_TOKEN and token != CRON_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    debug("[cron] çağrıldı, job() arka planda çalışacak...")

    def bg():
        try:
            cnt = job()
            debug(f"[cron] job bitti, yeni haber sayısı: {cnt}")
        except Exception as e:
            notify_error(f"/cron içinde arka plan hatası: {e}")

    threading.Thread(target=bg, daemon=True).start()
    return jsonify({"ok": True, "message": "job started"}), 200


@app.get("/test")
def test_notification():
    """Telegram'a test bildirimi yollar."""
    send_telegram("✅ Test bildirimi: Sistem çalışıyor (/test).")
    return "Test bildirimi gönderildi.", 200


@app.get("/restart")
def restart():
    """Render instance'ı yeniden başlatmak için (cron'dan çağırmak istersen)."""
    token = request.args.get("token", "").strip()
    if RESTART_TOKEN and token != RESTART_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    debug("Restart endpoint'i çağrıldı, process exit(0)...")
    # Render'da process ölünce otomatik yeniden başlıyor
    os._exit(0)


# ============================================================
# Main (lokal çalıştırmak istersen)
# ============================================================

def main():
    port = int(os.environ.get("PORT", "10000"))
    debug(f"Flask başlıyor, port={port}")
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
