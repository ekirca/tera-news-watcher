# -*- coding: utf-8 -*-
"""
Tera News Watcher — Render için sade ve temiz versiyon

- Google News RSS'ten anahtar kelimelere göre haber çeker
- Filtreler: tekrar, zaman, domain beyaz liste, Tera şirket eşleşmesi
- Yeni haberleri Telegram kanalına yollar
- /health ve /test endpointleri ile kontrol / test
"""

import os
import time
import threading
from datetime import datetime, timedelta
from urllib.parse import quote_plus, urlparse
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

import requests
from flask import Flask, jsonify
import schedule

# =========================
# Ortam değişkenleri / Ayar
# =========================

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# Haber tarama periyodu (dakika)
POLL_INTERVAL_MIN = int(os.getenv("POLL_INTERVAL_MIN", "10"))

# "Eski haber" eşiği (UTC; varsayılan: son 72 saat)
MAX_AGE_HOURS = int(os.getenv("MAX_AGE_HOURS", "72"))

# Domain filtresini komple kapatmak için True yap (debug için)
DISABLE_DOMAIN_FILTER = False

# Hata bildirimi için global durumlar
LAST_JOB_TIME = None          # job() en son ne zaman başarıyla bitti
LAST_ERROR_TIME = None        # son hata bildirimi zamanı
ERROR_COOLDOWN_MIN = 30       # aynı tür hatayı en az kaç dakika arayla Telegram'a gönderelim

# ----------------------------
# Anahtar kelimeler (Google News araması)
# ----------------------------
KEYWORDS = [
    "tera",
    "tera yatırım",
    "tera yatirim",
    "tehol",
    "trhol",
    "tly",
    "tera şirketleri",
]

# ----------------------------
# Şirket isimleri (eşleşme için)
# ----------------------------
COMPANY_TOKENS = [
    # Holding / ana şirket
    "tera yatırım",
    "tera yatırım menkul değerler",
    "tera yatırım menkul degerler",
    "tera yatırım menkul değerler a.ş",
    "tera yatırım menkul degerler a.s",

    # Finans
    "tera bank",
    "tera finans faktoring",
    "tera portföy",
    "tera girişim sermayesi",
    "kointra",
    "tera finansal yatırımlar holding",

    # Teknoloji
    "tera yatırım teknoloji holding",
    "barikat grup",
    "barikat",
    "tra bilişim",
    "tra bilisim",

    # Tarım / Su
    "viva terra hayvancılık",
    "viva terra su",

    # Hizmet
    "tera özel güvenlik",

    # Fon / ürün
    "tly fonu",
    "tera ly",
    "tera ly fonu",
]

# Şirket eşleşmesini biraz daha agresif yapmak için çekirdek anahtarlar
BASE_KEYWORDS = [
    "tera",
    "tera yatirim",
    "tera yatırım",
    "tera yatırım menkul",
    "tera yatırım menkul değerler",
    "tera yatırım teknoloji holding",
    "tera finansal yatırımlar holding",
    "barikat",
    "tra bilisim",
    "tra bilişim",
    "viva terra",
]

# ----------------------------
# Domain beyaz liste
# ----------------------------
ALLOWED_DOMAINS = [
    # Büyük haber portalları
    "hurriyet.com.tr",
    "milliyet.com.tr",
    "cnnturk.com",
    "ntv.com.tr",
    "bbc.com",
    "reuters.com",
    "bloomberg.com",
    "bloomberght.com",
    "aa.com.tr",
    "trthaber.com",
    "aljazeera.com",

    # Ekonomi / Finans
    "dunya.com",
    "ekonomim.com",
    "foreks.com",
    "investing.com",
    "ekoturk.com",
    "haberturk.com",
    "sozcu.com.tr",
    "sabah.com.tr",
    "t24.com.tr",
    "patronlardunyasi.com",
    "borsagundem.com.tr",
    "finansgundem.com",
    "bigpara.hurriyet.com.tr",
    "tr.investing.com",

    # Resmi / kurumsal
    "kap.org.tr",
    "kamuyuaydinlatma.com",
]

# =========================
# Dosyalar
# =========================

SEEN_FILE = "seen_ids.txt"
INIT_FILE = ".initialized"
MAX_SEEN_IDS = 50000  # 50 bin id'den fazlasını tutma (çok fazlası gereksiz)


# =========================
# Yardımcı fonksiyonlar
# =========================

def debug_print(*args):
    """Basit log helper (anında flush)."""
    print(*args, flush=True)


def normalize_text(txt: str) -> str:
    """
    Türkçe karakterleri sadeleştirip küçük harfe çevirir.
    Böylece 'yatırım / yatirim / YATIRIM' hepsi aynı hale gelir.
    """
    table = str.maketrans(
        "ÇçĞğİIıÖöŞşÜü",
        "ccggiiioossuu"
    )
    return txt.translate(table).lower()


def domain_allowed(link: str) -> bool:
    """Link'in domaini beyaz listedeyse True döndürür."""
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


def matches_company(it: dict) -> bool:
    """
    Başlık + açıklama içinde Tera ile ilişkili şirket adları var mı?
    Türkçe karakterler normalize edilerek karşılaştırılır.
    """
    text = normalize_text((it.get("title", "") + " " + it.get("desc", "")))

    tokens = [normalize_text(k) for k in (COMPANY_TOKENS + BASE_KEYWORDS)]

    return any(k in text for k in tokens)


def send_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        debug_print("⚠️ TELEGRAM_BOT_TOKEN veya TELEGRAM_CHAT_ID yok, mesaj gönderilmedi.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
    try:
        r = requests.post(url, data=data, timeout=15)
        debug_print("Telegram gönderildi:", r.status_code)
    except Exception as e:
        debug_print("Telegram hata:", e)


def notify_error(message: str):
    """Hata durumunda hem log'a yaz, hem de Telegram'a makul sıklıkta uyarı gönder."""
    global LAST_ERROR_TIME
    now = datetime.utcnow()

    if LAST_ERROR_TIME is None or (now - LAST_ERROR_TIME).total_seconds() > ERROR_COOLDOWN_MIN * 60:
        try:
            send_telegram(f"⚠️ Hata uyarısı:\n{message}")
            LAST_ERROR_TIME = now
        except Exception as e:
            print("notify_error içinde hata:", e)

    print("ERROR:", message)


def google_news_rss(query: str) -> str:
    """Google News RSS URL'ini çağırır ve XML döndürür."""
    q = quote_plus(query + " site:tr OR site:.com OR site:.com.tr")
    u = f"https://news.google.com/rss/search?q={q}&hl=tr&gl=TR&ceid=TR:tr"
    r = requests.get(u, timeout=30)
    r.raise_for_status()
    return r.text


def parse_rss(xml_text: str):
    """RSS'i parse edip {id,title,link,pub,pub_dt,desc} listesi döndürür."""
    root = ET.fromstring(xml_text)
    items = []
    for it in root.findall(".//item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        guid = (it.findtext("guid") or link or title).strip()
        pub = (it.findtext("pubDate") or "").strip()
        desc = (it.findtext("description") or "").strip()

        pub_dt = None
        if pub:
            try:
                dt = parsedate_to_datetime(pub)
                if dt.tzinfo is not None:
                    dt = dt.astimezone(tz=None).replace(tzinfo=None)
                pub_dt = dt
            except Exception:
                pub_dt = None

        items.append(
            {
                "id": guid or link or title,
                "title": title,
                "link": link,
                "pub": pub,
                "pub_dt": pub_dt,
                "desc": desc,
            }
        )
    return items


def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()
    with open(SEEN_FILE, "r", encoding="utf-8") as f:
        return set(l.strip() for l in f if l.strip())


def save_seen(seen: set):
    # Set sırasız, ama çok büyürse rastgele bazı eski kayıtlar uçmuş olur — problem değil.
    if len(seen) > MAX_SEEN_IDS:
        seen = set(list(seen)[:MAX_SEEN_IDS])

    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(seen))


def bootstrap():
    """
    İlk çalıştırmada mevcut haberlerin hepsini seen'e işaretler,
    böylece bir anda eski yüzlerce haber Telegram'a düşmez.
    """
    seen = load_seen()
    added = 0
    for kw in KEYWORDS:
        try:
            debug_print(f"[bootstrap] {kw!r} için Google News RSS çekiliyor...")
            xml = google_news_rss(kw)
            for it in parse_rss(xml):
                if it["id"] not in seen:
                    seen.add(it["id"])
                    added += 1
        except Exception as e:
            debug_print("Bootstrap hata:", kw, e)

    save_seen(seen)
    with open(INIT_FILE, "w", encoding="utf-8") as f:
        f.write(datetime.utcnow().isoformat())
    debug_print(f"✅ İlk kurulum tamam: {added} mevcut haber işaretlendi (bildirim yok).")


# =========================
# Ana iş — periyodik tarama
# =========================

def job():
    global LAST_JOB_TIME

    now = datetime.utcnow()
    cutoff_time = now - timedelta(hours=MAX_AGE_HOURS)

    debug_print("===== JOB BAŞLANGIÇ =====", now.isoformat(), "cutoff_time:", cutoff_time.isoformat())

    seen = load_seen()
    debug_print("load_seen:", len(seen), "adet id")

    new = []

    for kw in KEYWORDS:
        try:
            debug_print(f"[{kw}] Google News RSS çekiliyor...")
            xml = google_news_rss(kw)
            items = parse_rss(xml)
            debug_print(f"[{kw}] RSS item sayısı:", len(items))

            for it in items:
                title = it.get("title", "").strip()
                link = it.get("link", "").strip()

                # 1) tekrar kontrolü
                if it["id"] in seen:
                    continue

                # 2) zaman filtresi
                if it["pub_dt"] is not None and it["pub_dt"] < cutoff_time:
                    # debug_print(f"[SKIP][{kw}] Eski haber:", title)
                    continue

                # 3) domain filtresi
                if not domain_allowed(link):
                    # debug_print(f"[SKIP][{kw}] Domain izinli değil: {link}")
                    continue

                # 4) şirket eşleşmesi
                if not matches_company(it):
                    debug_print(f"[SKIP][{kw}] Şirket eşleşmedi: {title}")
                    continue

                # Buraya gelmişse gerçekten TERA ile ilgili yeni haber
                new.append((kw, it))
                seen.add(it["id"])

        except Exception as e:
            notify_error(f"{kw!r} kelimesi taranırken hata oluştu: {e}")

    LAST_JOB_TIME = datetime.utcnow()

    if new:
        for kw, it in new:
            msg = (
                f"📰 <b>{kw.upper()}</b>\n"
                f"{it['title']}\n{it['link']}\n{it.get('pub') or ''}"
            )
            send_telegram(msg)
        save_seen(seen)
        debug_print(LAST_JOB_TIME, "-", len(new), "haber gönderildi.")
    else:
        debug_print(LAST_JOB_TIME, "- Yeni haber yok.")
    debug_print("===== JOB BİTTİ =====")


def scheduler_thread():
    """Schedule döngüsünü ayrı bir thread'de çalıştır."""
    # İlk seferde bootstrap
    if not os.path.exists(INIT_FILE):
        bootstrap()

    # Çalışır çalışmaz bir defa dene
    job()

    # Sonra periyodik olarak devam et
    schedule.every(POLL_INTERVAL_MIN).minutes.do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)


# =========================
# Flask (health / test)
# =========================

app = Flask(__name__)


@app.get("/")
def home():
    return "Alive", 200


@app.get("/health")
def health():
    now = datetime.utcnow()

    if LAST_JOB_TIME is None:
        last_job_iso = None
        last_job_ago_sec = None
    else:
        last_job_iso = LAST_JOB_TIME.isoformat()
        last_job_ago_sec = (now - LAST_JOB_TIME).total_seconds()

    return jsonify(
        ok=True,
        time=now.isoformat(),
        last_job=last_job_iso,
        last_job_ago_seconds=last_job_ago_sec,
    ), 200


@app.get("/test")
def test_notification():
    """Telegram'a test mesajı göndermek için basit endpoint."""
    message = "🧪 Test bildirimi: TERA test haberi bulundu!"
    send_telegram(message)
    return "Test bildirimi gönderildi (Telegram’a bak 👀)", 200


# =========================
# Entry point
# =========================

def main():
    # Haber tarama işini ayrı thread'de başlat
    threading.Thread(target=scheduler_thread, daemon=True).start()

    # Flask web server — Render PORT değişkenini kullan
    port = int(os.environ.get("PORT", "10000"))
    debug_print(f"🌐 Flask başlıyor, port={port}")
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
