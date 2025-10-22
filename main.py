# -*- coding: utf-8 -*-
"""
Tera News Watcher — Telegram bildirim botu
- Google News RSS'ten anahtar kelimelere göre haber çeker
- Filtreler: tekrar, zaman, domain beyaz liste, şirket eşleşmesi
- Yeni bulunanları Telegram kanalına yollar
- /health ve / endpointleri ile uptime kontrolü
"""

import os
import time
import threading
import requests
import schedule
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib.parse import quote_plus, urlparse
from flask import Flask, jsonify
from email.utils import parsedate_to_datetime

# =========================
# Ortam değişkenleri / Ayar
# =========================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "").strip()
POLL_INTERVAL_MIN  = int(os.getenv("POLL_INTERVAL_MIN", "10"))

# İlk çalıştırmada eski haberleri görmemek için zaman eşiği
# (İstersen saat aralığını ayarlayabilirsin.)
START_TIME = datetime.utcnow() - timedelta(hours=24)

# Domain filtresini geçici kapatmak için True yapabilirsin (debug için)
DISABLE_DOMAIN_FILTER = False

# ----------------------------
# Tera anahtar kelimeleri
# ----------------------------
KEYWORDS = [
    "tera", "tehol", "trhol", "tly", "tera şirketleri"
]

# Şirket isimleri (eşleşme için; başlık/açıklama/link içinde arar — küçük harf)
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

# Haberleri kaydettiğimiz dosyalar
SEEN_FILE = "seen_ids.txt"
INIT_FILE = ".initialized"

# Domain beyaz liste (sondan eşleşir)
ALLOWED_DOMAINS = [
    # Büyük portallar
    "hurriyet.com.tr", "milliyet.com.tr", "cnnturk.com", "ntv.com.tr",
    "bbc.com", "reuters.com", "bloomberg.com", "bloomberght.com",
    "aa.com.tr", "anadoluajansi.com.tr", "trthaber.com", "aljazeera.com",
    # Ekonomi / teknoloji siteleri
    "dunya.com", "ekonomim.com", "foreks.com", "investing.com", "ekoturk.com",
    "webrazzi.com", "haberturk.com", "sozcu.com.tr", "sabah.com.tr",
    "t24.com.tr", "bloomberght.com", "patronlardunyasi.com","borsagundem.com.tr",
    "ekonomim.com","finansgundem.com","bigpara.hurriyet.com.tr","haberturk.com",
    "milliyet.com.tr","tr.investing.com"
    # Resmi / kurumsal
    "kap.org.tr", "kamuyuaydinlatma.com",
    # genel .com.tr ve .com da izinli olsun istersen aşağıyı aç
    # ".com.tr", ".com"
]


# =========================
# Yardımcı fonksiyonlar
# =========================
def domain_allowed(link: str) -> bool:
    """Link'in domaini beyaz listedeyse True döndürür."""
    if DISABLE_DOMAIN_FILTER:
        return True
    try:
        netloc = urlparse(link).netloc.lower()
        # www. kaldır
        if netloc.startswith("www."):
            netloc = netloc[4:]
        for d in ALLOWED_DOMAINS:
            if netloc.endswith(d):
                return True
        return False
    except Exception:
        return False


def matches_company(it):
    text = (it["title"] + " " + it.get("summary", "")).lower()
    keywords = ["tera", "tera yatırım", "tera portföy", "barikat", "tra bilişim", "viva terra"]
    return any(k in text for k in keywords)



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
    """RSS'i parse edip {id,title,link,pub,pub_dt,desc} döndürür."""
    root = ET.fromstring(xml_text)
    items = []
    for it in root.findall(".//item"):
        title = (it.findtext("title") or "").strip()
        link  = (it.findtext("link") or "").strip()
        guid  = (it.findtext("guid") or link).strip()
        pub   = (it.findtext("pubDate") or "").strip()
        desc  = (it.findtext("description") or "").strip()

        pub_dt = None
        if pub:
            try:
                pub_dt = parsedate_to_datetime(pub)
                # timezone-aware olmayanı UTC'le
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=None)
                else:
                    pub_dt = pub_dt.astimezone(tz=None).replace(tzinfo=None)
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


def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()
    with open(SEEN_FILE, "r", encoding="utf-8") as f:
        return set(l.strip() for l in f if l.strip())


def save_seen(seen: set):
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(seen))


def bootstrap():
    """İlk çalıştırmada mevcutları işaretler, bildirim göndermez."""
    seen = load_seen()
    added = 0
    for kw in KEYWORDS:
        try:
            xml = google_news_rss(kw)
            for it in parse_rss(xml):
                if it["id"] not in seen:
                    seen.add(it["id"])
                    added += 1
        except Exception as e:
            print("Bootstrap hata:", kw, e)
    save_seen(seen)
    with open(INIT_FILE, "w", encoding="utf-8") as f:
        f.write(datetime.utcnow().isoformat())
    print(f"✅ İlk kurulum tamam: {added} mevcut haber işaretlendi (bildirim yok).")


# =========================
# Ana iş — periyodik tarama
# =========================
def job():
    seen = load_seen()
    new = []

    for kw in KEYWORDS:
        try:
            xml = google_news_rss(kw)
            items = parse_rss(xml)

            for it in items:
                # 1) tekrar kontrolü
                if it["id"] in seen:
                    continue

                # 2) zaman filtresi
                if it["pub_dt"] is not None and it["pub_dt"] < START_TIME:
                    continue

                # 3) domain filtresi
                if not domain_allowed(it["link"]):
                    continue

                # 4) şirket eşleşmesi (başlık+açıklama)
                if not matches_company(it):
                    continue

                new.append((kw, it))
                seen.add(it["id"])

        except Exception as e:
            print("Hata:", kw, e)

    if new:
        for kw, it in new:
            msg = (
                f"📰 <b>{kw.upper()}</b>\n"
                f"{it['title']}\n{it['link']}\n{it.get('pub') or ''}"
            )
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
        # daha önce çalışmışsa ilk anda bir kere dene
        job()
        schedule.every(POLL_INTERVAL_MIN).minutes.do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)


# =========================
# Flask (health/keepalive)
# =========================
app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    return jsonify(ok=True, time=datetime.utcnow().isoformat()), 200


def main():
    # işleyici thread’i
    threading.Thread(target=scheduler_thread, daemon=True).start()
    # web (health)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))


if __name__ == "__main__":
    main()
