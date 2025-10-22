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
START_TIME = datetime.utcnow() - timedelta(hours=3)

# Domain filtresini geçici kapatmak için True yapabilirsin (debug için)
DISABLE_DOMAIN_FILTER = True

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
    # Ekonomi / finans
    "dunya.com", "ekonomim.com", "foreks.com", "investing.com", "tr.investing.com",
    "ekoturk.com", "webrazzi.com", "haberturk.com", "sozcu.com.tr", "sabah.com.tr",
    "t24.com.tr", "patronlardunyasi.com", "borsagundem.com.tr", "finansgundem.com",
    "bigpara.hurriyet.com.tr",
    # Resmi / kurumsal
    "kap.org.tr", "kamuyuaydinlatma.com"
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
    text = (it["title"] + " " + it.get("desc", "") + " " + it.get("link", "")).lower()
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


import re

def _strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s or "").strip()

def parse_rss(xml_text: str):
    root = ET.fromstring(xml_text)
    items = []
    for it in root.findall(".//item"):
        title = (it.findtext("title") or "").strip()
        link  = (it.findtext("link")  or "").strip()
        guid  = (it.findtext("guid")  or link).strip()
        pub   = (it.findtext("pubDate") or "").strip()
        desc  = _strip_html(it.findtext("description") or "")

        # feedburner:origLink varsa gerçek kaynak linki odur
        try:
            orig = it.find("{http://rssnamespace.org/feedburner/ext/1.0}origLink")
            if orig is not None and orig.text:
                link = orig.text.strip()
        except Exception:
            pass

        pub_dt = None
        if pub:
            try:
                pub_dt = parsedate_to_datetime(pub)
                # Zaman bilgisini naive UTC'ye indir
                if pub_dt.tzinfo is not None:
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


# --- DEBUG bayrakları ---
DEBUG_VERBOSE = True       # True: her döngüde detaylı log bas
DISABLE_DOMAIN_FILTER = False  # Geçici teşhis için True yapabilirsin

last_stats = {}  # /debug için son istatistikler

def job():
    global last_stats
    seen = load_seen()
    new = []
    all_stats = {"run_utc": datetime.utcnow().isoformat(), "keywords": {}}

    for kw in KEYWORDS:
        stat = {
            "fetched": 0, "dup": 0, "time_drop": 0,
            "domain_drop": 0, "company_drop": 0, "accepted": 0,
            "samples_dropped": []
        }
        try:
            xml = google_news_rss(kw)
            items = parse_rss(xml)
            stat["fetched"] = len(items)

            for it in items:
                title = it["title"] or ""
                link  = it["link"]  or ""
                pubdt = it.get("pub_dt")

                # 1) tekrar
                if it["id"] in seen:
                    stat["dup"] += 1
                    continue

                # 2) zaman
                if pubdt is not None and pubdt < START_TIME:
                    stat["time_drop"] += 1
                    if len(stat["samples_dropped"]) < 3:
                        stat["samples_dropped"].append({"why":"time", "t":title, "p":str(pubdt)})
                    continue

                # 3) domain
                if not domain_allowed(link):
                    stat["domain_drop"] += 1
                    if len(stat["samples_dropped"]) < 3:
                        stat["samples_dropped"].append({"why":"domain", "t":title, "link":link})
                    continue

                # 4) şirket eşleşmesi
                if not matches_company(it):
                    stat["company_drop"] += 1
                    if len(stat["samples_dropped"]) < 3:
                        stat["samples_dropped"].append({"why":"company", "t":title})
                    continue

                # kabul
                stat["accepted"] += 1
                new.append((kw, it))
                seen.add(it["id"])

        except Exception as e:
            print("Hata:", kw, e)

        all_stats["keywords"][kw] = stat

        if DEBUG_VERBOSE:
            print(f"[{kw}] fetched={stat['fetched']} "
                  f"dup={stat['dup']} time_drop={stat['time_drop']} "
                  f"domain_drop={stat['domain_drop']} company_drop={stat['company_drop']} "
                  f"accepted={stat['accepted']}")
            if stat["samples_dropped"]:
                print(f"  örnek redler: {stat['samples_dropped']}")

    last_stats = all_stats  # /debug için sakla

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

# --- /debug endpoint'i: Son tarama istatistiklerini gör ---
@app.get("/debug")
def debug_view():
    return jsonify(last_stats), 200

def matches_company(it):
    # açıklamadaki HTML'ler temizlenmiş olmalı (parse_rss içinde)
    text = (it["title"] + " " + it.get("desc", "") + " " + it.get("link", "")).lower()
    # daha kapsayıcı eşleşme
    tokens = [t.lower() for t in COMPANY_TOKENS] + ["tera", "tehol", "trhol", "tly", "tera yatırım"]
    return any(tok in text for tok in tokens)


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
