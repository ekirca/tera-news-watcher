# -*- coding: utf-8 -*-
"""
Tera News Watcher — Telegram bildirim botu
- Google News RSS'ten anahtar kelimelere göre haber çeker
- Filtreler: tekrar, zaman, domain beyaz liste, şirket eşleşmesi
- Yeni bulunanları Telegram kanalına yollar
- /health endpoint'i uptime için
- keepalive thread'i Render'ın uyanık kalmasına yardım eder
"""

import os
import time
import threading
import requests
import schedule
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus, urlparse
from flask import Flask, jsonify
from email.utils import parsedate_to_datetime

#################################
# 1) Ortam değişkenleri / Ayar  #
#################################

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# Dakika bazlı tarama aralığı
POLL_INTERVAL_MIN  = int(os.getenv("POLL_INTERVAL_MIN", "10"))

# Çok eski haberleri bildirme. Örn: sadece son 24 saat.
MAX_AGE_HOURS = 24

# Render URL'in (keepalive ping'i buraya atıyoruz)
RENDER_URL = os.getenv(
    "PUBLIC_BASE_URL",
    "https://tera-news-watcher.onrender.com"
).rstrip("/")

# Kaydedilen durum dosyaları
SEEN_FILE = "seen_ids.txt"
INIT_FILE = ".initialized"

# Domain beyaz liste (izin verilen haber kaynakları)
ALLOWED_DOMAINS = [
    # ekonomi / finans / genel haber
    "hurriyet.com.tr", "bigpara.hurriyet.com.tr", "milliyet.com.tr",
    "cnnturk.com", "ntv.com.tr", "haberturk.com", "bloomberght.com",
    "borsagundem.com", "borsagundem.com.tr", "dunya.com", "ekonomim.com",
    "investing.com", "tr.investing.com", "foreks.com", "ekoturk.com",
    "patronlardunyasi.com", "finansgundem.com",
    "reuters.com", "bbc.com",
    "aa.com.tr", "anadoluajansi.com.tr", "trthaber.com",
    # resmi açıklama
    "kap.org.tr", "kamuyuaydinlatma.com",
    # teknoloji
    "webrazzi.com", "t24.com.tr", "sozcu.com.tr", "sabah.com.tr",
]

# Bu şirketlerden / yapılardan bahseden haberleri istiyoruz:
COMPANY_TOKENS = [
    # Finans
    "tera yatırım", "tera portföy", "tera finansal yatırımlar", "tera finansal yatırımlar holding",
    "tera bank", "tera finans faktoring", "tera girişim sermayesi", "kointra",
    # Teknoloji
    "tera yatırım teknoloji holding", "barikat", "barikat grup", "barikat a.ş",
    "tra bilişim", "tra bilişim hizmetleri",
    # Tarım / Su
    "viva terra hayvancılık", "viva terra su",
    # Hizmet / güvenlik
    "tera özel güvenlik",
    # Fon
    "tly fonu", "tera ly", "tera ly fonu", "tera ly portföy"
]

# Haber çekerken kullandığımız kelime aramaları:
KEYWORDS = [
    "tera yatırım",
    "tera finansal yatırımlar",
    "tera portföy",
    "tera yatırım teknoloji holding",
    "barikat siber güvenlik",
    "barikat grup",
    "tra bilişim",
    "viva terra su",
    "viva terra hayvancılık",
    "tera özel güvenlik",
    "tly fonu",
    "tera ly fonu",
]

#################################
# 2) Yardımcı fonksiyonlar      #
#################################

def debug_print(*args):
    """Sessizce patlamayalım diye tek noktadan log."""
    try:
        print(*args, flush=True)
    except Exception:
        pass

def domain_allowed(link: str) -> bool:
    """Haber linkinin domaini izin verilenlerden mi?"""
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

def normalize_dt_to_naive_utc(dtobj):
    """RSS tarihlerini karşılaştırabilmek için naive UTC datetime'a indirger."""
    if dtobj is None:
        return None
    if dtobj.tzinfo is None:
        # zaten naive -> UTC varsay
        return dtobj
    return dtobj.astimezone(timezone.utc).replace(tzinfo=None)

def parse_pubdate(pub_raw: str):
    """
    RSS pubDate'i datetime objesine çevir.
    Sonuç naive (tzinfo=None) UTC benzeri olsun.
    """
    if not pub_raw:
        return None
    try:
        dt = parsedate_to_datetime(pub_raw)
        return normalize_dt_to_naive_utc(dt)
    except Exception:
        return None

def google_news_rss(query: str) -> str:
    """
    Google News RSS feed'i çek.
    Burada site:tr OR site:.com OR site:.com.tr ekliyoruz ki Türk kaynaklar öne çıksın.
    """
    q = quote_plus(query + " site:tr OR site:.com OR site:.com.tr")
    u = f"https://news.google.com/rss/search?q={q}&hl=tr&gl=TR&ceid=TR:tr"
    r = requests.get(u, timeout=30)
    r.raise_for_status()
    return r.text

def parse_rss(xml_text: str):
    """
    RSS XML içinden item'ları çıkar.
    Dönen her item:
    {
        "id": str,
        "title": str,
        "link": str,
        "pub": str,     # orijinal pubDate string
        "pub_dt": datetime or None,
        "summary": str
    }
    """
    root = ET.fromstring(xml_text)
    out_items = []
    for it in root.findall(".//item"):
        title = (it.findtext("title") or "").strip()
        link  = (it.findtext("link") or "").strip()
        guid  = (it.findtext("guid") or link or title).strip()
        pub   = (it.findtext("pubDate") or "").strip()
        desc  = (it.findtext("description") or "").strip()

        pub_dt = parse_pubdate(pub)

        out_items.append({
            "id": guid or link or title,
            "title": title,
            "link": link,
            "pub": pub,
            "pub_dt": pub_dt,
            "summary": desc,
        })
    return out_items

def load_seen():
    """Daha önce gönderilen haber ID'lerini oku."""
    if not os.path.exists(SEEN_FILE):
        return set()
    try:
        with open(SEEN_FILE, "r", encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    except Exception:
        return set()

def save_seen(seen_ids: set):
    """Gönderilen haber ID'lerini kaydet."""
    try:
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(seen_ids)))
    except Exception as e:
        debug_print("save_seen hata:", e)

def has_company_match(item: dict) -> bool:
    """
    Haberin title+summary kısmında Tera ekosisteminden bir şey geçiyor mu?
    Çok genel 'tera' kelimesi yerine listemizdeki şirket isimlerini / markaları arıyoruz.
    """
    txt = (item["title"] + " " + item.get("summary", "")).lower()
    for token in COMPANY_TOKENS:
        if token.lower() in txt:
            return True
    return False

def is_fresh_enough(pub_dt: datetime, max_age_hours: int) -> bool:
    """
    Haber çok eski mi? (ör: 24 saatten eskiyse bildirmeyelim)
    pub_dt None ise es geçme (bildir).
    """
    if pub_dt is None:
        return True
    cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
    return pub_dt >= cutoff

def send_telegram(msg: str):
    """Telegram kanalına mesaj yolla."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        debug_print("Telegram env yok, mesaj atılmadı.")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "parse_mode": "HTML"
    }
    try:
        r = requests.post(url, data=data, timeout=15)
        debug_print("Telegram status:", r.status_code)
    except Exception as e:
        debug_print("Telegram hata:", e)

#################################
# 3) Çek / filtrele / bildir    #
#################################

def collect_news():
    """
    Tüm KEYWORDS için RSS çek, filtrele, yeni haberleri döndür.
    return: list of (kw, item)
    """
    results = []
    seen = load_seen()

    for kw in KEYWORDS:
        try:
            xml = google_news_rss(kw)
            items = parse_rss(xml)

            for it in items:
                # tekrar kontrol
                if it["id"] in seen:
                    continue

                # domain kontrol
                if not domain_allowed(it["link"]):
                    continue

                # şirket anahtar kelimeleri var mı?
                if not has_company_match(it):
                    continue

                # çok eski mi?
                if not is_fresh_enough(it["pub_dt"], MAX_AGE_HOURS):
                    continue

                # buraya kadar geldiyse bu haberi yeni listesine ekliyoruz
                results.append((kw, it))
                seen.add(it["id"])

        except Exception as e:
            debug_print("collect_news hata:", kw, e)

    if results:
        save_seen(seen)

    return results

def job():
    """
    Periyodik olarak çağrılır.
    Yeni haberleri bulur ve Telegram'a yollar.
    """
    new_items = collect_news()
    if not new_items:
        debug_print(datetime.utcnow(), "- Yeni haber yok.")
        return

    debug_print(datetime.utcnow(), f"- {len(new_items)} yeni haber bulundu.")

    for kw, it in new_items:
        msg = (
            f"📰 <b>{kw.upper()}</b>\n"
            f"{it['title']}\n"
            f"{it['link']}\n"
            f"{it.get('pub') or ''}"
        )
        send_telegram(msg)

#################################
# 4) İlk kurulum (bootstrap)    #
#################################

def bootstrap_if_needed():
    """
    İlk defa çalışıyorsak:
    - şu anki sonuçları 'görülmüş' olarak işaretle
    - bildirim YOLLAMA
    Sonraki çalıştırmalarda direkt job() devreye girsin.
    """
    if os.path.exists(INIT_FILE):
        return  # zaten init edilmiş

    seen = load_seen()
    added = 0
    for kw in KEYWORDS:
        try:
            xml = google_news_rss(kw)
            items = parse_rss(xml)
            for it in items:
                if it["id"] not in seen:
                    seen.add(it["id"])
                    added += 1
        except Exception as e:
            debug_print("bootstrap hata:", kw, e)

    save_seen(seen)

    try:
        with open(INIT_FILE, "w", encoding="utf-8") as f:
            f.write(datetime.utcnow().isoformat())
    except Exception as e:
        debug_print("INIT_FILE yazılamadı:", e)

    debug_print(f"✅ Bootstrap tamam: {added} mevcut haber işaretlendi (bildirim yok).")

#################################
# 5) Scheduler thread           #
#################################

def scheduler_thread():
    """
    - bootstrap'i bir kere çalıştır
    - schedule.every(...).minutes.do(job)
    - sonsuz döngü
    """
    bootstrap_if_needed()

    # ilk turda hemen bir job() çalıştır
    job()

    schedule.every(POLL_INTERVAL_MIN).minutes.do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)

#################################
# 6) Keepalive (Render uyanık)  #
#################################

def keepalive():
    """
    Render free dyno uykuya geçmesin diye
    kendi /health endpoint'imize periyodik GET at.
    """
    while True:
        try:
            url = RENDER_URL + "/health"
            requests.get(url, timeout=10)
        except Exception as e:
            debug_print("keepalive hata:", e)
        time.sleep(600)  # 10 dk

#################################
# 7) Flask app (health check)   #
#################################

app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    return jsonify(
        ok=True,
        time=datetime.utcnow().isoformat()
    ), 200

#################################
# 8) Main entrypoint            #
#################################

def main():
    # 1) haber tarayıcı thread
    threading.Thread(target=scheduler_thread, daemon=True).start()
    # 2) keepalive thread
    threading.Thread(target=keepalive, daemon=True).start()
    # 3) Flask server
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))

if __name__ == "__main__":
    main()
