# -*- coding: utf-8 -*-
"""
TERA grubu haber botu – 7/24 (Flask + schedule)
- TERA şirket adları + TLY için Google News RSS tarar
- Başlık + açıklama (description) eşleşmesi yapar
- .tr/.com.tr uzantılarını ve geniş domain whitelist'i kabul eder
- Google FeedBurner origLink kullanır (varsa)
- Başlangıç anından önceki haberleri göndermez
- Keep-alive ve 09:15 günlük ping içerir
"""

import os, re, time, threading, hashlib, requests, schedule, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import quote_plus, urlparse
from email.utils import parsedate_to_datetime
from flask import Flask

# ------------------ ENV / SABİTLER ------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
POLL_INTERVAL_MIN  = int(os.getenv("POLL_INTERVAL_MIN") or 10)

SEEN_FILE = "seen_ids.txt"
INIT_FILE = ".initialized"

# Botun başlama anı: bundan önceki haberleri asla gönderme
START_TIME = datetime.utcnow()

# --- TERA grubu ifadeleri (senin verdiğin liste + kısaltmalar) ---
TERA_COMPANY_PHRASES = [
    # Finans
    "tera yatırım",
    "tera bank",
    "tera finans faktoring",
    "tera portföy",
    "tera girişim sermayesi",
    "kointra",
    "tera finansal yatırımlar holding",
    # Teknoloji
    "tera yatırım teknoloji holding",
    "barikat grup",
    "tra bilişim",
    # Tarım / Hayvancılık / Su
    "viva terra hayvancılık",
    "viva terra su",
    # Hizmet
    "tera özel güvenlik",
    # Kısaltmalar / semboller
    "tehol", "trhol", "tly", "tera şirketleri",
]

# Aramada kullanılacak anahtarlar (terimlerin kendisi)
KEYWORDS = list(dict.fromkeys(TERA_COMPANY_PHRASES))

# Domain whitelist + uzantı bazlı kabul
DOMAIN_WHITELIST = {
    "kap.org.tr", "bloomberght.com", "dunya.com", "haberturk.com",
    "ntv.com.tr", "aa.com.tr", "trthaber.com", "hurriyet.com.tr",
    "milliyet.com.tr", "sozcu.com.tr", "ekonomim.com", "borsagundem.com",
    "investing.com", "tr.investing.com", "investing.com.tr",
    "reuters.com", "foreks.com", "foreksnews.com",
}
ALLOWED_SUFFIXES = [".com.tr", ".gov.tr", ".edu.tr", ".org.tr", ".net.tr", ".tr"]

# Teşhis için hızlı aç/kapat (geçici). True yaparsan domain filtresi kapanır.
DISABLE_DOMAIN_FILTER = False

# ------------------ FLASK ------------------
app = Flask(__name__)

@app.get("/")
def home():
    return "Alive", 200

@app.get("/health")
def health():
    return {"ok": True, "time": datetime.utcnow().isoformat()}, 200

# ------------------ YARDIMCI ------------------
def send_telegram(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️ TELEGRAM_BOT_TOKEN/CHAT_ID eksik.")
        return
    url  = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
    try:
        r = requests.post(url, data=data, timeout=15)
        print("Telegram gönderildi:", r.status_code)
        if r.status_code != 200:
            print("Yanıt:", r.text)
    except Exception as e:
        print("Telegram hata:", e)

def google_news_rss(query: str) -> str:
    # TR odaklı
    q  = quote_plus(query + " site:tr OR site:.com OR site:.com.tr")
    url = f"https://news.google.com/rss/search?q={q}&hl=tr&gl=TR&ceid=TR:tr"
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    return resp.text

def strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s or "").strip()

def parse_rss(rss_xml: str):
    root = ET.fromstring(rss_xml)
    items = []

    for it in root.findall(".//item"):
        title = (it.findtext("title") or "").strip()
        link  = (it.findtext("link")  or "").strip()
        guid  = (it.findtext("guid")  or "").strip()
        pub   = (it.findtext("pubDate") or "").strip()

        desc  = strip_html(it.findtext("description") or "")

        # feedburner:origLink varsa gerçek link odur
        try:
            orig = it.find("{http://rssnamespace.org/feedburner/ext/1.0}origLink")
            if orig is not None and orig.text:
                link = orig.text.strip()
        except Exception:
            pass

        # pubDate -> datetime (UTC naive)
        pub_dt = None
        if pub:
            try:
                pub_dt = parsedate_to_datetime(pub)
                if pub_dt.tzinfo is not None:
                    pub_dt = pub_dt.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                pub_dt = None

        uid = guid or hashlib.sha256((link + "||" + title).encode("utf-8")).hexdigest()
        items.append({
            "id": uid,
            "title": title,
            "desc": desc,
            "link": link,
            "pub": pub,
            "pub_dt": pub_dt
        })
    return items

def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()
    return set(l.strip() for l in open(SEEN_FILE, encoding="utf-8") if l.strip())

def save_seen(seen: set):
    open(SEEN_FILE, "w", encoding="utf-8").write("\n".join(seen))

def domain_allowed(link: str) -> bool:
    if DISABLE_DOMAIN_FILTER:
        return True
    try:
        host = (urlparse(link).hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]

        # 1) Beyaz listede ise kabul
        if host in DOMAIN_WHITELIST:
            return True

        # 2) Uzantı kabul listesi
        for suf in ALLOWED_SUFFIXES:
            if host.endswith(suf):
                return True

        return False
    except Exception:
        return False

def matches_company(item) -> bool:
    haystack = (item.get("title","") + " " + item.get("desc","")).lower()
    return any(p in haystack for p in TERA_COMPANY_PHRASES)

# ------------------ İŞ AKIŞI ------------------
def bootstrap():
    """İlk çalıştırmada mevcut haberleri 'görüldü' işaretler; bildirim göndermez."""
    seen = load_seen()
    added = 0
    for kw in KEYWORDS:
        try:
            for it in parse_rss(google_news_rss(kw)):
                if it["id"] not in seen:
                    seen.add(it["id"]); added += 1
        except Exception as e:
            print("Bootstrap hata", kw, e)
    save_seen(seen)
    open(INIT_FILE, "w").write(START_TIME.isoformat())
    print(f"✅ İlk kurulum tamam: {added} mevcut haber işaretlendi (bildirim yok).")

def job():
    seen = load_seen()
    new  = []
    for kw in KEYWORDS:
        try:
            for it in parse_rss(google_news_rss(kw)):
                # 1) tekrar kontrolü
                if it["id"] in seen:
                    continue
                # 2) tarih filtresi
                if it["pub_dt"] is not None and it["pub_dt"] < START_TIME:
                    continue
                # 3) domain filtresi
                if not domain_allowed(it["link"]):
                    continue
                # 4) şirket eşleşmesi (başlık + açıklama)
                if not matches_company(it):
                    continue

                new.append((kw, it))
                seen.add(it["id"])
        except Exception as e:
            print("Hata", kw, e)

    if new:
        for kw, it in new:
            msg = f"📰 <b>{kw.upper()}</b>\n{it['title']}\n{it['link']}\n{it.get('pub') or ''}"
            send_telegram(msg)
        save_seen(seen)
        print(datetime.utcnow(), "-", len(new), "haber gönderildi.")
    else:
        print(datetime.utcnow(), "- Yeni haber yok.")

def daily_ping():
    """Her sabah sistemin ayakta olduğunu göstermek için ping mesajı yollar."""
    send_telegram("🟢 <b>Bot aktif</b> – sistem çalışıyor ✅")
    print(datetime.utcnow(), "- Günlük ping gönderildi.")

def scheduler_thread():
    booted_now = False
    if not os.path.exists(INIT_FILE):
        bootstrap()
        booted_now = True

    if booted_now:
        print("⏳ Başlangıç sessiz modu: ilk döngüde bildirim yok.")
        schedule.every(POLL_INTERVAL_MIN).minutes.do(job)
    else:
        job()
        schedule.every(POLL_INTERVAL_MIN).minutes.do(job)

    # Günlük ping – saatini sen 09:15 yaptım demiştin
    schedule.every().day.at("09:15").do(daily_ping)

    while True:
        schedule.run_pending()
        time.sleep(1)

def keepalive_thread():
    url = os.getenv("KEEPALIVE_URL")
    if not url:
        return
    while True:
        try:
            requests.get(url, timeout=10)
        except Exception:
            pass
        time.sleep(240)  # 4 dakikada bir ping

# ------------------ RESET (opsiyonel) ------------------
if os.getenv("RESET") == "1":
    for f in (SEEN_FILE, INIT_FILE):
        try:
            os.remove(f); print("Silindi:", f)
        except FileNotFoundError:
            pass

# ------------------ ENTRYPOINT ------------------
if __name__ == "__main__":
    print("Routes:", app.url_map)
    threading.Thread(target=scheduler_thread, daemon=True).start()
    threading.Thread(target=keepalive_thread, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
