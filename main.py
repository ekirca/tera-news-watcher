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
import urllib
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
import feedparser
import requests
from flask import Flask, jsonify, request
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
    "terayatirim.com",
    "terayatirim.com.tr",
    "x.com",
    "twitter.com",
    "nitter.net",


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

def process_extra_sources(cutoff_time, seen):
    """config.yaml’daki 'sources' listesinden gelen öğeleri işler.
       - zaman filtresi (cutoff_time)
       - domain filtresi
       - tekrarı önleme (seen)
       - Telegram’a gönderim
    """
    new_count = 0
    try:
        extras = gather_extra_sources()
    except Exception as e:
        notify_error(f"extra sources fetch error: {e}")
        return 0

    for it in extras:
        title = (it.get("title") or "").strip()
        url   = (it.get("url")   or "").strip()
        pubts = it.get("published")  # epoch saniye (veya None)
        src   = it.get("source") or "extra"

        # ID: url + timestamp kombinasyonu
        iid = f"{url}|{int(pubts or 0)}"
        if iid in seen:
            continue

        # zaman filtresi
        if pubts:
            try:
                dt = datetime.utcfromtimestamp(pubts)
                if dt < cutoff_time:
                    continue
            except Exception:
                pass  # tarih yoksa geç

        # domain filtresi
        if not domain_allowed(url):
            continue

        # Telegram
        msg = f"🧩 <b>{src}</b>\n{title}\n{url}"
        send_telegram(msg)

        seen.add(iid)
        new_count += 1

    return new_count


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


# --- SEEN dosyasını artımlı yazmak ve son MAX satırı tutmak için ---
def save_seen_incremental(added_ids):
    """Bu run'da bulunan yeni id'leri sona ekler, sonra dosyayı son MAX satıra kırpar."""
    if not added_ids:
        return

    # 1) Sona ekle
    with open(SEEN_FILE, "a", encoding="utf-8") as f:
        for uid in added_ids:
            f.write(uid + "\n")

    # 2) Gerekirse dosyayı son MAX satıra kırp
    try:
        with open(SEEN_FILE, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        return

    if len(lines) > MAX_SEEN_IDS:
        # Sadece SON MAX_SEEN_IDS satırı tut (en tazeler)
        keep = lines[-MAX_SEEN_IDS:]
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(keep))

def save_seen_overwrite(seen_set):
    """Bootstrap gibi 'tam yenileme' durumları için: sırayı umursamadan komple yazar."""
    data = list(seen_set)
    if len(data) > MAX_SEEN_IDS:
        data = data[-MAX_SEEN_IDS:]  # burada sıra önemsiz; bootstrap'ta bildirim de atmıyoruz
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(data))


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

    save_seen_overwrite(seen)
    with open(INIT_FILE, "w", encoding="utf-8") as f:
        f.write(datetime.utcnow().isoformat())
    debug_print(f"✅ İlk kurulum tamam: {added} mevcut haber işaretlendi (bildirim yok).")

    # --- EK KAYNAKLAR (config.yaml) ---
    try:
        extra = gather_extra_sources()
    except Exception as e:
        notify_error(f"extra sources error: {e}")
        extra = []

    for e in extra:
        try:
            title = (e.get("title") or "").strip()
            link  = (e.get("url") or "").strip()
            # ek kaynaklarda benzersiz id:
            uid = f"{e.get('source','ext')}::{link or title}"

            # tekrar kontrolü
            if uid in seen:
                continue

            # zaman filtresi (milisaniye yoksa None gelebilir)
            pub_ts = e.get("published")
            pub_dt = datetime.utcfromtimestamp(pub_ts) if pub_ts else None
            if pub_dt is not None and pub_dt < cutoff_time:
                continue

            # domain filtresi
            if not domain_allowed(link):
                continue

            # şirket eşleşmesi
            item = {"title": title, "desc": "", "link": link}
            if not matches_company(item):
                # X’te @terayatirim ise doğrudan kabul edelim (kurumsal hesap)
                if not (e.get("source") == "x_user" and e.get("meta", {}).get("user") == "terayatirim"):
                    continue

            # gerçekten yeni & ilgili
            new.append(("external", {
                "id": uid,
                "title": title,
                "link": link,
                "pub": "",
                "pub_dt": pub_dt,
                "desc": "",
            }))
            seen.add(uid)
            added_ids.append(uid)
        except Exception as ie:
            notify_error(f"extra item error: {ie}")



# --- ADD: google news fetcher ---
urllib.parse, feedparser

def fetch_google_news(query, lang="tr", region="TR", weight=0):
    params = {"q": query, "hl": lang, "gl": region, "ceid": f"{region}:{lang}"}
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(params)
    feed = feedparser.parse(url)
    items = []
    for e in feed.entries:
        ts = getattr(e, "published_parsed", None)
        items.append({
            "title": e.title,
            "url": e.link,
            "published": time.mktime(ts) if ts else None,
            "source": "google_news",
            "weight": int(weight),
        })
    return items


# --- ADD: x/ nitter fetcher ---


def nitter_to_x(url: str) -> str:
    return url.replace("https://nitter.net/", "https://x.com/")

def fetch_x_user(users, nitter_base="https://nitter.net", weight=0):
    all_items = []
    headers = {"User-Agent": "Mozilla/5.0"}
    for u in users:
        rss = f"{nitter_base.rstrip('/')}/{u}/rss"
        try:
            r = requests.get(rss, timeout=12, headers=headers)
            r.raise_for_status()
        except Exception:
            continue
        feed = feedparser.parse(r.text)
        for e in feed.entries:
            ts = getattr(e, "published_parsed", None)
            all_items.append({
                "title": e.title,                # tweet metni
                "url": nitter_to_x(e.link),      # x.com’a çevir
                "published": time.mktime(ts) if ts else None,
                "source": "x_user",
                "weight": int(weight),
                "meta": {"user": u},
            })
    return all_items

TRIM_SEEN_KEEP = int(os.getenv("TRIM_SEEN_KEEP", "20000"))  # en yeni kaç ID kalsın
TRIM_RUN_HOUR  = os.getenv("TRIM_RUN_HOUR", "03:10")        # her gün şu saatte çalışsın (GMT+3'e göre)

def trim_seen_file(keep: int = TRIM_SEEN_KEEP):
    """seen_ids.txt'yi budar: en yeni KEEP satırı bırakır."""
    try:
        if not os.path.exists(SEEN_FILE):
            return
        with open(SEEN_FILE, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        if len(lines) <= keep:
            debug_print(f"[trim] Gerek yok (satır={len(lines)} <= keep={keep}).")
            return
        # En sondaki satırlar en yeni eklenenler olduğu için sondan KEEP kadarını al
        new_lines = lines[-keep:]
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines))
        debug_print(f"[trim] seen_ids.txt budandı: {len(lines)} -> {len(new_lines)}")
    except Exception as e:
        notify_error(f"seen_ids.txt budanırken hata: {e}")


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

    added_ids = []  # bu run'da ilk kez görülen id'ler

    
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
                added_ids.append(it["id"])   # <-- EKLEDİK


                added_ids.append(it["id"])      # Google News tarafında
                # ve external blokta:
                added_ids.append(uid)           # x_user / extra kaynaklar tarafında


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
            save_seen_incremental(added_ids)
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

    # Günlük budama (ör. 03:10)
    schedule.every().day.at(TRIM_RUN_HOUR).do(trim_seen_file)


# --- ADD: config.yaml oku ve kaynakları çalıştır ---
import yaml, os
from urllib.parse import urlparse

def load_config():
    try:
        with open("config.yaml", "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

CFG = load_config()

def gather_extra_sources():
    items = []
    for src in CFG.get("sources", []):
        t = src.get("type")
        if t == "google_news":
            items.extend(fetch_google_news(
                query=src.get("query", "TERA YATIRIM"),
                lang=src.get("lang", "tr"),
                region=src.get("region", "TR"),
                weight=src.get("weight", 0),
            ))
        elif t == "x_user":
            items.extend(fetch_x_user(
                users=src.get("users", []),
                nitter_base=src.get("nitter_base", "https://nitter.net"),
                weight=src.get("weight", 0),
            ))
    return items

def job():
    global LAST_JOB_TIME
    now = datetime.utcnow()
    cutoff_time = now - timedelta(hours=MAX_AGE_HOURS)

    debug_print("===== JOB BAŞLANGIÇ =====", now.isoformat(), "cutoff_time:", cutoff_time.isoformat())
    seen = load_seen()
    new = []

    # (1) Google News (anahtar kelime) taraması – sizde zaten var
    for kw in KEYWORDS:
        ...
        # uygun haberleri new listesine ekleyip seen’e ekliyorsunuz
        ...

    # (2) Ek kaynaklar (config.yaml: google_news / x_user)
    try:
        extra_sent = process_extra_sources(cutoff_time, seen)
    except Exception as e:
        notify_error(f"extra item error: {e}")
        extra_sent = 0

    LAST_JOB_TIME = datetime.utcnow()

    # (3) Anahtar kelime kısmından çıkanları gönderin
    if new:
        for kw, it in new:
            msg = f"📰 <b>{kw.upper()}</b>\n{it['title']}\n{it['link']}\n{it.get('pub') or ''}"
            send_telegram(msg)

    # (4) seen’i bir kere kaydedin
    save_seen(seen)

    sent_total = (len(new) if new else 0) + extra_sent
    if sent_total > 0:
        debug_print(LAST_JOB_TIME, "-", sent_total, "haber gönderildi.")
    else:
        debug_print(LAST_JOB_TIME, "- Yeni haber yok.")
    debug_print("===== JOB BİTTİ =====")


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
    """
    /test?msg=...  -> Telegram'a serbest mesaj yollar.
    parametre verilmezse varsayılan kısa test mesajı atar.
    """
    msg = request.args.get("msg", "").strip()
    if not msg:
        msg = "🧪 Test bildirimi: sistem çalışıyor."
    send_telegram(msg)
    return f"Test bildirimi gönderildi: {msg}", 200


@app.get("/restart")
def restart():
    """
    Self-restart endpoint:
    - Cron-job burayı çağırınca
    - Uygulama 2 saniye sonra kendini kapatır
    - Render otomatik olarak yeniden ayağa kaldırır
    """

    # İsteğe bağlı güvenlik: RESTART_TOKEN tanımlıysa, token=... ile gelmeyenleri reddet
    env_token = os.getenv("RESTART_TOKEN", "").strip()
    req_token = (request.args.get("token") or "").strip()

    if env_token:
        if req_token != env_token:
            return jsonify({"ok": False, "error": "unauthorized"}), 403

    debug_print("♻️ Self-restart istendi, 2 saniye içinde çıkış yapılacak...")

    def _do_exit():
        time.sleep(2)
        debug_print("Self-restart: process sonlandırılıyor (Render yeniden başlatacak).")
        os._exit(0)

    threading.Thread(target=_do_exit, daemon=True).start()

    return jsonify({"ok": True, "message": "restart scheduled"}), 200




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
