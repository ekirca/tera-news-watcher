#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tera News Watcher – runner.py

Çalışma mantığı (cron ile tetiklenir):
  - 07:00 → --mode morning
  - 17:00 → --mode evening

GÖREV:
  1) .env ve config.yaml yükle
  2) kaynakları (RSS/Web) çek
  3) dil/anahtar kelime/domain filtrelerini uygula
  4) dedupe (seen.json) → tekrarları engelle
  5) Telegram'a gönder
  6) {"ok": true, "count": N} çıktısı ver ve çık

GEREKSİNİMLER (requirements.txt)
  requests
  pyyaml
  python-dotenv  (opsiyonel; .env okumak için)
  feedparser     (opsiyonel; RSS parse için)

ENV (örnek .env)
  TOKEN=123:abc
  CHAT_ID=-100123456789
  DISABLE_DOMAIN_FILTER=false
  TZ=Europe/Istanbul

KONUM ÖNERİSİ
  /opt/tera/runner.py
  /opt/tera/config.yaml
  /opt/tera/.env
  /var/lib/tera/seen.json  (otomatik oluşturulur)
  /var/log/tera/app.log     (opsiyonel)
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List

# --- üçüncü parti ---
try:
    import yaml  # pyyaml
except Exception as e:
    print("[fatal] pyyaml eksik: pip install pyyaml", file=sys.stderr)
    raise

try:
    import requests
except Exception as e:
    print("[fatal] requests eksik: pip install requests", file=sys.stderr)
    raise

# .env opsiyonel
try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    def load_dotenv(*_args: Any, **_kwargs: Any) -> None:
        pass

# RSS için feedparser opsiyonel; yoksa çok basit XML fallback yapılır
try:
    import feedparser  # type: ignore
except Exception:
    feedparser = None  # type: ignore
    import xml.etree.ElementTree as ET


# ————————————————————————————————————————————————————————————
# Logging
# ————————————————————————————————————————————————————————————
LOG = logging.getLogger("tera")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")


# ————————————————————————————————————————————————————————————
# Utilities
# ————————————————————————————————————————————————————————————
ISO = "%Y-%m-%dT%H:%M:%SZ"
SEEN_PATH = "/var/lib/tera/seen.json"
DEFAULT_TIMEOUT = 15


def ensure_dirs() -> None:
    try:
        os.makedirs(os.path.dirname(SEEN_PATH), exist_ok=True)
    except Exception:
        pass


def load_env(env_path: str) -> None:
    """Load .env if exists."""
    if os.path.isfile(env_path):
        load_dotenv(env_path)
        LOG.info(".env yüklendi: %s", env_path)
    else:
        LOG.info(".env bulunamadı (opsiyonel): %s", env_path)


def load_config(cfg_path: str) -> Dict[str, Any]:
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    # Env override
    if os.getenv("KEYWORDS_INCLUDE"):
        cfg.setdefault("filters", {})["keywords_include"] = [s.strip() for s in os.getenv("KEYWORDS_INCLUDE", "").split(",") if s.strip()]
    if os.getenv("KEYWORDS_EXCLUDE"):
        cfg.setdefault("filters", {})["keywords_exclude"] = [s.strip() for s in os.getenv("KEYWORDS_EXCLUDE", "").split(",") if s.strip()]
    if os.getenv("DOMAINS_ALLOWLIST"):
        cfg.setdefault("filters", {})["domains_allowlist"] = [s.strip() for s in os.getenv("DOMAINS_ALLOWLIST", "").split(",") if s.strip()]
    return cfg


def extract_domain(url: str) -> str:
    try:
        m = re.match(r"^https?://([^/]+)/?", url)
        return (m.group(1) if m else "").lower()
    except Exception:
        return ""


# ————————————————————————————————————————————————————————————
# Fetchers
# ————————————————————————————————————————————————————————————

def fetch_rss(url: str, timeout: int) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        if feedparser is not None:
            d = feedparser.parse(url)  # type: ignore
            for e in d.entries:
                link = getattr(e, "link", "")
                items.append({
                    "uid": getattr(e, "id", link) or link,
                    "title": getattr(e, "title", "").strip(),
                    "summary": getattr(e, "summary", ""),
                    "url": link,
                    "domain": extract_domain(link),
                    "lang": "tr" if "lang=tr" in url else None,
                })
            return items
        # Basit XML fallback
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        for item in root.findall(".//item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            desc = (item.findtext("description") or "").strip()
            items.append({
                "uid": link or title,
                "title": title,
                "summary": desc,
                "url": link,
                "domain": extract_domain(link),
                "lang": "tr" if "lang=tr" in url else None,
            })
    except Exception as e:
        LOG.warning("RSS fetch fail: %s: %s", url, e)
    return items


def fetch_sources(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    runtime = cfg.get("runtime", {})
    timeout = int(runtime.get("request_timeout_s", DEFAULT_TIMEOUT))

    items: List[Dict[str, Any]] = []
    rss_list: Iterable[str] = cfg.get("sources", {}).get("rss", [])
    for url in rss_list:
        items.extend(fetch_rss(url, timeout))

    # İleride web scraping veya API eklenecekse buraya eklenebilir.
    return items


# ————————————————————————————————————————————————————————————
# Filters & Dedupe
# ————————————————————————————————————————————————————————————

def passes_filters(item: Dict[str, Any], flt: Dict[str, Any]) -> bool:
    text = f"{item.get('title','')} {item.get('summary','')}".lower()

    # Dil filtresi (çok kaba)
    lang_req = flt.get("lang")
    if lang_req and item.get("lang") and item.get("lang") != lang_req:
        return False

    inc = [s.lower() for s in flt.get("keywords_include", [])]
    exc = [s.lower() for s in flt.get("keywords_exclude", [])]
    if inc and not all(k in text for k in inc):
        return False
    if any(k in text for k in exc):
        return False

    allow = flt.get("domains_allowlist", [])
    disable_domain_filter = os.getenv("DISABLE_DOMAIN_FILTER", "false").lower() == "true"
    if allow and not disable_domain_filter:
        dom = (item.get("domain") or "").lower()
        if dom not in [d.lower() for d in allow]:
            return False

    return True


def dedupe(items: List[Dict[str, Any]], window_hours: int) -> List[Dict[str, Any]]:
    ensure_dirs()
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)

    try:
        with open(SEEN_PATH, "r", encoding="utf-8") as f:
            seen: Dict[str, str] = json.load(f)
    except Exception:
        seen = {}

    out: List[Dict[str, Any]] = []
    for it in items:
        uid = it.get("uid") or it.get("url")
        if not uid:
            continue
        ts = seen.get(uid)
        if ts:
            try:
                if datetime.fromisoformat(ts.replace("Z", "+00:00")) > cutoff:
                    continue
            except Exception:
                pass
        out.append(it)
        seen[uid] = datetime.utcnow().strftime(ISO)

    try:
        with open(SEEN_PATH, "w", encoding="utf-8") as f:
            json.dump(seen, f, ensure_ascii=False)
    except Exception as e:
        LOG.warning("seen.json yazılamadı: %s", e)

    return out


# ————————————————————————————————————————————————————————————
# Telegram
# ————————————————————————————————————————————————————————————

def fmt_telegram(item: Dict[str, Any], mode: str) -> str:
    tag = "SABAH" if mode == "morning" else "AKŞAM"
    title = item.get("title", "(başlık yok)")
    url = item.get("url", "")
    src = item.get("domain", "")
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    return f"<b>[{tag}]</b> {title}\n<b>Kaynak:</b> {src} | <a href='{url}'>link</a> | <i>{ts}</i>"


def send_telegram(msgs: List[str], token: str, chat_id: str) -> None:
    api = f"https://api.telegram.org/bot{token}/sendMessage"
    for m in msgs:
        try:
            requests.post(api, json={"chat_id": chat_id, "text": m, "parse_mode": "HTML"}, timeout=15)
            time.sleep(0.25)
        except Exception as e:
            LOG.error("telegram err: %s", e)


# ————————————————————————————————————————————————————————————
# Main
# ————————————————————————————————————————————————————————————

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["morning", "evening"], default="morning")
    ap.add_argument("--config", default="/opt/tera/config.yaml")
    ap.add_argument("--env", default="/opt/tera/.env")
    args = ap.parse_args()

    load_env(args.env)

    token = os.environ.get("TOKEN")
    chat_id = os.environ.get("CHAT_ID")
    if not token or not chat_id:
        print(json.dumps({"ok": False, "error": "TOKEN/CHAT_ID missing"}))
        sys.exit(2)

    cfg = load_config(args.config)
    runtime = cfg.get("runtime", {})

    LOG.info("Mode=%s", args.mode)
    items = fetch_sources(cfg)

    flt = cfg.get("filters", {})
    items = [it for it in items if passes_filters(it, flt)]

    window = int(runtime.get("dedupe_window_hours", 48))
    items = dedupe(items, window)

    max_items = int(runtime.get("max_items", 25))
    items = items[:max_items]

    msgs = [fmt_telegram(it, args.mode) for it in items]

    if msgs:
        send_telegram(msgs, token, chat_id)
        LOG.info("sent %d items", len(msgs))
    else:
        LOG.info("no items to send")

    print(json.dumps({"ok": True, "count": len(msgs)}))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        LOG.exception("fatal error: %s", e)
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(1)
