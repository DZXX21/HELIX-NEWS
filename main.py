# -*- coding: utf-8 -*-
"""
Siber güvenlik haberlerini toplar, Gemini ile TÜRKÇE özetler ve Telegram'a gönderir.
Kullanım:
  python x2.py --telegram --today                    # Bugünün haberleri
  python x2.py --telegram --since 3 --max-per-run 10 # Son 3 gün, maks 10 haber
  python x2.py --telegram --stream-delay 5           # Her haber arası 5 sn
"""

import argparse, json, time, requests, feedparser, os, re, html as _html
import random
from pathlib import Path
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
from dateutil import parser as dtparse
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# .env dosyası desteği
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Zaman dilimi
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

LOCAL_TZ_NAME = "Europe/Istanbul"

# Gemini API
import google.generativeai as genai
# Hardcoded defaults (güvenlik için production'da .env kullanın)
GOOGLE_API_KEY = "AIzaSyCQ5fP6qv_rpjKmnIWOHk7GKUHg_GYtkHA"
TELEGRAM_BOT_TOKEN = "8296265153:AAFaC70LW7mmFWVL4jpu-ZhMJ0KLQSKo7ik"
TELEGRAM_CHAT_ID = "@hlxnews"

# .env varsa override et
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", GOOGLE_API_KEY)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID)

# Gemini hata sınıfları
try:
    from google.api_core import exceptions as gex
except ImportError:
    gex = None

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 20
AI_MAX_RETRIES = 5
AI_INITIAL_BACKOFF = 8

# RSS kaynakları
RSS_SOURCES = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "DarkReading": "https://www.darkreading.com/rss.xml",
    "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml",
    "Malwarebytes Labs": "https://www.malwarebytes.com/blog/rss",
    "Cisco Talos": "https://blog.talosintelligence.com/feeds/posts/default?alt=rss",
    "Mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
    "Unit 42": "https://unit42.paloaltonetworks.com/feed/",
}
KREBS_HOME = "https://krebsonsecurity.com/"

# ============= YARDIMCI FONKSİYONLAR =============

def log(msg: str, emoji: str = "ℹ️"):
    """Zaman damgalı log mesajı"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {emoji} {msg}")

def get_local_tz():
    """Yerel saat dilimini al"""
    if ZoneInfo:
        try:
            return ZoneInfo(LOCAL_TZ_NAME)
        except Exception:
            pass
    return timezone.utc

def parse_date(d):
    """Tarih string'ini UTC datetime'a çevir"""
    if not d:
        return None
    try:
        dt = dtparse.parse(d)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def clean_text(html_content, limit=800):
    """HTML'den temiz metin çıkar"""
    soup = BeautifulSoup(html_content or "", "html.parser")
    for tag in soup(["script", "style", "noscript", "iframe"]):
        tag.decompose()
    text = " ".join(soup.get_text(" ").split())
    return text[:limit].strip()

def extract_image(entry):
    """RSS entry'den resim URL'i çıkar"""
    # Media içeriği
    media = entry.get("media_content") or entry.get("media_thumbnail")
    if media and isinstance(media, list) and media[0].get("url"):
        return media[0]["url"]
    
    # Link içinde resim
    if "links" in entry:
        for link in entry["links"]:
            if link.get("type", "").startswith("image") and "href" in link:
                return link["href"]
    
    # Summary/description içinde <img>
    desc = entry.get("summary") or entry.get("description") or ""
    soup = BeautifulSoup(desc, "html.parser")
    img = soup.find("img")
    if img and img.get("src"):
        return img["src"]
    
    return None

def is_today(dt_utc, local_tz):
    """Tarih bugün mü kontrol et"""
    if not dt_utc:
        return False
    now_local = datetime.now(local_tz)
    start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = start_local + timedelta(days=1)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc = end_local.astimezone(timezone.utc)
    return start_utc <= dt_utc < end_utc

# ============= STATE YÖNETİMİ =============

def load_state(path: Path) -> set:
    """Görülen URL'leri yükle"""
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return set(data if isinstance(data, list) else [])
        except Exception as e:
            log(f"State yükleme hatası: {e}", "⚠️")
            return set()
    return set()

def save_state(path: Path, url_set: set):
    """Görülen URL'leri kaydet"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(sorted(url_set), ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
    except Exception as e:
        log(f"State kaydetme hatası: {e}", "⚠️")

def filter_new_items(items, seen: set):
    """Yeni haberleri filtrele"""
    return [item for item in items if item.get("url") and item["url"] not in seen]

# ============= URL İŞLEMLERİ =============

DROP_QS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"}

def normalize_url(url: str) -> str:
    """URL'i normalize et"""
    if not url:
        return url
    try:
        parsed = urlparse(url)
        query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) 
                 if k.lower() not in DROP_QS]
        normalized = parsed._replace(
            scheme=parsed.scheme.lower() or "https",
            netloc=parsed.netloc.lower(),
            path=parsed.path.rstrip("/") or "/",
            params="",
            query=urlencode(query, doseq=True),
            fragment=""
        )
        return urlunparse(normalized)
    except Exception:
        return url

def dedupe_by_url(items):
    """Tekrarlayan URL'leri temizle"""
    seen, unique = set(), []
    for item in items:
        url = normalize_url(item.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        item["url"] = url
        unique.append(item)
    return unique

# ============= MAKALE İÇERİĞİ =============

def _meta(soup, *names):
    """Meta tag'den değer al"""
    for name in names:
        meta = soup.find("meta", attrs={"name": name}) or \
               soup.find("meta", attrs={"property": name})
        if meta and meta.get("content"):
            return meta["content"].strip()
    return None

def fetch_article_body(url: str, timeout=20) -> str:
    """Makale içeriğini çek"""
    try:
        response = requests.get(url, headers={"User-Agent": UA}, timeout=timeout)
        response.raise_for_status()
    except Exception:
        return ""

    soup = BeautifulSoup(response.text, "html.parser")
    meta_desc = _meta(soup, "og:description", "description", "twitter:description") or ""
    parts = [meta_desc]

    # İçerik seçicileri
    candidates = [
        "article", "[itemprop='articleBody']",
        ".article-content", ".post-content", ".entry-content",
        ".c-article__body", ".td-post-content", ".postBody",
        ".content__article-body", ".single-post-content",
        ".main-content", ".content"
    ]
    
    text_chunks = []
    for selector in candidates:
        node = soup.select_one(selector)
        if node:
            for p in node.select("p"):
                text = p.get_text(" ", strip=True)
                if len(text) > 40:
                    text_chunks.append(text)
            if text_chunks:
                break

    # Site-spesifik seçiciler
    host = urlparse(url).netloc.lower()
    if not text_chunks:
        site_selectors = {
            "darkreading.com": "div.article-content p",
            "securityweek.com": "div.node-content p, article p",
            "thehackernews.com": "div.post-body p"
        }
        for domain, selector in site_selectors.items():
            if domain in host:
                for p in soup.select(selector):
                    text = p.get_text(" ", strip=True)
                    if len(text) > 40:
                        text_chunks.append(text)
                break

    if text_chunks:
        parts.append("\n".join(text_chunks))

    full_text = " ".join(parts)
    full_text = re.sub(r"\s+", " ", full_text).strip()
    return full_text[:6000]

# ============= HABER TOPLAYICILAR =============

def fetch_rss(name, url, since_days=7, today_only=False, local_tz=timezone.utc):
    """RSS feed'den haberleri topla"""
    results = []
    feed = feedparser.parse(url)
    threshold = datetime.now(timezone.utc) - timedelta(days=since_days)
    
    for entry in feed.entries:
        pub_date = parse_date(entry.get("published") or entry.get("updated") or entry.get("pubDate"))
        
        if today_only:
            if not is_today(pub_date, local_tz):
                continue
        else:
            if pub_date and pub_date < threshold:
                continue

        link = (entry.get("link") or "").strip()
        desc_html = entry.get("summary") or entry.get("description") or ""
        snippet = clean_text(desc_html, limit=1200)

        # Kısa snippet varsa tam makaleyi çek
        if link and len(snippet) < 200:
            body = fetch_article_body(link)
            if len(body) > len(snippet):
                snippet = body

        results.append({
            "source": name,
            "title_raw": (entry.get("title") or "").strip(),
            "url": link,
            "published_utc": pub_date.isoformat() if pub_date else None,
            "snippet": snippet,
            "image_url": extract_image(entry),
        })
    
    return results

def fetch_krebs(today_only=False, local_tz=timezone.utc, max_pages=1, limit=10):
    """Krebs On Security'den haberleri topla"""
    results, seen, url = [], set(), KREBS_HOME
    session = requests.Session()
    session.headers["User-Agent"] = UA
    pages = 0
    
    while url and pages < max_pages and len(results) < limit:
        try:
            response = session.get(url, timeout=TIMEOUT)
            response.raise_for_status()
        except Exception as e:
            log(f"Krebs sayfası çekilemedi: {e}", "⚠️")
            break
            
        soup = BeautifulSoup(response.text, "html.parser")
        
        for anchor in soup.select("h2.entry-title a"):
            link = anchor.get("href")
            title_raw = anchor.get_text(strip=True)
            
            if not link or link in seen:
                continue
            seen.add(link)

            # Tarih bilgisini al
            pub_dt = None
            try:
                article_response = session.get(link, timeout=TIMEOUT)
                article_response.raise_for_status()
                article_soup = BeautifulSoup(article_response.text, "html.parser")
                time_tag = article_soup.find("time", {"class": "entry-date"}) or \
                          article_soup.find("meta", {"property": "article:published_time"})
                if time_tag:
                    raw_date = time_tag.get("datetime") if time_tag.has_attr("datetime") else \
                              time_tag.get("content") if time_tag.has_attr("content") else None
                    pub_dt = parse_date(raw_date)
            except Exception:
                pass

            if today_only and not is_today(pub_dt, local_tz):
                continue

            # Resim bul
            img = None
            article = anchor.find_parent("article")
            if article:
                img_tag = article.find("img")
                if img_tag and img_tag.get("src"):
                    img = img_tag["src"]

            body = fetch_article_body(link)

            results.append({
                "source": "KrebsOnSecurity",
                "title_raw": title_raw,
                "url": link,
                "published_utc": pub_dt.isoformat() if pub_dt else None,
                "snippet": body if body else "",
                "image_url": img,
            })
            
            if len(results) >= limit:
                break
        
        next_link = soup.select_one("a.older-posts, .nav-previous a")
        url = next_link.get("href") if next_link else None
        pages += 1
    
    return results

# ============= AI ÖZETLEMscripE =============

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)

def safe_json_extract(text: str):
    """Markdown fence'leri temizleyip JSON çıkar"""
    if not text:
        return None
    text = _JSON_FENCE_RE.sub("", text.strip())
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end+1])
        except Exception:
            return None
    return None

PROMPT_TEMPLATE = """
Sen profesyonel bir Türk siber güvenlik analistisiniz.

KURALLAR:
- YANIT DİLİ: SADECE TÜRKÇE (JSON alan adları İngilizce, değerler Türkçe)
- KALIP CÜMLE YOK: "Bu haber önemli..." gibi genel ifadeler YASAK
- SPESIFIK OL: Ürün/sürüm, CVE, istismar durumu, yama bilgisi, etki alanı belirt
- TEKRARpython, YAPMA

TERİM ÇEVİRİLERİ:
malware→kötücül yazılım, vulnerability→güvenlik açığı, exploit→istismar,
patch→yama, ransomware→fidye yazılımı, phishing→oltalama,
zero-day→sıfır gün açığı, breach→ihlal, APT→gelişmiş kalıcı tehdit

JSON ŞEMASI:
{{
  "title": "TÜRKÇE başlık (kısa ve öz)",
  "url": "string",
  "summary": "TÜRKÇE özet (2-4 cümle, tamamen somut)",
  "key_points": ["Somut madde 1", "Somut madde 2", "Somut madde 3"],
  "tags": ["türkçe-etiket1", "türkçe-etiket2"],
  "risk_level": "low|medium|high",
  "entities": {{
    "vendors": ["Şirket adı"],
    "products": ["Ürün ve sürüm"],
    "cves": ["CVE-YYYY-NNNN"],
    "malware": ["Kötücül yazılım adı"],
    "apt_groups": ["Tehdit grubu adı"]
  }}
}}

RİSK SEVİYESİ:
- high: Aktif istismar/veri sızıntısı/geniş etki/acil yama gerekli
- medium: Yama mevcut VEYA sınırlı koşullarda istismar
- low: Düşük etki/teorik risk

MAKALE:
Başlık: {title}
URL: {url}
İçerik: {snippet}

SADECE GEÇERLİ JSON ÇIKTI VER (markdown yok).
"""

GENERIC_PATTERNS = [
    "bu haber siber güvenlik alanında önemli",
    "kullanıcılar dikkatli olmalı",
    "güvenlik uzmanları durumu yakından takip"
]

def looks_generic(data: dict) -> bool:
    """Özet jenerik mi kontrol et"""
    summary = (data.get("summary") or "").lower()
    key_points = " ".join(data.get("key_points") or []).lower()
    
    if len(summary) < 60:
        return True
    
    return any(pattern in summary or pattern in key_points for pattern in GENERIC_PATTERNS)

def enrich_entities_from_text(data: dict, raw_text: str):
    """Metinden varlıkları çıkar ve zenginleştir"""
    text = raw_text or ""
    
    # CVE'leri bul
    cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.I))
    if cves:
        data.setdefault("entities", {}).setdefault("cves", [])
        for cve in cves:
            if cve.upper() not in data["entities"]["cves"]:
                data["entities"]["cves"].append(cve.upper())

    # Ürün/şirket adlarını bul (basit)
    candidates = set()
    blob = (data.get("title", "") + " " + text[:800])
    for token in re.findall(r"\b[A-Z][A-Za-z0-9\-\._]{2,}\b", blob):
        if token.lower() not in {"the", "and", "for", "with", "this", "that", "has", "was", "are"}:
            candidates.add(token)

    if candidates:
        data.setdefault("entities", {}).setdefault("vendors", [])
        for cand in list(candidates)[:8]:
            if cand not in data["entities"]["vendors"]:
                data["entities"]["vendors"].append(cand)

_RETRY_SECONDS_RE = re.compile(r"seconds:\s*(\d+)", re.I)

def _extract_retry_delay_seconds(err) -> int:
    """Hata mesajından retry süresi çıkar"""
    try:
        match = _RETRY_SECONDS_RE.search(str(err))
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return 0

def generate_json_with_retry(model, prompt: str) -> dict:
    """Gemini'den JSON al (retry/backoff ile)"""
    for attempt in range(1, AI_MAX_RETRIES + 1):
        try:
            response = model.generate_content(prompt)
            response_text = (getattr(response, "text", "") or "").strip()
            
            if len(response_text) > 100:
                log(f"Gemini yanıt (ilk 150 kar): {response_text[:150]}...", "🤖")
            
            data = safe_json_extract(response_text)
            if data:
                return data
            
            raise ValueError("Model JSON üretemedi")
            
        except Exception as e:
            retriable = False
            delay = 0

            if gex:
                retriable_types = (
                    gex.ResourceExhausted,
                    gex.ServiceUnavailable,
                    gex.DeadlineExceeded,
                    gex.Aborted,
                )
                if isinstance(e, retriable_types):
                    retriable = True
                    delay = _extract_retry_delay_seconds(e)

            if isinstance(e, requests.RequestException):
                retriable = True

            if attempt >= AI_MAX_RETRIES or not retriable:
                log(f"Gemini hata ({attempt}/{AI_MAX_RETRIES}): {e}", "❌")
                return None

            base_delay = delay if delay else (AI_INITIAL_BACKOFF * (2 ** (attempt - 1)))
            sleep_time = base_delay + random.uniform(0, 0.3 * base_delay)
            log(f"Retry {attempt}/{AI_MAX_RETRIES} — {sleep_time:.1f}s bekleniyor", "⏳")
            time.sleep(sleep_time)
    
    return None

def summarize_one(item, model, delay=1.0):
    """Bir haberi özetle"""
    title = item.get("title_raw") or ""
    url = item.get("url") or ""
    snippet = item.get("snippet") or ""

    # İlk deneme
    prompt1 = PROMPT_TEMPLATE.format(title=title, url=url, snippet=snippet[:4000])
    data = generate_json_with_retry(model, prompt1)

    # Jenerik geldiyse ikinci deneme
    if not data or looks_generic(data):
        log("Jenerik özet, yeniden deneniyor...", "🔄")
        prompt2 = PROMPT_TEMPLATE + "\n\nÖNEMLİ: Kalıp cümle kurma! Somut bulgular: CVE, ürün, sürüm, yama durumu belirt."
        prompt2 = prompt2.format(title=title, url=url, snippet=snippet[:4000])
        data = generate_json_with_retry(model, prompt2)

    # Hala başarısızsa fallback
    if not data:
        log(f"JSON çıkarılamadı, fallback özet oluşturuluyor", "⚠️")
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", snippet or "", flags=re.I)
        data = {
            "title": title if title else "Siber Güvenlik Haberi",
            "url": url,
            "summary": "Siber güvenlik alanında yeni bir gelişme rapor edildi. Detaylı bilgi için kaynak makaleye bakılmalıdır.",
            "key_points": ["Sınırlı veri mevcut", "Kaynak sayfasını inceleyin", "Güncellemeleri takip edin"],
            "tags": ["siber-güvenlik", "genel-haber"],
            "risk_level": "medium",
            "entities": {
                "vendors": [],
                "products": [],
                "cves": [c.upper() for c in cves],
                "malware": [],
                "apt_groups": []
            },
        }

    # Varlıkları zenginleştir
    enrich_entities_from_text(data, snippet)

    # Gecikme
    time.sleep(delay)
    
    # Resim ekle
    if item.get("image_url"):
        data["image_url"] = item["image_url"]
    
    return data

# ============= TELEGRAM =============

TG_API_BASE = "https://api.telegram.org/bot{token}"

def html_escape(text: str) -> str:
    """HTML özel karakterlerini escape et"""
    return _html.escape(text or "", quote=True)

def format_summary_html(item: dict) -> str:
    """Özeti Telegram HTML formatına çevir"""
    title = html_escape(item.get("title") or "Başlık yok")
    url = (item.get("url") or "").strip()
    summary = html_escape(item.get("summary") or "")
    risk = (item.get("risk_level") or "medium").lower()
    risk_emoji = {"low": "🟢", "medium": "🟠", "high": "🔴"}.get(risk, "🟠")

    # Key points
    key_points = item.get("key_points") or []
    kp_block = "\n".join(f"• {html_escape(kp)}" for kp in key_points) if key_points else ""

    # Entities
    entities = item.get("entities") or {}
    entity_lines = []
    
    tags = item.get("tags") or []
    if tags:
        entity_lines.append("<b>📌 Etiketler:</b>\n" + "\n".join(f"• {html_escape(t)}" for t in tags))
    
    if entities.get("cves"):
        entity_lines.append("<b>🔍 CVE:</b>\n" + "\n".join(f"• <code>{html_escape(c)}</code>" for c in entities["cves"]))
    
    if entities.get("malware"):
        entity_lines.append("<b>🦠 Kötücül Yazılım:</b>\n" + "\n".join(f"• {html_escape(m)}" for m in entities["malware"]))
    
    if entities.get("apt_groups"):
        entity_lines.append("<b>👥 Tehdit Grupları:</b>\n" + "\n".join(f"• {html_escape(a)}" for a in entities["apt_groups"]))
    
    if entities.get("vendors"):
        vendor_list = entities["vendors"][:5]  # İlk 5'i göster
        entity_lines.append("<b>🏢 Şirketler:</b>\n" + "\n".join(f"• {html_escape(v)}" for v in vendor_list))
    
    if entities.get("products"):
        product_list = entities["products"][:5]
        entity_lines.append("<b>💻 Ürünler:</b>\n" + "\n".join(f"• {html_escape(p)}" for p in product_list))
    
    entity_block = "\n\n".join(entity_lines)
    link_text = f"👉 <a href=\"{html_escape(url)}\">Haberi Oku</a>" if url else ""

    # Tüm parçaları birleştir
    parts = [
        f"<b>{title}</b> {risk_emoji}",
        f"\n{summary}" if summary else "",
        f"\n\n<b>📋 Önemli Noktalar:</b>\n{kp_block}" if kp_block else "",
        f"\n\n{link_text}" if link_text else "",
        f"\n\n{entity_block}" if entity_block else ""
    ]
    
    return "".join(parts).strip()

def tg_send_message(token: str, chat_id: str, text_html: str):
    """Telegram'a metin mesajı gönder"""
    url = TG_API_BASE.format(token=token) + "/sendMessage"
    data = {
        "chat_id": chat_id,
        "text": text_html,
        "parse_mode": "HTML",
        "disable_web_page_preview": False
    }
    response = requests.post(url, data=data, timeout=30)
    if response.status_code != 200:
        raise RuntimeError(f"Telegram sendMessage hata: {response.status_code} - {response.text}")
    return response.json()

def tg_send_photo(token: str, chat_id: str, photo_url: str, caption_html: str):
    """Telegram'a fotoğraflı mesaj gönder"""
    url = TG_API_BASE.format(token=token) + "/sendPhoto"
    
    # Caption uzunluk kontrolü (Telegram limiti: 1024 karakter)
    if len(caption_html) > 1024:
        caption_html = caption_html[:1020] + "..."
    
    data = {
        "chat_id": chat_id,
        "photo": photo_url,
        "caption": caption_html,
        "parse_mode": "HTML"
    }
    response = requests.post(url, data=data, timeout=30)
    if response.status_code != 200:
        raise RuntimeError(f"Telegram sendPhoto hata: {response.status_code} - {response.text}")
    return response.json()

def tg_send_news(token: str, chat_id: str, item: dict):
    """Haberi Telegram'a gönder"""
    caption = format_summary_html(item)
    img_url = item.get("image_url")
    
    if img_url:
        try:
            return tg_send_photo(token, chat_id, img_url, caption)
        except Exception as e:
            log(f"Fotoğraf gönderilemedi, metin olarak gönderiliyor: {e}", "⚠️")
            return tg_send_message(token, chat_id, caption)
    else:
        return tg_send_message(token, chat_id, caption)

# ============= ANA AKIŞ =============

def run_once(args):
    """Ana işlem akışı"""
    global LOCAL_TZ_NAME, AI_MAX_RETRIES, AI_INITIAL_BACKOFF
    LOCAL_TZ_NAME = args.tz
    AI_MAX_RETRIES = max(1, int(args.ai_max_retries))
    AI_INITIAL_BACKOFF = max(1, int(args.ai_initial_backoff))

    local_tz = get_local_tz()
    state_path = Path(args.state).expanduser().resolve()
    seen_urls = set() if args.reset_state else load_state(state_path)
    
    log(f"Başlatıldı | today={args.today} since={args.since} seen={len(seen_urls)} tz={LOCAL_TZ_NAME}", "🚀")

    # ========== HABER TOPLAMA ==========
    items = []
    log(f"RSS kaynaklarından haberler toplanıyor ({len(RSS_SOURCES)} kaynak)...", "📡")
    
    for name, url in RSS_SOURCES.items():
        try:
            fetched = fetch_rss(name, url, since_days=args.since, today_only=args.today, local_tz=local_tz)
            items.extend(fetched)
            if fetched:
                log(f"  ✓ {name}: {len(fetched)} haber", "")
        except Exception as e:
            log(f"  ✗ {name}: {e}", "⚠️")
    
    # Krebs On Security
    try:
        krebs_items = fetch_krebs(today_only=args.today, local_tz=local_tz)
        items.extend(krebs_items)
        if krebs_items:
            log(f"  ✓ KrebsOnSecurity: {len(krebs_items)} haber", "")
    except Exception as e:
        log(f"  ✗ KrebsOnSecurity: {e}", "⚠️")

    # Temizleme ve filtreleme
    items = dedupe_by_url(items)
    new_items = filter_new_items(items, seen_urls)
    
    if args.max_per_run and args.max_per_run > 0:
        new_items = new_items[:args.max_per_run]
    
    log(f"Toplam {len(items)} haber toplandı, {len(new_items)} yeni haber bulundu", "📊")
    
    if not new_items:
        log("İşlenecek yeni haber yok", "✓")
        return

    # ========== AI MODELİ HAZIRLAMA ==========
    api_key = os.getenv("GOOGLE_API_KEY") or GOOGLE_API_KEY
    if not api_key or api_key == "":
        raise RuntimeError("❌ GOOGLE_API_KEY tanımlı değil! .env dosyasını kontrol edin.")
    
    genai.configure(api_key=api_key)
    
    generation_config = {
        "temperature": 0.7,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 2048,
    }
    
    model = genai.GenerativeModel(
        model_name=args.gemini_model or "gemini-2.0-flash",
        generation_config=generation_config
    )
    log(f"Gemini model hazır: {args.gemini_model or 'gemini-2.0-flash'}", "🤖")

    # ========== TELEGRAM YAPILANDIRMASI ==========
    token = args.tg_token or os.getenv("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    chat_id = args.tg_chat or os.getenv("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID)
    
    if args.telegram:
        if not token:
            log("TELEGRAM_BOT_TOKEN bulunamadı!", "⚠️")
        if not chat_id:
            log("TELEGRAM_CHAT_ID bulunamadı!", "⚠️")
        if token and chat_id:
            log(f"Telegram aktif: {chat_id}", "✅")

    # ========== ÇIKTI DOSYASI ==========
    out_path = Path(args.out or "cyber_news_stream.json")
    try:
        existing = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else []
        if not isinstance(existing, list):
            existing = []
    except Exception:
        existing = []

    # ========== HABER İŞLEME DÖNGÜSÜ ==========
    log(f"Haberler işleniyor ({len(new_items)} adet)...", "⚙️")
    success_count = 0
    error_count = 0
    
    for idx, item in enumerate(new_items, 1):
        try:
            log(f"[{idx}/{len(new_items)}] İşleniyor: {item.get('title_raw', 'Başlık yok')[:60]}...", "📰")
            
            # AI ile özetle
            summary = summarize_one(item, model, delay=1.0)
            
            # JSON'a kaydet
            existing.append(summary)
            out_path.write_text(
                json.dumps(existing, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            log(f"  ✓ Kaydedildi: {summary.get('title', '(başlık yok)')[:60]}", "💾")

            # Telegram'a gönder
            if args.telegram and token and chat_id:
                try:
                    tg_send_news(token, chat_id, summary)
                    log(f"  ✓ Telegram'a gönderildi", "📤")
                except Exception as e:
                    log(f"  ✗ Telegram hatası: {e}", "❌")
                    error_count += 1

            # State güncelle
            if item.get("url"):
                seen_urls.add(item["url"])
                save_state(state_path, seen_urls)

            success_count += 1
            
            # Bekleme (rate limiting)
            if idx < len(new_items):  # Son haberde bekleme
                time.sleep(args.stream_delay)

        except KeyboardInterrupt:
            log("Kullanıcı tarafından durduruldu (Ctrl+C)", "⏹️")
            break
        except Exception as e:
            log(f"  ✗ İşleme hatası: {e}", "❌")
            error_count += 1
            continue

    # ========== ÖZET ==========
    log("=" * 60, "")
    log(f"İşlem tamamlandı!", "✅")
    log(f"  Başarılı: {success_count}/{len(new_items)}", "")
    if error_count > 0:
        log(f"  Hatalı: {error_count}/{len(new_items)}", "")
    log(f"  Çıktı dosyası: {out_path}", "")
    log(f"  State dosyası: {state_path}", "")
    log("=" * 60, "")

# ============= KOMUT SATIRI =============

def main():
    """Ana fonksiyon"""
    ap = argparse.ArgumentParser(
        description="🔐 Siber Güvenlik Haber Toplayıcı - RSS'den haberleri toplar, AI ile özetler ve Telegram'a gönderir",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Kullanım Örnekleri:
  %(prog)s --telegram --today                           # Bugünün haberleri
  %(prog)s --telegram --since 3 --max-per-run 10       # Son 3 gün, maks 10 haber
  %(prog)s --telegram --stream-delay 5                 # Her haber arası 5 saniye
  %(prog)s --reset-state --today --telegram            # State sıfırla ve bugünü işle

Ortam Değişkenleri (.env dosyası):
  GOOGLE_API_KEY=your_gemini_api_key
  TELEGRAM_BOT_TOKEN=your_bot_token
  TELEGRAM_CHAT_ID=@your_channel
        """
    )
    
    # Tarih filtreleri
    ap.add_argument("--since", type=int, default=7, 
                    help="Son N günün haberlerini topla (varsayılan: 7)")
    ap.add_argument("--today", action="store_true", 
                    help="Sadece bugünün haberlerini topla")
    
    # Dosya ayarları
    ap.add_argument("--out", default="cyber_news_stream.json",
                    help="Çıktı JSON dosyası (varsayılan: cyber_news_stream.json)")
    ap.add_argument("--state", default="seen_urls.json",
                    help="State dosyası (varsayılan: seen_urls.json)")
    ap.add_argument("--reset-state", action="store_true",
                    help="State dosyasını sıfırla (tüm haberleri yeniden işle)")
    
    # Haber limitleri
    ap.add_argument("--max-per-run", type=int,
                    help="Bir seferde işlenecek maksimum haber sayısı")
    
    # AI ayarları
    ap.add_argument("--gemini-model", default="gemini-2.0-flash",
                    help="Gemini model adı (varsayılan: gemini-2.0-flash)")
    ap.add_argument("--ai-max-retries", type=int, default=5,
                    help="AI çağrısı için maksimum deneme sayısı (varsayılan: 5)")
    ap.add_argument("--ai-initial-backoff", type=int, default=8,
                    help="İlk backoff süresi saniye (varsayılan: 8)")
    
    # Telegram ayarları
    ap.add_argument("--telegram", action="store_true",
                    help="Haberleri Telegram'a gönder")
    ap.add_argument("--tg-token",
                    help="Telegram bot token (veya .env'den TELEGRAM_BOT_TOKEN)")
    ap.add_argument("--tg-chat",
                    help="Telegram chat ID (veya .env'den TELEGRAM_CHAT_ID)")
    ap.add_argument("--stream-delay", type=int, default=10,
                    help="Her haber arası bekleme süresi saniye (varsayılan: 10)")
    
    # Diğer
    ap.add_argument("--tz", default=os.getenv("LOCAL_TZ_NAME", "Europe/Istanbul"),
                    help="Yerel saat dilimi (varsayılan: Europe/Istanbul)")
    
    args = ap.parse_args()
    
    try:
        run_once(args)
    except KeyboardInterrupt:
        log("Program kullanıcı tarafından sonlandırıldı", "⏹️")
    except Exception as e:
        log(f"Kritik hata: {e}", "❌")
        raise

if __name__ == "__main__":
    main()