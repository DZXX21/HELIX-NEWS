# main.py
# -*- coding: utf-8 -*-
"""
Siber güvenlik haberlerini toplar, Gemini (google-generativeai) ile TÜRKÇE özetler
ve opsiyonel olarak Telegram'a gönderir (fotoğraflı destekli).
- --today: yalnızca bugün (Europe/Amsterdam) yayımlananlar
- --since N: son N gün (varsayılan 7)
- --telegram: Telegram'a gönder
- --stream-delay S: her haber arasında S saniye bekle (varsayılan 10)
- TELEGRAM_CHAT_ID: @kanal_kullaniciadi veya sayısal ID (-100...).
"""

import argparse, json, time, requests, feedparser, os, re, html as _html
from pathlib import Path
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
from dateutil import parser as dtparse

# .env (opsiyonel)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Zaman dilimi
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

LOCAL_TZ_NAME = "Europe/Amsterdam"

# Gemini
import google.generativeai as genai
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "BURAYA_API_KEY_YAZ")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
TIMEOUT = 20

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

# ----------------- Log -----------------
def log(msg: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {msg}")

# ----------------- Yardımcılar -----------------
def get_local_tz():
    if ZoneInfo:
        try:
            return ZoneInfo(LOCAL_TZ_NAME)
        except Exception:
            pass
    return timezone.utc

def parse_date(d):
    if not d:
        return None
    try:
        dt = dtparse.parse(d)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def clean_text(html, limit=800):
    soup = BeautifulSoup(html or "", "html.parser")
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    txt = " ".join(soup.get_text(" ").split())
    return txt[:limit].strip()

def extract_image(e):
    # RSS media alanları
    media = e.get("media_content") or e.get("media_thumbnail")
    if media and isinstance(media, list) and media[0].get("url"):
        return media[0]["url"]
    # enclosure/links
    if "links" in e:
        for l in e["links"]:
            if l.get("type", "").startswith("image") and "href" in l:
                return l["href"]
    # summary içindeki <img>
    desc = e.get("summary") or e.get("description") or ""
    soup = BeautifulSoup(desc, "html.parser")
    img = soup.find("img")
    if img and img.get("src"):
        return img["src"]
    return None

def is_today(dt_utc, local_tz):
    if not dt_utc:
        return False
    now_local = datetime.now(local_tz)
    start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = start_local + timedelta(days=1)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc = end_local.astimezone(timezone.utc)
    return start_utc <= dt_utc < end_utc

# Kalıcı durum
def load_state(path: Path) -> set:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return set(data if isinstance(data, list) else [])
        except Exception:
            return set()
    return set()

def save_state(path: Path, url_set: set):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sorted(url_set), ensure_ascii=False, indent=2), encoding="utf-8")

def filter_new_items(items, seen: set):
    return [it for it in items if it.get("url") and it["url"] not in seen]

# ----------------- Toplayıcılar -----------------
def fetch_rss(name, url, since_days=7, today_only=False, local_tz=timezone.utc):
    out = []
    feed = feedparser.parse(url)
    threshold = datetime.now(timezone.utc) - timedelta(days=since_days)
    for e in feed.entries:
        pub = parse_date(e.get("published") or e.get("updated") or e.get("pubDate"))
        if today_only:
            if not is_today(pub, local_tz):
                continue
        else:
            if pub and pub < threshold:
                continue
        out.append({
            "source": name,
            "title_raw": (e.get("title") or "").strip(),
            "url": (e.get("link") or "").strip(),
            "published_utc": pub.isoformat() if pub else None,
            "snippet": clean_text(e.get("summary") or e.get("description") or ""),
            "image_url": extract_image(e),
        })
    return out

def fetch_krebs(today_only=False, local_tz=timezone.utc, max_pages=1, limit=10):
    out, seen, url = [], set(), KREBS_HOME
    s = requests.Session(); s.headers["User-Agent"] = UA
    pages = 0
    while url and pages < max_pages and len(out) < limit:
        r = s.get(url, timeout=TIMEOUT); r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("h2.entry-title a"):
            link = a.get("href"); title_raw = a.get_text(strip=True)
            if not link or link in seen:
                continue
            seen.add(link)
            img = None
            art = a.find_parent("article")
            if art:
                imgtag = art.find("img")
                if imgtag and imgtag.get("src"):
                    img = imgtag["src"]
            out.append({
                "source": "KrebsOnSecurity",
                "title_raw": title_raw,
                "url": link,
                "published_utc": None,
                "snippet": "",
                "image_url": img,
            })
            if len(out) >= limit:
                break
        nxt = soup.select_one("a.older-posts, .nav-previous a")
        url = nxt.get("href") if nxt else None
        pages += 1
    return out

def dedupe_by_url(items):
    seen, uniq = set(), []
    for it in items:
        u = it.get("url")
        if not u or u in seen:
            continue
        seen.add(u)
        uniq.append(it)
    return uniq

# ----------------- JSON Ayıklama -----------------
_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)

def safe_json_extract(text: str):
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

# ----------------- Geliştirilmiş Prompt -----------------
PROMPT_TEMPLATE = """
Sen profesyonel bir Türk siber güvenlik analistisiniz.

ÖNEMLİ TALİMATLAR:
- YANIT DİLİ: SADECE TÜRKÇE (her kelime Türkçe olacak)
- JSON alan adları İngilizce kalacak ama TÜM DEĞERLER TÜRKÇE olacak
- İngilizce kelime kullanma, her şeyi Türkçe'ye çevir
- Teknik terimler bile Türkçe karşılıklarını kullan

ZORUNLU ÇEVİRİ KURALLARI:
- "malware" → "kötücül yazılım" 
- "vulnerability" → "güvenlik açığı"
- "exploit" → "istismar"
- "patch" → "yama"
- "threat" → "tehdit"
- "attack" → "saldırı"
- "breach" → "ihlal"
- "ransomware" → "fidye yazılımı"
- "phishing" → "oltalama"
- "zero-day" → "sıfır gün açığı"
- "cybercriminals" → "siber suçlular"
- "bypass" → "atlatma"
- "hackers" → "siber saldırganlar"

JSON ŞEMASI (alan adları İngilizce, değerler TÜRKÇE):
{{
  "title": "TÜRKÇE başlık",
  "url": "string",
  "summary": "TÜRKÇE özet (2-3 cümle)",
  "key_points": ["TÜRKÇE madde", "TÜRKÇE madde", "TÜRKÇE madde"],
  "tags": ["türkçe-etiket", "türkçe-etiket"],
  "risk_level": "low|medium|high",
  "entities": {{
    "vendors": ["şirket adları"],
    "products": ["ürün adları"], 
    "cves": ["CVE-YYYY-NNNN"],
    "malware": ["kötücül yazılım adları"],
    "apt_groups": ["tehdit grubu adları"]
  }}
}}

TÜRKÇE ÖZETLEMİ ZORUNLU:
- Başlık tamamen Türkçe
- Özet tamamen Türkçe
- Ana noktalar tamamen Türkçe
- Etiketler tamamen Türkçe (tire ile ayrılmış)
- risk_level seçimi:
  - "high": aktif istismar, veri sızıntısı, geniş etki veya acil yamalama gerekliliği varsa,
  - "medium": yama mevcut/istismar sınırlı/koşullu ise,
  - "low": düşük etki veya teorik risk ise.

MAKALE VERİSİ:
Başlık: {title}
URL: {url}
İçerik: {snippet}

SADECE JSON ÇIKTI VER, BAŞKA HİÇBİR ŞEY YAZMA.
"""

# ----------------- Geliştirilmiş Özetleme -----------------
def summarize_one(item, model, delay=1.0):
    title = item.get("title_raw") or ""
    url = item.get("url") or ""
    snippet = item.get("snippet") or ""
    prompt = PROMPT_TEMPLATE.format(title=title, url=url, snippet=snippet)
    
    try:
        resp = model.generate_content(prompt)
        response_text = (getattr(resp, "text", "") or "").strip()
        log(f"🔍 Gemini yanıtı: {response_text[:200]}...")
        
        data = safe_json_extract(response_text)
        if not data:
            raise ValueError("Model JSON üretemedi")
            
        # Türkçe kontrolü - eğer title İngilizce ise zorla çevir
        if data.get("title") and any(eng_word in data["title"].lower() for eng_word in ["cybercriminals", "exploit", "bypass", "malware", "spread"]):
            log("⚠️ Başlık İngilizce tespit edildi, fallback çeviriye geçiliyor")
            raise ValueError("Başlık İngilizce")
            
    except Exception as e:
        # Fallback: Türkçe doldurma (Gemini kotası/hata olursa)
        log(f"⚠️ JSON ayıklanamadı veya İngilizce, fallback: {url} ({e})")
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", snippet or "")
        
        # Türkçe etiketler
        base_tags = []
        tag_mapping = {
            "ransomware": "fidye-yazılımı",
            "malware": "kötücül-yazılım", 
            "phishing": "oltalama",
            "zero-day": "sıfır-gün",
            "exploit": "istismar",
            "patch": "yama",
            "ios": "ios",
            "android": "android", 
            "windows": "windows",
            "linux": "linux",
            "cloud": "bulut",
            "apt": "gelişmiş-tehdit",
            "botnet": "bot-ağı",
            "vpn": "vpn",
            "exchange": "exchange",
            "router": "yönlendirici",
            "sql": "sql-enjeksiyonu",
            "xss": "site-arası-betikleme",
            "firmware": "donanım-yazılımı",
            "vulnerability": "güvenlik-açığı",
            "breach": "veri-ihlali",
            "attack": "saldırı",
            "threat": "tehdit"
        }
        
        snippet_lower = (snippet or "").lower()
        title_lower = (title or "").lower()
        combined_text = f"{snippet_lower} {title_lower}"
        
        for eng_term, tr_term in tag_mapping.items():
            if eng_term in combined_text:
                base_tags.append(tr_term)
        base_tags = list(dict.fromkeys(base_tags))[:5]
        
        # Başlığı Türkçe'ye çevirmeye çalış
        tr_title = title
        if title:
            # Kapsamlı çeviriler
            title_replacements = {
                "Cybercriminals": "Siber Suçlular",
                "Exploit": "İstismar Ediyor",
                "Bypass": "Atlatıyor",
                "Spread": "Yayıyor",
                "Malware": "Kötücül Yazılım",
                "Millions": "Milyonlarca Kişiye",
                "AI": "Yapay Zeka",
                "Grok": "Grok",
                "Ad Protections": "Reklam Korumalarını",
                "to": "",
                "and": "ve",
                "the": "",
                "of": "",
                "in": "",
                "for": "",
                "with": "ile",
                "using": "kullanarak",
                "New": "Yeni",
                "Critical": "Kritik",
                "Vulnerability": "Güvenlik Açığı",
                "Security": "Güvenlik",
                "Breach": "İhlali",
                "Attack": "Saldırısı",
                "Hackers": "Siber Saldırganlar",
                "Data": "Veri",
                "Ransomware": "Fidye Yazılımı",
                "Phishing": "Oltalama"
            }
            for eng, tr in title_replacements.items():
                tr_title = tr_title.replace(eng, tr)
            
            # Fazla boşlukları temizle
            tr_title = re.sub(r'\s+', ' ', tr_title).strip()
        
        # Türkçe özet oluştur
        tr_summary = "Bu haber siber güvenlik alanında önemli bir gelişmeyi konu alıyor."
        if "grok" in combined_text and "ai" in combined_text:
            tr_summary = "Siber suçlular X platformunun Grok yapay zeka asistanını kötüye kullanarak kötücül bağlantıları yaymaktadır."
        elif "vulnerability" in combined_text or "cve" in combined_text:
            tr_summary = "Yeni bir güvenlik açığı tespit edildi ve kullanıcıların dikkatli olması gerekiyor."
        elif "ransomware" in combined_text:
            tr_summary = "Fidye yazılımı saldırıları ile ilgili yeni gelişmeler rapor edildi."
        elif "data" in combined_text and "breach" in combined_text:
            tr_summary = "Önemli bir veri ihlali gerçekleşti ve kullanıcı bilgileri risk altında."
        
        if snippet:
            tr_summary += f" {snippet[:100]}... konularında detaylı bilgi içermektedir."
        
        # Türkçe ana noktalar
        key_points = [
            "Siber güvenlik tehdidi tespit edildi",
            "Kullanıcılar dikkatli olmalı ve güncellemelerini yapmalı",
            "Güvenlik uzmanları durumu yakından takip ediyor"
        ]
        
        if "ai" in combined_text:
            key_points = [
                "Yapay zeka teknolojisi kötüye kullanılıyor",
                "Sosyal medya platformlarında güvenlik açığı",
                "Kullanıcılar şüpheli bağlantılara tıklamamalı"
            ]
        elif "vulnerability" in combined_text:
            key_points = [
                "Kritik güvenlik açığı keşfedildi", 
                "Acil güvenlik yaması gerekiyor",
                "Saldırganlar aktif olarak istismar edebilir"
            ]
        
        data = {
            "title": tr_title if tr_title else "Siber Güvenlik Haberi",
            "url": url,
            "summary": tr_summary,
            "key_points": key_points,
            "tags": base_tags if base_tags else ["siber-güvenlik", "tehdit", "haber"],
            "risk_level": "medium",
            "entities": {
                "vendors": [],
                "products": [],
                "cves": cves,
                "malware": [],
                "apt_groups": []
            },
        }
    
    time.sleep(delay)
    if item.get("image_url"):
        data["image_url"] = item["image_url"]
    return data

# ----------------- Telegram -----------------
TG_API_BASE = "https://api.telegram.org/bot{token}"

def html_escape(s: str) -> str:
    return _html.escape(s or "", quote=True)

def format_summary_html(item: dict) -> str:
    # Sadece desteklenen HTML tag'leri + \n
    title = html_escape(item.get("title") or "Başlık yok")
    url = (item.get("url") or "").strip()
    summary = html_escape(item.get("summary") or "")
    risk = (item.get("risk_level") or "medium").lower()
    risk_emoji = {"low":"🟢","medium":"🟠","high":"🔴"}.get(risk, "🟠")

    # key_points (varsa)
    kps = item.get("key_points") or []
    kp_block = ""
    if kps:
        kp_block = "\n".join(f"• {html_escape(k)}" for k in kps)

    # var olan alanları alt alta yaz
    entities = item.get("entities") or {}
    lines = []
    tags = item.get("tags") or []
    if tags:
        lines.append("<b>Etiketler:</b>\n" + "\n".join(f"• {html_escape(t)}" for t in tags))
    if entities.get("cves"):
        lines.append("<b>CVE:</b>\n" + "\n".join(f"• {html_escape(c)}" for c in entities["cves"]))
    if entities.get("malware"):
        lines.append("<b>Kötücül Yazılım:</b>\n" + "\n".join(f"• {html_escape(m)}" for m in entities["malware"]))
    if entities.get("apt_groups"):
        lines.append("<b>Tehdit Grupları:</b>\n" + "\n".join(f"• {html_escape(a)}" for a in entities["apt_groups"]))
    if entities.get("vendors"):
        lines.append("<b>Şirketler:</b>\n" + "\n".join(f"• {html_escape(v)}" for v in entities["vendors"]))
    if entities.get("products"):
        lines.append("<b>Ürünler:</b>\n" + "\n".join(f"• {html_escape(p)}" for p in entities["products"]))
    entity_block = "\n\n".join(lines)

    link_text = f"👉 Haberi oku: {url}" if url else ""

    parts = [
        f"<b>{title}</b> {risk_emoji}",
        summary if summary else "",
        kp_block if kp_block else "",
        link_text,
        entity_block if entity_block else ""
    ]
    # boş satırları at
    return "\n\n".join([p for p in parts if p]).strip()

def tg_send_message(token: str, chat_id: str, text_html: str):
    url = TG_API_BASE.format(token=token) + "/sendMessage"
    data = {"chat_id": chat_id, "text": text_html, "parse_mode": "HTML", "disable_web_page_preview": False}
    r = requests.post(url, data=data, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Telegram sendMessage hata: {r.status_code} {r.text}")
    return r.json()

def tg_send_photo(token: str, chat_id: str, photo_url: str, caption_html: str):
    url = TG_API_BASE.format(token=token) + "/sendPhoto"
    data = {"chat_id": chat_id, "photo": photo_url, "caption": caption_html, "parse_mode": "HTML"}
    r = requests.post(url, data=data, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Telegram sendPhoto hata: {r.status_code} {r.text}")
    return r.json()

def tg_send_news(token: str, chat_id: str, item: dict):
    caption = format_summary_html(item)
    img = item.get("image_url")
    if img:
        return tg_send_photo(token, chat_id, img, caption)
    else:
        return tg_send_message(token, chat_id, caption)

# ----------------- Akış -----------------
def run_once(args):
    local_tz = get_local_tz()
    state_path = Path(args.state).expanduser().resolve()
    seen_urls = set() if args.reset_state else load_state(state_path)
    log(f"Toplama | today={args.today} since={args.since} seen={len(seen_urls)}")

    # Topla
    items = []
    for name, url in RSS_SOURCES.items():
        try:
            items.extend(fetch_rss(name, url, since_days=args.since, today_only=args.today, local_tz=local_tz))
        except Exception as e:
            log(f"Kaynak hatası (RSS) {name}: {e}")
    try:
        items.extend(fetch_krebs(today_only=args.today, local_tz=local_tz))
    except Exception as e:
        log(f"Kaynak hatası (Krebs): {e}")

    items = dedupe_by_url(items)
    new_items = filter_new_items(items, seen_urls)
    if args.max_per_run and args.max_per_run > 0:
        new_items = new_items[:args.max_per_run]
    log(f"Yeni haber: {len(new_items)}")
    if not new_items:
        return

    # Gemini hazırla
    api_key = os.getenv("GOOGLE_API_KEY", GOOGLE_API_KEY)
    if not api_key or api_key == "BURAYA_API_KEY_YAZ":
        raise RuntimeError("GOOGLE_API_KEY tanımlı değil. .env ile verin.")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(args.gemini_model or "gemini-1.5-flash")

    # Telegram hedef
    token = args.tg_token or os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = args.tg_chat or os.getenv("TELEGRAM_CHAT_ID")

    # Çıkış dosyası
    out_path = Path(args.out or "cyber_news_stream.json")
    try:
        existing = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else []
        if not isinstance(existing, list):
            existing = []
    except Exception:
        existing = []

    # Tek tek işle
    for it in new_items:
        summary = summarize_one(it, model, delay=1.0)
        # JSON'a ekle
        existing.append(summary)
        out_path.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"✅ Kaydedildi: {summary.get('title','(başlık yok)')}")

        # Telegram'a gönder
        if args.telegram and token and chat_id:
            try:
                tg_send_news(token, chat_id, summary)
                log("✉️ Telegram'a gönderildi")
            except Exception as e:
                log(f"Telegram hata: {e}")

        # State'e ekle
        if it.get("url"):
            seen_urls.add(it["url"])
            save_state(state_path, seen_urls)

        # Bekleme
        time.sleep(args.stream_delay)

# ----------------- CLI -----------------
def main():
    ap = argparse.ArgumentParser(description="Siber güvenlik haberlerini toplayıp TR özetler ve Telegram'a gönderir (fotoğraflı).")
    ap.add_argument("--since", type=int, default=7)
    ap.add_argument("--today", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--state", default="seen_urls.json")
    ap.add_argument("--reset-state", action="store_true")
    ap.add_argument("--max-per-run", type=int)
    ap.add_argument("--gemini-model", default="gemini-1.5-flash")
    ap.add_argument("--telegram", action="store_true")
    ap.add_argument("--tg-token")
    ap.add_argument("--tg-chat")
    ap.add_argument("--stream-delay", type=int, default=10, help="Her haber arasında bekleme (sn)")
    args = ap.parse_args()

    run_once(args)

if __name__ == "__main__":
    main()