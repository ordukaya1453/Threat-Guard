from flask import Flask, render_template, request, jsonify, make_response
import os
import re
import ssl
import socket
import sqlite3
import ipaddress
import hashlib
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

try:
    import requests
except Exception:
    requests = None

app = Flask(__name__)
DB_NAME = os.environ.get("THREATGUARD_DB", "threatguard_pro_max.db")

# -----------------------------
# ThreatGuard Pro Max - Link Analiz Motoru 2.0
# -----------------------------
# Bu sürüm gerçek kontroller içerir:
# - URL yapısı analizi
# - HTTPS / SSL sertifika kontrolü
# - Redirect zinciri analizi
# - RDAP üzerinden domain yaşı sorgusu
# - VirusTotal ve Google Safe Browsing desteği (API key varsa)
# - SMS / haber / mail için gelişmiş kural tabanlı risk puanlama

OFFICIAL_DOMAINS = [
    "afad.gov.tr", "icisleri.gov.tr", "saglik.gov.tr", "turkiye.gov.tr",
    "edevlet.gov.tr", "e-devlet.gov.tr", "ptt.gov.tr", "egm.gov.tr",
    "gov.tr", "edu.tr", "kizilay.org.tr"
]

BRAND_KEYWORDS = [
    "afad", "edevlet", "e-devlet", "turkiye", "ptt", "ziraat", "akbank",
    "garanti", "isbank", "yapikredi", "vakifbank", "halkbank", "kuveytturk",
    "papara", "trendyol", "hepsiburada", "sahibinden", "whatsapp",
    "instagram", "facebook", "google", "microsoft", "netflix"
]

SUSPICIOUS_WORDS = [
    "acil", "hemen", "son şans", "son sans", "tıkla", "tikla",
    "şifre", "sifre", "giriş yap", "giris yap", "ödeme", "odeme",
    "bağış", "bagis", "iban", "para", "yardım", "yardim",
    "kampanya", "doğrula", "dogrula", "hesabınız", "hesabiniz",
    "askıya alınacaktır", "askiya alinacaktir", "ödül", "odul",
    "kazandınız", "kazandiniz", "kargo", "teslimat", "fatura",
    "kart", "limit", "blokeli", "aktivasyon", "onayla"
]

FAKE_NEWS_WORDS = [
    "kesin bilgi", "saklanan gerçek", "saklanan gercek", "gizli gerçek",
    "gizli gercek", "paylaşmadan geçme", "paylasmadan gecme",
    "herkesten saklanıyor", "herkesten saklaniyor", "şok", "sok",
    "inanılmaz", "inanilmaz", "büyük iddia", "buyuk iddia",
    "son dakika", "panik", "kimse bilmiyor", "devlet saklıyor",
    "devlet sakliyor", "yetkililer açıklamıyor", "yetkililer aciklamiyor"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly",
    "rebrand.ly", "s.id", "shorturl.at", "lnkd.in", "buff.ly", "rb.gy"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".zip", ".mov", ".country", ".gq", ".tk",
    ".ml", ".cf", ".work", ".support", ".cam", ".rest", ".quest"
]


def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module TEXT,
            input_text TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            threat_type TEXT,
            ai_comment TEXT,
            created_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def db():
    return sqlite3.connect(DB_NAME)


def normalize_url(raw_url):
    if not raw_url:
        return ""
    raw_url = raw_url.strip().strip(".,;()[]{}<>\"'")
    if raw_url.startswith("www."):
        return "http://" + raw_url
    if not raw_url.startswith(("http://", "https://")):
        return "http://" + raw_url
    return raw_url


def extract_urls(text):
    pattern = r"(https?://[^\s<>'\"]+|www\.[^\s<>'\"]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>'\"]*)?)"
    matches = re.findall(pattern, text or "")
    cleaned = []
    for item in matches:
        url = normalize_url(item)
        if url and url not in cleaned:
            cleaned.append(url)
    return cleaned


def get_domain(url):
    try:
        parsed = urlparse(normalize_url(url))
        host = parsed.netloc.lower()
        if "@" in host:
            host = host.split("@")[-1]
        if ":" in host:
            host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def is_official_domain(domain):
    if not domain:
        return False
    return any(domain == item or domain.endswith("." + item) for item in OFFICIAL_DOMAINS)


def has_brand_impersonation(domain):
    if not domain or is_official_domain(domain):
        return False, []
    found = [brand for brand in BRAND_KEYWORDS if brand in domain]
    return bool(found), found


def days_between(date_value):
    if not date_value:
        return None
    try:
        if date_value.endswith("Z"):
            date_value = date_value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(date_value)
        now = datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, (now - parsed).days)
    except Exception:
        return None


def fetch_rdap_domain_age(domain):
    result = {
        "checked": False,
        "available": False,
        "domain_age_days": None,
        "registration_date": None,
        "registrar": None,
        "error": None
    }

    if not requests or not domain or is_ip_address(domain):
        result["error"] = "RDAP kontrolü için geçerli domain bulunamadı."
        return result

    try:
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url, timeout=5)
        result["checked"] = True
        if r.status_code != 200:
            result["error"] = f"RDAP yanıtı alınamadı: HTTP {r.status_code}"
            return result

        data = r.json()
        result["available"] = True

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                result["registrar"] = entity.get("handle") or entity.get("fn")
                break

        for event in data.get("events", []):
            action = (event.get("eventAction") or "").lower()
            if action in ["registration", "registered"]:
                date_value = event.get("eventDate")
                result["registration_date"] = date_value
                result["domain_age_days"] = days_between(date_value)
                break

        return result
    except Exception as exc:
        result["checked"] = True
        result["error"] = str(exc)
        return result


def check_ssl_certificate(domain):
    result = {
        "checked": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "not_after": None,
        "days_left": None,
        "error": None
    }

    if not domain or is_ip_address(domain):
        result["error"] = "SSL kontrolü için geçerli domain bulunamadı."
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["checked"] = True
                result["valid"] = True

                issuer_parts = []
                for part in cert.get("issuer", []):
                    for key, value in part:
                        if key in ["organizationName", "commonName"]:
                            issuer_parts.append(value)
                result["issuer"] = ", ".join(issuer_parts) if issuer_parts else "Bilinmiyor"

                subject_parts = []
                for part in cert.get("subject", []):
                    for key, value in part:
                        if key in ["commonName", "organizationName"]:
                            subject_parts.append(value)
                result["subject"] = ", ".join(subject_parts) if subject_parts else domain

                not_after = cert.get("notAfter")
                result["not_after"] = not_after
                if not_after:
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    delta = expires - datetime.utcnow()
                    result["days_left"] = delta.days
                    if delta.days < 0:
                        result["valid"] = False
                return result
    except Exception as exc:
        result["checked"] = True
        result["error"] = str(exc)
        return result


def check_redirects(url):
    result = {
        "checked": False,
        "count": 0,
        "chain": [],
        "final_url": url,
        "error": None
    }

    if not requests:
        result["error"] = "requests modülü yüklü değil."
        return result

    try:
        r = requests.get(url, timeout=6, allow_redirects=True, headers={"User-Agent": "ThreatGuard/1.0"})
        result["checked"] = True
        result["count"] = len(r.history)
        result["chain"] = [x.url for x in r.history] + [r.url]
        result["final_url"] = r.url
        return result
    except Exception as exc:
        result["checked"] = True
        result["error"] = str(exc)
        return result


def check_virustotal(url):
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    result = {
        "enabled": bool(key),
        "checked": False,
        "malicious": None,
        "suspicious": None,
        "harmless": None,
        "error": None
    }

    if not key:
        result["error"] = "VirusTotal API anahtarı eklenmemiş."
        return result

    if not requests:
        result["error"] = "requests modülü yüklü değil."
        return result

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        r = requests.get(api, timeout=8, headers={"x-apikey": key})
        result["checked"] = True

        if r.status_code == 404:
            result["error"] = "Bu URL VirusTotal veritabanında bulunamadı."
            return result

        if r.status_code != 200:
            result["error"] = f"VirusTotal HTTP {r.status_code}"
            return result

        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        return result
    except Exception as exc:
        result["checked"] = True
        result["error"] = str(exc)
        return result


def check_google_safe_browsing(url):
    key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    result = {
        "enabled": bool(key),
        "checked": False,
        "unsafe": None,
        "threats": [],
        "error": None
    }

    if not key:
        result["error"] = "Google Safe Browsing API anahtarı eklenmemiş."
        return result

    if not requests:
        result["error"] = "requests modülü yüklü değil."
        return result

    try:
        api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
        payload = {
            "client": {"clientId": "threatguard-pro-max", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(api, json=payload, timeout=8)
        result["checked"] = True

        if r.status_code != 200:
            result["error"] = f"Google Safe Browsing HTTP {r.status_code}"
            return result

        data = r.json()
        matches = data.get("matches", [])
        result["unsafe"] = bool(matches)
        result["threats"] = [m.get("threatType") for m in matches]
        return result
    except Exception as exc:
        result["checked"] = True
        result["error"] = str(exc)
        return result


def analyze_url_structure(url):
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    domain = get_domain(normalized)
    path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

    issues = []
    positives = []
    score = 0

    if parsed.scheme == "https":
        positives.append("URL HTTPS protokolü kullanıyor.")
    else:
        score += 15
        issues.append("URL HTTPS yerine HTTP kullanıyor veya protokol belirtilmemiş.")

    if domain in URL_SHORTENERS:
        score += 25
        issues.append("URL kısaltıcı servis kullanıyor. Gerçek hedef gizlenmiş olabilir.")

    if "@" in parsed.netloc:
        score += 25
        issues.append("URL içinde @ karakteri var. Kullanıcıyı farklı domaine yönlendirme riski olabilir.")

    if is_ip_address(domain):
        score += 25
        issues.append("Alan adı yerine doğrudan IP adresi kullanılmış.")

    if domain.startswith("xn--") or ".xn--" in domain:
        score += 20
        issues.append("Punycode/IDN kullanımı tespit edildi. Harf taklidi riski olabilir.")

    if len(normalized) > 120:
        score += 12
        issues.append("URL normalden uzun görünüyor. Gizleme veya takip parametresi içerebilir.")

    if domain.count(".") >= 3:
        score += 10
        issues.append("Domain çok fazla alt alan adı içeriyor.")

    if "-" in domain:
        score += 8
        issues.append("Domain içinde tire karakteri var. Taklit domainlerde sık görülebilir.")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        issues.append("Şüpheli veya kötüye kullanımı sık görülen TLD kullanılmış.")

    brand_hit, brands = has_brand_impersonation(domain)
    if brand_hit:
        score += 25
        issues.append("Domain içinde bilinen kurum/marka adı geçiyor fakat resmi domain değil.")
    elif is_official_domain(domain):
        score -= 12
        positives.append("Domain resmi veya güvenilir alan adı listesiyle uyumlu görünüyor.")

    if path_query:
        lower_path = path_query.lower()
        risky_path_words = ["login", "giris", "signin", "verify", "dogrula", "odeme", "payment", "secure", "account"]
        found = [w for w in risky_path_words if w in lower_path]
        if found:
            score += 12
            issues.append("URL yolunda giriş/doğrulama/ödeme çağrışımı yapan ifadeler var.")

    return {
        "url": normalized,
        "domain": domain,
        "scheme": parsed.scheme,
        "score": max(0, min(score, 100)),
        "issues": issues,
        "positives": positives,
        "brand_impersonation": brand_hit,
        "brand_keywords": brands if brand_hit else []
    }


def determine_threat_type(module, text, urls):
    low = text.lower()

    if module == "mail":
        return "E-posta Phishing Analizi"
    if module == "news":
        return "Dezenformasyon / Haber Analizi"
    if module == "qr":
        return "QR Kod / Link Riski"
    if module == "sms":
        return "SMS Dolandırıcılığı"

    if urls and any(w in low for w in ["şifre", "sifre", "giriş", "giris", "hesap", "doğrula", "dogrula", "banka"]):
        return "Phishing / Kimlik Avı"

    if any(w in low for w in ["bağış", "bagis", "yardım", "yardim", "iban", "para"]):
        return "Kriz / Bağış Dolandırıcılığı"

    if any(w in low for w in FAKE_NEWS_WORDS):
        return "Dezenformasyon"

    if urls:
        return "Şüpheli Link"

    return "Genel Hibrit Tehdit Riski"


def build_ai_comment(score, threat_type, reasons, checks):
    if score >= 80:
        intro = "Bu içerik çok yüksek riskli görünüyor."
        action = "Bağlantıyı açmayın, kişisel bilgi girmeyin ve kaynağı resmi kanaldan doğrulayın."
    elif score >= 60:
        intro = "Bu içerik yüksek risk göstergeleri taşıyor."
        action = "İşlem yapmadan önce domaini, kurum adını ve sertifika bilgisini doğrulayın."
    elif score >= 35:
        intro = "Bu içerikte bazı şüpheli göstergeler var."
        action = "Dikkatli ilerleyin ve kritik bilgi paylaşmayın."
    else:
        intro = "Bu içerikte belirgin yüksek risk göstergesi bulunmadı."
        action = "Yine de hassas işlemleri yalnızca resmi kanallardan yapın."

    top_reasons = reasons[:4] if reasons else ["Belirgin risk göstergesi sınırlı."]
    reason_text = " ".join([f"{i+1}) {r}" for i, r in enumerate(top_reasons)])

    real_check_summary = []
    for key in ["ssl", "rdap", "redirect", "virustotal", "google_safe_browsing"]:
        if key in checks:
            real_check_summary.append(key)

    check_text = ", ".join(real_check_summary) if real_check_summary else "kural tabanlı analiz"
    return f"{intro} Tespit edilen tehdit türü: {threat_type}. Ana bulgular: {reason_text} Kullanılan kontrol katmanları: {check_text}. Öneri: {action}"


def analyze_content(text, module="general", deep=True):
    low = (text or "").lower()
    urls = extract_urls(text)
    reasons = []
    suggestions = []
    positives = []
    checks = {}
    score = 0

    found = [w for w in SUSPICIOUS_WORDS if w in low]
    if found:
        add = min(len(found) * 7, 35)
        score += add
        reasons.append(f"Şüpheli/acil işlem dili tespit edildi: {', '.join(found[:6])}.")
        suggestions.append("Şifre, IBAN, ödeme veya kişisel bilgi paylaşmadan önce kaynağı doğrula.")

    fake = [w for w in FAKE_NEWS_WORDS if w in low]
    if fake:
        score += min(len(fake) * 8, 30)
        reasons.append(f"Dezenformasyon diline benzeyen ifadeler bulundu: {', '.join(fake[:5])}.")
        suggestions.append("Haberi resmi kurumlar ve güvenilir haber kaynaklarıyla karşılaştır.")

    url_reports = []
    for url in urls:
        structure = analyze_url_structure(url)
        url_reports.append(structure)
        score += structure["score"]
        reasons.extend(structure["issues"])
        positives.extend(structure["positives"])

        domain = structure["domain"]
        normalized = structure["url"]

        if deep and domain:
            if normalized.startswith("https://"):
                ssl_result = check_ssl_certificate(domain)
                checks["ssl"] = ssl_result
                if ssl_result.get("valid"):
                    score -= 10
                    positives.append("SSL sertifikası geçerli görünüyor.")
                else:
                    score += 18
                    reasons.append("SSL sertifikası doğrulanamadı veya geçerli değil.")
                if ssl_result.get("days_left") is not None and ssl_result["days_left"] < 15:
                    score += 10
                    reasons.append("SSL sertifikasının süresi çok kısa süre içinde doluyor.")
            else:
                reasons.append("HTTPS olmadığı için SSL sertifikası kontrol edilemedi.")

            rdap_result = fetch_rdap_domain_age(domain)
            checks["rdap"] = rdap_result
            age = rdap_result.get("domain_age_days")
            if age is not None:
                if age < 30:
                    score += 25
                    reasons.append(f"Domain çok yeni görünüyor: yaklaşık {age} günlük.")
                elif age < 180:
                    score += 10
                    reasons.append(f"Domain görece yeni: yaklaşık {age} günlük.")
                else:
                    score -= 5
                    positives.append(f"Domain yaşı daha güven verici: yaklaşık {age} günlük.")
            elif rdap_result.get("error"):
                checks["rdap"]["note"] = "Domain yaşı alınamadı; bu tek başına risk kanıtı değildir."

            redirect_result = check_redirects(normalized)
            checks["redirect"] = redirect_result
            if redirect_result.get("count", 0) >= 3:
                score += 15
                reasons.append(f"URL {redirect_result['count']} kez yönlendiriyor.")
            elif redirect_result.get("count", 0) > 0:
                score += 5
                positives.append(f"URL {redirect_result['count']} yönlendirme içeriyor; bu ayrıca kontrol edildi.")

            vt = check_virustotal(normalized)
            checks["virustotal"] = vt
            if vt.get("malicious", 0):
                score += 35
                reasons.append(f"VirusTotal üzerinde {vt['malicious']} motor zararlı olarak işaretledi.")
            elif vt.get("checked") and vt.get("malicious") == 0:
                positives.append("VirusTotal sonucunda zararlı işaretleme görülmedi.")

            gsb = check_google_safe_browsing(normalized)
            checks["google_safe_browsing"] = gsb
            if gsb.get("unsafe"):
                score += 40
                reasons.append(f"Google Safe Browsing tehdit tespit etti: {', '.join(gsb.get('threats', []))}.")
            elif gsb.get("checked") and gsb.get("unsafe") is False:
                positives.append("Google Safe Browsing üzerinde tehdit eşleşmesi bulunmadı.")

    if module == "sms" and len(text.split()) < 25 and found:
        score += 10
        reasons.append("SMS kısa, baskı kuran ve hızlı aksiyon isteyen bir yapıya sahip.")

    if module == "mail" and any(w in low for w in ["ek", "fatura", "dosya", "giriş", "hesap", "şifre", "sifre"]):
        score += 12
        reasons.append("E-posta içeriği dosya, hesap veya giriş bilgisiyle ilişkili riskli ifadeler içeriyor.")

    if module == "news" and fake:
        score += 8
        reasons.append("Haber metni iddialı ve yayılmaya teşvik eden ifadeler içeriyor.")

    if not urls and not found and not fake:
        positives.append("Metinde belirgin yüksek risk göstergesi bulunmadı.")
        suggestions.append("Yine de hassas işlemleri resmi kanallardan doğrula.")

    score = max(0, min(int(score), 100))
    level, color = ("Tehlikeli", "red") if score >= 70 else (("Şüpheli", "yellow") if score >= 35 else ("Düşük Risk", "green"))
    trust = max(0, 100 - score)
    threat_type = determine_threat_type(module, text, urls)

    if not reasons:
        reasons.append("Belirgin yüksek risk göstergesi bulunmadı.")

    if not suggestions:
        suggestions.append("Kaynağı doğrulamadan kişisel bilgi veya ödeme bilgisi paylaşma.")

    ai_comment = build_ai_comment(score, threat_type, list(dict.fromkeys(reasons)), checks)

    return {
        "risk_score": score,
        "trust_score": trust,
        "risk_level": level,
        "color": color,
        "threat_type": threat_type,
        "ai_comment": ai_comment,
        "reasons": list(dict.fromkeys(reasons)),
        "suggestions": list(dict.fromkeys(suggestions)),
        "positives": list(dict.fromkeys(positives)),
        "urls": urls,
        "url_reports": url_reports,
        "checks": checks
    }


def save_analysis(module, text, result):
    conn = db()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO analyses
        (module, input_text, risk_score, risk_level, threat_type, ai_comment, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            module,
            text,
            result["risk_score"],
            result["risk_level"],
            result["threat_type"],
            result["ai_comment"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze-page")
def analyze_page():
    return render_template("analyze.html", module="general", title="Genel Hibrit Tehdit Analizi")


@app.route("/link")
def link_page():
    return render_template("analyze.html", module="link", title="Link Analizi")


@app.route("/sms")
def sms_page():
    return render_template("analyze.html", module="sms", title="SMS Analizi")


@app.route("/news")
def news_page():
    return render_template("analyze.html", module="news", title="Haber / Dezenformasyon Analizi")


@app.route("/dashboard")
def dashboard():
    conn = db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM analyses")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Tehlikeli'")
    dangerous = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Şüpheli'")
    suspicious = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Düşük Risk'")
    low = c.fetchone()[0]
    c.execute("SELECT threat_type, COUNT(*) FROM analyses GROUP BY threat_type")
    threat_stats = c.fetchall()
    c.execute("SELECT module,input_text,risk_score,risk_level,threat_type,created_at FROM analyses ORDER BY id DESC LIMIT 12")
    recent = c.fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        total=total,
        dangerous=dangerous,
        suspicious=suspicious,
        low=low,
        threat_stats=threat_stats,
        recent=recent
    )


@app.route("/admin")
def admin():
    return dashboard()


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json() or {}
    text = data.get("text", "").strip()
    module = data.get("module", "general").strip()

    if not text:
        return jsonify({"error": "Lütfen analiz edilecek bir metin girin."}), 400

    result = analyze_content(text, module, deep=True)
    save_analysis(module, text, result)
    return jsonify(result)


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "ThreatGuard Pro Max",
        "time": datetime.now().isoformat(),
        "virustotal_enabled": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        "google_safe_browsing_enabled": bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"))
    })


@app.route("/export.csv")
def export_csv():
    conn = db()
    c = conn.cursor()
    c.execute("SELECT id,module,input_text,risk_score,risk_level,threat_type,created_at FROM analyses ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    lines = ["id,module,input_text,risk_score,risk_level,threat_type,created_at"]
    for row in rows:
        safe = []
        for item in row:
            value = str(item).replace('"', '""').replace("\n", " ")
            safe.append(f'"{value}"')
        lines.append(",".join(safe))

    response = make_response("\n".join(lines))
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=threatguard_analyses.csv"
    return response


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json() or {}
    text = data.get("text", "").strip()
    module = data.get("module", "general").strip()

    if not text:
        return jsonify({"error": "Rapor için önce analiz metni girin."}), 400

    result = analyze_content(text, module, deep=True)

    content = f"""ThreatGuard Pro Max Analiz Raporu

Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Modül: {module}

Girilen İçerik:
{text}

Risk Seviyesi: {result['risk_level']}
Risk Puanı: {result['risk_score']}/100
Güven Puanı: {result['trust_score']}/100
Tehdit Türü: {result['threat_type']}

ThreatGuard AI Yorumu:
{result['ai_comment']}

Tespit Edilen Bulgular:
- """ + "\n- ".join(result["reasons"]) + """

Olumlu Bulgular:
- """ + "\n- ".join(result.get("positives", ["Olumlu bulgu bulunamadı."])) + """

Güvenlik Önerileri:
- """ + "\n- ".join(result["suggestions"]) + """

Not:
Bu rapor kesin hüküm vermek yerine karar destek amacıyla oluşturulmuştur.
API anahtarları tanımlıysa VirusTotal ve Google Safe Browsing sonuçları da değerlendirmeye dahil edilir.
"""

    response = make_response(content)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=ThreatGuard_Analiz_Raporu.txt"
    return response


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5050))
    print(f"ThreatGuard Pro Max çalışıyor: http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
