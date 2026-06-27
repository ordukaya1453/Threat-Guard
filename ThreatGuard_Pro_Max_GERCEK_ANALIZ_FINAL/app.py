
from flask import Flask, render_template, request, jsonify, make_response
import os
import re
import ssl
import csv
import json
import socket
import sqlite3
import hashlib
import ipaddress
import requests
from io import StringIO
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

app = Flask(__name__)
DB_NAME = os.environ.get("DB_NAME", "threatguard_pro_max.db")
REQUEST_TIMEOUT = 7

OFFICIAL_DOMAINS = [
    "afad.gov.tr", "icisleri.gov.tr", "saglik.gov.tr", "turkiye.gov.tr",
    "edevlet.gov.tr", "e-devlet.gov.tr", "gov.tr", "edu.tr", "ptt.gov.tr"
]

BRAND_KEYWORDS = [
    "afad", "edevlet", "e-devlet", "turkiye", "ziraat", "garanti", "akbank",
    "yapikredi", "isbank", "vakifbank", "halkbank", "ptt", "sahibinden",
    "trendyol", "hepsiburada", "instagram", "facebook", "whatsapp"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "lnkd.in", "rb.gy"
]

SUSPICIOUS_WORDS = [
    "acil", "hemen", "son şans", "son sans", "tıkla", "tikla",
    "şifre", "sifre", "giriş yap", "giris yap", "ödeme", "odeme",
    "hesap", "doğrula", "dogrula", "banka", "iban", "para",
    "yardım", "yardim", "bağış", "bagis", "kampanya", "ödül", "odul",
    "kazandınız", "kazandiniz", "askıya alınacaktır", "hesabınız", "hesabiniz"
]

FAKE_NEWS_WORDS = [
    "kesin bilgi", "saklanan gerçek", "saklanan gercek", "gizli gerçek",
    "gizli gercek", "paylaşmadan geçme", "paylasmadan gecme",
    "herkesten saklanıyor", "herkesten saklaniyor", "şok", "sok",
    "inanılmaz", "inanilmaz", "büyük iddia", "son dakika", "panik",
    "devlet saklıyor", "yetkililer açıklamıyor"
]

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module TEXT,
            input_text TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            threat_type TEXT,
            ai_comment TEXT,
            details_json TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def extract_urls(text):
    pattern = r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*)'
    urls = re.findall(pattern, text or "")
    cleaned = []
    for u in urls:
        cleaned.append(u.strip().rstrip(".,);]"))
    return list(dict.fromkeys(cleaned))

def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        return ""
    if raw.startswith("www."):
        return "http://" + raw
    if not raw.startswith(("http://", "https://")):
        return "http://" + raw
    return raw

def get_domain(url):
    parsed = urlparse(normalize_url(url))
    domain = parsed.netloc.lower().split("@")[-1].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def is_ip_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except Exception:
        return False

def is_official_domain(domain):
    return any(domain == official or domain.endswith("." + official) for official in OFFICIAL_DOMAINS)

def check_ssl(domain):
    result = {
        "checked": False,
        "valid": False,
        "issuer": "Bilinmiyor",
        "expires": "Bilinmiyor",
        "days_left": None,
        "tls_version": "Bilinmiyor",
        "error": None
    }
    if not domain or is_ip_domain(domain):
        result["error"] = "Alan adı SSL kontrolü için uygun değil."
        return result
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["checked"] = True
                result["valid"] = True
                result["tls_version"] = ssock.version() or "Bilinmiyor"
                issuer = cert.get("issuer", [])
                issuer_parts = []
                for item in issuer:
                    for key, value in item:
                        if key.lower() in ["organizationname", "commonname"]:
                            issuer_parts.append(value)
                result["issuer"] = ", ".join(issuer_parts) if issuer_parts else "Bilinmiyor"
                not_after = cert.get("notAfter")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["expires"] = exp.strftime("%Y-%m-%d")
                    result["days_left"] = max(0, (exp - datetime.now(timezone.utc)).days)
                    if result["days_left"] <= 0:
                        result["valid"] = False
        return result
    except Exception as e:
        result["checked"] = True
        result["valid"] = False
        result["error"] = str(e)[:160]
        return result

def rdap_lookup(domain):
    result = {
        "checked": False,
        "source": "RDAP",
        "registrar": "Bilinmiyor",
        "created": "Bilinmiyor",
        "age_days": None,
        "country": "Bilinmiyor",
        "error": None
    }
    if not domain or is_ip_domain(domain):
        result["error"] = "Alan adı WHOIS/RDAP için uygun değil."
        return result
    try:
        # rdap.org redirects to the correct registry where possible.
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": "ThreatGuard-Pro-Max/1.0"})
        result["checked"] = True
        if r.status_code >= 400:
            result["error"] = f"RDAP sorgusu başarısız: HTTP {r.status_code}"
            return result
        data = r.json()
        for event in data.get("events", []):
            if event.get("eventAction") in ["registration", "registered"]:
                created = event.get("eventDate", "")
                if created:
                    result["created"] = created[:10]
                    try:
                        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        result["age_days"] = max(0, (datetime.now(timezone.utc) - dt).days)
                    except Exception:
                        pass
        entities = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [None, []])[1]
                for row in vcard:
                    if row and row[0] == "fn":
                        result["registrar"] = row[3]
                        break
        if data.get("country"):
            result["country"] = data.get("country")
        return result
    except Exception as e:
        result["checked"] = True
        result["error"] = str(e)[:160]
        return result

def follow_redirects(url):
    result = {"checked": False, "count": 0, "final_url": normalize_url(url), "chain": [], "error": None}
    try:
        r = requests.get(normalize_url(url), allow_redirects=True, timeout=REQUEST_TIMEOUT, headers={"User-Agent": "ThreatGuard-Pro-Max/1.0"})
        result["checked"] = True
        result["count"] = len(r.history)
        result["final_url"] = r.url
        result["chain"] = [resp.url for resp in r.history] + [r.url]
        return result
    except Exception as e:
        result["checked"] = True
        result["error"] = str(e)[:160]
        return result

def google_safe_browsing(url):
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {"enabled": False, "checked": False, "malicious": False, "message": "API anahtarı tanımlı değil."}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "threatguard-pro-max", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalize_url(url)}],
        },
    }
    try:
        r = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT)
        data = r.json() if r.text else {}
        matches = data.get("matches", [])
        return {"enabled": True, "checked": True, "malicious": bool(matches), "matches": matches[:5], "message": "Kontrol tamamlandı."}
    except Exception as e:
        return {"enabled": True, "checked": True, "malicious": False, "error": str(e)[:160]}

def virustotal_url_scan(url):
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"enabled": False, "checked": False, "malicious": 0, "suspicious": 0, "message": "API anahtarı tanımlı değil."}
    headers = {"x-apikey": api_key}
    normalized = normalize_url(url)
    try:
        # Query existing report by URL id (base64url without padding)
        import base64
        url_id = base64.urlsafe_b64encode(normalized.encode()).decode().strip("=")
        report = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=REQUEST_TIMEOUT)
        if report.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": normalized}, timeout=REQUEST_TIMEOUT)
            return {"enabled": True, "checked": True, "pending": True, "malicious": 0, "suspicious": 0, "message": "VirusTotal taraması başlatıldı, sonuç için kısa süre sonra tekrar analiz et."}
        data = report.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "enabled": True,
            "checked": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "message": "VirusTotal raporu alındı."
        }
    except Exception as e:
        return {"enabled": True, "checked": True, "malicious": 0, "suspicious": 0, "error": str(e)[:160]}

def determine_threat_type(module, text, urls):
    low = (text or "").lower()
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

def analyze_single_url(url):
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    domain = get_domain(normalized)
    checks = {
        "input": url,
        "normalized_url": normalized,
        "domain": domain,
        "scheme": parsed.scheme,
        "https": parsed.scheme == "https",
        "official_domain": is_official_domain(domain),
        "is_ip": is_ip_domain(domain),
        "shortener": domain in SHORTENERS,
        "contains_at": "@" in normalized,
        "punycode": "xn--" in domain,
        "long_url": len(normalized) > 120,
        "many_subdomains": domain.count(".") >= 3,
        "hyphenated_domain": "-" in domain,
        "brand_impersonation": any(b in domain for b in BRAND_KEYWORDS) and not is_official_domain(domain),
        "path_suspicious_words": [w for w in SUSPICIOUS_WORDS if w in normalized.lower()],
    }
    checks["ssl"] = check_ssl(domain) if checks["https"] else {"checked": False, "valid": False, "error": "HTTPS kullanılmıyor."}
    checks["rdap"] = rdap_lookup(domain)
    checks["redirects"] = follow_redirects(normalized)
    checks["google_safe_browsing"] = google_safe_browsing(normalized)
    checks["virustotal"] = virustotal_url_scan(normalized)
    return checks

def score_url_checks(checks):
    score = 0
    reasons = []
    suggestions = []

    if not checks["https"]:
        score += 18
        reasons.append("Bağlantı HTTPS kullanmıyor.")
        suggestions.append("HTTP bağlantılarda kişisel bilgi veya şifre girmeyin.")
    else:
        reasons.append("Bağlantı HTTPS kullanıyor.")

    ssl_info = checks.get("ssl", {})
    if checks["https"] and ssl_info.get("checked"):
        if ssl_info.get("valid"):
            reasons.append(f"SSL sertifikası geçerli görünüyor. Veren: {ssl_info.get('issuer','Bilinmiyor')}.")
            if ssl_info.get("days_left") is not None and ssl_info["days_left"] < 15:
                score += 8
                reasons.append("SSL sertifikasının süresi çok yakında doluyor.")
        else:
            score += 22
            reasons.append("SSL sertifikası doğrulanamadı veya geçersiz.")
            suggestions.append("Sertifika hatası veren sitelerde işlem yapmayın.")

    if checks["official_domain"]:
        score -= 15
        reasons.append("Alan adı resmi/güvenilir alan adı yapısına benziyor.")
    else:
        score += 8
        reasons.append("Alan adı resmi kurum alan adı listesinde değil.")

    if checks["is_ip"]:
        score += 25
        reasons.append("Alan adı yerine doğrudan IP adresi kullanılmış.")
    if checks["shortener"]:
        score += 18
        reasons.append("URL kısaltıcı kullanılmış; gerçek hedef gizlenmiş olabilir.")
        suggestions.append("Kısaltılmış bağlantıları açmadan önce hedef adresi kontrol edin.")
    if checks["contains_at"]:
        score += 18
        reasons.append("URL içinde '@' karakteri var; hedef alan adı gizleniyor olabilir.")
    if checks["punycode"]:
        score += 22
        reasons.append("Punycode/IDN kullanımı tespit edildi; sahte karakterle marka taklidi olabilir.")
    if checks["long_url"]:
        score += 10
        reasons.append("URL olağandan uzun.")
    if checks["many_subdomains"]:
        score += 10
        reasons.append("Çok fazla alt alan adı kullanılmış.")
    if checks["hyphenated_domain"]:
        score += 8
        reasons.append("Alan adında tire kullanımı var.")
    if checks["brand_impersonation"]:
        score += 25
        reasons.append("Alan adı resmi kurum, banka veya bilinen marka taklidi yapıyor olabilir.")
        suggestions.append("Resmi sitelere bağlantıdan değil, adresi kendiniz yazarak girin.")
    if checks["path_suspicious_words"]:
        score += min(len(checks["path_suspicious_words"]) * 5, 18)
        reasons.append("URL içinde acil işlem, ödeme, doğrulama gibi riskli ifadeler var.")

    rdap = checks.get("rdap", {})
    if rdap.get("age_days") is not None:
        if rdap["age_days"] < 30:
            score += 18
            reasons.append(f"Domain çok yeni görünüyor: {rdap['age_days']} günlük.")
        elif rdap["age_days"] < 180:
            score += 8
            reasons.append(f"Domain nispeten yeni: {rdap['age_days']} günlük.")
        else:
            reasons.append(f"Domain yaşı daha olgun görünüyor: {rdap['age_days']} gün.")
    elif rdap.get("error"):
        reasons.append("Domain yaşı bilgisi alınamadı.")

    redir = checks.get("redirects", {})
    if redir.get("count", 0) >= 3:
        score += 12
        reasons.append(f"Çoklu yönlendirme tespit edildi: {redir['count']} yönlendirme.")
    elif redir.get("count", 0) > 0:
        score += 4
        reasons.append(f"Yönlendirme tespit edildi: {redir['count']} yönlendirme.")

    gsb = checks.get("google_safe_browsing", {})
    if gsb.get("enabled") and gsb.get("malicious"):
        score += 45
        reasons.append("Google Safe Browsing bu URL için tehdit eşleşmesi döndürdü.")
        suggestions.append("Bu bağlantıyı açmayın.")

    vt = checks.get("virustotal", {})
    if vt.get("enabled"):
        malicious = int(vt.get("malicious", 0) or 0)
        suspicious = int(vt.get("suspicious", 0) or 0)
        if malicious:
            score += min(50, malicious * 12)
            reasons.append(f"VirusTotal üzerinde {malicious} güvenlik motoru zararlı işaretledi.")
        if suspicious:
            score += min(20, suspicious * 6)
            reasons.append(f"VirusTotal üzerinde {suspicious} motor şüpheli işaretledi.")

    return score, reasons, suggestions

def analyze_content(text, module="general"):
    low = (text or "").lower()
    score = 0
    reasons = []
    suggestions = []
    urls = extract_urls(text)
    url_details = []

    found = [w for w in SUSPICIOUS_WORDS if w in low]
    if found:
        score += min(len(found) * 7, 35)
        reasons.append("İçerikte aciliyet, para, şifre, hesap veya doğrulama isteyen ifadeler bulundu.")
        suggestions.append("Kişisel bilgi, şifre, IBAN veya ödeme bilgisi paylaşmadan önce kaynağı doğrulayın.")

    fake = [w for w in FAKE_NEWS_WORDS if w in low]
    if fake:
        score += min(len(fake) * 7, 30)
        reasons.append("İçerikte panik, abartı veya doğrulanmamış haber dili bulunuyor.")
        suggestions.append("Haberi resmi kaynaklardan ve güvenilir haber sitelerinden kontrol edin.")

    for url in urls[:3]:
        checks = analyze_single_url(url)
        url_score, url_reasons, url_suggestions = score_url_checks(checks)
        score += min(url_score, 75)
        reasons.extend(url_reasons)
        suggestions.extend(url_suggestions)
        url_details.append(checks)

    if module == "sms" and len(text.split()) < 22 and found:
        score += 10
        reasons.append("SMS kısa, baskı kuran ve hızlı aksiyon isteyen bir yapıya sahip.")
    if module == "mail" and any(w in low for w in ["ek", "fatura", "dosya", "giriş", "hesap", "şifre", "sifre"]):
        score += 12
        reasons.append("E-posta içeriğinde dosya, hesap veya giriş bilgisiyle ilişkili riskli ifadeler var.")
    if module == "news" and fake:
        score += 8
        reasons.append("Haber metni iddialı ve yayılmaya teşvik eden ifadeler içeriyor.")

    score = max(0, min(score, 100))
    if score >= 75:
        level, color = "Tehlikeli", "red"
    elif score >= 40:
        level, color = "Şüpheli", "yellow"
    else:
        level, color = "Düşük Risk", "green"

    if not reasons:
        reasons.append("Belirgin bir yüksek risk göstergesi bulunmadı.")
        suggestions.append("Yine de kritik işlemlerde resmi kaynaklardan doğrulama yapın.")

    tt = determine_threat_type(module, text, urls)
    trust = max(0, 100 - score)

    if score >= 75:
        intro = "Bu içerik yüksek riskli görünüyor ve kimlik avı/dolandırıcılık ihtimali güçlü."
    elif score >= 40:
        intro = "Bu içerik bazı şüpheli göstergeler içeriyor; dikkatli doğrulama önerilir."
    else:
        intro = "Bu içerikte belirgin bir yüksek risk göstergesi bulunmadı."

    top_reasons = " ".join(list(dict.fromkeys(reasons))[:3])
    ai = f"{intro} Tespit edilen ana tehdit türü: {tt}. Öne çıkan bulgular: {top_reasons}"

    return {
        "risk_score": score,
        "trust_score": trust,
        "risk_level": level,
        "color": color,
        "threat_type": tt,
        "ai_comment": ai,
        "reasons": list(dict.fromkeys(reasons))[:12],
        "suggestions": list(dict.fromkeys(suggestions))[:8],
        "urls": urls,
        "url_details": url_details,
        "api_status": {
            "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
            "google_safe_browsing": bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")),
        }
    }

def save_analysis(module, text, result):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "INSERT INTO analyses (module,input_text,risk_score,risk_level,threat_type,ai_comment,details_json,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (
            module,
            text,
            result["risk_score"],
            result["risk_level"],
            result["threat_type"],
            result["ai_comment"],
            json.dumps(result, ensure_ascii=False),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()

@app.before_request
def ensure_db():
    init_db()

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

@app.route("/mail")
def mail_page():
    return render_template("analyze.html", module="mail", title="E-posta Phishing Analizi")

@app.route("/qr")
def qr_page():
    return render_template("analyze.html", module="qr", title="QR / Link Analizi")

@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DB_NAME)
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
    c.execute("SELECT module,input_text,risk_score,risk_level,threat_type,created_at FROM analyses ORDER BY id DESC LIMIT 20")
    recent = c.fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        total=total,
        dangerous=dangerous,
        suspicious=suspicious,
        low=low,
        threat_stats=threat_stats,
        recent=recent,
    )

@app.route("/admin")
def admin():
    return render_template("admin.html", vt=bool(os.environ.get("VIRUSTOTAL_API_KEY")), gsb=bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")))

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})

@app.route("/api-status")
def api_status():
    return jsonify({
        "ssl": True,
        "rdap_whois": True,
        "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        "google_safe_browsing": bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")),
    })

@app.route("/export.csv")
def export_csv():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id,module,input_text,risk_score,risk_level,threat_type,created_at FROM analyses ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "module", "input_text", "risk_score", "risk_level", "threat_type", "created_at"])
    writer.writerows(rows)
    response = make_response(out.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=threatguard_analyses.csv"
    return response

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    module = data.get("module", "general").strip()
    if not text:
        return jsonify({"error": "Lütfen analiz edilecek bir metin girin."}), 400
    result = analyze_content(text, module)
    save_analysis(module, text, result)
    return jsonify(result)

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    module = data.get("module", "general").strip()
    if not text:
        return jsonify({"error": "Rapor için önce analiz metni girin."}), 400
    result = analyze_content(text, module)
    content = f"""ThreatGuard Pro Max Profesyonel Analiz Raporu

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

Güvenlik Önerileri:
- """ + "\n- ".join(result["suggestions"]) + """

API Durumu:
- VirusTotal: """ + ("Aktif" if result["api_status"]["virustotal"] else "API anahtarı yok") + """
- Google Safe Browsing: """ + ("Aktif" if result["api_status"]["google_safe_browsing"] else "API anahtarı yok") + """

Not:
Bu rapor karar destek amaçlıdır. Kritik güvenlik kararlarında resmi kaynak ve profesyonel doğrulama önerilir.
"""
    response = make_response(content)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=ThreatGuard_Profesyonel_Rapor.txt"
    return response

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
