from flask import Flask, render_template, request, jsonify, make_response
import sqlite3, re, os, ssl, socket, json, ipaddress, hashlib, csv, io
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime, timezone

app = Flask(__name__)
DB_NAME = "threatguard_pro_max.db"

OFFICIAL_DOMAINS = ["afad.gov.tr", "icisleri.gov.tr", "saglik.gov.tr", "turkiye.gov.tr", "gov.tr", "edu.tr"]
TRUSTED_SAFE_DOMAINS = ["afad.gov.tr", "turkiye.gov.tr", "icisleri.gov.tr", "saglik.gov.tr"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "ow.ly", "shorturl.at", "lnkd.in"]
SUSPICIOUS_TLDS = ["xyz", "top", "click", "monster", "work", "country", "stream", "zip", "mov", "cam", "icu"]
BRAND_WORDS = ["afad", "edevlet", "e-devlet", "turkiye", "yardim", "banka", "ptt", "deprem", "icisleri", "saglik", "ziraat", "vakif", "garanti", "akbank"]
SUSPICIOUS_WORDS = ["acil", "hemen", "son şans", "son sans", "tıkla", "tikla", "şifre", "sifre", "giriş yap", "giris yap", "ödeme", "odeme", "bağış", "bagis", "iban", "para", "yardım", "yardim", "kampanya", "doğrula", "dogrula", "hesabınız", "hesabiniz", "askıya alınacaktır", "askiya alinacaktir", "ödül", "odul", "kazandınız", "kazandiniz", "kimlik", "kart", "kredi"]
FAKE_NEWS_WORDS = ["kesin bilgi", "saklanan gerçek", "gizli gerçek", "paylaşmadan geçme", "herkesten saklanıyor", "şok", "inanılmaz", "büyük iddia", "son dakika", "panik", "kimse bilmiyor", "devlet saklıyor", "yetkililer açıklamıyor"]
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]
HOMOGLYPH_HINTS = ["xn--", "ı", "İ", "ş", "ğ", "ü", "ö", "ç"]
CRITICAL_ACTION_WORDS = ["şifrenizi", "sifrenizi", "kart", "kredi", "kimlik", "tc", "iban", "ödeme yap", "odeme yap", "giriş yaparak", "giris yaparak"]
SAFE_SOURCE_WORDS = ["resmi", "resmî", "duyuru", "bilgilendirme", "afad", "turkiye.gov.tr", "e-devlet"]

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        module TEXT,
        input_text TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        threat_type TEXT,
        ai_comment TEXT,
        created_at TEXT
    )""")
    conn.commit()
    conn.close()

def extract_urls(text):
    return re.findall(r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)

def normalize_domain(url):
    clean = url.strip().rstrip('.,);]\n\r\t')
    if not clean.startswith(("http://", "https://")):
        clean = "https://" + clean
    parsed = urlparse(clean)
    domain = parsed.netloc.lower().split("@")[ -1].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return clean, domain, parsed.scheme

def is_official_domain(domain):
    domain = domain.lower().strip('.')
    for official in OFFICIAL_DOMAINS:
        if domain == official or domain.endswith('.' + official):
            return True
    return False

def is_trusted_safe(domain):
    domain = domain.lower().strip('.')
    return any(domain == d or domain.endswith('.' + d) for d in TRUSTED_SAFE_DOMAINS)

def check_ip_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except Exception:
        return False

def check_ssl_certificate(domain, timeout=3):
    info = {"checked": False, "valid": False, "issuer": "Bilinmiyor", "expires": "Bilinmiyor", "days_left": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        issuer_parts = cert.get("issuer", [])
        issuer = []
        for part in issuer_parts:
            for key, value in part:
                if key in ("organizationName", "commonName"):
                    issuer.append(value)
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (exp - datetime.now(timezone.utc)).days
        info.update({"checked": True, "valid": days_left >= 0, "issuer": ", ".join(issuer) if issuer else "Okunamadı", "expires": exp.strftime("%Y-%m-%d"), "days_left": days_left})
    except Exception as e:
        info.update({"checked": True, "valid": False, "error": str(e)[:100]})
    return info

def inspect_http(url, timeout=3):
    info = {"checked": False, "final_url": None, "redirect_count": 0, "security_headers": {}, "error": None}
    try:
        req = Request(url, method="GET", headers={"User-Agent": "ThreatGuard-Pro-Max/2.0"})
        with urlopen(req, timeout=timeout) as resp:
            final_url = resp.geturl()
            headers = {k.lower(): v for k, v in resp.headers.items()}
        present = {h: (h in headers) for h in SECURITY_HEADERS}
        redirect_count = 0 if final_url.rstrip('/') == url.rstrip('/') else 1
        info.update({"checked": True, "final_url": final_url, "redirect_count": redirect_count, "security_headers": present})
    except Exception as e:
        info.update({"checked": True, "error": str(e)[:100]})
    return info

def optional_reputation_checks(domain, url):
    vt = "API anahtarı yok; VirusTotal kontrolü pasif."
    gsb = "API anahtarı yok; Google Safe Browsing kontrolü pasif."
    if os.environ.get("VIRUSTOTAL_API_KEY"):
        vt = "API anahtarı tanımlı; canlı ortamda VirusTotal entegrasyonu eklenebilir."
    if os.environ.get("GOOGLE_SAFE_BROWSING_KEY"):
        gsb = "API anahtarı tanımlı; canlı ortamda Google Safe Browsing entegrasyonu eklenebilir."
    return {"virustotal": vt, "google_safe_browsing": gsb}


def offline_domain_intelligence(domain):
    """API anahtarı gerektirmeyen alan adı sinyalleri. Kesin WHOIS yerine karar destek göstergeleri üretir."""
    labels = [x for x in domain.split('.') if x]
    root = labels[-2] if len(labels) >= 2 else domain
    entropy_source = root.replace('-', '')
    digits = sum(ch.isdigit() for ch in domain)
    hyphens = domain.count('-')
    long_label = any(len(x) > 22 for x in labels)
    punycode = any(x.startswith('xn--') for x in labels)
    brand_hits = [b for b in BRAND_WORDS if b in domain]
    score = 0
    notes = []
    if digits >= 3:
        score += 8; notes.append('Alan adında fazla rakam kullanımı var.')
    if hyphens >= 1:
        score += 6; notes.append('Alan adında tire kullanımı var.')
    if long_label:
        score += 8; notes.append('Alan adında alışılmadık uzun bölüm var.')
    if punycode:
        score += 20; notes.append('Punycode/homograf benzeri alan adı görüldü.')
    if brand_hits and not is_official_domain(domain):
        score += 18; notes.append('Marka/kurum taklidi olabilecek kelime içeriyor: ' + ', '.join(brand_hits[:4]))
    fingerprint = hashlib.sha256(domain.encode('utf-8')).hexdigest()[:10]
    return {"score": score, "notes": notes, "fingerprint": fingerprint, "labels": labels}

def classify_action(score, threat_type):
    if score >= 80:
        return {"verdict":"Çok yüksek risk", "priority":"Acil", "action":"Linke tıklama; bilgileri paylaşma; mesajı engelle ve mümkünse ilgili kuruma bildir."}
    if score >= 70:
        return {"verdict":"Yüksek risk", "priority":"Yüksek", "action":"İşlem yapma; kaynağı resmî kanaldan doğrula ve mesajı şüpheli olarak işaretle."}
    if score >= 35:
        return {"verdict":"Kontrol gerekli", "priority":"Orta", "action":"Tıklamadan önce alan adını, kaynağı ve duyuruyu ikinci bir kanaldan doğrula."}
    return {"verdict":"Düşük risk", "priority":"Düşük", "action":"Belirgin risk yok; yine de kritik işlemlerde adresi kendin yazarak ilerle."}

def mitre_like_mapping(threat_type, urls):
    low = threat_type.lower()
    if 'phishing' in low or 'kimlik' in low or 'sms' in low or 'e-posta' in low:
        return "Sosyal mühendislik / Kimlik avı girişimi"
    if 'dezenformasyon' in low or 'haber' in low:
        return "Bilgi manipülasyonu / Dezenformasyon yayılımı"
    if urls:
        return "Şüpheli yönlendirme / Zararlı bağlantı ihtimali"
    return "Genel dijital risk göstergesi"

def determine_threat_type(module, text, urls):
    low = text.lower()
    if module == "mail": return "E-posta Phishing Analizi"
    if module == "news": return "Dezenformasyon / Haber Analizi"
    if module == "qr": return "QR Kod / Link Riski"
    if module == "pdf": return "PDF / Zararlı Dosya Ön Kontrolü"
    if module == "sms": return "SMS Dolandırıcılığı"
    if urls and any(w in low for w in ["şifre", "sifre", "giriş", "giris", "hesap", "doğrula", "dogrula", "kimlik"]): return "Phishing / Kimlik Avı"
    if any(w in low for w in ["bağış", "bagis", "yardım", "yardim", "iban", "para"]): return "Kriz Dolandırıcılığı"
    if any(w in low for w in FAKE_NEWS_WORDS): return "Dezenformasyon"
    if urls: return "Şüpheli Link"
    return "Genel Hibrit Tehdit Riski"

def add_unique(arr, value):
    if value and value not in arr:
        arr.append(value)

def analyze_content(text, module="general"):
    low = text.lower()
    score = 0
    reasons, suggestions = [], []
    urls = extract_urls(text)
    url_details = []

    found = [w for w in SUSPICIOUS_WORDS if w in low]
    fake = [w for w in FAKE_NEWS_WORDS if w in low]

    if found:
        score += min(len(found) * 7, 35)
        add_unique(reasons, "Metinde aciliyet, şifre, hesap, ödeme veya doğrulama isteyen ifadeler var.")
        add_unique(suggestions, "Şifre, kart, kimlik, IBAN veya ödeme bilgisi paylaşmadan önce kaynağı doğrula.")
    if fake:
        score += min(len(fake) * 8, 35)
        add_unique(reasons, "Metinde panik, abartı veya doğrulanmamış haber dili var.")
        add_unique(suggestions, "Haberi resmî kaynaklardan ve güvenilir haber sitelerinden kontrol et.")

    for url in urls:
        clean, domain, scheme = normalize_domain(url)
        if not domain:
            continue
        tld = domain.split('.')[-1]
        official = is_official_domain(domain)
        trusted = is_trusted_safe(domain)
        details = {"url": clean, "domain": domain, "https": scheme == "https", "official": official, "ssl": None, "http": None, "reputation": None}

        if trusted:
            score -= 25
            add_unique(reasons, f"{domain} resmî/güvenilir kurum alan adıyla eşleşiyor.")
        elif official:
            score -= 12
            add_unique(reasons, f"{domain} resmî alan adı uzantısıyla eşleşiyor; yine de sayfa içeriği kontrol edilmeli.")
        else:
            score += 20
            add_unique(reasons, f"{domain} resmî kurum alan adıyla eşleşmiyor.")
            add_unique(suggestions, "Linke tıklamadan önce alan adını elle kontrol et.")

        if domain in URL_SHORTENERS:
            score += 18
            add_unique(reasons, "Link kısaltıcı kullanılmış; gerçek hedef gizlenmiş olabilir.")
            add_unique(suggestions, "Kısaltılmış linkleri açmadan önce hedef adresi doğrula.")
        if scheme != "https":
            score += 15
            add_unique(reasons, f"{domain} HTTPS kullanmıyor veya adres HTTP olarak girilmiş.")
        if '-' in domain and not trusted:
            score += 9
            add_unique(reasons, "Alan adında tire var; sahte kampanya ve taklit adreslerde sık görülebilir.")
        if domain.count('.') >= 3 and not trusted:
            score += 8
            add_unique(reasons, "Alan adında fazla alt alan adı/nokta var; kullanıcıyı yanıltma amacı olabilir.")
        if tld in SUSPICIOUS_TLDS:
            score += 10
            add_unique(reasons, f".{tld} uzantısı riskli kampanyalarda sık görülebilen bir uzantıdır.")
        if check_ip_domain(domain):
            score += 25
            add_unique(reasons, "Alan adı yerine doğrudan IP adresi kullanılmış; bu phishing için güçlü risk göstergesidir.")
        intel = offline_domain_intelligence(domain)
        details["domain_intel"] = intel
        if not trusted and intel["score"]:
            score += intel["score"]
            for note in intel["notes"][:3]:
                add_unique(reasons, note)
        if any(h in domain for h in HOMOGLYPH_HINTS) and not trusted:
            score += 10
            add_unique(reasons, "Alan adı homograf/punycode benzeri karakter riski taşıyor olabilir.")
        if any(x in domain for x in BRAND_WORDS) and not official:
            score += 28
            add_unique(reasons, "Alan adı resmî kurum, banka, kargo veya kriz yardımı taklidi yapıyor olabilir.")
            add_unique(suggestions, "Resmî sitelere linkten değil, adresi kendin yazarak gir.")

        if scheme == "https":
            ssl_info = check_ssl_certificate(domain)
            details["ssl"] = ssl_info
            if ssl_info["valid"]:
                add_unique(reasons, f"{domain} için HTTPS sertifikası geçerli görünüyor. Bitiş: {ssl_info['expires']}.")
                if ssl_info["days_left"] is not None and ssl_info["days_left"] < 14:
                    score += 8
                    add_unique(reasons, "Sertifikanın süresi çok yakında doluyor; ek kontrol önerilir.")
            else:
                # Resmi ve güvenilir alanlarda geçici bağlantı/sertifika okunamama hatasını ağır cezalandırma.
                score += 8 if trusted else 18
                add_unique(reasons, f"{domain} için HTTPS sertifikası doğrulanamadı veya okunamadı.")
                add_unique(suggestions, "Sertifikası doğrulanamayan adreslerde giriş/ödeme işlemi yapma.")

        http_info = inspect_http(clean)
        details["http"] = http_info
        if http_info["checked"] and http_info.get("security_headers"):
            missing = [h for h, present in http_info["security_headers"].items() if not present]
            if len(missing) >= 4 and not trusted:
                score += 8
                add_unique(reasons, "Web sitesinde temel güvenlik başlıklarının çoğu eksik görünüyor.")
        if http_info.get("final_url"):
            f_clean, f_domain, _ = normalize_domain(http_info["final_url"])
            if f_domain and f_domain != domain:
                score += 12
                add_unique(reasons, f"Link farklı bir alan adına yönleniyor: {f_domain}.")
        details["reputation"] = optional_reputation_checks(domain, clean)
        url_details.append(details)

    critical_hits = [w for w in CRITICAL_ACTION_WORDS if w in low]
    if critical_hits:
        score += min(20, len(critical_hits) * 6)
        add_unique(reasons, "Kullanıcıdan kritik işlem veya hassas bilgi isteme belirtisi var.")
        add_unique(suggestions, "Hesap doğrulama veya ödeme işlemlerini mesajdaki linkten değil, kurumun resmî uygulamasından yap.")

    if module == "sms" and len(text.split()) < 22 and found:
        score += 10
        add_unique(reasons, "SMS kısa, baskı kuran ve hızlı aksiyon isteyen bir yapıda.")
    if module == "mail" and any(w in low for w in ["ek", "fatura", "dosya", "giriş", "hesap", "şifre"]):
        score += 12
        add_unique(reasons, "E-posta içeriğinde dosya, hesap veya giriş bilgisiyle ilişkili riskli ifadeler var.")
    if module == "news" and fake:
        score += 8
        add_unique(reasons, "Haber metni iddialı ve yayılmaya teşvik eden ifadeler içeriyor.")
    if module == "pdf" and any(w in low for w in ["javascript", "makro", "macro", "enable content", "şifreli ek", "sifreli ek", "fatura", "dekont"]):
        score += 18
        add_unique(reasons, "Dosya/PDF senaryosunda makro, JavaScript, fatura veya ek açtırma belirtisi var.")
        add_unique(suggestions, "Bilinmeyen PDF veya eklerde makro/aktif içerik açma; dosyayı güvenli ortamda kontrol et.")

    # Temiz resmî link senaryolarında gereksiz tehlikeli sonucu engelle.
    if urls and all(is_trusted_safe(normalize_domain(u)[1]) for u in urls) and len(found) <= 1 and not fake:
        score = min(score, 18)
        add_unique(suggestions, "Resmî kurum duyurularını yine de tarayıcı adres çubuğundan doğrulayarak aç.")

    score = max(0, min(int(score), 100))
    level, color = ("Tehlikeli", "red") if score >= 70 else (("Şüpheli", "yellow") if score >= 35 else ("Düşük Risk", "green"))
    if not reasons:
        add_unique(reasons, "Belirgin bir yüksek risk göstergesi bulunmadı.")
        add_unique(suggestions, "Yine de kritik işlemlerde resmî kaynaklardan doğrulama yap.")

    threat_type = determine_threat_type(module, text, urls)
    trust = max(0, 100 - score)
    decision = classify_action(score, threat_type)
    mitre = mitre_like_mapping(threat_type, urls)
    intro = "Bu içerik yüksek riskli görünüyor." if score >= 70 else ("Bu içerik bazı şüpheli göstergeler içeriyor." if score >= 35 else "Bu içerikte belirgin bir yüksek risk göstergesi bulunmadı.")
    ai = f"{intro} Ana tehdit türü: {threat_type}. En güçlü bulgu: {reasons[0]} Sistem; dil, alan adı, HTTPS/SSL, yönlendirme, güvenlik başlıkları, alan adı zekâsı ve kullanıcı aksiyonu göstergelerini birlikte değerlendirdi."
    result = {"risk_score": score, "trust_score": trust, "risk_level": level, "color": color, "threat_type": threat_type, "ai_comment": ai, "reasons": reasons, "suggestions": suggestions, "urls": urls, "url_details": url_details, "decision": decision, "mitre_mapping": mitre, "evidence_count": len(reasons)}
    result["confidence"] = confidence_score(result)
    result["threat_stage"] = threat_stage(score)
    result["external_apis"] = external_api_status()
    result["quick_summary"] = {
        "bulgu_sayisi": len(reasons),
        "link_sayisi": len(urls),
        "sertifika_kontrolu": any(bool(d.get("ssl")) for d in url_details),
        "onerilen_oncelik": decision.get("priority", "-")
    }
    return result


def external_api_status():
    """Render ortam değişkenleri üzerinden gerçek API entegrasyon durumunu gösterir."""
    return {
        "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        "google_safe_browsing": bool(os.environ.get("GOOGLE_SAFE_BROWSING_KEY")),
        "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY")),
        "openai": bool(os.environ.get("OPENAI_API_KEY"))
    }

def confidence_score(result):
    base = 55 + min(result.get("evidence_count", 0) * 8, 32)
    if result.get("urls"):
        base += 8
    if result.get("url_details"):
        base += 5
    return max(0, min(98, base))

def threat_stage(score):
    if score >= 85:
        return "Kritik alarm"
    if score >= 70:
        return "Yüksek öncelikli inceleme"
    if score >= 35:
        return "Doğrulama gerekli"
    return "Normal izleme"

def simulated_threat_map():
    """Sunum/demo için canlı tehdit haritası verisi. Gerçek olay iddiası değildir."""
    return [
        {"city":"İstanbul", "phishing":38, "sms":24, "news":12, "risk":"Yüksek"},
        {"city":"Ankara", "phishing":22, "sms":18, "news":16, "risk":"Orta"},
        {"city":"İzmir", "phishing":18, "sms":11, "news":9, "risk":"Orta"},
        {"city":"Kocaeli", "phishing":14, "sms":9, "news":5, "risk":"Orta"},
        {"city":"Bursa", "phishing":16, "sms":10, "news":8, "risk":"Orta"},
        {"city":"Antalya", "phishing":11, "sms":8, "news":6, "risk":"Düşük"}
    ]


def presentation_metrics():
    """Jüri sunumu için tek ekranda gösterilecek özet metrikler."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM analyses")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Tehlikeli'")
    dangerous = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Şüpheli'")
    suspicious = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Düşük Risk'")
    safe = c.fetchone()[0]
    conn.close()
    return {"total": total, "dangerous": dangerous, "suspicious": suspicious, "safe": safe}

def save_analysis(module, text, result):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO analyses (module,input_text,risk_score,risk_level,threat_type,ai_comment,created_at) VALUES (?,?,?,?,?,?,?)", (module, text, result["risk_score"], result["risk_level"], result["threat_type"], result["ai_comment"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

@app.route("/")
def home(): return render_template("index.html", metrics=presentation_metrics(), threat_map=simulated_threat_map())
@app.route("/analyze-page")
def analyze_page(): return render_template("analyze.html", module="general", title="Genel Hibrit Tehdit Analizi")
@app.route("/link")
def link_page(): return render_template("analyze.html", module="link", title="Gelişmiş Link ve Sertifika Analizi")
@app.route("/sms")
def sms_page(): return render_template("analyze.html", module="sms", title="SMS Analizi")
@app.route("/news")
def news_page(): return render_template("analyze.html", module="news", title="Haber / Dezenformasyon Analizi")
@app.route("/qr")
def qr_page(): return render_template("analyze.html", module="qr", title="QR Kod Link Analizi")
@app.route("/mail")
def mail_page(): return render_template("analyze.html", module="mail", title="E-posta Phishing Analizi")
@app.route("/pdf")
def pdf_page(): return render_template("analyze.html", module="pdf", title="PDF / Dosya Link Analizi")

@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM analyses"); total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Tehlikeli'"); dangerous = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Şüpheli'"); suspicious = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Düşük Risk'"); low = c.fetchone()[0]
    c.execute("SELECT threat_type, COUNT(*) FROM analyses GROUP BY threat_type"); threat_stats = c.fetchall()
    c.execute("SELECT module,input_text,risk_score,risk_level,threat_type,created_at FROM analyses ORDER BY id DESC LIMIT 12"); recent = c.fetchall()
    conn.close()
    return render_template("dashboard.html", total=total, dangerous=dangerous, suspicious=suspicious, low=low, threat_stats=threat_stats, recent=recent)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json() or {}
    text = data.get("text", "").strip()
    module = data.get("module", "general").strip()
    if not text:
        return jsonify({"error": "Lütfen analiz edilecek bir metin girin."}), 400
    result = analyze_content(text, module)
    save_analysis(module, text, result)
    return jsonify(result)

@app.route("/admin")
def admin_page():
    return render_template("admin.html", api_status=external_api_status(), threat_map=simulated_threat_map())

@app.route("/api/status")
def api_status():
    return jsonify({"status":"ok", "version":"v7", "apis": external_api_status(), "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

@app.route("/api/threat-map")
def api_threat_map():
    return jsonify(simulated_threat_map())

@app.route("/export-json")
def export_json():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT module,input_text,risk_score,risk_level,threat_type,ai_comment,created_at FROM analyses ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    data = [{"module":r[0],"input_text":r[1],"risk_score":r[2],"risk_level":r[3],"threat_type":r[4],"ai_comment":r[5],"created_at":r[6]} for r in rows]
    resp = make_response(json.dumps(data, ensure_ascii=False, indent=2))
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=ThreatGuard_v6_analiz_gecmisi.json"
    return resp

@app.route("/export-csv")
def export_csv():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT module,input_text,risk_score,risk_level,threat_type,created_at FROM analyses ORDER BY id DESC LIMIT 200")
    rows = c.fetchall()
    conn.close()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Modül", "İçerik", "Risk Puanı", "Risk", "Tehdit Türü", "Tarih"])
    writer.writerows(rows)
    resp = make_response(out.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=ThreatGuard_v6_analiz_gecmisi.csv"
    return resp

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json() or {}
    text = data.get("text", "").strip()
    module = data.get("module", "general").strip()
    if not text:
        return jsonify({"error": "Rapor için önce analiz metni girin."}), 400
    result = analyze_content(text, module)
    url_section = ""
    for d in result.get("url_details", []):
        ssl_text = "Yok"
        if d.get("ssl"):
            ssl_text = f"Geçerli: {d['ssl'].get('valid')} | Bitiş: {d['ssl'].get('expires')} | Sağlayıcı: {d['ssl'].get('issuer')}"
        url_section += f"\n- {d.get('domain')} | HTTPS: {d.get('https')} | Resmî: {d.get('official')} | SSL: {ssl_text}"
    content = f"""ThreatGuard Pro Max v7 Analiz Raporu

Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Modül: {module}

Girilen İçerik:
{text}

Risk Seviyesi: {result['risk_level']}
Risk Puanı: {result['risk_score']}/100
Güven Puanı: {result['trust_score']}/100
Tehdit Türü: {result['threat_type']}
Karar: {result.get('decision',{}).get('verdict','-')}
Önerilen İşlem: {result.get('decision',{}).get('action','-')}
MITRE-benzeri Sınıflandırma: {result.get('mitre_mapping','-')}
Güven Skoru: {result.get('confidence','-')}
Tehdit Aşaması: {result.get('threat_stage','-')}

AI Risk Yorumu:
{result['ai_comment']}

Link/Sertifika Detayı:{url_section if url_section else '\n- Link bulunmadı.'}

Tespit Edilen Bulgular:
- """ + "\n- ".join(result["reasons"]) + """

Güvenlik Önerileri:
- """ + "\n- ".join(result["suggestions"]) + """

Not:
Bu rapor kesin hüküm değil, karar destek amacıyla oluşturulmuştur.
"""
    response = make_response(content)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=ThreatGuard_Pro_Max_v7_Rapor.txt"
    return response

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"ThreatGuard Pro Max v7 çalışıyor: http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
