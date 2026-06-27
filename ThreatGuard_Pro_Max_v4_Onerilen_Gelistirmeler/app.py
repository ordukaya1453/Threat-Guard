from flask import Flask, render_template, request, jsonify, make_response
import sqlite3, re, os, ssl, socket, json, ipaddress
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
        req = Request(url, method="GET", headers={"User-Agent": "ThreatGuard-Pro-Max/1.0"})
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

def determine_threat_type(module, text, urls):
    low = text.lower()
    if module == "mail": return "E-posta Phishing Analizi"
    if module == "news": return "Dezenformasyon / Haber Analizi"
    if module == "qr": return "QR Kod / Link Riski"
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

    if module == "sms" and len(text.split()) < 22 and found:
        score += 10
        add_unique(reasons, "SMS kısa, baskı kuran ve hızlı aksiyon isteyen bir yapıda.")
    if module == "mail" and any(w in low for w in ["ek", "fatura", "dosya", "giriş", "hesap", "şifre"]):
        score += 12
        add_unique(reasons, "E-posta içeriğinde dosya, hesap veya giriş bilgisiyle ilişkili riskli ifadeler var.")
    if module == "news" and fake:
        score += 8
        add_unique(reasons, "Haber metni iddialı ve yayılmaya teşvik eden ifadeler içeriyor.")

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
    intro = "Bu içerik yüksek riskli görünüyor." if score >= 70 else ("Bu içerik bazı şüpheli göstergeler içeriyor." if score >= 35 else "Bu içerikte belirgin bir yüksek risk göstergesi bulunmadı.")
    ai = f"{intro} Ana tehdit türü: {threat_type}. En güçlü bulgu: {reasons[0]} Sistem; dil, alan adı, HTTPS/SSL, yönlendirme ve güvenlik başlıklarını birlikte değerlendirdi."
    return {"risk_score": score, "trust_score": trust, "risk_level": level, "color": color, "threat_type": threat_type, "ai_comment": ai, "reasons": reasons, "suggestions": suggestions, "urls": urls, "url_details": url_details}

def save_analysis(module, text, result):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO analyses (module,input_text,risk_score,risk_level,threat_type,ai_comment,created_at) VALUES (?,?,?,?,?,?,?)", (module, text, result["risk_score"], result["risk_level"], result["threat_type"], result["ai_comment"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

@app.route("/")
def home(): return render_template("index.html")
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
    content = f"""ThreatGuard Pro Max v4 Analiz Raporu

Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Modül: {module}

Girilen İçerik:
{text}

Risk Seviyesi: {result['risk_level']}
Risk Puanı: {result['risk_score']}/100
Güven Puanı: {result['trust_score']}/100
Tehdit Türü: {result['threat_type']}

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
    response.headers["Content-Disposition"] = "attachment; filename=ThreatGuard_Pro_Max_v4_Rapor.txt"
    return response

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"ThreatGuard Pro Max v4 çalışıyor: http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
