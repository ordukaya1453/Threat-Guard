from flask import Flask, render_template, request, jsonify, make_response
import sqlite3, re, os
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)
DB_NAME = "threatguard_pro_max.db"

OFFICIAL_DOMAINS = ["afad.gov.tr","icisleri.gov.tr","saglik.gov.tr","turkiye.gov.tr","gov.tr","edu.tr"]
SUSPICIOUS_WORDS = ["acil","hemen","son şans","son sans","tıkla","tikla","şifre","sifre","giriş yap","giris yap","ödeme","odeme","bağış","bagis","iban","para","yardım","yardim","kampanya","doğrula","dogrula","hesabınız","hesabiniz","askıya alınacaktır","ödül","odul","kazandınız","kazandiniz"]
FAKE_NEWS_WORDS = ["kesin bilgi","saklanan gerçek","gizli gerçek","paylaşmadan geçme","herkesten saklanıyor","şok","inanılmaz","büyük iddia","son dakika","panik","kimse bilmiyor","devlet saklıyor","yetkililer açıklamıyor"]

def init_db():
    conn=sqlite3.connect(DB_NAME); c=conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS analyses (id INTEGER PRIMARY KEY AUTOINCREMENT,module TEXT,input_text TEXT,risk_score INTEGER,risk_level TEXT,threat_type TEXT,ai_comment TEXT,created_at TEXT)")
    conn.commit(); conn.close()

def extract_urls(text):
    return re.findall(r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)

def determine_threat_type(module, text, urls):
    low=text.lower()
    if module=="mail": return "E-posta Phishing Analizi"
    if module=="news": return "Dezenformasyon / Haber Analizi"
    if module=="qr": return "QR Kod / Link Riski"
    if module=="sms": return "SMS Dolandırıcılığı"
    if urls and any(w in low for w in ["şifre","sifre","giriş","giris","hesap","doğrula","dogrula"]): return "Phishing / Kimlik Avı"
    if any(w in low for w in ["bağış","bagis","yardım","yardim","iban","para"]): return "Kriz Dolandırıcılığı"
    if any(w in low for w in FAKE_NEWS_WORDS): return "Dezenformasyon"
    if urls: return "Şüpheli Link"
    return "Genel Hibrit Tehdit Riski"

def analyze_content(text, module="general"):
    low=text.lower(); score=0; reasons=[]; suggestions=[]; urls=extract_urls(text)
    found=[w for w in SUSPICIOUS_WORDS if w in low]
    if found:
        score+=min(len(found)*8,35)
        reasons.append("İçerikte aciliyet, para, şifre, hesap veya doğrulama isteyen ifadeler bulundu.")
        suggestions.append("Kişisel bilgi, şifre, IBAN veya ödeme bilgisi paylaşmadan önce kaynağı doğrula.")
    fake=[w for w in FAKE_NEWS_WORDS if w in low]
    if fake:
        score+=min(len(fake)*8,30)
        reasons.append("İçerikte panik, abartı veya doğrulanmamış haber dili bulunuyor.")
        suggestions.append("Haberi resmi kaynaklardan ve güvenilir haber sitelerinden kontrol et.")
    for url in urls:
        clean=url if url.startswith("http") else "http://"+url
        domain=urlparse(clean).netloc.replace("www.","").lower()
        if any(o in domain for o in OFFICIAL_DOMAINS):
            score-=10; reasons.append(f"{domain} alan adı resmi veya güvenilir görünüyor.")
        else:
            score+=25; reasons.append(f"{domain} alan adı resmi kurum alan adına benzemiyor.")
            suggestions.append("Linke tıklamadan önce alan adını manuel olarak kontrol et.")
        if "-" in domain or domain.count(".")>=2:
            score+=10; reasons.append("Alan adında tire veya fazla nokta kullanımı var; bu phishing belirtisi olabilir.")
        if any(x in domain for x in ["afad","edevlet","e-devlet","yardim","banka","ptt","deprem"]) and not any(o in domain for o in OFFICIAL_DOMAINS):
            score+=20; reasons.append("Alan adı resmi kurum veya banka taklidi yapıyor olabilir.")
            suggestions.append("Resmi sitelere adresi kendin yazarak gir.")
    if module=="sms" and len(text.split())<20 and found:
        score+=10; reasons.append("SMS kısa, baskı kuran ve hızlı aksiyon isteyen bir yapıya sahip.")
    if module=="mail" and any(w in low for w in ["ek","fatura","dosya","giriş","hesap","şifre"]):
        score+=12; reasons.append("E-posta içeriğinde dosya, hesap veya giriş bilgisiyle ilişkili riskli ifadeler var.")
    if module=="news" and fake:
        score+=8; reasons.append("Haber metni iddialı ve yayılmaya teşvik eden ifadeler içeriyor.")
    score=max(0,min(score,100))
    level,color=("Tehlikeli","red") if score>=70 else (("Şüpheli","yellow") if score>=35 else ("Düşük Risk","green"))
    if not reasons:
        reasons.append("Belirgin bir yüksek risk göstergesi bulunmadı.")
        suggestions.append("Yine de kritik işlemlerde resmi kaynaklardan doğrulama yap.")
    tt=determine_threat_type(module,text,urls); trust=max(0,100-score)
    intro="Bu içerik yüksek riskli görünüyor." if score>=70 else ("Bu içerik bazı şüpheli göstergeler içeriyor." if score>=35 else "Bu içerikte belirgin bir yüksek risk göstergesi bulunmadı.")
    ai=f"{intro} Tespit edilen ana tehdit türü: {tt}. {reasons[0]} Kullanıcının resmi kaynaklardan doğrulama yapması önerilir."
    return {"risk_score":score,"trust_score":trust,"risk_level":level,"color":color,"threat_type":tt,"ai_comment":ai,"reasons":list(dict.fromkeys(reasons)),"suggestions":list(dict.fromkeys(suggestions)),"urls":urls}

def save_analysis(module,text,result):
    conn=sqlite3.connect(DB_NAME); c=conn.cursor()
    c.execute("INSERT INTO analyses (module,input_text,risk_score,risk_level,threat_type,ai_comment,created_at) VALUES (?,?,?,?,?,?,?)",(module,text,result["risk_score"],result["risk_level"],result["threat_type"],result["ai_comment"],datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); conn.close()

@app.route("/")
def home(): return render_template("index.html")
@app.route("/analyze-page")
def analyze_page(): return render_template("analyze.html", module="general", title="Genel Hibrit Tehdit Analizi")
@app.route("/link")
def link_page(): return render_template("analyze.html", module="link", title="Link Analizi")
@app.route("/sms")
def sms_page(): return render_template("analyze.html", module="sms", title="SMS Analizi")
@app.route("/news")
def news_page(): return render_template("analyze.html", module="news", title="Haber / Dezenformasyon Analizi")

@app.route("/dashboard")
def dashboard():
    conn=sqlite3.connect(DB_NAME); c=conn.cursor()
    c.execute("SELECT COUNT(*) FROM analyses"); total=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Tehlikeli'"); dangerous=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Şüpheli'"); suspicious=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='Düşük Risk'"); low=c.fetchone()[0]
    c.execute("SELECT threat_type, COUNT(*) FROM analyses GROUP BY threat_type"); threat_stats=c.fetchall()
    c.execute("SELECT module,input_text,risk_score,risk_level,threat_type,created_at FROM analyses ORDER BY id DESC LIMIT 12"); recent=c.fetchall()
    conn.close()
    return render_template("dashboard.html", total=total, dangerous=dangerous, suspicious=suspicious, low=low, threat_stats=threat_stats, recent=recent)

@app.route("/analyze", methods=["POST"])
def analyze():
    data=request.get_json(); text=data.get("text","").strip(); module=data.get("module","general").strip()
    if not text: return jsonify({"error":"Lütfen analiz edilecek bir metin girin."}),400
    result=analyze_content(text,module); save_analysis(module,text,result); return jsonify(result)

@app.route("/report", methods=["POST"])
def report():
    data=request.get_json(); text=data.get("text","").strip(); module=data.get("module","general").strip()
    if not text: return jsonify({"error":"Rapor için önce analiz metni girin."}),400
    result=analyze_content(text,module)
    content=f"""ThreatGuard Pro Max Analiz Raporu

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

Tespit Edilen Bulgular:
- """+"\n- ".join(result["reasons"])+"""

Güvenlik Önerileri:
- """+"\n- ".join(result["suggestions"])+"""

Not:
Bu rapor kesin hüküm vermek yerine karar destek amacıyla oluşturulmuştur.
"""
    response=make_response(content)
    response.headers["Content-Type"]="text/plain; charset=utf-8"
    response.headers["Content-Disposition"]="attachment; filename=ThreatGuard_Analiz_Raporu.txt"
    return response

# Render/Gunicorn ortamında da veritabanı tablosu hazır olsun.
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"ThreatGuard Pro Max çalışıyor: http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
