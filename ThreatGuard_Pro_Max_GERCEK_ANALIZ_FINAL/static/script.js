
const examples = {
  safe: "https://www.afad.gov.tr/duyurular",
  suspicious: "Acil destek kampanyası başladı, hemen tıkla ve bilgilerini doğrula: http://yardim-kampanya2026.com",
  danger: "Hesabınız askıya alınacaktır. Şifrenizi doğrulamak için giriş yapın: https://edevlet-dogrula-yardim.com/login"
};

function setExample(type){
  document.getElementById("inputText").value = examples[type];
  document.getElementById("result").classList.add("hidden");
  document.getElementById("steps").classList.add("hidden");
}

function animateScore(target){
  const el = document.getElementById("riskScore");
  const circle = document.querySelector(".circle");
  let v = 0;
  const timer = setInterval(()=>{
    v += Math.max(1, Math.ceil(target/35));
    if(v >= target){ v = target; clearInterval(timer); }
    el.textContent = v;
    circle.style.background = `conic-gradient(${target>=75?'#fb7185':target>=40?'#fbbf24':'#36d399'} ${v*3.6}deg,#1b2c46 0deg)`;
  }, 18);
}

function listItems(id, arr){
  const ul = document.getElementById(id);
  ul.innerHTML = "";
  (arr || []).forEach(x=>{
    const li = document.createElement("li");
    li.textContent = x;
    ul.appendChild(li);
  });
}

function renderUrlDetails(details){
  const wrap = document.getElementById("urlDetails");
  wrap.innerHTML = "";
  if(!details || !details.length){
    wrap.innerHTML = "<p class='muted'>Link bulunmadı.</p>";
    return;
  }
  details.forEach(d=>{
    const div = document.createElement("div");
    div.className = "detail";
    const ssl = d.ssl || {};
    const rdap = d.rdap || {};
    const vt = d.virustotal || {};
    const gsb = d.google_safe_browsing || {};
    div.innerHTML = `
      <h4>${d.domain}</h4>
      <span class="pill">HTTPS: ${d.https ? "Var" : "Yok"}</span>
      <span class="pill">SSL: ${ssl.valid ? "Geçerli" : "Geçersiz/Yok"}</span>
      <span class="pill">TLS: ${ssl.tls_version || "Bilinmiyor"}</span>
      <span class="pill">Domain Yaşı: ${rdap.age_days ?? "Bilinmiyor"}</span>
      <span class="pill">Redirect: ${(d.redirects && d.redirects.count) || 0}</span>
      <span class="pill">VirusTotal: ${vt.enabled ? ((vt.malicious||0)+" zararlı") : "API yok"}</span>
      <span class="pill">Safe Browsing: ${gsb.enabled ? (gsb.malicious ? "Tehdit" : "Temiz") : "API yok"}</span>
      <p class="muted">Final URL: ${(d.redirects && d.redirects.final_url) || d.normalized_url}</p>
    `;
    wrap.appendChild(div);
  });
}

async function runAnalysis(){
  const text = document.getElementById("inputText").value.trim();
  const module = document.getElementById("module").value;
  if(!text){ alert("Lütfen analiz edilecek metin/link gir."); return; }

  document.getElementById("result").classList.add("hidden");
  const steps = document.getElementById("steps");
  steps.classList.remove("hidden");

  const res = await fetch("/analyze", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({text, module})
  });
  const data = await res.json();
  steps.classList.add("hidden");

  if(data.error){ alert(data.error); return; }

  document.getElementById("result").classList.remove("hidden");
  document.getElementById("riskLevel").textContent = data.risk_level;
  document.getElementById("threatType").textContent = data.threat_type;
  document.getElementById("trustScore").textContent = data.trust_score + "/100";
  document.getElementById("urlCount").textContent = (data.urls || []).length;
  document.getElementById("apiStatus").textContent = `VT: ${data.api_status.virustotal ? "Aktif" : "API yok"} / GSB: ${data.api_status.google_safe_browsing ? "Aktif" : "API yok"}`;
  document.getElementById("aiComment").textContent = data.ai_comment;
  listItems("reasons", data.reasons);
  listItems("suggestions", data.suggestions);
  renderUrlDetails(data.url_details);
  animateScore(data.risk_score);
}

async function downloadReport(){
  const text = document.getElementById("inputText").value.trim();
  const module = document.getElementById("module").value;
  if(!text){ alert("Önce analiz metni gir."); return; }
  const res = await fetch("/report", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({text,module})});
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "ThreatGuard_Profesyonel_Rapor.txt";
  document.body.appendChild(a); a.click(); a.remove();
  window.URL.revokeObjectURL(url);
}
