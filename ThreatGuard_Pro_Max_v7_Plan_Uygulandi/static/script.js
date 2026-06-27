async function analyzeText(){
    const text=document.getElementById("inputText").value;
    const module=document.getElementById("moduleType").value;
    const resultBox=document.getElementById("result");
    const loadingBox=document.getElementById("loadingBox");

    if(!text.trim()){alert("Lütfen analiz edilecek metni gir.");return;}
    resultBox.classList.add("hidden");
    startScanTimeline();

    try{
        const response=await fetch("/analyze",{
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body:JSON.stringify({text:text,module:module})
        });
        const data=await response.json();
        stopScanTimeline();
        if(data.error){alert(data.error);return;}

        resultBox.classList.remove("hidden");
        document.getElementById("riskLevel").innerText="Risk Seviyesi: "+data.risk_level;
        document.getElementById("threatType").innerText="Tehdit Türü: "+data.threat_type;
        document.getElementById("trustScore").innerText="Güven Puanı: "+data.trust_score+"/100";
        document.getElementById("riskScore").innerText=data.risk_score+"/100";
        document.getElementById("aiComment").innerText=data.ai_comment;
        const verdict=document.getElementById("verdictBox");
        updateControlPanel(data);

        const extra=document.getElementById("v6Extra");
        if(extra){
            document.getElementById("confidenceText").innerText=(data.confidence || "-")+"/100";
            document.getElementById("stageText").innerText=data.threat_stage || "-";
            const apis=data.external_apis || {};
            const active=Object.keys(apis).filter(k=>apis[k]).join(", ") || "Demo modu / API anahtarı yok";
            document.getElementById("apiText").innerText=active;
            extra.classList.remove("hidden");
        }
        if(verdict && data.decision){
            document.getElementById("verdictText").innerText=data.decision.verdict || "-";
            document.getElementById("priorityText").innerText=data.decision.priority || "-";
            document.getElementById("actionText").innerText=data.decision.action || "-";
            document.getElementById("mitreText").innerText=data.mitre_mapping || "-";
            verdict.classList.remove("hidden");
        }

        const barFill=document.getElementById("barFill");
        const trustFill=document.getElementById("trustFill");
        barFill.style.width=data.risk_score+"%";
        trustFill.style.width=data.trust_score+"%";
        if(data.color==="red")barFill.style.background="#ff3b3b";
        else if(data.color==="yellow")barFill.style.background="#f5b942";
        else barFill.style.background="#0fb9b1";

        const reasonsList=document.getElementById("reasons");
        reasonsList.innerHTML="";
        data.reasons.forEach(reason=>{
            const li=document.createElement("li");
            li.innerText=reason;
            reasonsList.appendChild(li);
        });

        const suggestionsList=document.getElementById("suggestions");
        suggestionsList.innerHTML="";
        data.suggestions.forEach(suggestion=>{
            const li=document.createElement("li");
            li.innerText=suggestion;
            suggestionsList.appendChild(li);
        });

        const urlBox=document.getElementById("urlDetailsBox");
        const urlList=document.getElementById("urlDetails");
        if(urlBox && urlList){
            urlList.innerHTML="";
            if(data.url_details && data.url_details.length>0){
                urlBox.classList.remove("hidden");
                data.url_details.forEach(item=>{
                    const li=document.createElement("li");
                    let sslText="SSL kontrolü yapılmadı";
                    if(item.ssl){
                        sslText=item.ssl.valid
                            ? `SSL geçerli | Bitiş: ${item.ssl.expires} | Sağlayıcı: ${item.ssl.issuer}`
                            : `SSL doğrulanamadı/geçersiz${item.ssl.error ? " | Hata: "+item.ssl.error : ""}`;
                    }
                    let httpText="HTTP kontrolü yapılamadı";
                    if(item.http && item.http.checked){
                        const headers=item.http.security_headers || {};
                        const present=Object.keys(headers).filter(k=>headers[k]).length;
                        const total=Object.keys(headers).length;
                        httpText=`Final URL: ${item.http.final_url || "Okunamadı"} | Güvenlik başlığı: ${present}/${total}`;
                    }
                    let repText="";
                    if(item.reputation){
                        repText=` | VT: ${item.reputation.virustotal} | GSB: ${item.reputation.google_safe_browsing}`;
                    }
                    let intelText="";
                    if(item.domain_intel){
                        const notes=(item.domain_intel.notes || []).join(", ");
                        intelText=` | Alan adı izi: ${item.domain_intel.fingerprint || "-"}${notes ? " | Sinyal: "+notes : ""}`;
                    }
                    li.innerText=`${item.domain} | HTTPS: ${item.https ? "Var" : "Yok"} | Resmî alan adı: ${item.official ? "Evet" : "Hayır"} | ${sslText} | ${httpText}${intelText}${repText}`;
                    urlList.appendChild(li);
                });
            }else{
                urlBox.classList.add("hidden");
            }
        }
    }catch(error){
        stopScanTimeline();
        alert("Analiz sırasında hata oluştu. Lütfen tekrar dene.");
        console.error(error);
    }
}

function clearResult(){
    const resultBox=document.getElementById("result");
    const loadingBox=document.getElementById("loadingBox");
    const timeline=document.getElementById("scanTimeline");
    if(resultBox) resultBox.classList.add("hidden");
    if(loadingBox) loadingBox.classList.add("hidden");
    if(timeline) timeline.classList.add("hidden");
}

let scanTimer=null;
function startScanTimeline(){
    const loadingBox=document.getElementById("loadingBox");
    const timeline=document.getElementById("scanTimeline");
    const text=document.getElementById("loadingText");
    if(loadingBox) loadingBox.classList.remove("hidden");
    if(timeline) timeline.classList.remove("hidden");
    const steps=timeline ? Array.from(timeline.querySelectorAll("div")) : [];
    steps.forEach(x=>x.classList.remove("active","done"));
    let i=0;
    if(text) text.innerText="ThreatGuard v7 analiz motoru çalışıyor...";
    scanTimer=setInterval(()=>{
        steps.forEach((x,idx)=>{
            x.classList.toggle("active", idx===i);
            if(idx<i) x.classList.add("done");
        });
        i=(i+1)%Math.max(steps.length,1);
    },650);
}
function stopScanTimeline(){
    const loadingBox=document.getElementById("loadingBox");
    const timeline=document.getElementById("scanTimeline");
    if(scanTimer){clearInterval(scanTimer);scanTimer=null;}
    if(loadingBox) loadingBox.classList.add("hidden");
    if(timeline){
        timeline.querySelectorAll("div").forEach(x=>{x.classList.remove("active");x.classList.add("done");});
        setTimeout(()=>timeline.classList.add("hidden"),350);
    }
}
function updateControlPanel(data){
    const panel=document.getElementById("controlPanel");
    if(!panel) return;
    const details=data.url_details || [];
    const hasSsl=details.some(d=>d.ssl && d.ssl.valid);
    const hasRedirect=details.some(d=>d.http && d.http.final_url && d.http.final_url.indexOf(d.domain)===-1);
    const hasIntel=details.some(d=>d.domain_intel);
    const apis=data.external_apis || {};
    const active=Object.keys(apis).filter(k=>apis[k]);
    document.getElementById("sslStatus").innerText=details.length ? (hasSsl ? "Geçerli" : "Kontrol / şüpheli") : "Link yok";
    document.getElementById("whoisStatus").innerText=hasIntel ? "Sinyal üretildi" : "Yok";
    document.getElementById("redirectStatus").innerText=details.length ? (hasRedirect ? "Var" : "Yok") : "Link yok";
    document.getElementById("apiModeStatus").innerText=active.length ? active.join(", ") : "Demo";
    panel.classList.remove("hidden");
}

function setExample(text, autoAnalyze=true){
    document.getElementById("inputText").value=text;
    clearResult();
    if(autoAnalyze){setTimeout(analyzeText, 50);}
}

function loadDanger(){
    setExample("ACİL! Depremzedelere yardım için hemen yardim-afad2026.com adresinden bağış yapın. Son şans, herkes paylaşsın!", true);
}
function loadSuspicious(){
    setExample("Bilinmeyen bir numaradan gelen mesaj: Siparişiniz hakkında bilgi almak için kargo-bilgi.com adresini kontrol edin.", true);
}
function loadSafe(){
    setExample("AFAD'ın güncel duyurularını takip etmek için https://www.afad.gov.tr adresini ziyaret edebilirsiniz.", true);
}

async function downloadReport(){
    const text=document.getElementById("inputText").value;
    const module=document.getElementById("moduleType").value;
    if(!text.trim()){alert("Rapor için önce analiz metni gir.");return;}
    const response=await fetch("/report",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({text:text,module:module})
    });
    const blob=await response.blob();
    const url=window.URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;
    a.download="ThreatGuard_Pro_Max_v7_Rapor.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
}
