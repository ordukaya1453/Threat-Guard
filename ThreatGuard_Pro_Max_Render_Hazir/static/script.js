async function analyzeText(){
    const text=document.getElementById("inputText").value;
    const module=document.getElementById("moduleType").value;
    const resultBox=document.getElementById("result");
    const loadingBox=document.getElementById("loadingBox");

    if(!text.trim()){alert("Lütfen analiz edilecek bir metin gir.");return;}

    resultBox.classList.add("hidden");
    loadingBox.classList.remove("hidden");

    setTimeout(async ()=>{
        const response=await fetch("/analyze",{
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body:JSON.stringify({text:text,module:module})
        });

        const data=await response.json();
        loadingBox.classList.add("hidden");

        if(data.error){alert(data.error);return;}

        resultBox.classList.remove("hidden");
        document.getElementById("riskLevel").innerText="Risk Seviyesi: "+data.risk_level;
        document.getElementById("threatType").innerText="Tehdit Türü: "+data.threat_type;
        document.getElementById("trustScore").innerText="Güven Puanı: "+data.trust_score+"/100";
        document.getElementById("riskScore").innerText=data.risk_score+"/100";
        document.getElementById("aiComment").innerText=data.ai_comment;

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
    }, 500);
}

function setExample(text){
    document.getElementById("inputText").value=text;
}

function loadDanger(){
    document.getElementById("inputText").value="ACİL! Depremzedelere yardım için hemen yardim-afad2026.com adresinden bağış yapın. Son şans, herkes paylaşsın!";
}
function loadSuspicious(){
    document.getElementById("inputText").value="Hesabınız güvenlik nedeniyle askıya alınacaktır. Hemen giriş yaparak şifrenizi doğrulayın: banka-giris-guvenlik.com";
}
function loadSafe(){
    document.getElementById("inputText").value="AFAD'ın güncel duyurularını takip etmek için afad.gov.tr adresini ziyaret edebilirsiniz.";
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
    a.download="ThreatGuard_Analiz_Raporu.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
}
