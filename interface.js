"use strict";
const byId=id=>document.getElementById(id);
const esc=value=>String(value).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const pct=x=>(x*100).toFixed(1)+"%";
function table(headers,rows){
  return '<div class="scroll"><table><thead><tr>'+headers.map(h=>"<th>"+esc(h)+"</th>").join("")+
    "</tr></thead><tbody>"+rows.map(row=>"<tr>"+row.map(v=>"<td>"+esc(v)+"</td>").join("")+"</tr>").join("")+"</tbody></table></div>";
}
function bars(items,global=false){
  const max=Math.max(...items.map(x=>Math.abs(x.impact)),0.00001);
  return items.map(x=>'<div class="impact"><span>'+esc(x.feature)+'</span><div class="track"><div class="bar '+
    (!global && x.impact>0?"pos":"")+'" style="width:'+Math.abs(x.impact)/max*100+'%"></div></div><span class="metric">'+
    (x.impact>0&&!global?"+":"")+x.impact.toFixed(2)+'</span></div>').join("");
}
const method="Exact interventional linear SHAP in log-odds relative to the mean transformed training vector.";
const limitations="ClaMP historical header data. Scores are uncalibrated. Family and temporal generalization are untested. Packing signals have no verified ground truth.";
let active=0;
function start(){
  active++;
  byId("report").hidden=true;
  byId("status").textContent="";
  return active;
}
function show(record) {
  const r=record.prediction, pe=record.pe, example=!pe;
  const report=byId("report");
  report.innerHTML='<div class="card"><div class="topline"><h2>'+esc(record.name)+'</h2><button id="save">Save JSON report</button></div>'+
    '<p class="meta">'+esc(example?"ClaMP held-out record · dataset label "+record.datasetLabel:pe.format+" · "+record.size.toLocaleString()+" bytes · machine "+pe.machine)+'</p>'+
    (example?'':'<p class="meta">SHA-256 '+esc(record.sha256)+'</p>')+
    '<div class="result"><strong>'+r.label+'</strong></div><p>Malicious-class model score <b>'+pct(r.score)+'</b> · Logistic regression · Decision threshold 0.50</p>'+
    '<small>'+esc(limitations)+'</small></div>'+
    '<div class="grid"><div class="card"><h3>Why the score moved</h3><p>Largest local SHAP contributions in log-odds. Positive values raise the malicious-class score.</p>'+
    bars(r.contributions.slice(0,5))+'</div><div class="card"><h3>Packing evidence</h3>'+
    (example?'<p>The dataset record contains only model inputs. Section bytes and import tables are unavailable.</p>':
    '<p><b>Packing status unverified.</b> '+(pe.indicators.length?'Observed structural indicators are listed below.':'No configured indicator triggered.')+'</p>'+
    pe.indicators.map(s=>'<div>'+esc(s)+'</div>').join("")+'<p>Whole-file entropy <b>'+pe.fileEntropy.toFixed(3)+'</b> bits/byte.</p>')+'</div></div>'+
    (example?'':'<details><summary>Sections and imports</summary>'+table(["Section","Raw bytes","Virtual bytes","Permissions","Entropy"],pe.sections.map(s=>[s.name,s.rawSize,s.virtualSize,s.permissions,s.entropy?.toFixed(3)??"Empty"]))+
    '<p>Visible imported DLLs ('+pe.imports.length+')</p><div class="meta">'+esc(pe.imports.join(", ")||"None listed")+'</div>'+
    pe.warnings.map(s=>'<p>'+esc(s)+'</p>').join("")+'</details>')+
    '<details><summary>All header values and model contributions</summary><p>Baseline '+r.baselineLogOdds.toFixed(3)+' + contributions = '+r.logOdds.toFixed(3)+' final log-odds.</p>'+
    table(["Header field","Observed value","SHAP (log-odds)"],r.contributions.map(x=>[x.feature,x.value,x.impact.toFixed(4)]))+'</details>';
  report.hidden=false;
  byId("save").onclick=()=>{
    const url=URL.createObjectURL(new Blob([JSON.stringify(record,null,2)],{type:"application/json"}));
    const link=document.createElement("a");link.href=url;link.download="pe-forensics-report.json";link.click();
    setTimeout(()=>URL.revokeObjectURL(url),5000);
  };
}
function record(name,values,extra){
  return {name,analyzedUTC:new Date().toISOString(),model:MODEL.version,threshold:0.5,dataset:"ClaMP Raw 5184",
    trainingSourceSHA256:MODEL.digest,explanationMethod:method,limitations,prediction:score(values),...extra};
}
function example(i){
  start(); byId("file").value="";
  const e=MODEL.examples[i];
  show(record(i?"Malware reference case":"Benign reference case",e.features,
    {inputType:"held-out feature vector",datasetLabel:i?"malware":"benign",packingStatus:"Unavailable"}));
}
byId("benign").onclick=()=>example(0);
byId("malware").onclick=()=>example(1);
byId("file").onchange=async event=>{
  const f=event.target.files[0]; if(!f)return;
  const id=start();byId("status").textContent="Reading file…";
  try {
    if(f.size>32*1024*1024)throw Error("File exceeds the 32 MiB inspection limit.");
    const buffer=await f.arrayBuffer(), pe=parsePE(buffer);
    const digest=await crypto.subtle.digest("SHA-256",buffer);
    if(id!==active)return;
    const sha256=Array.from(new Uint8Array(digest),x=>x.toString(16).padStart(2,"0")).join("");
    show(record(f.name,MODEL.features.map(k=>pe.fields[k]),{inputType:"static PE bytes",size:f.size,sha256,
      fileModifiedUTC:new Date(f.lastModified).toISOString(),pe,packingStatus:"Unverified"}));
    byId("status").textContent="";
  }catch(err){if(id===active)byId("status").textContent=err.message;}
};
const metrics=MODEL.metrics;
byId("metrics").innerHTML='<p>ClaMP Raw supplied '+MODEL.sourceRows+' labeled rows. Grouping identical model inputs produced '+MODEL.unique+' vectors. We excluded '+MODEL.conflicted+' conflicting vectors and kept one row per remaining vector.</p>'+
  '<p>Stratified split, seed 42. Training included '+MODEL.trainCounts.join(" benign / ")+' malware records. Testing included '+MODEL.testCounts.join(" benign / ")+' malware records. Related families may span splits.</p>'+
  table(["Model","Accuracy","Precision","Recall","F1","ROC-AUC","False-positive rate"],metrics.map(m=>[m.name,pct(m.accuracy),pct(m.precision),pct(m.recall),m.f1.toFixed(3),m.auc.toFixed(3),pct(m.fpr)]))+
  table(["Model","True benign","False alarms","Missed malware","True malware"],metrics.map(m=>[m.name,m.tn,m.fp,m.fn,m.tp]))+
  '<h3>Global feature influence</h3><p>Mean absolute SHAP contribution on the held-out split for the deployed logistic regression, in log-odds.</p>'+
  bars(MODEL.features.map((feature,i)=>({feature,impact:MODEL.globalImpact[i]})).sort((a,b)=>b.impact-a.impact).slice(0,7),true)+
  '<p>The linear model was chosen in advance for exact additive explanations. All three models use the same inputs and split.</p>';

