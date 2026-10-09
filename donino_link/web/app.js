"use strict";
const $ = id => document.getElementById(id);
let csrf = "", state = null;
const colors = ["#967ccb", "#5794a3", "#c89765", "#a780a2", "#748bb8"];
const fa = n => new Intl.NumberFormat("fa-IR", {maximumFractionDigits:1}).format(n);
const bytes = n => n >= 2**30 ? (n/2**30).toFixed(2)+" GB" : n >= 2**20 ? (n/2**20).toFixed(1)+" MB" : (n/1024).toFixed(1)+" KB";
function el(tag, text, cls) { const n=document.createElement(tag); if(text!==undefined) n.textContent=text; if(cls) n.className=cls; return n; }
async function api(path, body) {
  const r=await fetch(path,{credentials:"same-origin",method:body===undefined?"GET":"POST",headers:body===undefined?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body===undefined?undefined:JSON.stringify(body)});
  if(!r.ok){ if(r.status===401 && path!=="/api/login") loggedOut(); throw new Error(r.status===429?"تلاش‌ها زیاد بوده؛ پنج دقیقه صبر کن.":r.status===401?"رمز نادرست است یا نشست پایان یافته.":"درخواست انجام نشد؛ اتصال و دسترسی را بررسی کن."); }
  return r.json();
}
function loggedOut(){ $("login").hidden=false; $("dashboard").hidden=true; csrf=""; }
function loggedIn(){ $("login").hidden=true; $("dashboard").hidden=false; refresh(); }
function notice(text){ $("notice").textContent=text; $("notice").hidden=!text; }
async function action(path, name){try{await api("/api/action",{path,action:name}); await refresh();}catch(e){notice(e.message);}}
$("login-form").addEventListener("submit",async e=>{e.preventDefault();$("login-error").textContent=""; const b=e.target.querySelector("button");b.disabled=true;try{const d=await api("/api/login",{password:$("password").value});csrf=d.csrf;$("password").value="";loggedIn();}catch(e){$("login-error").textContent=e.message;}finally{b.disabled=false;}});
$("logout").onclick=async()=>{try{await api("/api/logout",{});}finally{loggedOut();}};
$("mobile-logout").onclick=$("logout").onclick;
$("auto").onclick=()=>action(null,"auto");
$("pause").onclick=()=>action(null,state?.paused?"resume":"pause");
$("export").onclick=()=>{window.location.href="/api/export";};
const modeNames={enabled:"فعال",disabled:"غیرفعال",draining:"در حال تخلیه"};
const eventNames={"path-health":"سلامت مسیر","operator":"عملیات مدیر","login":"ورود مدیر","login-failed":"ورود ناموفق","route-change":"تغییر مسیر","backend-connect-failed":"مقصد در دسترس نیست"};
function render(d){
  state=d;
  const healthy=d.paths.filter(p=>p.healthy&&p.mode==="enabled");
  $("healthy").textContent=fa(healthy.length)+" / "+fa(d.paths.length);
  $("active").textContent=fa(d.active);
  const selected=d.paths.find(p=>p.id===d.selected);
  $("selected").textContent=d.paused?"ورودی جدید متوقف است":d.selected||"مسیر سالمی در دسترس نیست";
  $("hero-description").textContent=d.preferred?"مسیر ترجیحی: "+d.preferred+" · در صورت خرابی، مسیر سالم بعدی انتخاب می‌شود.":"انتخاب خودکار فعال است؛ سلامت هر مسیر با پاسخ امضاشدهٔ سرور خارج بررسی می‌شود.";
  $("latency").textContent=selected?.latency_ms!==null&&selected?.latency_ms!==undefined?selected.latency_ms.toFixed(1)+" ms":"—";
  $("traffic").textContent=bytes(d.paths.reduce((s,p)=>s+p.bytes_up+p.bytes_down,0));
  $("pause").textContent=d.paused?"ادامهٔ اتصال‌های جدید":"توقف اتصال‌های جدید";
  $("live").textContent="به‌روز · "+new Date(d.time*1000).toLocaleTimeString("fa-IR");$("live").className="badge good";
  notice(d.paused?"ورودی اتصال‌های جدید متوقف است؛ ارتباط‌های جاری ادامه دارند.":!d.selected?"هیچ مسیر سالمی موجود نیست. وضعیت سرویس تانل و دسترسی دو سرور را بررسی کن.":"");
  const cards=d.paths.map(p=>{
    const card=$("path-template").content.firstElementChild.cloneNode(true);
    if(p.id===d.selected) card.classList.add("selected");
    card.querySelector("h3").textContent=p.id;
    card.querySelector(".transport").textContent=p.transport.toUpperCase();
    const b=card.querySelector(".path-status"); b.textContent=p.healthy?"سالم":"ناموفق";b.classList.add(p.healthy?"good":"bad");
    const metrics=card.querySelector(".path-metrics");
    [[p.latency_ms===null?"—":p.latency_ms.toFixed(1)+" ms","تأخیر"],[fa(p.active),"اتصال فعال"],[bytes(p.bytes_up+p.bytes_down),"ترافیک"]].forEach(([v,l])=>{const n=el("div");n.append(el("b",v),el("span",l));metrics.append(n);});
    card.querySelector(".mode").textContent=modeNames[p.mode];
    const menu=card.querySelector("select");menu.onchange=()=>{if(menu.value)action(p.id,menu.value);};
    return card;
  });if(document.activeElement?.tagName!=="SELECT")$("path-list").replaceChildren(...cards);
  chart(d.paths);
  const remote=d.paths.find(p=>p.healthy&&p.remote?.memory_total)?.remote;
  const hosts=[["سرور ایران",d.host],["سرور خارج",remote]];
  $("hosts").replaceChildren(...hosts.map(([name,h])=>{const n=el("div",undefined,"host"),head=el("div",undefined,"host-head");head.append(el("strong",name),el("span",h?"دادهٔ زنده":"در انتظار پاسخ","muted"));n.append(head);if(h){const details=el("div",undefined,"host-details");details.append(el("span","بار CPU: "+fa(h.load?.[0]||0)),el("span","حافظه: "+(h.memory_total?fa(100*h.memory_used/h.memory_total)+"٪":"—")));n.append(details);}return n;}));
  $("counters").textContent="پذیرفته‌شده: "+fa(d.accepted)+" · ردشده: "+fa(d.rejected)+" · تغییر مسیر: "+fa(d.route_changes);
  $("event-list").replaceChildren(...d.events.map(e=>{const n=el("div",undefined,"event");n.append(el("span",eventNames[e.kind]||e.kind,"event-kind"),el("span",JSON.stringify(e.detail),"event-detail"),el("time",new Date(e.time*1000).toLocaleString("fa-IR")));return n;}));
  $("updated").textContent="به‌روز هر ۳ ثانیه";
  $("uptime").textContent="زمان فعالیت: "+fa(Math.floor(d.uptime/60))+" دقیقه";
}
function svg(tag,attrs,text){const n=document.createElementNS("http://www.w3.org/2000/svg",tag);Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,v));if(text!==undefined)n.textContent=text;return n;}
function chart(paths){
  const c=$("chart"),nodes=[];
  const max=Math.max(20,...paths.flatMap(p=>p.history.filter(x=>x.ok).map(x=>x.latency||0)))*1.15;
  for(let i=0;i<5;i++){const y=20+i*45;nodes.push(svg("line",{x1:45,y1:y,x2:705,y2:y,stroke:"#eceff5","stroke-dasharray":"3 5"}));nodes.push(svg("text",{x:5,y:y+4},Math.round(max*(1-i/4))+" ms"));}
  paths.forEach((p,i)=>{const points=[];p.history.forEach((h,j)=>{if(!h.ok){if(points.length){nodes.push(svg("polyline",{points:points.join(" "),fill:"none",stroke:colors[i%colors.length],"stroke-width":2}));points.length=0;}return;}points.push((45+660*j/Math.max(1,p.history.length-1))+","+(200-180*h.latency/max));});if(points.length)nodes.push(svg("polyline",{points:points.join(" "),fill:"none",stroke:colors[i%colors.length],"stroke-width":2}));});
  c.replaceChildren(...nodes);
  $("legend").replaceChildren(...paths.map((p,i)=>el("span",p.id,"c"+(i%5))));
}
let refreshing=false;
async function refresh(){if(!csrf||refreshing)return;refreshing=true;try{render(await api("/api/status"));}catch(e){$("live").textContent="ارتباط پنل قطع است";$("live").className="badge bad";notice(e.message);}finally{refreshing=false;}}
api("/api/session").then(d=>{csrf=d.csrf;loggedIn();}).catch(()=>loggedOut());
setInterval(()=>{if(!$("dashboard").hidden)refresh();},3000);
