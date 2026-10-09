"use strict";
const $ = id => document.getElementById(id);
let csrf = "", state = null, actionPending = false, previousTraffic = null, toastTimer = null;
const colors = ["#a48bd7", "#69a6b3", "#d9ad71", "#bb83a9", "#7e9fd4"];
const fa = n => new Intl.NumberFormat("fa-IR", {maximumFractionDigits:1}).format(n);
const bytes = n => n >= 2**30 ? (n/2**30).toFixed(2)+" GB" : n >= 2**20 ? (n/2**20).toFixed(1)+" MB" : (n/1024).toFixed(1)+" KB";
function el(tag, text, cls) { const n=document.createElement(tag); if(text!==undefined) n.textContent=text; if(cls) n.className=cls; return n; }
async function api(path, body) {
  const r=await fetch(path,{credentials:"same-origin",method:body===undefined?"GET":"POST",headers:body===undefined?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body===undefined?undefined:JSON.stringify(body)});
  if(!r.ok){ if(r.status===401 && path!=="/api/login") loggedOut(); throw new Error(r.status===429?"تلاش‌ها زیاد بوده؛ پنج دقیقه صبر کن.":r.status===401?"رمز نادرست است یا نشست پایان یافته.":"درخواست انجام نشد؛ اتصال و دسترسی را بررسی کن."); }
  return r.json();
}
function loggedOut(){ $("login").hidden=false; $("dashboard").hidden=true; csrf=""; state=null; previousTraffic=null; }
function loggedIn(){ $("login").hidden=true; $("dashboard").hidden=false; refresh(); }
function notice(text){ $("notice").textContent=text; $("notice").hidden=!text; }
function toast(text){$("toast").textContent=text;$("toast").hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$("toast").hidden=true,4500);}
async function action(path,name){
  if(actionPending)return;actionPending=true;$("auto").disabled=true;$("pause").disabled=true;
  try{await api("/api/action",{path,action:name});await refresh();toast("تنظیم مسیر به‌روز شد.");}catch(e){toast(e.message);}finally{actionPending=false;$("auto").disabled=false;$("pause").disabled=false;}
}
$("login-form").addEventListener("submit",async e=>{e.preventDefault();$("login-error").textContent=""; const b=e.target.querySelector("button");b.disabled=true;try{const d=await api("/api/login",{password:$("password").value});csrf=d.csrf;$("password").value="";loggedIn();}catch(e){$("login-error").textContent=e.message;}finally{b.disabled=false;}});
$("logout").onclick=async()=>{try{await api("/api/logout",{});loggedOut();}catch(e){toast(e.message);}};
$("mobile-logout").onclick=$("logout").onclick;
$("auto").onclick=()=>action(null,"auto");
$("pause").onclick=()=>action(null,state?.paused?"resume":"pause");
$("export").onclick=()=>{window.location.href="/api/export";};
$("refresh").onclick=()=>refresh();
function setTheme(theme){document.documentElement.dataset.theme=theme;$("theme").setAttribute("aria-pressed",String(theme==="dark"));try{localStorage.setItem("donino-theme",theme);}catch{}}
let savedTheme="light";try{savedTheme=localStorage.getItem("donino-theme")||"light";}catch{}
setTheme(savedTheme==="dark"?"dark":"light");
$("theme").onclick=()=>setTheme(document.documentElement.dataset.theme==="dark"?"light":"dark");
document.querySelectorAll(".connection-mode").forEach(n=>n.textContent=location.protocol==="https:"?"HTTPS":"HTTP");
document.querySelectorAll("nav a").forEach(a=>a.onclick=()=>{document.querySelectorAll("nav a").forEach(n=>n.classList.toggle("nav-active",n===a));});
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
  const total=d.paths.reduce((sum,p)=>sum+p.bytes_up+p.bytes_down,0);
  $("traffic").textContent=bytes(total);
  if(previousTraffic&&d.time>previousTraffic.time&&total>=previousTraffic.total){$("traffic-rate").textContent="نرخ مجموع دو جهت: "+bytes((total-previousTraffic.total)/(d.time-previousTraffic.time))+"/s";}
  previousTraffic={time:d.time,total};
  $("routing-mode").textContent=d.preferred?"مسیر ترجیحی":"انتخاب خودکار";
  $("path-summary").textContent=fa(d.paths.length)+" مسیر · "+fa(healthy.length)+" سالم و فعال";
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
  $("hosts").replaceChildren(...hosts.map(([name,h])=>{
    const n=el("div",undefined,"host"),head=el("div",undefined,"host-head");
    head.append(el("strong",name),el("span",h?"دادهٔ زنده":"در انتظار پاسخ","muted"));n.append(head);
    if(h){
      const details=el("div",undefined,"host-details"),memory=h.memory_total?Math.max(0,Math.min(100,100*h.memory_used/h.memory_total)):null;
      details.append(el("span","بار پردازنده: "+(Number.isFinite(h.load?.[0])?fa(h.load[0]):"—")),el("span","حافظه: "+(memory===null?"—":fa(memory)+"٪")));n.append(details);
      if(memory!==null){const meter=el("meter");meter.min=0;meter.max=100;meter.value=memory;meter.setAttribute("aria-label","مصرف حافظهٔ "+name);n.append(meter);}
    }
    return n;
  }));
  $("counters").textContent="پذیرفته‌شده: "+fa(d.accepted)+" · ردشده: "+fa(d.rejected)+" · تغییر مسیر: "+fa(d.route_changes);
  $("event-list").replaceChildren(...d.events.map(e=>{const n=el("div",undefined,"event");n.append(el("span",eventNames[e.kind]||e.kind,"event-kind"),el("span",eventDescription(e),"event-detail"),el("time",new Date(e.time*1000).toLocaleString("fa-IR")));return n;}));
  if(!d.events.length)$("event-list").append(el("p","هنوز رویدادی ثبت نشده است.","empty-events"));
  $("updated").textContent="به‌روز هر ۳ ثانیه";
  $("uptime").textContent="زمان فعالیت: "+fa(Math.floor(d.uptime/60))+" دقیقه";
}
function eventDescription(e){
  const d=e.detail||{};
  if(e.kind==="operator")return ({prefer:"مسیر ترجیحی",enable:"فعال‌کردن مسیر",disable:"غیرفعال‌کردن مسیر",drain:"تخلیهٔ مسیر",pause:"توقف ورودی جدید",resume:"ادامهٔ ورودی جدید",auto:"بازگشت به انتخاب خودکار"}[d.action]||"تغییر تنظیمات")+(d.path?" · "+d.path:"");
  if(e.kind==="route-change")return (d.from||"—")+" ← "+(d.to||"—");
  if(e.kind==="path-health")return (d.path||"مسیر")+" · "+(d.healthy?"پاسخ معتبر دریافت شد":"آزمون سلامت ناموفق");
  if(e.kind==="login")return "ورود به مرکز فرمان";
  if(e.kind==="login-failed")return "رمز واردشده معتبر نبود";
  if(e.kind==="backend-connect-failed")return (d.path||"مسیر")+" · سرویس مقصد در دسترس نیست";
  return JSON.stringify(d);
}
function svg(tag,attrs,text){const n=document.createElementNS("http://www.w3.org/2000/svg",tag);Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,v));if(text!==undefined)n.textContent=text;return n;}
function chart(paths){
  const c=$("chart"),nodes=[];
  const max=Math.max(20,...paths.flatMap(p=>p.history.filter(x=>x.ok).map(x=>x.latency||0)))*1.15;
  for(let i=0;i<5;i++){const y=20+i*45;nodes.push(svg("line",{x1:45,y1:y,x2:705,y2:y,class:"chart-grid","stroke-dasharray":"3 5"}));nodes.push(svg("text",{x:5,y:y+4},Math.round(max*(1-i/4))+" ms"));}
  paths.forEach((p,i)=>{const points=[];p.history.forEach((h,j)=>{if(!h.ok){if(points.length){nodes.push(svg("polyline",{points:points.join(" "),fill:"none",stroke:colors[i%colors.length],"stroke-width":2}));points.length=0;}return;}points.push((45+660*j/Math.max(1,p.history.length-1))+","+(200-180*h.latency/max));});if(points.length)nodes.push(svg("polyline",{points:points.join(" "),fill:"none",stroke:colors[i%colors.length],"stroke-width":2}));});
  c.replaceChildren(...nodes);
  $("legend").replaceChildren(...paths.map((p,i)=>el("span",p.id,"c"+(i%5))));
}
let refreshTask=null;
function refresh(){
  if(!csrf)return Promise.resolve();if(refreshTask)return refreshTask;
  const currentSession=csrf;
  refreshTask=(async()=>{try{const d=await api("/api/status");if(csrf===currentSession)render(d);}catch(e){$("live").textContent="ارتباط پنل قطع است";$("live").className="badge bad";notice(e.message);}finally{refreshTask=null;}})();
  return refreshTask;
}
api("/api/session").then(d=>{csrf=d.csrf;loggedIn();}).catch(()=>loggedOut());
setInterval(()=>{if(!$("dashboard").hidden)refresh();},3000);
