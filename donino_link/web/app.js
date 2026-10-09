"use strict";
const $ = id => document.getElementById(id);
let csrf = "", state = null, actionPending = false, previousTraffic = null, toastTimer = null;
const colors = ["#a48bd7", "#69a6b3", "#d9ad71", "#bb83a9", "#7e9fd4"];
const fa = n => new Intl.NumberFormat("fa-IR", {maximumFractionDigits:1}).format(n);
const bytes = n => n >= 2**30 ? (n/2**30).toFixed(2)+" GB" : n >= 2**20 ? (n/2**20).toFixed(1)+" MB" : (n/1024).toFixed(1)+" KB";
function el(tag, text, cls) { const n=document.createElement(tag); if(text!==undefined) n.textContent=text; if(cls) n.className=cls; return n; }
async function api(path, body) {
  const r=await fetch(path,{credentials:"same-origin",method:body===undefined?"GET":"POST",headers:body===undefined?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body===undefined?undefined:JSON.stringify(body)});
  if(!r.ok){ let detail="";if(path.startsWith("/api/provision/")||path.startsWith("/api/foreign/")){try{detail=(await r.json()).error||"";}catch{}} if(r.status===401 && path!=="/api/login") loggedOut(); throw new Error(detail||(r.status===429?"تلاش‌ها زیاد بوده؛ پنج دقیقه صبر کن.":r.status===401?"رمز نادرست است یا نشست پایان یافته.":"درخواست انجام نشد؛ اتصال و دسترسی را بررسی کن.")); }
  return r.json();
}
function loggedOut(){ $("login").hidden=false; $("dashboard").hidden=true; csrf=""; state=null; previousTraffic=null; $("foreign-code-value").value="";$("connection-code").value=""; }
function loggedIn(){ $("login").hidden=true; $("dashboard").hidden=false; refresh(); setTimeout(pollSetup,0); }
function notice(text){ $("notice").textContent=text; $("notice").hidden=!text; }
function toast(text){$("toast").textContent=text;$("toast").hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$("toast").hidden=true,4500);}
async function action(path,name){
  if(actionPending)return;actionPending=true;$("auto").disabled=true;$("pause").disabled=true;$("adaptive").disabled=true;
  try{await api("/api/action",{path,action:name});await refresh();toast("تنظیم مسیر به‌روز شد.");}catch(e){toast(e.message);}finally{actionPending=false;$("auto").disabled=false;$("pause").disabled=false;$("adaptive").disabled=false;}
}
$("login-form").addEventListener("submit",async e=>{e.preventDefault();$("login-error").textContent=""; const b=e.target.querySelector("button");b.disabled=true;try{const d=await api("/api/login",{password:$("password").value});csrf=d.csrf;$("password").value="";loggedIn();}catch(e){$("login-error").textContent=e.message;}finally{b.disabled=false;}});
$("logout").onclick=async()=>{try{await api("/api/logout",{});loggedOut();}catch(e){toast(e.message);}};
$("mobile-logout").onclick=$("logout").onclick;
$("auto").onclick=()=>action(null,"auto");
$("adaptive").onclick=()=>action(null,state?.routing_strategy==="adaptive"?"static":"adaptive");
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
const eventNames={"path-health":"سلامت مسیر","operator":"عملیات مدیر","login":"ورود مدیر","login-failed":"ورود ناموفق","route-change":"تغییر مسیر","backend-connect-failed":"مقصد در دسترس نیست","unit-state":"وضعیت سرویس","foreign-action":"مدیریت خارج","provision":"نصب تانل"};
function render(d){
  state=d;
  const foreign=d.role==="foreign";configureRole(foreign);
  const healthy=d.paths.filter(p=>p.healthy&&p.mode==="enabled");
  $("healthy").textContent=fa(healthy.length)+" / "+fa(d.paths.length);
  $("active").textContent=d.active===null?"—":fa(d.active);
  const selected=foreign?healthy[0]:d.paths.find(p=>p.id===d.selected);
  $("selected").textContent=d.paused?"ورودی جدید متوقف است":d.selected||"مسیر سالمی در دسترس نیست";
  $("hero-description").textContent=d.preferred?"مسیر ترجیحی: "+d.preferred+" · در صورت خرابی، مسیر سالم بعدی انتخاب می‌شود.":"انتخاب خودکار فعال است؛ سلامت هر مسیر با پاسخ امضاشدهٔ سرور خارج بررسی می‌شود.";
  $("latency").textContent=selected?.latency_ms!==null&&selected?.latency_ms!==undefined?selected.latency_ms.toFixed(1)+" ms":"—";
  const total=foreign?(d.metrics?d.metrics.bytes_up+d.metrics.bytes_down:null):d.paths.reduce((sum,p)=>sum+p.bytes_up+p.bytes_down,0);
  $("traffic").textContent=total===null?"—":bytes(total);
  if(total!==null&&previousTraffic&&d.time>previousTraffic.time&&total>=previousTraffic.total){$("traffic-rate").textContent="نرخ مجموع دو جهت: "+bytes((total-previousTraffic.total)/(d.time-previousTraffic.time))+"/s";}
  previousTraffic=total===null?null:{time:d.time,total};
  $("routing-mode").textContent=d.preferred?"مسیر ترجیحی":d.routing_strategy==="adaptive"?"هستهٔ تطبیقی":"انتخاب خودکار";
  $("adaptive").textContent=d.routing_strategy==="adaptive"?"بازگشت به اولویت ثابت":"فعال‌کردن هستهٔ تطبیقی";$("adaptive").setAttribute("aria-pressed",String(d.routing_strategy==="adaptive"));
  $("path-summary").textContent=fa(d.paths.length)+" مسیر · "+fa(healthy.length)+" سالم و فعال";
  $("pause").textContent=d.paused?"ادامهٔ اتصال‌های جدید":"توقف اتصال‌های جدید";
  $("live").textContent="به‌روز · "+new Date(d.time*1000).toLocaleTimeString("fa-IR");$("live").className="badge good";
  notice(d.paused?"ورودی اتصال‌های جدید متوقف است؛ ارتباط‌های جاری ادامه دارند.":!d.selected?"هیچ مسیر سالمی موجود نیست. وضعیت سرویس تانل و دسترسی دو سرور را بررسی کن.":"");
  const cards=d.paths.map(p=>{
    const card=$("path-template").content.firstElementChild.cloneNode(true);
    if(p.id===d.selected) card.classList.add("selected");
    card.querySelector("h3").textContent=p.id;
    card.querySelector(".transport").textContent=p.transport.toUpperCase();
    const b=card.querySelector(".path-status"); b.textContent=foreign&&p.observation==="unknown"?"نامشخص":p.healthy?"سالم":"ناموفق";if(p.healthy)b.classList.add("good");else if(!(foreign&&p.observation==="unknown"))b.classList.add("bad");
    const metrics=card.querySelector(".path-metrics");
    (foreign?[[p.latency_ms===null?"—":p.latency_ms.toFixed(1)+" ms","آزمون از ایران"],[d.units.find(u=>u.unit==="donino-link-"+p.id+".service")?.active?"روشن":"خاموش","سرویس محلی"],[p.observation==="fresh"?"تازه":"نامشخص","شاهد ارتباط"]]:[[p.latency_ms===null?"—":p.latency_ms.toFixed(1)+" ms","تأخیر"],[fa(p.active),"اتصال فعال"],[bytes(p.bytes_up+p.bytes_down),"ترافیک"]]).forEach(([v,l])=>{const n=el("div");n.append(el("b",v),el("span",l));metrics.append(n);});
    card.querySelector(".mode").textContent=modeNames[p.mode];
    if(!foreign&&d.routing_strategy==="adaptive"&&p.quality)card.append(el("p","هزینهٔ مسیر: "+fa(p.quality.cost)+" · کمتر بهتر است","field-help"));
    const menu=card.querySelector("select");menu.hidden=foreign;if(foreign)card.querySelector(".mode").textContent="پایش از پنل ایران";menu.onchange=()=>{if(menu.value)action(p.id,menu.value);};
    return card;
  });if(document.activeElement?.tagName!=="SELECT")$("path-list").replaceChildren(...cards);
  chart(d.paths);
  const remote=d.paths.find(p=>p.healthy&&p.remote?.memory_total)?.remote;
  const hosts=foreign?[["سرور خارج",d.host]]:[["سرور ایران",d.host],["سرور خارج",remote]];
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
  if(foreign)renderForeign(d);
  else if(d.bootstrap)notice("پنل ایران آماده است. ابتدا خارج را جفت‌سازی کن، سپس نقشهٔ تانل را بساز.");
  $("uptime").textContent="زمان فعالیت: "+fa(Math.floor(d.uptime/60))+" دقیقه";
}
function eventDescription(e){
  const d=e.detail||{};
  if(e.kind==="operator")return ({prefer:"مسیر ترجیحی",enable:"فعال‌کردن مسیر",disable:"غیرفعال‌کردن مسیر",drain:"تخلیهٔ مسیر",pause:"توقف ورودی جدید",resume:"ادامهٔ ورودی جدید",auto:"بازگشت به انتخاب خودکار",adaptive:"فعال‌کردن هستهٔ تطبیقی",static:"بازگشت به اولویت ثابت"}[d.action]||"تغییر تنظیمات")+(d.path?" · "+d.path:"");
  if(e.kind==="route-change")return (d.from||"—")+" ← "+(d.to||"—");
  if(e.kind==="path-health")return (d.path||"مسیر")+" · "+(d.healthy?"پاسخ معتبر دریافت شد":"آزمون سلامت ناموفق");
  if(e.kind==="login")return "ورود به مرکز فرمان";
  if(e.kind==="login-failed")return "رمز واردشده معتبر نبود";
  if(e.kind==="unit-state")return (d.unit||"سرویس")+" · "+({active:"روشن",inactive:"خاموش",failed:"ناموفق"}[d.state]||d.state);
  if(e.kind==="foreign-action"||e.kind==="provision")return ({"/code":"ساخت کد جفت‌سازی","/pair":"جفت‌سازی خارج","/revoke":"لغو مدیریت","/action":"عملیات سرویس","/preview":"نقشهٔ نصب","/start":"شروع نصب"}[d.operation]||d.operation)+(d.unit?" · "+d.unit:"");
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

// Typed installer workflow; installation continues on the server after logout.
let setupState=null, setupPlan=null, setupRequest=false, setupPolling=false;
const setupStageNames={queued:"در صف",preflight:"بررسی اتصال دو سرور","prepare-foreign":"آماده‌سازی خارج","prepare-iran":"آماده‌سازی ایران","activate-foreign":"فعال‌سازی خارج","activate-iran":"فعال‌سازی ایران",verify:"آزمون تمام مسیرها",complete:"پایان نصب","rollback-iran":"بازگشت ایران","rollback-foreign":"بازگشت خارج",failure:"خطای نصب",recovery:"بازیابی پس از راه‌اندازی مجدد"};
const setupStatusNames={running:"در حال اجرا",succeeded:"نصب موفق",failed:"ناموفق",rollback_failed:"بازگشت نیازمند بررسی",interrupted:"متوقف و بازیابی‌شده"};
function invalidatePlan(){setupPlan=null;$("setup-review").hidden=true;$("setup-confirm").checked=false;$("setup-start").disabled=true;}
function addServiceRow(value={id:"app",listen:"0.0.0.0:443",target:"127.0.0.1:8443"}){
  if($("setup-services").children.length>=40){toast("حداکثر ۴۰ سرویس قابل تعریف است.");return;}
  const row=el("div",undefined,"service-row"),head=el("div",undefined,"service-row-head"),id=el("input"),remove=el("button","حذف");
  id.value=value.id;id.required=true;id.maxLength=32;id.pattern="[a-z][a-z0-9-]{0,31}";id.dir="ltr";id.setAttribute("aria-label","شناسهٔ سرویس");id.dataset.field="id";
  remove.type="button";remove.onclick=()=>{if($("setup-services").children.length>1){row.remove();invalidatePlan();}else toast("حداقل یک سرویس لازم است.");};head.append(id,remove);row.append(head);
  const pair=el("div",undefined,"field-pair");[["listen","ورودی روی ایران"],["target","مقصد loopback خارج"]].forEach(([field,text])=>{const label=el("label",text),input=el("input");input.value=value[field];input.required=true;input.dir="ltr";input.dataset.field=field;label.append(input);pair.append(label);});row.append(pair);$("setup-services").append(row);invalidatePlan();
}
addServiceRow();
$("setup-add-service").onclick=()=>addServiceRow({id:"app"+($("setup-services").children.length+1),listen:"",target:""});
$("setup-form").addEventListener("input",invalidatePlan);
$("setup-confirm").onchange=()=>$("setup-start").disabled=!setupPlan||!$("setup-confirm").checked||setupRequest||setupState?.busy;
$("setup-copy-key").onclick=async()=>{try{if(navigator.clipboard)await navigator.clipboard.writeText($("setup-public-key").value);else{$("setup-public-key").select();if(!document.execCommand("copy"))throw Error();}toast("کلید عمومی کپی شد.");}catch{toast("کلید عمومی را از کادر انتخاب و کپی کن.");}};
function renderSetup(data){
  setupState=data;const available=data.available;
  $("setup-status").textContent=available?(data.busy?"نصب در حال اجرا":"آمادهٔ راه‌اندازی"):"نیاز به فعال‌سازی";$("setup-status").className="badge "+(available?"good":"bad");
  $("setup-unavailable").hidden=!!available;$("setup-unavailable").textContent=data.reason||"سرویس نصب خودکار در دسترس نیست.";
  $("setup-controls").hidden=!available;if(!available)return;
  $("setup-public-key").value=data.public_key;
  if(data.iran_address&&!$("setup-iran").value)$("setup-iran").value=data.iran_address;
  const select=$("setup-profile"),selected=select.value,ids=JSON.stringify(data.profiles.map(p=>[p.id,p.name]));
  if(select.dataset.profiles!==ids){select.replaceChildren(el("option",data.profiles.length?"انتخاب سرور خارج":"ابتدا اتصال خارج را ثبت کن"));select.firstChild.value="";data.profiles.forEach(p=>{const opt=el("option",p.name+" · "+p.host);opt.value=p.id;select.append(opt);});select.value=selected||(data.profiles.length===1?data.profiles[0].id:"");select.dataset.profiles=ids;}
  if(!$("setup-transports").children.length){data.transports.forEach(t=>{const label=el("label"),input=el("input");input.type="checkbox";input.value=t.id;input.checked=["frp-wss","frp-quic"].includes(t.id);input.dataset.experimental=String(t.experimental);label.append(input,el("span",t.id+(t.experimental?" · آزمایشی":"")));$("setup-transports").append(label);});}
  $("setup-controls").setAttribute("aria-busy",String(!!data.busy));
  $("connection-save").disabled=!!data.busy||setupRequest;$("setup-preview").disabled=!!data.busy||setupRequest;$("setup-start").disabled=!!data.busy||setupRequest||!setupPlan||!$("setup-confirm").checked;
  const job=data.jobs[0];$("setup-job").hidden=!job;if(!job)return;
  $("setup-job-status").textContent=setupStatusNames[job.status]||job.status;$("setup-job-status").className="badge "+(job.status==="succeeded"?"good":["failed","rollback_failed","interrupted"].includes(job.status)?"bad":"");
  $("setup-job-detail").textContent=(setupStageNames[job.stage]||job.stage)+" · "+new Date(job.created*1000).toLocaleString("fa-IR")+(job.error?" · "+job.error:"");
  const latest=new Map();job.events.forEach(e=>latest.set(e.stage,e));$("setup-job-steps").replaceChildren(...[...latest.values()].map(e=>{const n=el("li",undefined,"step-"+e.status);n.append(el("strong",setupStageNames[e.stage]||e.stage),el("small",e.status==="done"?"انجام شد":e.status==="running"?"در حال اجرا":"نیاز به بررسی"));return n;}));
  $("setup-job-probes").replaceChildren(...job.probes.map(p=>{const failed=Object.entries(p.services||{}).filter(([,ok])=>!ok).map(([id])=>id);return el("div",p.path+" · "+(p.ok?"مسیر سالم · "+p.latency_ms+" ms":"مسیر ناموفق")+(failed.length?" · مقصد ناموفق: "+failed.join(", "):""),"setup-job-probe");}));
}
async function pollSetup(){if(!csrf||setupPolling||state?.role==="foreign")return;setupPolling=true;const session=csrf;try{const d=await api("/api/provision/state");if(csrf===session)renderSetup(d);}catch(e){if(csrf===session){$("setup-status").textContent="در انتظار ارتباط";$("setup-status").className="badge bad";}}finally{setupPolling=false;}}
async function setupCall(path,body){if(setupRequest)throw new Error("یک درخواست نصب در حال انجام است؛ منتظر نتیجه بمان.");setupRequest=true;$("connection-save").disabled=true;$("setup-preview").disabled=true;$("setup-start").disabled=true;try{return await api(path,body);}finally{setupRequest=false;if(setupState)renderSetup(setupState);}}
$("connection-form").onsubmit=async e=>{e.preventDefault();$("connection-result").textContent="در حال تأیید هویت خارج و نصب خودکار کلید SSH…";try{const p=await setupCall("/api/provision/pair",{name:$("connection-name").value.trim(),host:$("connection-host").value.trim(),agent_port:Number($("connection-agent-port").value),code:$("connection-code").value.trim()});$("connection-code").value="";await pollSetup();$("setup-profile").value=p.id;invalidatePlan();$("connection-result").textContent="خارج جفت شد؛ اتصال SSH با هویت تأییدشده آماده است.";}catch(e){$("connection-result").textContent=e.message;}};
$("manual-connection-form").onsubmit=async e=>{e.preventDefault();try{const p=await setupCall("/api/provision/profiles",{name:$("connection-name").value.trim()||"خارج",host:$("manual-host").value.trim(),port:Number($("connection-port").value),fingerprint:$("connection-pin").value.trim()});await pollSetup();$("setup-profile").value=p.id;invalidatePlan();toast("اتصال قدیمی ثبت شد.");}catch(e){toast(e.message);}};
$("setup-form").onsubmit=async e=>{e.preventDefault();invalidatePlan();$("setup-error").textContent="";const transports=[...$("setup-transports").querySelectorAll("input:checked")].map(n=>n.value);if(!transports.length){$("setup-error").textContent="حداقل یک پروتکل انتخاب کن.";return;}const services=[...$("setup-services").children].map(row=>Object.fromEntries([...row.querySelectorAll("input")].map(n=>[n.dataset.field,n.value.trim()])));const spec={profile_id:$("setup-profile").value,iran:$("setup-iran").value.trim(),services,transports,experimental:$("setup-experimental").checked,open_ufw:$("setup-open-ufw").checked,base_port:Number($("setup-base").value),carrier_base:Number($("setup-carrier").value),health_port:Number($("setup-health").value),paqet_port:Number($("setup-paqet").value)};if($("setup-foreign").value.trim())spec.foreign=$("setup-foreign").value.trim();if($("setup-browser").value)spec.browser_port=Number($("setup-browser").value);try{const p=await setupCall("/api/provision/preview",spec);setupPlan=p;$("setup-review-summary").textContent=p.summary.iran+" ⇄ "+p.summary.foreign+" · "+p.summary.transports.join(" + ")+" · "+fa(p.summary.services.length)+" سرویس";$("setup-firewall").replaceChildren(...["iran","foreign"].map(role=>{const n=el("div");n.append(el("strong",role==="iran"?"پورت‌های ورودی ایران":"پورت‌های ورودی خارج"));["tcp","udp"].forEach(proto=>{n.append(el("code",proto.toUpperCase()+": "+(p.summary.firewall[role][proto].join(", ")||"—")));});return n;}));$("setup-review").hidden=false;$("setup-confirm").checked=false;$("setup-review").scrollIntoView({behavior:"smooth",block:"nearest"});}catch(e){$("setup-error").textContent=e.message;}};
$("setup-start").onclick=async()=>{if(!setupPlan||!$("setup-confirm").checked)return;try{await setupCall("/api/provision/start",{plan_id:setupPlan.id,confirm_replace:true});invalidatePlan();await pollSetup();toast("عملیات نصب شروع شد؛ مراحل روی سرور ادامه پیدا می‌کنند.");}catch(e){$("setup-error").textContent=e.message;toast(e.message);}};
$("setup-details").addEventListener("toggle",()=>{if($("setup-details").open)pollSetup();});
setInterval(()=>{if(csrf)pollSetup();},4000);

// Foreign role has local controls and dated end-to-end observations, not routing.
let displayedRole="",foreignPending=false;
const foreignUnitCards=new Map();
function configureRole(foreign){
  const role=foreign?"foreign":"iran";if(displayedRole===role)return;displayedRole=role;
  $("setup").hidden=foreign;$("foreign-node").hidden=!foreign;$("nav-setup").hidden=foreign;$("nav-foreign").hidden=!foreign;
  $("auto").hidden=foreign;$("adaptive").hidden=foreign;$("pause").hidden=foreign;
  document.querySelector("header h1").firstChild.textContent=foreign?"مرکز مدیریت خارج":"مرکز فرمان ارتباط";
  document.querySelector("header p").textContent=foreign?"سرور خروج، سرویس مقصد و اتصال تأییدشده به ایران.":"هر مسیر، هر اتصال؛ یک تصویر روشن.";
  document.querySelector("#overview .eyebrow").textContent=foreign?"پایش ارتباط دو سرور":"مسیر انتخاب‌شده برای اتصال‌های جدید";
  document.querySelectorAll(".kpi-title span")[2].textContent=foreign?"تأخیر نخستین مسیر سالم":"تأخیر مسیر انتخاب‌شده";
  document.querySelector("#paths .section-heading p").textContent=foreign?"سلامت حامل، وضعیت محلی و تازگی آزمون از ایران.":"انتخاب مستقل هر مسیر، بر اساس سلامت و اولویت.";
  if(foreign){document.querySelector("#guide h3").textContent="سه بررسی، سه نتیجهٔ مستقل";const ps=document.querySelectorAll("#guide p");ps[0].textContent="روشن بودن systemd فقط وضعیت سرویس محلی است. دسترسی TCP مقصد جدا سنجیده می‌شود. سلامت تانل به آزمون تازه و امضاشده از ایران نیاز دارد؛ شاهد قدیمی یا غایب نامشخص نمایش داده می‌شود.";ps[1].textContent="ترافیک و اتصال‌های فعال از relayهای همین سرور خوانده می‌شوند؛ شمارنده‌ها از شروع فرآیندهای فعلی‌اند. انتخاب مسیر و نصب کامل دو سرور در پنل ایران انجام می‌شود.";}
}
function renderForeign(d){
  const f=d.foreign||{},busy=foreignPending||f.action_busy||!!f.lease;
  $("selected").textContent=d.telemetry_fresh?"ارتباط از ایران تأیید شد":d.bootstrap?"آمادهٔ جفت‌سازی":"در انتظار آزمون ایران";
  $("hero-description").textContent=d.telemetry_fresh?"آزمون تازه از ایران دریافت شده؛ سلامت هر مسیر و سرویس مقصد را در کارت‌ها ببین.":"سرویس‌های خارج جداگانه پایش می‌شوند. برای تأیید دوطرفه، پنل ایران را جفت‌سازی و تانل را نصب کن.";
  $("routing-mode").textContent="نقش سرور: خارج";
  notice(!f.available?"سرویس مدیریت خارج در دسترس نیست؛ وضعیت systemd را بررسی کن.":f.lease?"نصب دو سرور در جریان است؛ کنترل دستی سرویس‌ها تا پایان نصب متوقف می‌شود.":!d.telemetry_fresh?"هنوز شاهد تازهٔ تانل از ایران نداریم. روشن بودن سرویس‌ها به‌تنهایی سلامت تانل را ثابت نمی‌کند.":"");
  $("foreign-agent-status").textContent=f.available?(f.lease?"نصب در جریان":"مدیریت آماده"):"نیاز به بررسی";$("foreign-agent-status").className="badge "+(f.available?"good":"bad");
  $("foreign-new-code").disabled=busy||!f.available;$("foreign-test").disabled=busy||!f.available;
  $("foreign-pair-port").textContent="پورت کانال جفت‌سازی: "+(f.agent_port||"—")+" / TCP · باید از ایران در دسترس باشد.";
  const peers=(f.paired||[]).filter(p=>!p.revoked);
  $("foreign-peer-list").replaceChildren(...peers.map(p=>{const row=el("div",undefined,"foreign-peer"),detail=el("div");detail.append(el("strong",p.name),el("code",p.source));const revoke=el("button","لغو مدیریت");revoke.type="button";revoke.disabled=busy;revoke.onclick=async()=>{try{await foreignCall("/api/foreign/revoke",{id:p.id});toast("دسترسی مدیریت و کلید جفت‌سازی لغو شد؛ تانل‌های جاری حفظ می‌شوند.");}catch(e){toast(e.message);}};row.append(detail,revoke);return row;}));
  if(!peers.length)$("foreign-peer-list").append(el("p","هنوز پنل ایران جفت نشده است.","muted"));
  $("foreign-targets").replaceChildren(...Object.entries(d.targets||{}).map(([id,t])=>{const row=el("div",undefined,"foreign-peer"),a=el("div");a.append(el("strong",id),el("code",t.target));row.append(a,el("span",t.reachable?"مقصد در دسترس":"مقصد ناموفق","badge "+(t.reachable?"good":"bad")));return row;}));
  if(!Object.keys(d.targets||{}).length)$("foreign-targets").append(el("p","مقصدی تعریف نشده؛ سرویس TCP را در نقشهٔ پنل ایران اضافه کن.","muted"));
  $("foreign-probe-note").textContent=(d.telemetry_fresh?"آزمون تازهٔ تانل دریافت شد":"آزمون دوطرفه نامشخص است")+(d.probe_time?" · آخرین دریافت: "+new Date(d.probe_time*1000).toLocaleString("fa-IR"):"");
  $("foreign-action-history").replaceChildren(...(f.actions||[]).slice(0,4).map(a=>el("p",a.unit+" · "+({start:"شروع",stop:"توقف",restart:"راه‌اندازی مجدد",test:"آزمون مقصد"}[a.action]||a.action)+" · "+({running:"در حال اجرا",succeeded:"موفق",failed:"ناموفق",interrupted:"متوقف‌شده"}[a.status]||a.status)+(a.error?" · "+a.error:""),"field-help")));
  for(const u of d.units||[]){let view=foreignUnitCards.get(u.unit);if(!view){const card=el("article",undefined,"setup-block foreign-unit"),head=el("div",undefined,"service-header"),badge=el("span",undefined,"badge");head.append(el("code",u.unit),badge);const metrics=el("p",undefined,"muted"),buttons=el("div",undefined,"foreign-service-buttons");const controls=[];for(const [op,text] of [["start","شروع"],["restart","راه‌اندازی مجدد"],["stop","توقف"]]){const b=el("button",text);b.type="button";b.onclick=async()=>{try{await foreignCall("/api/foreign/action",{unit:u.unit,action:op});toast("عملیات سرویس شروع شد؛ نتیجه در همین پنل ثبت می‌شود.");}catch(e){toast(e.message);}};buttons.append(b);controls.push(b);}card.append(head,metrics,buttons);view={card,badge,metrics,controls};foreignUnitCards.set(u.unit,view);$("foreign-units").append(card);}view.badge.textContent=u.active?"روشن":u.state;view.badge.className="badge "+(u.active?"good":"bad");view.metrics.textContent="راه‌اندازی مجدد: "+fa(u.restarts)+" · RAM: "+(u.memory===null?"—":bytes(u.memory));view.controls.forEach((b,i)=>b.disabled=busy||!f.available||(u.unit==="donino-link.service"&&i===2));}
  const unitIds=new Set((d.units||[]).map(u=>u.unit));for(const [id,v] of foreignUnitCards)if(!unitIds.has(id)){v.card.remove();foreignUnitCards.delete(id);}
  $("counters").textContent=d.metrics?"اتصال‌های پذیرفته‌شدهٔ relay: "+fa(d.metrics.accepted)+" · شمارنده‌های همین سرور":"شمارندهٔ relay هنوز در دسترس نیست.";
  if(!d.metrics)$("traffic-rate").textContent="در انتظار شمارندهٔ واقعی فرآیند";
}
async function foreignCall(path,body){if(foreignPending)throw Error("منتظر پایان درخواست قبلی بمان.");foreignPending=true;if(state?.role==="foreign")renderForeign(state);try{const result=await api(path,body);if(result.status==="running"&&state?.foreign)state.foreign.action_busy=true;return result;}finally{foreignPending=false;await refresh();}}
$("foreign-new-code").onclick=async()=>{try{const c=await foreignCall("/api/foreign/code",{});$("foreign-code-value").value=c.code;$("foreign-code-expiry").textContent="معتبر تا "+new Date(c.expires_at*1000).toLocaleTimeString("fa-IR");toast("کد یک‌بارمصرف ساخته شد؛ آن را در پنل ایران وارد کن.");}catch(e){toast(e.message);}};
$("foreign-copy-code").onclick=async()=>{try{if(!$("foreign-code-value").value)throw Error();if(navigator.clipboard)await navigator.clipboard.writeText($("foreign-code-value").value);else{$("foreign-code-value").select();if(!document.execCommand("copy"))throw Error();}toast("کد جفت‌سازی کپی شد.");}catch{toast("ابتدا کد بساز؛ می‌توانی آن را از کادر انتخاب و کپی کنی.");}};
$("foreign-test").onclick=async()=>{try{await foreignCall("/api/foreign/action",{unit:"all",action:"test"});toast("آزمون سلامت و مقصدها شروع شد.");}catch(e){toast(e.message);}};
