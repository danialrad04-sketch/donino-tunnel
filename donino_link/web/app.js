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
function loggedOut(){closeNavigation(false);closeInspector(); $("login").hidden=false; $("dashboard").hidden=true; csrf=""; state=null; previousTraffic=null; $("foreign-code-value").value="";$("connection-code").value=""; }
function loggedIn(){ $("login").hidden=true; $("dashboard").hidden=false; window.workspaceRefresh?.(); refresh(); setTimeout(pollSetup,0); }
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
// One navigation model for touch, keyboard and desktop pointer input.
const drawerQuery=window.matchMedia("(max-width: 1020px)");
let navigationOpen=false, navigationFrame=0, inspectorSource=null, navigationWatcher=null;
function setActiveSection(id){
  document.querySelectorAll("#sidebar nav a").forEach(link=>{
    const active=link.hash==="#"+id&&!link.hidden;
    link.classList.toggle("nav-active",active);
    if(active)link.setAttribute("aria-current","location");else link.removeAttribute("aria-current");
  });
}
function closeNavigation(restoreFocus=true){
  navigationWatcher?.destroy();navigationWatcher=null;
  navigationOpen=false;document.body.classList.remove("drawer-open");
  $("menu-toggle").setAttribute("aria-expanded","false");$("menu-toggle").setAttribute("aria-label","بازکردن منوی مدیریت");
  $("nav-backdrop").hidden=true;$("sidebar").inert=drawerQuery.matches;
  $("sidebar").removeAttribute("role");$("sidebar").removeAttribute("aria-modal");
  $("main-content").inert=false;document.querySelector(".mobile-topbar").inert=false;
  if(restoreFocus&&drawerQuery.matches&&!$("dashboard").hidden)$("menu-toggle").focus({preventScroll:true});
}
function openNavigation(){
  if(!drawerQuery.matches)return;
  navigationOpen=true;document.body.classList.add("drawer-open");$("sidebar").inert=false;
  $("sidebar").setAttribute("role","dialog");$("sidebar").setAttribute("aria-modal","true");
  $("menu-toggle").setAttribute("aria-expanded","true");$("menu-toggle").setAttribute("aria-label","بستن منوی مدیریت");
  $("nav-backdrop").hidden=false;$("main-content").inert=true;document.querySelector(".mobile-topbar").inert=true;
  $("sidebar").scrollTop=0;
  if(typeof window.CloseWatcher==="function"){navigationWatcher=new window.CloseWatcher();navigationWatcher.addEventListener("close",()=>closeNavigation());}
  $("menu-close").focus({preventScroll:true});
}
$("menu-toggle").onclick=()=>navigationOpen?closeNavigation():openNavigation();
$("menu-close").onclick=()=>closeNavigation();$("nav-backdrop").onclick=()=>closeNavigation();
drawerQuery.addEventListener("change",()=>closeNavigation(false));closeNavigation(false);
document.addEventListener("keydown",event=>{
  if(!navigationOpen||$("inspector-dialog").open)return;
  if(event.key==="Escape"){event.preventDefault();closeNavigation();return;}
  if(event.key!=="Tab")return;
  const items=[...$("sidebar").querySelectorAll("a[href],button:not(:disabled)")].filter(n=>!n.hidden&&n.getClientRects().length);
  const first=items[0],last=items.at(-1);if(!first)return;
  if(event.shiftKey&&(document.activeElement===first||!$("sidebar").contains(document.activeElement))){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&(document.activeElement===last||!$("sidebar").contains(document.activeElement))){event.preventDefault();first.focus();}
});
function syncNavigation(){
  $("nav-detected").hidden=$("detected-panel").hidden;$("nav-paqet").hidden=$("paqet-manager").hidden;
  $("mobile-role").textContent=state?.role==="foreign"?"سرور خارج":"سرور ایران";
  window.workspaceRefresh?.();
}
function closeInspector(){document.body.classList.remove("inspector-open");if($("inspector-dialog").open)$("inspector-dialog").close();inspectorSource=null;$("inspector-content").value="";}
function openInspector(source){
  inspectorSource=source;$("inspector-title").textContent=source==="logs"?"لاگ زندهٔ سرویس":"نمای بزرگ تنظیمات";
  $("inspector-note").textContent=source==="logs"?"همان لاگ سرویس انتخاب‌شده؛ دریافت زنده از پنل ادامه دارد.":"نمای خواندنی؛ برای تغییر و ذخیره از ویرایشگر اصلی استفاده کن.";
  $("inspector-status").textContent="";$("inspector-content").value=source==="logs"?$("detected-logs").textContent:$("detected-config").value;
  document.body.classList.add("inspector-open");$("inspector-dialog").showModal();$("inspector-close").focus();
}
$("inspector-close").onclick=()=>closeInspector();
$("inspector-dialog").addEventListener("cancel",event=>{event.preventDefault();closeInspector();});
$("inspector-dialog").addEventListener("close",()=>{document.body.classList.remove("inspector-open");inspectorSource=null;$("inspector-content").value="";});
$("inspector-dialog").addEventListener("click",event=>{if(event.target!==$("inspector-dialog"))return;const r=event.target.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)closeInspector();});
$("inspector-copy").onclick=async()=>{try{const value=$("inspector-content").value;if(navigator.clipboard)await navigator.clipboard.writeText(value);else{$("inspector-content").select();if(!document.execCommand("copy"))throw Error();}$("inspector-status").textContent="محتوا کپی شد.";}catch{$("inspector-status").textContent="کپی در این مرورگر در دسترس نیست؛ متن را انتخاب و کپی کن.";}};
$("detected-expand-logs").onclick=()=>openInspector("logs");$("detected-expand-config").onclick=()=>openInspector("config");
function syncInspector(){
  if(inspectorSource!=="logs"||!$("inspector-dialog").open)return;
  const view=$("inspector-content"),atEnd=view.scrollHeight-view.scrollTop-view.clientHeight<50,top=view.scrollTop;
  view.value=$("detected-logs").textContent;view.scrollTop=atEnd?view.scrollHeight:top;
}
const modeNames={enabled:"فعال",disabled:"غیرفعال",draining:"در حال تخلیه"};
const eventNames={"path-health":"سلامت مسیر","operator":"عملیات مدیر","login":"ورود مدیر","login-failed":"ورود ناموفق","route-change":"تغییر مسیر","backend-connect-failed":"مقصد در دسترس نیست","unit-state":"وضعیت سرویس","foreign-action":"مدیریت خارج","provision":"نصب تانل"};
function render(d){
  if(d.role==="iran"&&setupState?.inventory)d={...d,inventory:setupState.inventory,remote_inventory:setupState.remote_inventory};
  state=d;
  const foreign=d.role==="foreign";configureRole(foreign);
  const healthy=d.paths.filter(p=>p.healthy&&p.mode==="enabled");
  $("healthy").textContent=fa(healthy.length)+" / "+fa(d.paths.length);
  $("active").textContent=d.bootstrap||d.active===null?"—":fa(d.active);
  const selected=foreign?healthy[0]:d.paths.find(p=>p.id===d.selected);
  $("selected").textContent=d.bootstrap?"پایش نصب موجود":d.paused?"ورودی جدید متوقف است":d.selected||"مسیر سالمی در دسترس نیست";
  $("hero-description").textContent=d.bootstrap?"سرویس‌های فعلی را در بخش تشخیص مشاهده و مدیریت کن؛ هنوز مسیری از فرم نصب Donino فعال نشده است.":d.preferred?"مسیر ترجیحی: "+d.preferred+" · در صورت خرابی، مسیر سالم بعدی انتخاب می‌شود.":"انتخاب خودکار فعال است؛ سلامت هر مسیر با پاسخ امضاشدهٔ سرور خارج بررسی می‌شود.";
  $("latency").textContent=selected?.latency_ms!==null&&selected?.latency_ms!==undefined?selected.latency_ms.toFixed(1)+" ms":"—";
  const total=d.bootstrap?null:foreign?(d.metrics?d.metrics.bytes_up+d.metrics.bytes_down:null):d.paths.reduce((sum,p)=>sum+p.bytes_up+p.bytes_down,0);
  $("traffic").textContent=total===null?"—":bytes(total);
  if(total!==null&&previousTraffic&&d.time>previousTraffic.time&&total>=previousTraffic.total){$("traffic-rate").textContent="نرخ مجموع دو جهت: "+bytes((total-previousTraffic.total)/(d.time-previousTraffic.time))+"/s";}
  previousTraffic=total===null?null:{time:d.time,total};
  $("routing-mode").textContent=d.bootstrap?"تشخیص خودکار":d.preferred?"مسیر ترجیحی":d.routing_strategy==="adaptive"?"هستهٔ تطبیقی":"انتخاب خودکار";
  $("adaptive").textContent=d.routing_strategy==="adaptive"?"بازگشت به اولویت ثابت":"فعال‌کردن هستهٔ تطبیقی";$("adaptive").setAttribute("aria-pressed",String(d.routing_strategy==="adaptive"));
  $("path-summary").textContent=fa(d.paths.length)+" مسیر · "+fa(healthy.length)+" سالم و فعال";
  $("pause").textContent=d.paused?"ادامهٔ اتصال‌های جدید":"توقف اتصال‌های جدید";
  $("live").textContent="به‌روز · "+new Date(d.time*1000).toLocaleTimeString("fa-IR");$("live").className="badge good";
  notice(d.paused?"ورودی اتصال‌های جدید متوقف است؛ ارتباط‌های جاری ادامه دارند.":d.bootstrap?"هنوز تانلی از فرم نصب Donino فعال نشده است؛ نصب‌های فعلی در بخش تشخیص سرویس‌ها نمایش داده می‌شوند.":!d.selected?"هیچ مسیر سالمی موجود نیست. وضعیت سرویس تانل و دسترسی دو سرور را بررسی کن.":"");
  const cards=d.paths.map(p=>{
    const card=$("path-template").content.firstElementChild.cloneNode(true);
    if(p.id===d.selected) card.classList.add("selected");
    card.querySelector("h3").textContent=p.id;
    card.querySelector(".transport").textContent=p.transport.toUpperCase();
    const b=card.querySelector(".path-status"); b.textContent=foreign&&p.observation==="unknown"?"نامشخص":p.healthy?"سالم":"ناموفق";if(p.healthy)b.classList.add("good");else if(!(foreign&&p.observation==="unknown"))b.classList.add("bad");
    const metrics=card.querySelector(".path-metrics");
    (foreign?[[p.latency_ms===null?"—":p.latency_ms.toFixed(1)+" ms","آزمون از ایران"],[d.units.find(u=>u.unit==="donino-link-"+p.id+".service")?.active?"روشن":"خاموش","سرویس محلی"],[p.observation==="fresh"?"تازه":"نامشخص","شاهد ارتباط"]]:[[p.latency_ms===null?"—":p.latency_ms.toFixed(1)+" ms","تأخیر"],[fa(p.active),"اتصال فعال"],[bytes(p.bytes_up+p.bytes_down),"ترافیک"]]).forEach(([v,l])=>{const n=el("div");n.append(el("b",v),el("span",l));metrics.append(n);});
    if(p.id==="paqet"){const ok=foreign?p.udp_ok:p.remote?.udp_ok;const ms=foreign?p.udp_latency_ms:p.remote?.udp_latency_ms;card.append(el("p","UDP: "+(ok===true?"رفت‌وبرگشت معتبر"+(ms!==null&&ms!==undefined?" · "+ms+" ms":""):ok===false?"آزمون ناموفق":"در انتظار آزمون"),"field-help"));}
    if(p.id==="donino-continuum"){
      const t=p.continuum;
      card.append(el("p",t?"بازیابی موفق: "+fa(t.recoveries)+" · در حال بازیابی: "+fa(t.recovering_sessions)+" · بافر انتظار: "+bytes(t.pending_bytes):"در انتظار گزارش تازهٔ بازیابی نشست","field-help"));
    }
    card.querySelector(".mode").textContent=modeNames[p.mode];
    if(!foreign&&d.routing_strategy==="adaptive"&&p.quality)card.append(el("p","هزینهٔ مسیر: "+fa(p.quality.cost)+" · کمتر بهتر است","field-help"));
    const menu=card.querySelector("select");menu.hidden=foreign;if(foreign)card.querySelector(".mode").textContent="پایش از پنل ایران";menu.onchange=()=>{if(menu.value)action(p.id,menu.value);};
    const details=el("a","صفحهٔ این مسیر","workspace-link");details.href="#path/"+p.id;card.append(details);
    return card;
  });if(document.activeElement?.tagName!=="SELECT")$("path-list").replaceChildren(...cards);
  chart(d.paths);
  const remote=d.paths.find(p=>p.healthy&&p.remote?.memory_total)?.remote||(d.remote_inventory&&Date.now()/1000-d.remote_inventory.time<45?d.remote_inventory.host:null);
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
  $("counters").textContent=d.bootstrap?"شمارندهٔ اتصال و ترافیک نصب بیرونی هنوز اندازه‌گیری نمی‌شود؛ وضعیت و سلامت آن در بخش تشخیص نمایش داده می‌شود.":"پذیرفته‌شده: "+fa(d.accepted)+" · ردشده: "+fa(d.rejected)+" · تغییر مسیر: "+fa(d.route_changes);
  $("event-list").replaceChildren(...d.events.map(e=>{const n=el("div",undefined,"event");n.append(el("span",eventNames[e.kind]||e.kind,"event-kind"),el("span",eventDescription(e),"event-detail"),el("time",new Date(e.time*1000).toLocaleString("fa-IR")));return n;}));
  if(!d.events.length)$("event-list").append(el("p","هنوز رویدادی ثبت نشده است.","empty-events"));
  $("updated").textContent="به‌روز هر ۳ ثانیه";
  if(foreign)renderForeign(d);
  else if(d.bootstrap)notice("پنل ایران آماده است؛ برای نصب فعلی از بخش تشخیص سرویس‌های موجود استفاده کن.");
  syncNavigation();
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
  if((e.kind==="foreign-action"||e.kind==="provision")&&d.operation==="/imported-action")return ({manage:"تغییر اجازهٔ مدیریت",edit:"ذخیرهٔ تنظیمات",start:"شروع سرویس",stop:"توقف سرویس",restart:"راه‌اندازی مجدد سرویس",test:"آزمون سلامت و تشخیص"}[d.action]||"عملیات نصب موجود")+(d.unit?" · "+d.unit:"");
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
setInterval(()=>{if(!$("dashboard").hidden&&!document.hidden)refresh();},3000);

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
// Paqet's own data model is independent of gateway route selection.
let paqetFieldsReady=false,paqetPending=false,paqetActionId=null,paqetRole="iran";
const paqetActionNames={start:"شروع",stop:"توقف",restart:"راه‌اندازی مجدد",version:"نسخهٔ هسته",logs:"گزارش سرویس",ping:"ارسال بستهٔ Ping",dump:"گرفتن بسته‌ها (۳ ثانیه)","udp-test":"آزمون امضاشدهٔ UDP"};
function initPaqetFields(c){
  if(paqetFieldsReady)return;paqetFieldsReady=true;
  [["paqet-mode",c.modes,"normal"],["paqet-block",c.blocks,"aes-128-gcm"],["paqet-log",["none","debug","info","warn","error","fatal"],"warn"]].forEach(([id,values,chosen])=>{values.forEach(v=>{const n=el("option",v);n.value=v;$(id).append(n);});$(id).value=chosen;});
  Object.entries(c.kcp_numbers).forEach(([key,info])=>{const label=el("label",info.label+" (خالی = پیش‌فرض)"),input=el("input");input.type="number";input.min=info.min;input.max=info.max;input.id="paqet-kcp-"+key;input.dataset.kcp=key;if(key==="mtu")input.value=1150;label.append(input);$("paqet-kcp-fields").append(label);});
  [["wdelay","تجمیع ارسال"],["acknodelay","ACK بدون تأخیر"]].forEach(([key,text])=>{const label=el("label",text),select=el("select");select.id="paqet-kcp-"+key;select.dataset.kcp=key;select.dataset.boolean="true";[["","پیش‌فرض"],["true","فعال"],["false","غیرفعال"]].forEach(([v,t])=>{const o=el("option",t);o.value=v;select.append(o);});label.append(select);$("paqet-kcp-fields").append(label);});
  ["iran","foreign"].forEach(role=>{const box=el("fieldset"),pair=el("div",undefined,"field-pair");box.append(el("legend",role==="iran"?"شبکهٔ ایران؛ خالی = کشف خودکار":"شبکهٔ خارج؛ خالی = کشف خودکار"));[["interface","کارت شبکه"],["local_ip","IP محلی اصلی"],["router_mac","MAC دروازه"],["ipv6","IPv6 اضافی (اختیاری)"],["ipv6_router_mac","MAC دروازهٔ IPv6"]].concat(role==="iran"?[["source_port","پورت مبدأ ثابت؛ نیازمند یک اتصال"]]:[]).forEach(([key,text])=>{const label=el("label",text),input=el("input");input.id="paqet-net-"+role+"-"+key;input.dataset.role=role;input.dataset.network=key;input.dir="ltr";if(key==="source_port"){input.type="number";input.min=0;input.max=65535;}label.append(input);pair.append(label);});box.append(pair);$("paqet-networks").append(box);});
}
function addPaqetRow(kind,value={}){
  const holder=$(kind==="socks"?"paqet-socks":"paqet-forwards");if(holder.children.length>=(kind==="socks"?8:40)){toast("به سقف تعداد رسیدی.");return;}
  const row=el("div",undefined,"paqet-row");
  const fields=kind==="socks"?[["listen","ورودی SOCKS5"],["username","نام کاربری"],["password","رمز؛ خالی = حفظ رمز فعلی"]]:[["listen","ورودی ایران"],["target","مقصد loopback خارج"],["protocol","نوع ترافیک"]];
  fields.forEach(([field,text])=>{const label=el("label",text),input=el(field==="protocol"?"select":"input");input.dataset.paqet=field;input.dir="ltr";if(field==="protocol"){["tcp","udp"].forEach(v=>{const o=el("option",v.toUpperCase());o.value=v;input.append(o);});input.value=value[field]||"udp";}else{input.value=field==="password"?"":value[field]||(field==="listen"&&kind==="socks"?"127.0.0.1:1080":"");if(field==="password"){input.type="password";input.autocomplete="new-password";}if(["listen","target"].includes(field))input.required=true;}label.append(input);row.append(label);});
  const remove=el("button","حذف");remove.type="button";remove.onclick=()=>{row.remove();invalidatePlan();};row.append(remove);holder.append(row);invalidatePlan();
}
$("paqet-add-forward").onclick=()=>addPaqetRow("forward");$("paqet-add-socks").onclick=()=>addPaqetRow("socks");
function gatherPaqet(){
  const o={conn:Number($("paqet-conn").value),log_level:$("paqet-log").value,kcp:{mode:$("paqet-mode").value,block:$("paqet-block").value},allow_insecure:$("paqet-insecure").checked,network:{},forwards:[],socks5:[]};
  if($("paqet-pcap").value)o.pcap_sockbuf=Number($("paqet-pcap").value);if($("paqet-key").value)o.key=$("paqet-key").value;
  $("paqet-kcp-fields").querySelectorAll("[data-kcp]").forEach(n=>{if(n.value!=="")o.kcp[n.dataset.kcp]=n.dataset.boolean?n.value==="true":Number(n.value);});
  ["local","remote"].forEach(key=>{const v=$("paqet-"+key+"-flags").value.trim();if(v)o[key+"_flag"]=v.split(",").map(v=>v.trim());});
  $("paqet-networks").querySelectorAll("[data-network]").forEach(n=>{if(n.value!==""){o.network[n.dataset.role]??={};o.network[n.dataset.role][n.dataset.network]=n.dataset.network==="source_port"?Number(n.value):n.value.trim();}});
  [["paqet-forwards","forwards"],["paqet-socks","socks5"]].forEach(([id,key])=>{$(id).querySelectorAll(".paqet-row").forEach(row=>{const v={};row.querySelectorAll("[data-paqet]").forEach(n=>v[n.dataset.paqet]=n.dataset.paqet==="password"?n.value:n.value.trim());o[key].push(v);});});return o;
}
function loadPaqetSpec(){
  const s=setupState?.active_spec;if(!s){toast("تنظیمات نصب موفق این کنترل‌کننده موجود نیست؛ فرم نصب را تکمیل کن.");return;}
  $("setup-details").open=true;
  [["profile_id","setup-profile"],["iran","setup-iran"],["foreign","setup-foreign"],["base_port","setup-base"],["carrier_base","setup-carrier"],["health_port","setup-health"],["paqet_port","setup-paqet"],["browser_port","setup-browser"]].forEach(([key,id])=>{if(s[key]!==undefined)$(id).value=s[key];});
  $("setup-experimental").checked=!!s.experimental;$("setup-open-ufw").checked=!!s.open_ufw;
  $("setup-transports").querySelectorAll("input").forEach(n=>n.checked=s.transports.includes(n.value));
  $("setup-services").replaceChildren();s.services.forEach(addServiceRow);$("paqet-native-only").checked=!s.services.length;
  const o=s.paqet_options||{},k=o.kcp||{};$("paqet-conn").value=o.conn||2;$("paqet-mode").value=k.mode||"normal";$("paqet-block").value=k.block||"aes-128-gcm";$("paqet-log").value=o.log_level||"warn";$("paqet-pcap").value=o.pcap_sockbuf||"";$("paqet-key").value="";$("paqet-keep").checked=true;$("paqet-insecure").checked=!!o.allow_insecure;
  $("paqet-kcp-fields").querySelectorAll("[data-kcp]").forEach(n=>n.value=k[n.dataset.kcp]===undefined?"":String(k[n.dataset.kcp]));
  ["local","remote"].forEach(key=>$("paqet-"+key+"-flags").value=(o[key+"_flag"]||[]).join(","));
  $("paqet-networks").querySelectorAll("[data-network]").forEach(n=>n.value=o.network?.[n.dataset.role]?.[n.dataset.network]??"");
  $("paqet-forwards").replaceChildren();$("paqet-socks").replaceChildren();(o.forwards||[]).forEach(v=>addPaqetRow("forward",v));(o.socks5||[]).forEach(v=>addPaqetRow("socks",v));$("paqet-options").open=true;syncPaqetInputs();invalidatePlan();window.navigateWorkspace?.("#setup");toast("تنظیمات بارگذاری شد؛ تغییر بده، نقشه را بررسی کن و نصب دو سرور را شروع کن.");
}
$("paqet-edit").onclick=loadPaqetSpec;
function renderPaqet(p,foreign,agent){
  if(!p?.installed){$("paqet-manager").hidden=true;return;}$("paqet-manager").hidden=false;paqetRole=foreign?"foreign":"iran";
  if(p.managed_installation===false){
    $("paqet-installed").textContent=fa(p.instances?.length||0)+" نصب مستقل Paqet شناسایی شد؛ نسخه و کنترل به همان سرویس موجود مربوط‌اند.";
    $("paqet-summary").replaceChildren(...(p.instances||[]).map(row=>{const card=el("div");card.append(el("strong",row.unit),el("code",row.config_path||"تنظیمات نامشخص"));const link=el("a","بازکردن صفحهٔ همین Paqet","workspace-link");link.href="#service/"+row.id+"/overview";card.append(link);return card;}));
    $("paqet-help").textContent="فرایند، پورت فوروارد، مقصد خارج و آزمون امضاشده چهار مشاهدهٔ جدا هستند. نبود SOCKS5 به معنی خرابی نصب نیست.";
    $("paqet-actions").replaceChildren();$("paqet-edit").hidden=true;$("paqet-output").textContent="این نصب توسط Donino ساخته نشده است؛ تنظیمات، لاگ، کنترل اختیاری و آزمون سلامت را از صفحهٔ خودش باز کن.";return;
  }
  $("paqet-help").textContent="Ping فقط ارسال بسته را بررسی می‌کند؛ سلامت سرتاسری TCP و UDP از آزمون‌های امضاشده می‌آید.";
  $("paqet-installed").textContent=(foreign?"خارج":"ایران")+" · نسخهٔ تأییدشده "+p.version+" · KCP / "+p.kcp.mode+" · "+p.kcp.block+" · "+fa(p.conn)+" اتصال";
  const network=el("div"),forward=el("div");network.append(el("strong","شبکه و حامل"),el("code",p.network.interface+" · "+JSON.stringify(p.server)),el("code",JSON.stringify(p.network.ipv4||p.network.ipv6)));
  forward.append(el("strong","فوروارد و SOCKS5"));p.forwards.forEach(r=>forward.append(el("code",r.protocol.toUpperCase()+" "+r.listen+" → "+r.target)));p.socks5.forEach(r=>forward.append(el("code","SOCKS5 "+r.listen+(r.authenticated?" · احراز هویت":" · محلی"))));forward.append(el("small","شمارنده‌های gateway شامل فوروارد مستقیم و SOCKS5 نیستند."));$("paqet-summary").replaceChildren(network,forward);
  const actions=["start","stop","restart","version","logs",foreign?"dump":"ping",...(foreign?[]:["udp-test"])];
  $("paqet-actions").replaceChildren(...actions.map(action=>{const b=el("button",paqetActionNames[action]);b.type="button";b.disabled=paqetPending||!!(foreign?(agent?.action_busy||agent?.lease):setupState?.busy);b.onclick=()=>paqetAction(action);return b;}));$("paqet-edit").hidden=foreign||!setupState?.active_spec;
  if(foreign&&paqetActionId){const record=agent?.actions?.find(r=>r.id===paqetActionId);if(record&&record.status!=="running"){$("paqet-output").textContent=record.result?.output||record.error||record.status;paqetActionId=null;}}
}
async function paqetAction(action){
  if(paqetPending)return;paqetPending=true;$("paqet-output").textContent="در حال اجرا…";
  try{const foreign=paqetRole==="foreign",result=await api(foreign?"/api/foreign/action":"/api/provision/paqet-action",foreign?{unit:"donino-link-paqet.service",action}:{action});
    if(foreign){paqetActionId=result.id;$("paqet-output").textContent="عملیات ثبت شد؛ نتیجه پس از پایان نمایش داده می‌شود.";}
    else $("paqet-output").textContent=result.output||(result.latency_ms!==undefined?"UDP سالم · "+result.latency_ms+" ms":result.error||(result.ok?"انجام شد":"آزمون ناموفق"));
  }catch(e){$("paqet-output").textContent=e.message;}finally{paqetPending=false;}
}
$("setup-add-service").onclick=()=>addServiceRow({id:"app"+($("setup-services").children.length+1),listen:"",target:""});
$("setup-form").addEventListener("input",invalidatePlan);
$("setup-confirm").onchange=()=>$("setup-start").disabled=!setupPlan||!$("setup-confirm").checked||setupRequest||setupState?.busy;
$("setup-copy-key").onclick=async()=>{try{if(navigator.clipboard)await navigator.clipboard.writeText($("setup-public-key").value);else{$("setup-public-key").select();if(!document.execCommand("copy"))throw Error();}toast("کلید عمومی کپی شد.");}catch{toast("کلید عمومی را از کادر انتخاب و کپی کن.");}};
function renderSetup(data){
  setupState=data;renderDetected(data.inventory,false,data.remote_inventory);const available=data.available;
  if(data.paqet_capabilities)initPaqetFields(data.paqet_capabilities);renderPaqet(data.paqet,false);syncNavigation();
  $("setup-status").textContent=available?(data.busy?"نصب در حال اجرا":"آمادهٔ راه‌اندازی"):"نیاز به فعال‌سازی";$("setup-status").className="badge "+(available?"good":"bad");
  $("setup-unavailable").hidden=!!available;$("setup-unavailable").textContent=data.reason||"سرویس نصب خودکار در دسترس نیست.";
  $("setup-controls").hidden=!available;if(!available)return;
  $("setup-public-key").value=data.public_key;
  if(data.iran_address&&!$("setup-iran").value)$("setup-iran").value=data.iran_address;
  const select=$("setup-profile"),selected=select.value,ids=JSON.stringify(data.profiles.map(p=>[p.id,p.name]));
  if(select.dataset.profiles!==ids){select.replaceChildren(el("option",data.profiles.length?"انتخاب سرور خارج":"ابتدا اتصال خارج را ثبت کن"));select.firstChild.value="";data.profiles.forEach(p=>{const opt=el("option",p.name+" · "+p.host);opt.value=p.id;select.append(opt);});select.value=selected||(data.profiles.length===1?data.profiles[0].id:"");select.dataset.profiles=ids;}
  if(!$("setup-transports").children.length){data.transports.forEach(t=>{const label=el("label"),input=el("input");input.type="checkbox";input.value=t.id;input.checked=["frp-wss","frp-quic"].includes(t.id);input.dataset.experimental=String(t.experimental);label.append(input,el("span",t.id+(t.experimental?" · آزمایشی":"")));$("setup-transports").append(label);});}
  syncPaqetInputs();$("setup-controls").setAttribute("aria-busy",String(!!data.busy));
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
$("setup-form").onsubmit=async e=>{e.preventDefault();invalidatePlan();$("setup-error").textContent="";const transports=[...$("setup-transports").querySelectorAll("input:checked")].map(n=>n.value);if(!transports.length){$("setup-error").textContent="حداقل یک پروتکل انتخاب کن.";return;}const services=transports.includes("paqet")&&$("paqet-native-only").checked?[]:[...$("setup-services").children].map(row=>Object.fromEntries([...row.querySelectorAll("input")].map(n=>[n.dataset.field,n.value.trim()])));const spec={profile_id:$("setup-profile").value,iran:$("setup-iran").value.trim(),services,transports,experimental:$("setup-experimental").checked,open_ufw:$("setup-open-ufw").checked,base_port:Number($("setup-base").value),carrier_base:Number($("setup-carrier").value),health_port:Number($("setup-health").value),paqet_port:Number($("setup-paqet").value)};if($("setup-foreign").value.trim())spec.foreign=$("setup-foreign").value.trim();if($("setup-browser").value)spec.browser_port=Number($("setup-browser").value);if(transports.includes("donino-continuum")){spec.continuum_options={recovery_timeout:Number($("continuum-recovery").value),retry_max:Number($("continuum-retry").value),alternate_ports:$("continuum-ports").value.trim()?$("continuum-ports").value.split(",").map(v=>Number(v.trim())):[]};}if(transports.includes("paqet")){spec.paqet_options=gatherPaqet();spec.paqet_keep_secrets=$("paqet-keep").checked;}try{const p=await setupCall("/api/provision/preview",spec);setupPlan=p;$("setup-review-summary").textContent=p.summary.iran+" ⇄ "+p.summary.foreign+" · "+p.summary.transports.join(" + ")+" · "+fa(p.summary.services.length)+" سرویس";$("setup-firewall").replaceChildren(...["iran","foreign"].map(role=>{const n=el("div");n.append(el("strong",role==="iran"?"پورت‌های ورودی ایران":"پورت‌های ورودی خارج"));["tcp","udp"].forEach(proto=>{n.append(el("code",proto.toUpperCase()+": "+(p.summary.firewall[role][proto].join(", ")||"—")));});return n;}));$("setup-review").hidden=false;$("setup-confirm").checked=false;$("setup-review").scrollIntoView({behavior:"smooth",block:"nearest"});}catch(e){$("setup-error").textContent=e.message;}};
$("setup-start").onclick=async()=>{if(!setupPlan||!$("setup-confirm").checked)return;try{await setupCall("/api/provision/start",{plan_id:setupPlan.id,confirm_replace:true});invalidatePlan();await pollSetup();toast("عملیات نصب شروع شد؛ مراحل روی سرور ادامه پیدا می‌کنند.");}catch(e){$("setup-error").textContent=e.message;toast(e.message);}};
$("setup-details").addEventListener("toggle",()=>{if($("setup-details").open)pollSetup();});
setInterval(()=>{if(csrf&&!document.hidden)pollSetup();},4000);
document.addEventListener("visibilitychange",()=>{if(csrf&&!document.hidden){refresh();pollSetup();pollDetectedLogs();}});

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
  renderDetected(d.foreign?.inventory,true);
  renderPaqet(d.foreign?.paqet,true,d.foreign);
  const f=d.foreign||{},busy=foreignPending||f.action_busy||!!f.lease;
  $("selected").textContent=d.bootstrap?"پایش نصب موجود":d.telemetry_fresh?"ارتباط از ایران تأیید شد":"در انتظار آزمون ایران";
  $("hero-description").textContent=d.bootstrap?"وضعیت و سلامت نصب‌های فعلی را در بخش تشخیص ببین؛ آزمون نصب موجود از پنل ایران آغاز می‌شود.":d.telemetry_fresh?"آزمون تازه از ایران دریافت شده؛ سلامت هر مسیر و سرویس مقصد را در کارت‌ها ببین.":"سرویس‌های خارج جداگانه پایش می‌شوند. برای تأیید دوطرفه، پنل ایران را جفت‌سازی و تانل را نصب کن.";
  $("routing-mode").textContent="نقش سرور: خارج";
  notice(!f.available?"سرویس مدیریت خارج در دسترس نیست؛ وضعیت systemd را بررسی کن.":f.lease?"نصب دو سرور در جریان است؛ کنترل دستی سرویس‌ها تا پایان نصب متوقف می‌شود.":d.bootstrap?"سلامت نصب‌های موجود و زمان آخرین آزمون در بخش تشخیص نمایش داده می‌شود.":!d.telemetry_fresh?"هنوز شاهد تازهٔ تانل از ایران نداریم. روشن بودن سرویس‌ها به‌تنهایی سلامت تانل را ثابت نمی‌کند.":"");
  $("foreign-agent-status").textContent=f.available?(f.lease?"نصب در جریان":"مدیریت آماده"):"نیاز به بررسی";$("foreign-agent-status").className="badge "+(f.available?"good":"bad");
  $("foreign-new-code").disabled=busy||!f.available;$("foreign-test").disabled=busy||!f.available;
  $("foreign-pair-port").textContent="پورت کانال جفت‌سازی: "+(f.agent_port||"—")+" / TCP · باید از ایران در دسترس باشد.";
  const peers=(f.paired||[]).filter(p=>!p.revoked);
  $("foreign-peer-list").replaceChildren(...peers.map(p=>{const row=el("div",undefined,"foreign-peer"),detail=el("div");detail.append(el("strong",p.name),el("code",p.source));const revoke=el("button","لغو مدیریت");revoke.type="button";revoke.disabled=busy;revoke.onclick=async()=>{try{await foreignCall("/api/foreign/revoke",{id:p.id});toast("دسترسی مدیریت و کلید جفت‌سازی لغو شد؛ تانل‌های جاری حفظ می‌شوند.");}catch(e){toast(e.message);}};row.append(detail,revoke);return row;}));
  if(!peers.length)$("foreign-peer-list").append(el("p","هنوز پنل ایران جفت نشده است.","muted"));
  $("foreign-targets").replaceChildren(...Object.entries(d.targets||{}).map(([id,t])=>{const row=el("div",undefined,"foreign-peer"),a=el("div");a.append(el("strong",id),el("code",t.target));row.append(a,el("span",t.reachable?"مقصد در دسترس":"مقصد ناموفق","badge "+(t.reachable?"good":"bad")));return row;}));
  if(!Object.keys(d.targets||{}).length)$("foreign-targets").append(el("p","مقصدی تعریف نشده؛ سرویس TCP را در نقشهٔ پنل ایران اضافه کن.","muted"));
  $("foreign-probe-note").textContent=d.bootstrap?"نتیجهٔ آزمون نصب موجود در بخش تشخیص قابل مشاهده است.":(d.telemetry_fresh?"آزمون تازهٔ تانل دریافت شد":"آزمون دوطرفه نامشخص است")+(d.probe_time?" · آخرین دریافت: "+new Date(d.probe_time*1000).toLocaleString("fa-IR"):"");
  $("foreign-action-history").replaceChildren(...(f.actions||[]).slice(0,4).map(a=>el("p",a.unit+" · "+({start:"شروع",stop:"توقف",restart:"راه‌اندازی مجدد",test:"آزمون مقصد"}[a.action]||a.action)+" · "+({running:"در حال اجرا",succeeded:"موفق",failed:"ناموفق",interrupted:"متوقف‌شده"}[a.status]||a.status)+(a.error?" · "+a.error:""),"field-help")));
  for(const u of d.units||[]){let view=foreignUnitCards.get(u.unit);if(!view){const card=el("article",undefined,"setup-block foreign-unit"),head=el("div",undefined,"service-header"),badge=el("span",undefined,"badge");head.append(el("code",u.unit),badge);const metrics=el("p",undefined,"muted"),buttons=el("div",undefined,"foreign-service-buttons");const controls=[];for(const [op,text] of [["start","شروع"],["restart","راه‌اندازی مجدد"],["stop","توقف"]]){const b=el("button",text);b.type="button";b.onclick=async()=>{try{await foreignCall("/api/foreign/action",{unit:u.unit,action:op});toast("عملیات سرویس شروع شد؛ نتیجه در همین پنل ثبت می‌شود.");}catch(e){toast(e.message);}};buttons.append(b);controls.push(b);}card.append(head,metrics,buttons);view={card,badge,metrics,controls};foreignUnitCards.set(u.unit,view);$("foreign-units").append(card);}view.badge.textContent=u.active?"روشن":u.state;view.badge.className="badge "+(u.active?"good":"bad");view.metrics.textContent="راه‌اندازی مجدد: "+fa(u.restarts)+" · RAM: "+(u.memory===null?"—":bytes(u.memory));view.controls.forEach((b,i)=>b.disabled=busy||!f.available||(u.unit==="donino-link.service"&&i===2));}
  const unitIds=new Set((d.units||[]).map(u=>u.unit));for(const [id,v] of foreignUnitCards)if(!unitIds.has(id)){v.card.remove();foreignUnitCards.delete(id);}
  $("counters").textContent=d.bootstrap?"ترافیک و تعداد اتصال‌های نصب موجود اندازه‌گیری نشده‌اند.":d.metrics?"اتصال‌های پذیرفته‌شدهٔ relay: "+fa(d.metrics.accepted)+" · شمارنده‌های همین سرور":"شمارندهٔ relay هنوز در دسترس نیست.";
  if(!d.metrics)$("traffic-rate").textContent=d.bootstrap?"شمارندهٔ نصب موجود در دسترس نیست":"در انتظار شمارندهٔ واقعی فرآیند";
}
async function foreignCall(path,body){if(foreignPending)throw Error("منتظر پایان درخواست قبلی بمان.");foreignPending=true;if(state?.role==="foreign")renderForeign(state);try{const result=await api(path,body);if(result.status==="running"&&state?.foreign)state.foreign.action_busy=true;return result;}finally{foreignPending=false;await refresh();}}
$("foreign-new-code").onclick=async()=>{try{const c=await foreignCall("/api/foreign/code",{});$("foreign-code-value").value=c.code;$("foreign-code-expiry").textContent="معتبر تا "+new Date(c.expires_at*1000).toLocaleTimeString("fa-IR");toast("کد یک‌بارمصرف ساخته شد؛ آن را در پنل ایران وارد کن.");}catch(e){toast(e.message);}};
$("foreign-copy-code").onclick=async()=>{try{if(!$("foreign-code-value").value)throw Error();if(navigator.clipboard)await navigator.clipboard.writeText($("foreign-code-value").value);else{$("foreign-code-value").select();if(!document.execCommand("copy"))throw Error();}toast("کد جفت‌سازی کپی شد.");}catch{toast("ابتدا کد بساز؛ می‌توانی آن را از کادر انتخاب و کپی کنی.");}};
$("foreign-test").onclick=async()=>{try{await foreignCall("/api/foreign/action",{unit:"all",action:"test"});toast("آزمون سلامت و مقصدها شروع شد.");}catch(e){toast(e.message);}};

function syncPaqetInputs(){const continuum=[...$("setup-transports").querySelectorAll("input:checked")].some(n=>n.value==="donino-continuum");if($("continuum-options")){$("continuum-options").hidden=!continuum;$("continuum-options").querySelectorAll("input").forEach(n=>n.disabled=!continuum);}const enabled=[...$("setup-transports").querySelectorAll("input:checked")].some(n=>n.value==="paqet");$("paqet-options").hidden=!enabled;$("paqet-options").querySelectorAll("input,select,button").forEach(n=>n.disabled=!enabled);$("paqet-native-only").disabled=!enabled;const native=enabled&&$("paqet-native-only").checked;$("setup-services").querySelectorAll("input,button").forEach(n=>n.disabled=native);$("setup-add-service").disabled=native;}
$("setup-transports").addEventListener("change",syncPaqetInputs);$("paqet-native-only").onchange=syncPaqetInputs;

let detectedState=null,detectedForeign=false,detectedRemote=null,detectedSelected=null,detectedBusy=false,detectedCursor=null,detectedLines=[],detectedLogBusy=false,lastDetectedTest=0;
const detectedCards=new Map();
function selectedDetected(){return detectedState?.services?.find(r=>r.id===detectedSelected);}
function renderDetected(inventory,foreign,remote){
  if(!inventory)return;detectedState=inventory;detectedForeign=foreign;detectedRemote=remote||null;$("detected-panel").hidden=false;$("nav-detected").hidden=false;
  $("detected-count").textContent=fa(inventory.services.length)+" سرویس شناسایی‌شده";$("detected-error").textContent=inventory.error||(!inventory.services.length?"فعلاً سرویس شناخته‌شده‌ای دیده نشده است.":"");
  const ids=new Set();
  for(const row of inventory.services){
    ids.add(row.id);let view=detectedCards.get(row.id);
    if(!view){
      const card=el("article",undefined,"detected-service"),engine=el("strong"),unit=el("code"),status=el("span"),description=el("p",undefined,"field-help"),error=el("p",undefined,"field-help"),button=el("button","مشاهده و مدیریت");
      button.type="button";button.setAttribute("aria-controls","detected-detail");button.onclick=()=>selectDetected(row.id);
      card.append(engine,unit,status,description,error,button);view={card,engine,unit,status,description,error,button};detectedCards.set(row.id,view);$("detected-list").append(card);
    }
    view.card.classList.toggle("selected",row.id===detectedSelected);view.engine.textContent=row.engine;view.unit.textContent=row.unit;
    view.status.textContent=row.active?"در حال اجرا":"خاموش / "+row.state;view.status.className="badge "+(row.active?"good":"");
    view.description.textContent=(row.capabilities?.category==="auxiliary"?"سرویس کمکی / مانیتور یا رابط":row.role==="client"?"ایران / client":row.role==="server"?"خارج / server":"سرویس موجود")+" · "+(row.management_enabled?"مدیریت فعال":"فقط مشاهده");
    view.error.textContent=row.config_error||"";view.error.hidden=!row.config_error;view.button.hidden=false;
    view.button.setAttribute("aria-label","مشاهده و مدیریت "+row.unit);view.button.setAttribute("aria-expanded",String(row.id===detectedSelected));
  }
  for(const [id,view] of detectedCards)if(!ids.has(id)){view.card.remove();detectedCards.delete(id);}

  window.workspaceRefresh?.();
  const row=selectedDetected();$("detected-detail").hidden=!row;if(!row)return;
  $("detected-title").textContent=row.unit+" · "+(row.active?"روشن":"خاموش");$("detected-file").textContent=row.config_path||"مسیر تنظیمات تشخیص داده نشد";
  $("detected-manage").textContent=row.management_enabled?"لغو مدیریت؛ سرویس حفظ می‌شود":"فعال‌کردن مدیریت همین سرویس";$("detected-manage").disabled=detectedBusy||(!(row.capabilities?.control??row.editable)&&!row.management_enabled);
  ["start","stop","restart"].forEach(op=>$("detected-"+op).disabled=detectedBusy||!row.management_enabled);
  $("detected-save").disabled=detectedBusy||!row.management_enabled||!row.editable||!!row.managed_by_donino||!$("detected-confirm").checked;$("detected-config").readOnly=!row.management_enabled||!row.editable||!!row.managed_by_donino;
  const h=row.health;$("detected-health").textContent=h?("TCP: "+(h.tcp_ok===true?"رفت‌وبرگشت امضاشده سالم":h.tcp_ok===false?"ناموفق":"تأیید نشده")+" · UDP: "+(h.udp_ok===true?"رفت‌وبرگشت امضاشده سالم":h.udp_ok===false?"ناموفق":"تأیید نشده")+" · "+new Date(h.time*1000).toLocaleTimeString("fa-IR")):"روشن بودن فرآیند، سلامت ارتباط دو سرور را ثابت نمی‌کند؛ در انتظار آزمون تازه.";
  const fresh=remote&&Date.now()/1000-remote.time<45;const paired=fresh?remote.services?.find(r=>r.role!==row.role&&r.key_id&&r.key_id===row.key_id):null;
  $("detected-pair").textContent=row.engine!=="paqet"?"لاگ و وضعیت این موتور مستقل از آزمون مسیر Donino است؛ نبود آداپتر آزمون به معنی خراب بودن تانل نیست.":foreign?"نتیجهٔ آزمون پنل ایران اینجا هم ثبت می‌شود؛ از پنل ایران آزمون را شروع کن.":paired?"Paqet طرف مقابل شناسایی شد: "+paired.unit:!fresh?"برای تطبیق دو نقش و آزمون امضاشده، پنل خارج را جفت کن.":"نصب متناظر با همین کلید هنوز در خارج شناسایی نشده است.";
  $("detected-test").disabled=detectedBusy||(row.engine==="paqet"&&!foreign&&!setupState?.profiles?.length);
  $("detected-auto-test").disabled=foreign;
}
function selectDetected(id,tab="overview"){closeInspector();detectedSelected=id;detectedCursor=null;detectedLines=[];$("detected-logs").textContent="در انتظار journal…";$("detected-result").textContent="";$("detected-confirm").checked=false;$("detected-auto-test").checked=false;loadDetectedConfig();renderDetected(detectedState,detectedForeign,detectedRemote);window.navigateWorkspace?.("#service/"+id+"/"+tab);pollDetectedLogs();}
function loadDetectedConfig(){const row=selectedDetected();if(!row)return;$("detected-config").value=JSON.stringify(row.config||{},null,2);$("detected-config").dataset.revision=row.revision||"";}
async function detectedAction(action,extra={}){
 const row=selectedDetected();if(!row||detectedBusy)return;detectedBusy=true;$("detected-result").textContent="در حال اجرا…";renderDetected(detectedState,detectedForeign,detectedRemote);
 try{const body={id:row.id,action,...extra};if(action==="test"&&!detectedForeign)body.profile_id=$("service-peer")?.value||$("setup-profile").value||setupState?.profiles?.[0]?.id;const result=await api(detectedForeign?"/api/foreign/imported-action":"/api/provision/imported-action",body);if(row.id===detectedSelected){$("detected-result").textContent=(result.verification==="diagnostics-only"?"بررسی نصب فوروارد انجام شد؛ نتیجهٔ پورت و مقصد در صفحهٔ سلامت است. مسیر سرتاسری هنوز تأیید نشده.":result.verification==="process-only"?"وضعیت فرآیند بررسی شد؛ برای این نصب بیرونی آزمون امضاشدهٔ مسیر تعریف نشده.":null)||result.reason||result.error||(action==="test"?"TCP: "+String(result.tcp_ok)+" · UDP: "+String(result.udp_ok):action==="manage"?"اجازهٔ مدیریت تغییر کرد؛ خودِ سرویس تغییر نکرد.":action==="edit"?"انجام شد؛ فایل پشتیبان ذخیره شد. آزمون دوطرفه را دوباره اجرا کن.":"انجام شد؛ وضعیت و لاگ را بررسی کن.");if(action==="edit"){
   $("detected-confirm").checked=false;
   $("detected-config").value=JSON.stringify(result.config,null,2);
   $("detected-config").dataset.revision=result.revision;
  }}await refresh();if(!detectedForeign)await pollSetup();}
 catch(e){$("detected-result").textContent=e.message;}finally{detectedBusy=false;if(detectedState)renderDetected(detectedState,detectedForeign,detectedRemote);}
}
$("detected-manage").onclick=()=>detectedAction("manage",{enabled:!selectedDetected()?.management_enabled});["start","stop","restart","test"].forEach(op=>$("detected-"+op).onclick=()=>detectedAction(op));
$("detected-confirm").onchange=()=>renderDetected(detectedState,detectedForeign,detectedRemote);$("detected-reload").onclick=async()=>{const row=selectedDetected();if(!row)return;try{const inventory=await api(detectedForeign?"/api/foreign/imported-action":"/api/provision/imported-action",{id:row.id,action:"inspect"});renderDetected(inventory,detectedForeign,detectedRemote);loadDetectedConfig();}catch(e){$("detected-result").textContent=e.message;}};
$("detected-save").onclick=()=>{try{const cfg=JSON.parse($("detected-config").value);detectedAction("edit",{revision:$("detected-config").dataset.revision,config:cfg,ack_peer_change:$("detected-confirm").checked});}catch{$("detected-result").textContent="تنظیمات باید JSON معتبر باشد.";}};
async function pollDetectedLogs(){const row=selectedDetected();if(!csrf||!row||!$("detected-live").checked||detectedLogBusy||document.hidden||!window.serviceLogsVisible?.())return;detectedLogBusy=true;const id=row.id;try{const result=await api(detectedForeign?"/api/foreign/imported-action":"/api/provision/imported-action",{id,action:"logs",cursor:detectedCursor});if(id!==detectedSelected)return;detectedCursor=result.cursor;detectedLines.push(...result.lines.map(l=>(l.time?new Date(Number(l.time)/1000).toLocaleTimeString("fa-IR")+" · ":"")+l.message));detectedLines=detectedLines.slice(-300);$("detected-logs").textContent=detectedLines.join("\n")||"رویداد تازه‌ای در journal نیست؛ سطح لاگ فعلی موتور ممکن است none باشد.";if(result.reason)$("detected-logs").textContent=result.reason;syncInspector();if(result.truncated)$("detected-result").textContent="خروجی journal محدود شد؛ آخرین پیام‌های دریافت‌شده نمایش داده می‌شوند.";}catch(e){$("detected-logs").textContent=e.message;}finally{detectedLogBusy=false;}}
setInterval(()=>{pollDetectedLogs();if(csrf&&!document.hidden&&window.serviceHealthVisible?.()&&$("detected-auto-test").checked&&!detectedForeign&&selectedDetected()&&Date.now()-lastDetectedTest>15000){lastDetectedTest=Date.now();detectedAction("test");}},2000);
