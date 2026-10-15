"use strict";
// Distinct, addressable pages. Polling preserves the DOM, drafts and selection.
const workspacePages=new Map();
const pageNames={overview:"نمای کلی", "detected-panel":"سرویس‌های موجود", pairing:"جفت‌سازی سرورها", setup:"ساخت تانل", "foreign-node":"کنترل سرویس‌های خارج", targets:"مقصدهای خارج", "paqet-manager":"Paqet", paths:"مسیرهای مدیریت‌شده", monitor:"مانیتورینگ", events:"رویدادها", engines:"موتورها و سازگاری", resilience:"پایداری و بازیابی", settings:"تنظیمات پنل", guide:"راهنما", service:"سرویس", engine:"موتور", path:"مسیر"};
const engineNames={paqet:"Paqet",frp:"FRP",backpack:"BackPack",backhaul:"Backhaul",xray:"Xray","sing-box":"sing-box",wireguard:"WireGuard",rathole:"Rathole",gost:"GOST",chisel:"Chisel","browser-wss":"BrowserLink","donino-mux":"Donino Mux","donino-continuum":"Donino Continuum"};
let workspaceRoute={page:"overview",id:null,tab:"overview"}, workspaceBuilding=false;
function pageSurface(id,nodes=[]){
  const section=el("section",undefined,"workspace-page");section.dataset.page=id;section.hidden=true;section.setAttribute("aria-label",pageNames[id]||id);
  document.querySelector("main footer").before(section);nodes.forEach(n=>{if(n)section.append(n);});workspacePages.set(id,section);return section;
}
function surfaceHeading(title,description){const head=el("div",undefined,"section-heading");const detail=el("div");detail.append(el("h2",title),el("p",description,"muted"));head.append(detail);return head;}
function routeLink(text,hash,cls="workspace-link"){const a=el("a",text,cls);a.href=hash;return a;}
function makeNav(text,hash,id){const a=routeLink(text,hash);if(id)a.id=id;const icon=el("span",undefined,"nav-glyph");icon.textContent="◈";a.prepend(icon);return a;}
function setupWorkspace(){
  const main=$("main-content");
  pageSurface("overview",[$("overview"),main.querySelector(".kpis")]);
  const overview=el("article",undefined,"panel inventory-overview");overview.append(surfaceHeading("نصب‌های فعلی","وضعیت سرویس محلی و نتیجهٔ آزمون مسیر، جداگانه نمایش داده می‌شوند."),el("div",undefined,"inventory-kpis"));overview.lastChild.id="inventory-overview";overview.append(routeLink("بازکردن سرویس‌های موجود","#detected-panel"));workspacePages.get("overview").append(overview);
  // Pairing is a separate workflow from installing or replacing any tunnel.
  const pairing=pageSurface("pairing");pairing.append(surfaceHeading("جفت‌سازی دو پنل","کانال مدیریت امن؛ این کار خودش تانل موجود را جایگزین نمی‌کند."));
  const iranPair=$("connection-form").closest(".setup-block");iranPair.id="iran-pairing";pairing.append(iranPair);
  const foreignPair=$("foreign-new-code").closest(".setup-block");foreignPair.id="foreign-pairing";pairing.append(foreignPair);
  pageSurface("setup",[$("setup")]);
  $("setup-controls").prepend(routeLink("اتصال یا جفت‌سازی سرور خارج","#pairing"));
  const targets=pageSurface("targets");targets.append(surfaceHeading("سلامت مقصدهای خارج","دسترسی TCP مقصد، از سلامت خود تانل مستقل است."),$("foreign-targets").closest(".setup-block"));
  pageSurface("foreign-node",[$("foreign-node")]);
  pageSurface("detected-panel",[$("detected-panel")]);
  const service=pageSurface("service");service.id="service-page";
  const back=routeLink("← همهٔ سرویس‌ها","#detected-panel");const tabs=el("nav",undefined,"service-tabs");tabs.id="service-tabs";tabs.setAttribute("aria-label","صفحه‌های همین سرویس");service.append(back,tabs,$("detected-detail"));
  const detail=$("detected-detail"),overviewTab=el("div"),healthTab=el("div"),configTab=el("div"),logsTab=el("div");
  const actions=detail.querySelector(".paqet-actions");
  overviewTab.dataset.serviceTab="overview";overviewTab.className="service-overview-grid";
  const metrics=el("div",undefined,"panel");metrics.id="service-metrics";overviewTab.append(metrics,actions);
  healthTab.dataset.serviceTab="health";healthTab.append(surfaceHeading("سلامت همین مسیر","روشن بودن فرآیند یا باز بودن پورت به‌تنهایی ارتباط سرتاسری را تأیید نمی‌کند."),$("detected-health"),$("detected-pair"));
  const probe=el("div",undefined,"paqet-actions");probe.append(actions.querySelector("#detected-test"),actions.querySelector("#detected-auto-test").closest("label"));healthTab.append(probe);const diagnostics=el("div");diagnostics.id="service-diagnostics";healthTab.append(diagnostics);
  const peerLabel=el("label","سرور خارج برای بررسی این نصب"),peerSelect=el("select");peerSelect.id="service-peer";peerLabel.id="service-peer-label";peerLabel.className="setup-form";peerLabel.append(peerSelect);healthTab.insertBefore(peerLabel,probe);
  configTab.dataset.serviceTab="config";configTab.append($("detected-config-details"));
  logsTab.dataset.serviceTab="logs";logsTab.append(detail.querySelector(".log-workspace"));
  detail.querySelector(".detected-workspace").remove();detail.insertBefore(overviewTab,$("detected-result"));detail.insertBefore(healthTab,$("detected-result"));detail.insertBefore(configTab,$("detected-result"));detail.insertBefore(logsTab,$("detected-result"));
  pageSurface("paqet-manager",[$("paqet-manager")]);
  for(const id of ["paths","monitor","events","guide"])pageSurface(id,[$(id)]);
  const enginePage=pageSurface("engine");enginePage.id="engine-page";enginePage.append(routeLink("← همهٔ موتور‌ها","#engines"),surfaceHeading("موتور","امکانات سازگار با نصب فعلی"));const engineList=el("div",undefined,"detected-list");engineList.id="engine-services";enginePage.append(engineList);
  const catalog=pageSurface("engines");catalog.append(surfaceHeading("موتورها و سطح سازگاری","قابلیت‌های خواندن، لاگ و کنترل هر نصب مشخص‌اند؛ ویرایش فقط با آداپتر معتبر انجام می‌شود."));const catalogList=el("div",undefined,"engine-catalog");catalogList.id="engine-catalog";catalog.append(catalogList);
  const pathPage=pageSurface("path");pathPage.id="path-page";pathPage.append(routeLink("← تمام مسیرها","#paths"));const pathDetail=el("div",undefined,"panel");pathDetail.id="path-detail";pathPage.append(pathDetail);
  const monitorSummary=el("article",undefined,"panel");monitorSummary.append(surfaceHeading("نصب‌های موجود","ترافیک نصب‌های بیرونی بدون شمارندهٔ معتبر، نامشخص می‌ماند."));const matrix=el("div",undefined,"monitor-matrix");matrix.id="inventory-monitor";monitorSummary.append(matrix);workspacePages.get("monitor").prepend(monitorSummary);
  const resilience=pageSurface("resilience");resilience.append(surfaceHeading("پایداری و بازیابی","اتصال‌های امن WSS روی TCP، بازیابی نشست محدود و ورودی جایگزین برای همان سرور."));const summary=el("div",undefined,"inventory-kpis");summary.id="resilience-metrics";resilience.append(summary);
  const resilienceActions=el("article",undefined,"panel resilience-actions");resilienceActions.append(el("h3","مسیر تطبیقی و ساخت Continuum"),el("p","هستهٔ تطبیقی برای اتصال‌های جدید مسیر سالم را انتخاب می‌کند. Continuum اتصال جاری را فقط در همان دو فرآیند زنده و تا پایان مهلت بازیابی حفظ می‌کند.","muted"),$("adaptive"));const preset=el("button","آماده‌کردن فرم Continuum");preset.id="resilience-preset";preset.type="button";preset.onclick=()=>{if(state?.role==="foreign")return;$("setup-transports").querySelectorAll("input").forEach(n=>n.checked=n.value==="donino-continuum");$("setup-experimental").checked=true;syncPaqetInputs();invalidatePlan();navigateWorkspace("#setup");toast("فرم آماده شد؛ هنوز هیچ تانلی نصب یا جایگزین نشده است.");};resilienceActions.append(preset);resilience.append(resilienceActions);
  const limits=el("article",undefined,"panel");limits.append(el("h3","محدودهٔ عملکرد"),el("p","ورودی‌های جایگزین به همان سرور و همان هویت TLS وصل می‌شوند. قطع کامل مسیر بین‌الملل، مسدود شدن تمام آدرس‌ها یا از دست رفتن فرآیند مقصد با این روش برطرف نمی‌شود. UDP مستقیم Paqet بین این مسیرها مهاجرت نمی‌کند.","muted"));resilience.append(limits);
  const settings=pageSurface("settings");settings.append(surfaceHeading("تنظیمات پنل","نمایش و خروجی مشاهده‌ها"));const preferences=el("article",undefined,"panel");preferences.append(el("h3","ظاهر"));for(const [name,value] of [["روشن","light"],["تیره","dark"]]){const button=el("button",name);button.type="button";button.onclick=()=>setTheme(value);preferences.append(button);}preferences.append(el("h3","خروجی کامل دو پنل"),routeLink("دریافت وضعیت، سرویس‌ها و آزمون‌ها","/api/export"),el("p","خروجی شامل مشاهده‌های محلی و طرف مقابل است؛ رمزها و کلیدهای تنظیمات پنهان می‌مانند.","muted"));settings.append(preferences);
  const continuum=el("details",undefined,"port-options");continuum.id="continuum-options";continuum.append(el("summary","تنظیمات بازیابی Continuum"));const fields=el("div",undefined,"field-pair");for(const [id,label,value,type] of [["continuum-recovery","مهلت بازیابی نشست (ثانیه)",15,"number"],["continuum-retry","حداکثر فاصلهٔ تلاش مجدد (ثانیه)",1.5,"number"],["continuum-ports","پورت‌های ورودی جایگزین روی همان خارج","","text"]]){const n=el("label",label),input=el("input");input.id=id;input.type=type;input.value=value;input.dir="ltr";if(type==="number"){input.min=id.endsWith("retry")?.2:1;input.max=id.endsWith("retry")?5:60;input.step=id.endsWith("retry")?.1:1;}else input.placeholder="24450, 24451";n.append(input);fields.append(n);}continuum.append(fields,el("p","حداکثر چهار پورت بین ۱۰۲۴ و ۶۵۵۳۵. همه باید آزاد باشند و در فایروال باز شوند؛ نقشهٔ نصب قبل از فعال‌سازی بررسی می‌شود.","muted"));$("setup-preview").before(continuum);
  const nav=$("sidebar").querySelector("nav");nav.append(makeNav("جفت‌سازی","#pairing","nav-pairing"),makeNav("مقصدهای خارج","#targets","nav-targets"),makeNav("موتورها و سازگاری","#engines","nav-engines"),makeNav("پایداری و بازیابی","#resilience","nav-resilience"),makeNav("تنظیمات پنل","#settings","nav-settings"));
  for(const [id,node] of workspacePages){node.tabIndex=-1;node.setAttribute("aria-labelledby","page-title");}document.querySelector("header h1").id="page-title";
}
function readWorkspaceRoute(hash){
  const parts=(hash||"#overview").replace(/^#\/?/,"").split("/");
  const page=workspacePages.has(parts[0])?parts[0]:"overview";
  return {page,id:parts[1]||null,tab:["overview","health","config","logs"].includes(parts[2])?parts[2]:"overview"};
}
function navigateWorkspace(hash){
  if(location.hash!==hash)history.pushState(null,"",hash);
  workspaceRefresh(true);closeNavigation(false);
  const page=workspacePages.get(workspaceRoute.page);page?.focus({preventScroll:true});window.scrollTo({top:0,behavior:"instant"});
}
function healthText(h){if(!h)return "آزمون تازه نداریم";if(h.tcp_ok===true)return "TCP تأیید شد";if(h.tcp_ok===false)return "آزمون TCP ناموفق";return "مسیر تأیید نشده";}
function metricsCard(value,label){const card=el("div",undefined,"inventory-metric");card.append(el("strong",value),el("span",label));return card;}
function serviceLinkCard(row){const a=routeLink("","#service/"+row.id+"/overview","detected-service service-link");a.append(el("strong",row.unit),el("span",row.active?"فرآیند روشن":"فرآیند خاموش","badge "+(row.active?"good":"")),el("p",healthText(row.health),"muted"));return a;}
function workspaceRefresh(focus=false){
  if(workspaceBuilding)return;workspaceBuilding=true;
  try{
    workspaceRoute=readWorkspaceRoute(location.hash);const r=workspaceRoute,foreign=state?.role==="foreign";
    if(state&&((foreign&&r.page==="setup")||(!foreign&&["foreign-node","targets"].includes(r.page)))){r.page="overview";history.replaceState(null,"","#overview");}
    if(r.page==="setup"&&workspacePages.get("setup").hidden)$("setup-details").open=true;
    $("iran-pairing").hidden=foreign;$("foreign-pairing").hidden=!foreign;$("nav-targets").hidden=!foreign;
    workspacePages.forEach((page,id)=>page.hidden=id!==r.page);
    document.querySelectorAll("#sidebar nav a").forEach(link=>{const id=r.page==="service"?"detected-panel":r.page==="engine"?"engines":r.page==="path"?"paths":r.page;const active=link.hash==="#"+id;link.classList.toggle("nav-active",active);if(active)link.setAttribute("aria-current","page");else link.removeAttribute("aria-current");});
    let title=pageNames[r.page];const rows=detectedState?.services||[];
    if(r.page==="service"){
      const row=rows.find(v=>v.id===r.id);
      if(row&&detectedSelected!==row.id)selectDetected(row.id,r.tab);
      $("detected-detail").hidden=!row;
      if(row){title=(engineNames[row.engine]||row.engine)+" / "+row.unit;
        if($("service-tabs").dataset.serviceId!==row.id){$("service-tabs").replaceChildren(...[["overview","نمای سرویس"],["health","سلامت"],["config","تنظیمات"],["logs","لاگ زنده"]].map(([tab,label])=>routeLink(label,"#service/"+row.id+"/"+tab)));$("service-tabs").dataset.serviceId=row.id;}
        $("service-tabs").querySelectorAll("a").forEach(a=>{if(a.hash.endsWith("/"+r.tab))a.setAttribute("aria-current","page");else a.removeAttribute("aria-current");});
        $("detected-detail").querySelectorAll("[data-service-tab]").forEach(n=>n.hidden=n.dataset.serviceTab!==r.tab);
        if(r.tab==="config")$("detected-config-details").open=true;
        if(r.tab==="logs")pollDetectedLogs();
        $("service-metrics").replaceChildren(el("h3","وضعیت محلی"),metricsCard(row.active?"روشن":"خاموش","فرآیند"),metricsCard(row.memory===null||row.memory===undefined?"—":bytes(row.memory),"حافظهٔ همین سرویس"),metricsCard(row.restarts===null||row.restarts===undefined?"—":fa(row.restarts),"restart ثبت‌شده"),el("p",row.capabilities?.protocol||row.engine,"field-help"),el("p",row.capabilities?.category==="auxiliary"?"سرویس کمکی؛ جدا از مسیر انتقال داده":"نصب مستقل / "+(row.management_enabled?"مدیریت با اجازهٔ تو":"فقط مشاهده"),"muted"));
        renderDiagnostics(row);
        $("service-peer-label").hidden=foreign||row.engine!=="paqet";
        const peers=setupState?.profiles||[],key=JSON.stringify(peers.map(p=>[p.id,p.name]));
        if($("service-peer").dataset.profiles!==key){const selected=$("service-peer").value;$("service-peer").replaceChildren(...peers.map(peer=>{const o=el("option",peer.name+" · "+peer.host);o.value=peer.id;return o;}));if(peers.some(p=>p.id===selected))$("service-peer").value=selected;$("service-peer").dataset.profiles=key;}
        $("detected-test").textContent=foreign?"دریافت نتیجهٔ آزمون ایران":row.engine!=="paqet"?"بررسی تشخیصی سرویس":row.capabilities?.signed_probe?"آزمون امضاشدهٔ TCP و UDP":"بررسی ورودی و مقصد نصب موجود";
      }else{$("service-tabs").replaceChildren(el("p",detectedState?"این سرویس در اسکن فعلی موجود نیست؛ به فهرست برگرد و دوباره انتخاب کن.":"در حال دریافت فهرست سرویس‌ها…","muted"));}
    }
    if(r.page==="engine"){
      title=engineNames[r.id]||"موتور شناخته‌نشده";const head=$("engine-page").querySelector("h2");head.textContent=title;
      const matching=rows.filter(row=>row.engine===r.id);$("engine-services").replaceChildren(...matching.map(serviceLinkCard));if(!matching.length)$("engine-services").append(el("p","نصب فعالی از این موتور در اسکن محلی دیده نشده است. برای ساخت مسیر جدید از فرم نصب استفاده کن.","muted"),routeLink("فرم ساخت تانل","#setup"));
    }
    document.querySelector("header h1").firstChild.textContent=title;document.querySelector(".breadcrumbs").textContent=(foreign?"سرور خارج":"سرور ایران")+" / "+title;document.title=title+" · Donino Tunnel";
    $("inventory-overview").replaceChildren(metricsCard(fa(rows.filter(v=>v.active).length),"فرآیند روشن"),metricsCard(fa(rows.filter(v=>v.capabilities?.category!=="auxiliary").length),"سرویس اصلی"),metricsCard(fa(rows.filter(v=>v.capabilities?.category==="auxiliary").length),"سرویس کمکی"),metricsCard(fa(rows.filter(v=>v.health?.tcp_ok===true).length),"TCP با شاهد معتبر"));
    if(r.page==="monitor")renderInventoryMonitor(rows);
    if(r.page==="engines")$("engine-catalog").replaceChildren(...Object.entries(engineNames).map(([engine,name])=>{const card=routeLink("","#engine/"+engine,"panel engine-card");const found=rows.filter(v=>v.engine===engine);card.append(el("h3",name),el("span",fa(found.length)+" نصب شناسایی‌شده","pill"),el("p",engine==="paqet"?"تنظیمات، لاگ، کنترل و آزمون سازگار با نصب موجود":engine.startsWith("donino-")?"مسیر اختصاصی Donino با پایش و آزمون امضاشده":"تشخیص، تنظیمات خواندنی، journal و کنترل اختیاری","muted"));return card;}));
    if(r.page==="resilience")renderResilience();
    if(r.page==="path")renderPathPage(r.id);
    refreshWorkspaceV2();
    if(focus)workspacePages.get(r.page)?.focus({preventScroll:true});
  }finally{workspaceBuilding=false;}
}
function renderDiagnostics(row){
  const h=row.health,box=$("service-diagnostics");box.replaceChildren();
  if(row.config_error)box.append(el("p",row.config_error,"notice"));
  if(!h)return;
  if(h.verification==="diagnostics-only")box.append(el("p","این نصب فقط فوروارد دارد؛ بررسی پورت و مقصد انجام شده، اما مسیر TCP/UDP با پاسخ امضاشده تأیید نشده است. تنظیمات موجود تغییر نکرده‌اند.","notice"));
  if(h.config_match===false)box.append(el("p","نوع رمزنگاری KCP با طرف مقابل یکسان نیست؛ پیش از هر تغییر، تنظیمات دو سمت را بررسی کن.","notice"));
  for(const listener of h.local_listeners||[])box.append(el("p",listener.listen+" → "+listener.target+" · "+(listener.tcp_accepting?"ورودی TCP پاسخ داد":"ورودی TCP پاسخ نداد"),"field-help"));
  for(const target of h.origin_targets||[])box.append(el("p",target.target+" · "+(target.reachable?"مقصد روی خارج در دسترس":"مقصد روی خارج در دسترس نیست"),"field-help"));
}
function renderInventoryMonitor(rows){
  const matrix=$("inventory-monitor");matrix.replaceChildren(...rows.map(row=>{const card=el("article",undefined,"monitor-service"),head=routeLink(row.unit,"#service/"+row.id+"/health");card.append(head,el("span",row.active?"فرآیند روشن":"فرآیند خاموش","badge"),el("p",healthText(row.health),"muted"),el("p",row.health?"آخرین آزمون: "+new Date(row.health.time*1000).toLocaleTimeString("fa-IR"):"آزمون مسیر انجام نشده یا قدیمی است","field-help"));return card;}));
  if(!rows.length)matrix.append(el("p","فهرست سرویس‌های موجود هنوز دریافت نشده است.","muted"));
  if(!state?.paths?.length)chart(rows.filter(v=>v.history?.length).map(v=>({id:v.unit,history:v.history.map(h=>({time:h.time,ok:h.tcp_ok===true,latency:h.tcp_latency_ms??null}))})));
}
function renderResilience(){
  const data=state?.paths?.find(p=>p.id==="donino-continuum")?.continuum;
  $("resilience-metrics").replaceChildren(...(data?[[data.connected_lanes,"کانال متصل"],[data.recovering_sessions,"نشست در حال بازیابی"],[data.recoveries,"بازیابی موفق"],[data.endpoint_changes??0,"تغییر ورودی"],[bytes(data.pending_bytes),"بافر منتظر ACK"],[data.recovery_seconds+" s","مهلت بازیابی"]]:[["—","Continuum هنوز فعال نیست"]]).map(([value,label])=>metricsCard(typeof value==="number"?fa(value):value,label)));
  $("resilience-preset").hidden=state?.role==="foreign";
}
function renderPathPage(id){
  const path=state?.paths?.find(p=>p.id===id),box=$("path-detail");box.replaceChildren();if(!path){box.append(el("p","این مسیر هنوز در نصب مدیریت‌شده فعال نشده است.","muted"));return;}
  box.append(el("h2",path.id),el("p",path.healthy?"آزمون تازهٔ مسیر موفق است":"شاهد سلامت مسیر موجود نیست یا آزمون ناموفق بوده است","notice"),metricsCard(path.latency_ms===null?"—":path.latency_ms+" ms","تأخیر آزمون"),el("p",path.transport,"field-help"));
  const row=detectedState?.services?.find(r=>r.unit==="donino-link-"+id+".service");if(row)box.append(routeLink("لاگ زندهٔ موتور","#service/"+row.id+"/logs"));
  if(state?.role!=="foreign")for(const [op,label] of [["prefer","ترجیح این مسیر"],["drain","تخلیه"],["enable","فعال"],["disable","غیرفعال برای اتصال جدید"]]){const button=el("button",label);button.type="button";button.onclick=()=>action(id,op);box.append(button);}
  if(path.continuum)box.append(routeLink("جزئیات بازیابی نشست","#resilience"));
}
window.navigateWorkspace=navigateWorkspace;window.workspaceRefresh=workspaceRefresh;
window.serviceLogsVisible=()=>workspaceRoute.page==="service"&&workspaceRoute.tab==="logs";
window.serviceHealthVisible=()=>workspaceRoute.page==="service"&&workspaceRoute.tab==="health";
setupWorkspace();
setupWorkspaceV2();
document.addEventListener("click",event=>{
  const link=event.target.closest("a[href^='#']");if(!link||link.classList.contains("skip-link")||link.hash==="#main-content")return;
  if($("dashboard").hidden)return;event.preventDefault();navigateWorkspace(link.hash);
});
window.addEventListener("popstate",()=>workspaceRefresh());window.addEventListener("hashchange",()=>workspaceRefresh());
workspaceRefresh();

// Workspace 02: local assets, real observations, no external UI dependencies.
function v2Icon(name){const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.classList.add('icon');svg.setAttribute('aria-hidden','true');const use=document.createElementNS(svg.namespaceURI,'use');use.setAttribute('href','#i-'+name);svg.append(use);return svg;}
function v2Panel(title,description,id){const card=el('article',undefined,'panel v2-card');card.append(surfaceHeading(title,description));if(id){const body=el('div');body.id=id;card.append(body);}return card;}
function v2Status(text,good=false){return el('span',text,'v2-status'+(good?' is-good':''));}
function v2Action(title,description,hash,icon='arrow'){
  const card=routeLink('',hash,'v2-action');const mark=el('span',undefined,'v2-icon-tile');mark.append(v2Icon(icon));const body=el('span');body.append(el('strong',title),el('small',description));card.append(mark,body,v2Icon('arrow'));return card;
}
function setupWorkspaceV2(){
  pageNames.overview='نمای کلی شبکه';pageNames.features='مرکز قابلیت‌ها';pageNames.datagrams='ارتباط UDP';pageNames.settings='تنظیمات و منابع';
  document.documentElement.classList.add('workspace-v2');
  const nav=$('sidebar').querySelector('nav');
  nav.append(makeNav('مرکز قابلیت‌ها','#features','nav-features'),makeNav('ارتباط UDP','#datagrams','nav-datagrams'));
  const groups=[['فضای کار',['overview','features','monitor','events']],['شبکه و ارتباط',['paths','datagrams','resilience','setup','pairing']],['زیرساخت',['detected-panel','paqet-manager','engines','foreign-node','targets']],['مدیریت',['settings','guide']]];
  for(const [label,ids] of groups){const group=el('div',undefined,'v2-nav-group');group.append(el('p',label,'v2-nav-label'));for(const id of ids){const a=[...nav.querySelectorAll('a')].find(a=>a.hash==='#'+id);if(!a)continue;const icon={overview:'grid',features:'grid',monitor:'pulse',events:'clock',paths:'route',datagrams:'route',resilience:'pulse',setup:'server',pairing:'route',engines:'grid',settings:'theme',guide:'info'}[id]||'server';a.querySelectorAll('svg,.nav-glyph').forEach(n=>n.remove());a.prepend(v2Icon(icon));group.append(a);}nav.append(group);}
  $('sidebar').querySelector('.sidebar-label').remove();
  const environment=el('div',undefined,'v2-environment');environment.append(v2Icon('server'));const env=el('div');env.append(el('strong','فضای مدیریت'),el('code','LOCAL NODE'));env.id='v2-environment';environment.append(env,el('span','01','v2-env-count'));nav.before(environment);
  const search=el('button',undefined,'v2-search-button');search.id='v2-search-open';search.type='button';search.setAttribute('aria-label','جست‌وجو در فضای کار');search.append(v2Icon('grid'),el('span','جست‌وجو در فضای کار'),el('kbd','⌘ K'));document.querySelector('header').append(search);search.onclick=openV2Search;
  const overview=workspacePages.get('overview'),headline=el('div',undefined,'v2-page-intro');
  const greeting=el('div');greeting.append(el('p','NETWORK WORKSPACE / 02','v2-eyebrow'),el('h2','ارتباطت را با اطمینان مدیریت کن.'),el('p','از سلامت دو سرور تا کوچک‌ترین جریان؛ همه در یک نمای منظم.','muted'));
  const create=routeLink('ساخت ارتباط جدید','#setup','v2-primary-link');create.id='v2-create';create.prepend(v2Icon('route'));headline.append(greeting,create);overview.prepend(headline);
  const kpis=overview.querySelector('.kpis');headline.after(kpis);
  const topology=$('overview');topology.classList.add('v2-topology');
  const grid=el('div',undefined,'v2-overview-grid'),quality=v2Panel('کیفیت ارتباط','رفت‌وبرگشت آزمون‌های واقعی مسیر','v2-quality'),nodes=v2Panel('سلامت زیرساخت','آخرین مشاهدهٔ منابع دو سرور','v2-nodes');
  quality.querySelector('.section-heading').append(routeLink('پایش کامل ←','#monitor'));nodes.querySelector('.section-heading').append(v2Status('LIVE',true));grid.append(quality,nodes);topology.after(grid);
  const operations=el('div',undefined,'v2-overview-grid');const routes=v2Panel('مسیرهای ارتباط','اولویت، وضعیت و تأخیر هر مسیر','v2-routes');routes.querySelector('.section-heading').append(routeLink('همهٔ مسیرها ←','#paths'));
  const activity=v2Panel('آخرین فعالیت‌ها','تغییرات و رویدادهای ثبت‌شده','v2-activity');activity.querySelector('.section-heading').append(routeLink('تاریخچه ←','#events'));operations.append(routes,activity);grid.after(operations);
  const shortcuts=el('div',undefined,'v2-shortcuts');shortcuts.append(v2Action('جفت‌سازی سرورها','یک کانال مدیریت امن برای دو سرور','#pairing','server'),v2Action('سرویس‌های موجود','تشخیص، لاگ و مدیریت نصب‌های فعلی','#detected-panel','grid'),v2Action('منابع و ظرفیت','کنترل اتصال‌ها و فشار حافظه','#settings','pulse'));operations.after(shortcuts);
  const features=pageSurface('features');features.append(surfaceHeading('هر قابلیت، در جای خودش','مسیر ساخت، مشاهده و مدیریت هر بخش را از اینجا پیدا کن.'));const catalog=el('div');catalog.id='v2-feature-catalog';features.append(catalog);
  const datagrams=pageSurface('datagrams');datagrams.append(surfaceHeading('ارتباط UDP','ورودی مناسب WireGuard و سرویس‌های دیتاگرام؛ مستقل برای هر کلاینت.'));const udpMetrics=el('div',undefined,'inventory-kpis');udpMetrics.id='v2-udp-metrics';datagrams.append(udpMetrics,v2Panel('سرویس‌های UDP','ترافیک و وضعیت انجمن‌های فعال','v2-udp-services'));
  const contract=v2Panel('رفتار مسیر جایگزین','انتخاب مسیر براساس سلامت حامل‌ها');contract.append(el('p','در مسیر Paqet، دیتاگرام بومی اولویت دارد؛ پس از خرابی، پیام‌های تازه از حامل سالم جایگزین منتقل می‌شوند. سوکت مقصد خارج تا پایان مهلت انجمن حفظ می‌شود. پیام ازدست‌رفته دوباره ارسال نمی‌شود.','muted'),el('p','حداکثر هر پیام ۱۴۰۰ بایت، صف هر انجمن ۳۲ پیام و سقف کلی ۱۲۸ انجمن است. برای WireGuard، MTU برابر ۱۲۸۰ تنظیم کن. مسیر مبتنی بر TCP در شبکهٔ پرافت کیفیت تماس یا بازی را تضمین نمی‌کند.','muted'));const udpCreate=routeLink('تعریف ورودی UDP در فرم ساخت تانل ←','#setup');udpCreate.id='v2-udp-create';datagrams.append(contract,udpCreate);
  setupV2Settings();setupV2Search();setupV2ServiceFilters();
  const paqetEmpty=v2Panel('مدیریت Paqet','این بخش پس از شناسایی یا نصب Paqet آماده می‌شود.');paqetEmpty.id='v2-paqet-empty';paqetEmpty.append(el('p','برای نصب جدید از فرم ساخت تانل استفاده کن؛ اگر نصب مستقلی داری، آن را در سرویس‌های موجود بررسی کن.','muted'),routeLink('بررسی سرویس‌های موجود ←','#detected-panel'));workspacePages.get('paqet-manager').append(paqetEmpty);
  workspacePages.get('detected-panel').prepend(overview.querySelector('.inventory-overview'));
  $('guide').prepend(surfaceHeading('شروع ساده، کنترل دقیق','نصب روی هر دو سرور، جفت‌سازی امن و سپس ساخت ارتباط.'));
  $('setup-services').previousElementSibling.querySelector('strong').textContent='ورودی‌های TCP و UDP';
  const presets=el('div',undefined,'v2-presets');presets.append(el('span','شروع با یک الگو'));
  for(const [name,service,description] of [['VLESS / Xray',{id:'vless',listen:'0.0.0.0:443',target:'127.0.0.1:8443',protocol:'tcp'},'سرویس Xray موجود روی خارج باید در loopback پورت 8443 اجرا شود.'],['WireGuard',{id:'wireguard',listen:'0.0.0.0:51820',target:'127.0.0.1:51821',protocol:'udp'},'WireGuard موجود باید روی پورت 51821 خارج گوش کند؛ MTU کلاینت را 1280 قرار بده.'],['وب‌سرویس',{id:'web',listen:'0.0.0.0:8080',target:'127.0.0.1:8080',protocol:'tcp'},'مقصد باید پیش از نصب روی سرور خارج در دسترس باشد.']]){const button=el('button',name);button.type='button';button.onclick=()=>{$('setup-services').replaceChildren();addServiceRow(service);$('paqet-native-only').checked=false;syncPaqetInputs();invalidatePlan();$('v2-preset-note').textContent=description;};presets.append(button);}
  const note=el('p','الگو فرم را آماده می‌کند. برای حساب‌ها و اشتراک‌های VPN، پنل را در استودیوی شبکه متصل کن.','field-help');note.id='v2-preset-note';$('setup-services').before(presets,note);
}
function setupV2Settings(){
  const page=workspacePages.get('settings');page.replaceChildren(surfaceHeading('تنظیمات و منابع','تغییرات ظرفیت و پایش ذخیره می‌شوند و بدون قطع اتصال‌های جاری اعمال می‌شوند.'));
  const layout=el('div',undefined,'v2-settings-layout'),form=el('form',undefined,'panel v2-settings-form');form.id='v2-policy-form';
  const capacity=el('fieldset');capacity.append(el('legend','ظرفیت و محافظت از منابع'),el('p','با رسیدن به سقف، فقط اتصال‌های تازه رد می‌شوند. کاهش سقف، اتصال جاری را نمی‌بندد.','muted'));
  const preset=el('button','پروفایل سبک · سرور ۱ گیگابایتی');preset.id='v2-light-preset';preset.type='button';preset.onclick=()=>{for(const [key,value] of Object.entries({max_connections:512,max_udp_associations:128,memory_reserve_mb:128,probe_interval:3,probe_timeout:2}))form.querySelector('[name='+key+']').value=value;form.dataset.dirty='true';$('v2-settings-result').textContent='پروفایل در فرم آماده است؛ برای اعمال، تنظیمات را ذخیره کن.';};capacity.append(preset);
  const monitoring=el('fieldset');monitoring.append(el('legend','پایش و مهلت‌ها'),el('p','آزمون سریع‌تر، ترافیک و مصرف پردازندهٔ بیشتری دارد. مهلت‌ها را با تأخیر شبکه هماهنگ کن.','muted'));
  const fields=[['max_connections','سقف اتصال TCP',2048,1,100000,1,'capacity'],['max_udp_associations','سقف انجمن UDP',128,1,128,1,'capacity'],['memory_reserve_mb','حافظهٔ آزاد رزرو (MiB)',64,16,4096,1,'capacity'],['udp_idle_timeout','بیکاری UDP (ثانیه)',120,10,600,1,'monitoring'],['probe_interval','فاصلهٔ آزمون (ثانیه)',3,.1,300,.1,'monitoring'],['probe_timeout','مهلت آزمون (ثانیه)',2,.05,60,.05,'monitoring'],['failures','شکست متوالی تا خروج مسیر',3,1,50,1,'monitoring'],['recoveries','موفقیت متوالی تا بازگشت',2,1,50,1,'monitoring'],['connect_timeout','مهلت اتصال (ثانیه)',2,.05,60,.05,'monitoring'],['idle_timeout','بیکاری TCP (ثانیه)',300,1,86400,1,'monitoring']];
  for(const [name,label,value,min,max,step,group] of fields){const row=el('label',label),input=el('input');input.type='number';input.name=name;input.value=value;input.min=min;input.max=max;input.step=step;input.required=true;input.dir='ltr';row.append(input);(group==='capacity'?capacity:monitoring).append(row);}
  const submit=el('button','ذخیره و اعمال تنظیمات','primary');submit.type='submit';submit.id='v2-settings-save';const result=el('p','','v2-form-result');result.id='v2-settings-result';result.setAttribute('role','status');form.append(capacity,monitoring,submit,result);form.oninput=()=>form.dataset.dirty='true';
  form.onsubmit=async event=>{event.preventDefault();if(submit.disabled)return;const policy=Object.fromEntries(fields.map(([name])=>[name,Number(form.elements[name].value)]));submit.disabled=true;result.textContent='در حال ذخیره…';try{const response=await api('/api/settings',{policy});if(state)state.policy=response.policy;form.dataset.dirty='false';result.textContent='تنظیمات ذخیره شد و روی اتصال‌های تازه اعمال می‌شود.';toast('تنظیمات منابع به‌روز شد.');}catch(error){result.textContent=error.message;}finally{submit.disabled=false;}};
  const side=el('div',undefined,'v2-settings-side'),appearance=v2Panel('ظاهر فضای کار','انتخاب تم در همین مرورگر حفظ می‌شود.');const themes=el('div',undefined,'v2-theme-options');for(const [label,value] of [['روشن','light'],['تیره','dark']]){const button=el('button',label,'v2-theme-'+value);button.type='button';button.dataset.themeOption=value;button.onclick=()=>{setTheme(value);refreshWorkspaceV2();};themes.append(button);}appearance.append(themes);
  const security=v2Panel('امنیت و دسترسی','ارتباط مدیریتی دو سرور با HTTPS پین‌شده');const connection=el('div');connection.id='v2-security-info';security.append(connection,el('p','تغییر پورت پنل، گواهی و رمز مدیر از ترمینال سرور انجام می‌شود. کد جفت‌سازی را فقط به پنل ایران مورد اعتماد بده.','muted'));
  const output=v2Panel('گزارش قابل دانلود','برای عیب‌یابی و مقایسهٔ وضعیت');output.append(routeLink('دریافت گزارش JSON ←','/api/export'),el('p','گزارش شامل وضعیت، آزمون‌ها و رویدادهاست. رمز و کلیدهای تنظیمات پنهان می‌شوند.','muted'));side.append(appearance,security,output);layout.append(form,side);page.append(layout);
}
function setupV2Search(){
  const dialog=el('dialog',undefined,'v2-command');dialog.id='v2-command';dialog.setAttribute('aria-label','جست‌وجو در فضای کار');const head=el('div',undefined,'v2-command-head'),input=el('input'),close=el('button','بستن');input.id='v2-command-input';input.placeholder='صفحه، قابلیت یا نام سرویس…';input.setAttribute('aria-label','جست‌وجوی صفحه و سرویس');close.type='button';close.onclick=()=>dialog.close();head.append(input,close);const results=el('div');results.id='v2-command-results';dialog.append(head,results,el('p','Enter برای انتخاب · Escape برای بستن','v2-command-hint'));document.body.append(dialog);
  input.oninput=renderV2Search;input.onkeydown=event=>{if(event.key==='ArrowDown'){event.preventDefault();results.querySelector('a')?.focus();}if(event.key==='Enter'){event.preventDefault();results.querySelector('a')?.click();}};
  dialog.addEventListener('click',event=>{if(event.target.closest('a'))dialog.close();});dialog.addEventListener('close',()=>{$('v2-search-open').focus({preventScroll:true});input.value='';});
  document.addEventListener('keydown',event=>{if((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==='k'&&!$('dashboard').hidden){event.preventDefault();if(dialog.open)dialog.close();else openV2Search();}});
}
function openV2Search(){if(!$('v2-command'))return;$('v2-command').showModal();renderV2Search();$('v2-command-input').focus();}
function renderV2Search(){const query=$('v2-command-input').value.trim().toLocaleLowerCase();const foreign=state?.role==='foreign';const choices=Object.entries(pageNames).filter(([id])=>!['service','engine','path'].includes(id)&&!(foreign&&id==='setup')&&!(!foreign&&['foreign-node','targets'].includes(id))).map(([id,label])=>[label,'#'+id,'صفحه']);for(const row of detectedState?.services||[])choices.push([row.unit,'#service/'+row.id+'/overview',engineNames[row.engine]||row.engine]);const matches=choices.filter(([label])=>label.toLocaleLowerCase().includes(query)).slice(0,16);$('v2-command-results').replaceChildren(...matches.map(([label,hash,type])=>{const a=routeLink('',hash,'v2-command-result');a.append(v2Icon('arrow'),el('span',label),el('small',type));a.onclick=()=>navigateWorkspace(hash);return a;}));if(!matches.length)$('v2-command-results').append(el('p','نتیجه‌ای پیدا نشد؛ نام صفحه یا سرویس را امتحان کن.','v2-empty'));}
function refreshWorkspaceV2(){
  if(!$('v2-feature-catalog')||!state)return;
  const foreign=state.role==='foreign',rows=detectedState?.services||[],paths=state.paths||[],activePaths=paths.filter(p=>p.healthy&&p.mode==='enabled');
  const paqet=foreign?state.foreign?.paqet:setupState?.paqet;
  $('v2-paqet-empty').hidden=paqet?.installed===true;
  $('v2-udp-create').href=foreign?'#pairing':'#setup';$('v2-udp-create').textContent=foreign?'ورودی UDP در پنل ایران ساخته می‌شود؛ مدیریت جفت‌سازی ←':'تعریف ورودی UDP در فرم ساخت تانل ←';
  $('v2-policy-form').parentElement.classList.toggle('v2-foreign-settings',foreign);
  $('v2-environment').firstElementChild.textContent=foreign?'گره خارج':'گره ایران';$('v2-environment').lastElementChild.textContent=state.public_address||(foreign?'FOREIGN / EXIT':'IRAN / EDGE');
  $('v2-create').textContent=foreign?'جفت‌سازی با ایران':'ساخت ارتباط جدید';$('v2-create').href=foreign?'#pairing':'#setup';
  if(workspaceRoute.page==='overview')renderV2Overview(rows,paths,activePaths,foreign);
  if(workspaceRoute.page==='features')renderV2Features(rows,paths,foreign);
  if(workspaceRoute.page==='datagrams')renderV2Datagrams();
  const form=$('v2-policy-form');form.hidden=foreign;
  if(workspaceRoute.page==='settings'){
    if(state.policy&&form.dataset.dirty!=='true'){for(const [key,value] of Object.entries(state.policy))if(form.elements[key])form.elements[key].value=value;}
    $('v2-security-info').replaceChildren(v2Status(location.protocol==='https:'?'پنل با HTTPS':'پنل با HTTP',location.protocol==='https:'),el('p',location.protocol==='https:'?'مرورگر و پنل با TLS ارتباط دارند.':'برای شبکهٔ عمومی، TLS یا دسترسی از تونل SSH را فعال کن. HTTP رمز و نشست را در مسیر شبکه رمزنگاری نمی‌کند.','field-help'),el('p','نشست محدود · CSRF فعال · ورود دارای محدودیت تلاش','field-help'));
    document.querySelectorAll('[data-theme-option]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.themeOption===document.documentElement.dataset.theme)));
  }
}
function renderV2Overview(rows,paths,healthy,foreign){
  const quality=$('v2-quality'),plotted=paths.find(p=>p.id===state.selected)||healthy[0],series=(plotted?.history||[]).slice(-60),points=series.filter(h=>h.ok&&Number.isFinite(h.latency));
  quality.replaceChildren();const summary=el('div',undefined,'v2-chart-summary');summary.append(el('strong',points.length?fa(points.at(-1).latency)+' ms':'—'),el('span',points.length?'آخرین آزمون ثبت‌شده':'پس از ساخت مسیر، نمودار نمایش داده می‌شود.','muted'));quality.append(summary);
  if(points.length){const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 600 130');svg.setAttribute('role','img');svg.setAttribute('aria-label','تأخیر آزمون مسیر بر حسب میلی‌ثانیه');const max=Math.max(20,...points.map(p=>p.latency))*1.2;for(const y of [20,60,100]){const line=document.createElementNS(svg.namespaceURI,'line');for(const [key,value] of Object.entries({x1:0,x2:600,y1:y,y2:y}))line.setAttribute(key,value);line.classList.add('v2-chart-grid');svg.append(line);}let segment=[];const draw=()=>{if(!segment.length)return;const line=document.createElementNS(svg.namespaceURI,'polyline');line.setAttribute('points',segment.join(' '));line.classList.add('v2-chart-line');svg.append(line);segment=[];};series.forEach((point,i)=>{if(!point.ok||!Number.isFinite(point.latency)){draw();return;}segment.push(`${i*600/Math.max(1,series.length-1)},${115-point.latency/max*100}`);});draw();quality.append(svg);}else{const empty=el('div',undefined,'v2-chart-empty');empty.append(v2Icon('pulse'),el('p','هنوز دادهٔ کافی برای نمودار نداریم.'));quality.append(empty);}
  const legend=el('div',undefined,'v2-chart-legend');legend.append(el('span','● '+(plotted?.id||'آزمون امضاشده')),el('span',fa(points.length)+' مشاهده'));quality.append(legend);
  const remote=paths.find(p=>p.healthy&&p.remote?.memory_total)?.remote;const nodes=foreign?[['خارج',state.host,state.public_address]]:[['ایران',state.host,state.public_address],['خارج',remote,setupState?.profiles?.[0]?.host]];
  $('v2-nodes').replaceChildren(...nodes.map(([name,host,address])=>{const card=el('div',undefined,'v2-node');const top=el('div',undefined,'v2-node-top');top.append(v2Icon('server'),el('strong','سرور '+name),v2Status(host?'در دسترس':'بدون شاهد تازه',!!host));card.append(top,el('code',address||'آدرس ثبت نشده'));if(host){const value=host.memory_total?host.memory_used/host.memory_total*100:null;const details=el('div',undefined,'v2-node-details');details.append(el('span','حافظه'),el('b',value===null?'—':fa(value)+'٪'));card.append(details);if(value!==null){const meter=el('meter');meter.min=0;meter.max=100;meter.value=value;meter.setAttribute('aria-label','مصرف حافظهٔ سرور '+name);card.append(meter);}card.append(el('small','بار پردازنده: '+(Number.isFinite(host.load?.[0])?fa(host.load[0]):'—')+' · '+(host.memory_total?bytes(host.memory_total):'—')));}else card.append(el('p','پس از ارتباط و آزمون موفق، منابع خارج اینجا نمایش داده می‌شود.','muted'));return card;}));
  $('v2-routes').replaceChildren(...paths.slice(0,5).map(path=>{const row=routeLink('','#path/'+path.id,'v2-route-row');row.append(v2Icon('route'),el('strong',path.id),v2Status(path.healthy?'سالم':'نیازمند بررسی',path.healthy),el('code',Number.isFinite(path.latency_ms)?fa(path.latency_ms)+' ms':'—'));return row;}));
  if(!paths.length){const empty=el('div',undefined,'v2-empty');empty.append(v2Icon('route'),el('h3','ارتباط جدیدت از اینجا شروع می‌شود'),el('p',foreign?'از صفحهٔ جفت‌سازی یک کد بساز و در پنل ایران وارد کن.':'خارج را جفت کن، ورودی و مقصد را تعریف کن، سپس نقشهٔ نصب را بررسی کن.','muted'),routeLink(foreign?'ساخت کد جفت‌سازی ←':'شروع راه‌اندازی ←',foreign?'#pairing':'#setup'));$('v2-routes').append(empty);}
  $('v2-activity').replaceChildren(...(state.events||[]).slice(0,4).map(event=>{const row=el('div',undefined,'v2-activity-row');row.append(el('span',undefined,'v2-activity-dot'),el('div'));row.lastChild.append(el('strong',eventNames[event.kind]||event.kind),el('p',eventDescription(event),'muted'));row.append(el('time',new Date(event.time*1000).toLocaleTimeString('fa-IR',{hour:'2-digit',minute:'2-digit'})));return row;}));if(!state.events?.length)$('v2-activity').append(el('p','رویدادهای مدیریت از اینجا قابل پیگیری‌اند.','v2-empty'));
}
function renderV2Features(rows,paths,foreign){
  const groups=[['ارتباط و انتقال','ساخت و کنترل مسیرهای داده',[
    ['ساخت تانل','تعریف ورودی TCP/UDP، پیش‌نمایش پورت‌ها و نصب هماهنگ دو سرور.',foreign?'#pairing':'#setup','route',paths.length?'پیکربندی شده':'آمادهٔ راه‌اندازی',paths.length>0],
    ['انتخاب مسیر','اولویت ثابت، ترجیح دستی، تخلیه و انتخاب تطبیقی برای اتصال‌های تازه.','#paths','route',fa(paths.length)+' مسیر',paths.length>0],
    ['UDP و WireGuard','انجمن‌های محدود، Paqet بومی و انتقال پیام‌های تازه از مسیر جایگزین.','#datagrams','pulse',state.udp?.length?'فعال':'نیازمند تعریف ورودی',!!state.udp?.length],
    ['بازیابی Continuum','بازیابی محدود نشست TCP با حفظ مقصد و ورودی WSS جایگزین.','#resilience','refresh',paths.some(p=>p.id==='donino-continuum')?'پیکربندی شده':'آزمایشی',paths.some(p=>p.id==='donino-continuum')]]],
  ['مدیریت زیرساخت','کنترل دو گره و نصب‌های فعلی',[
    ['جفت‌سازی امن','اعتماد به گواهی، token اختصاصی و آزمون واقعی کانال مدیریت.','#pairing','server',foreign?(state.foreign?.paired?.some(p=>!p.revoked)?'جفت‌شده':'منتظر ایران'):(setupState?.profiles?.length?'اتصال ثبت‌شده':'جفت نشده'),foreign?!!state.foreign?.paired?.some(p=>!p.revoked):!!setupState?.profiles?.length],
    ['سرویس‌های موجود','کشف سرویس، کنترل با اجازهٔ مدیر، سلامت و journal مستقل هر نصب.','#detected-panel','grid',fa(rows.length)+' سرویس',rows.length>0],
    ['مدیریت Paqet','KCP، رمزنگاری، فوروارد، SOCKS5، آزمون و تنظیمات شبکه.','#paqet-manager','route',rows.some(r=>r.engine==='paqet')?'شناسایی شده':'نصب نشده',rows.some(r=>r.engine==='paqet')],
    ['کتابخانهٔ موتورها','سازگاری و امکانات هر موتور؛ Xray و WireGuard موجود قابل اتصال‌اند.','#engines','grid','مشاهدهٔ سازگاری',false]]],
  ['مشاهده و نگهداری','تصمیم‌گیری براساس دادهٔ تازه',[
    ['مانیتورینگ','تأخیر، منابع دو سرور و تفکیک سلامت فرآیند از سلامت مسیر.','#monitor','pulse','پایش زنده',true],
    ['کنترل منابع','سقف اتصال، ذخیرهٔ حافظه و مهلت‌ها، با ذخیرهٔ پایدار تنظیمات.','#settings','theme','قابل تنظیم',!foreign],
    ['رویدادهای مدیریت','ورودها، تغییرات مسیر و مراحل نصب، همراه زمان ثبت.','#events','clock',fa(state.events?.length||0)+' رویداد',true],
    ['راهنمای راه‌اندازی','مسیر نصب، جفت‌سازی و عیب‌یابی برای آماده‌سازی تست سرورها.','#guide','info','راهنمای گام‌به‌گام',false]]]];
  $('v2-feature-catalog').replaceChildren(...groups.map(([title,description,features])=>{const section=el('section',undefined,'v2-feature-group');section.append(surfaceHeading(title,description));const grid=el('div',undefined,'v2-feature-grid');for(const [name,desc,hash,icon,status,good] of features){const card=routeLink('',hash,'panel v2-feature');const head=el('div',undefined,'v2-feature-head');const mark=el('span',undefined,'v2-icon-tile');mark.append(v2Icon(icon));head.append(mark,v2Status(status,good));card.append(head,el('h3',name),el('p',desc,'muted'),el('span','بازکردن بخش ←','v2-feature-open'));grid.append(card);}section.append(grid);return section;}));
}
function renderV2Datagrams(){const rows=state.udp||[];const totals=rows.reduce((a,row)=>{for(const key of ['active','dropped','bytes_up','bytes_down'])a[key]+=row[key]||0;return a;},{active:0,dropped:0,bytes_up:0,bytes_down:0});$('v2-udp-metrics').replaceChildren(metricsCard(fa(totals.active),'انجمن فعال'),metricsCard(bytes(totals.bytes_up),'ارسال UDP'),metricsCard(bytes(totals.bytes_down),'دریافت UDP'),metricsCard(fa(totals.dropped),'پیام حذف‌شده'));
  $('v2-udp-services').replaceChildren(...rows.map(row=>{const card=el('div',undefined,'v2-udp-row');card.append(el('strong',row.service),v2Status(fa(row.active)+' انجمن',row.active>0),el('code',row.selected||'مقصد محلی'),el('span','↑ '+bytes(row.bytes_up)+' · ↓ '+bytes(row.bytes_down)));return card;}));if(!rows.length)$('v2-udp-services').append(el('p','هنوز ورودی UDP تعریف نشده است. در فرم ساخت تانل، نوع سرویس را UDP انتخاب کن یا الگوی WireGuard را باز کن.','v2-empty'));}

function setupV2ServiceFilters(){
 const bar=el('div',undefined,'v2-service-filters'),input=el('input'),status=el('select'),engine=el('select');
 input.id='v2-service-search';input.placeholder='جست‌وجوی نام سرویس یا موتور…';input.setAttribute('aria-label','جست‌وجوی سرویس‌ها');
 status.id='v2-service-state';status.setAttribute('aria-label','وضعیت فرآیند');for(const [value,label] of [['all','همهٔ وضعیت‌ها'],['true','در حال اجرا'],['false','خاموش']]){const option=el('option',label);option.value=value;status.append(option);}
 engine.id='v2-service-engine';engine.setAttribute('aria-label','فیلتر موتور');const all=el('option','همهٔ موتورها');all.value='all';engine.append(all);for(const [value,label] of Object.entries(engineNames)){const option=el('option',label);option.value=value;engine.append(option);}
 for(const field of [input,status,engine])field.addEventListener('input',filterV2Services);bar.append(input,engine,status);$('detected-list').before(bar);const empty=el('p','سرویسی با این فیلتر پیدا نشد.','v2-empty');empty.id='v2-service-empty';empty.hidden=true;$('detected-list').after(empty);
}
function filterV2Services(){if(!$('v2-service-search'))return;const query=$('v2-service-search').value.trim().toLowerCase(),engine=$('v2-service-engine').value,status=$('v2-service-state').value;let shown=0;for(const card of $('detected-list').children){card.hidden=!(card.textContent.toLowerCase().includes(query)&&(engine==='all'||card.dataset.engine===engine)&&(status==='all'||card.dataset.active===status));if(!card.hidden)shown++;}$('v2-service-empty').hidden=shown>0;}
window.filterV2Services=filterV2Services;
