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
document.addEventListener("click",event=>{
  const link=event.target.closest("a[href^='#']");if(!link||link.classList.contains("skip-link")||link.hash==="#main-content")return;
  if($("dashboard").hidden)return;event.preventDefault();navigateWorkspace(link.hash);
});
window.addEventListener("popstate",()=>workspaceRefresh());window.addEventListener("hashchange",()=>workspaceRefresh());
workspaceRefresh();
