'use strict';
// Actual HTML/CSS/JS in Chromium with declared API fixtures, never a real VPS.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const http=require('node:http');
const {execFileSync}=require('node:child_process');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'..');
const capabilities=JSON.parse(execFileSync('python',['-c','import json;from donino_link.paqet import capabilities;print(json.dumps(capabilities()))'],{cwd:root,encoding:'utf8'}));
const out=path.join(root,'ui-results');fs.mkdirSync(out,{recursive:true});
let logSequence=0,revision=1;
const config={role:'client',log:{level:'warn'},network:{interface:'eth0',ipv4:{addr:'192.0.2.10:0',router_mac:'02:00:00:00:00:01'}},server:{addr:'198.51.100.20:33434'},transport:{protocol:'kcp',conn:2,kcp:{mode:'normal',block:'aes-128-gcm',key:'[redacted]',mtu:1150}},socks5:[{listen:'127.0.0.1:1080',username:'fixture',password:'[redacted]'}]};
const profile={id:'a'.repeat(32),name:'سرور آزمایشی خارج با عنوان بلند برای بررسی چیدمان',host:'198.51.100.20',port:22};
function inventory(role){return {mode:'passive',checked_at:Date.now()/1000,error:'',services:[{id:'b'.repeat(24),unit:role==='foreign'?'vendor-exit.service':'vendor-edge.service',engine:'paqet',role:role==='foreign'?'server':'client',active:true,state:'active',management_enabled:true,editable:true,managed_by_donino:false,config_path:'/root/paqet/config/very-long-folder-name-for-layout/configuration.yaml',revision:String(revision).repeat(64),config:{...config,role:role==='foreign'?'server':'client'},health:{tcp_ok:true,udp_ok:true,time:Date.now()/1000}}, {id:'c'.repeat(24),unit:'vendor-very-long-secondary-tunnel-instance-name.service',engine:'xray',active:true,state:'active',management_enabled:false,editable:false}]};}
function paqet(){return {installed:true,version:'alpha.21',kcp:{mode:'normal',block:'aes-128-gcm'},conn:2,network:config.network,server:config.server,forwards:[{protocol:'tcp',listen:'0.0.0.0:443',target:'127.0.0.1:8443'}],socks5:[{listen:'127.0.0.1:1080',authenticated:true}]};}
function setup(){return {available:true,busy:false,public_key:'ssh-ed25519 AAAA-public-fixture-only',profiles:[profile],iran_address:'192.0.2.10',jobs:[],transports:['frp-wss','frp-quic','paqet','donino-continuum'].map(id=>({id,experimental:id==='donino-continuum'})),paqet_capabilities:capabilities,paqet:paqet(),inventory:inventory('iran')};}
function status(role){return {role,bootstrap:true,time:Date.now()/1000,uptime:300,paused:false,preferred:null,selected:null,active:null,accepted:0,rejected:0,route_changes:0,routing_strategy:'static',paths:[],units:[],targets:{},host:{load:[.15],memory_total:2147483648,memory_used:536870912},events:[{time:Date.now()/1000,kind:'login',detail:{}}],foreign:{available:true,agent_port:9444,paired:[],actions:[],inventory:inventory('foreign'),paqet:paqet()},telemetry_fresh:false};}
const mutations=[];
const server=http.createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,'http://fixture');const role=req.headers.cookie?.includes('fixture_role=foreign')?'foreign':'iran';
  const json=(data,code=200)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(data));};
  if(url.pathname==='/'){
   res.writeHead(200,{'Content-Type':'text/html','Set-Cookie':'fixture_role='+ (url.searchParams.get('role')==='foreign'?'foreign':'iran')+'; Path=/; SameSite=Strict'});
   return res.end(fs.readFileSync(path.join(root,'donino_link/web/index.html')));
  }
  if(['/app.js','/style.css','/Vazirmatn.woff2'].includes(url.pathname)){
   res.setHeader('Content-Type',url.pathname.endsWith('.js')?'text/javascript':url.pathname.endsWith('.css')?'text/css':'font/woff2');return res.end(fs.readFileSync(path.join(root,'donino_link/web',url.pathname.slice(1))));
  }
  let raw='';for await(const chunk of req)raw+=chunk;const body=raw?JSON.parse(raw):null;
  if(url.pathname==='/api/login'){res.setHeader('Set-Cookie','fixture_session=1; Path=/; SameSite=Strict');return json({csrf:'responsive-fixture'});}
  if(url.pathname==='/api/session')return json(req.headers.cookie?.includes('fixture_session=1')?{csrf:'responsive-fixture'}:{error:'login required'},req.headers.cookie?.includes('fixture_session=1')?200:401);
  if(url.pathname==='/api/status')return json(status(role));
  if(url.pathname==='/api/provision/state')return json(setup());
  if(url.pathname==='/api/foreign/state')return json(status('foreign').foreign);
  if(url.pathname.endsWith('/imported-action')){
   if(body.action==='logs')return json({ok:true,cursor:'s=fixture;i='+ ++logSequence,lines:[{time:String(Date.now()*1000),message:'[live '+logSequence+'] Paqet connection active — '+ '0123456789abcdef '.repeat(8)}]});
   if(body.action==='inspect')return json(inventory(role));
   if(body.action==='test')return json({tcp_ok:true,udp_ok:true});
   mutations.push(body);
   if(body.action==='edit'){assert.equal(body.ack_peer_change,true);assert.equal(body.revision,String(revision).repeat(64));revision++;config.log=body.config.log;return setTimeout(()=>json({ok:true,revision:String(revision).repeat(64),config,backup_saved:true,restarted:true}),150);}
   return json({ok:true});
  }
  if(url.pathname==='/api/logout')return json({ok:true});
  return json({error:'unexpected fixture request '+url.pathname},404);
 }catch(error){res.writeHead(500,{'Content-Type':'application/json'});res.end(JSON.stringify({error:error.message}));}
});
async function overflow(page,label){const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);assert.equal(overflow,false,label+' horizontal overflow');}
async function contrast(page){
 const rows=await page.locator('#sidebar nav a:visible').evaluateAll(items=>items.map(n=>{const s=getComputedStyle(n),parent=getComputedStyle(document.querySelector('#sidebar'));return {text:n.textContent.trim(),fg:s.color,bg:s.backgroundColor==='rgba(0, 0, 0, 0)'?parent.backgroundColor:s.backgroundColor};}));
 const luminance=color=>{const rgb=color.match(/[\d.]+/g).slice(0,3).map(Number).map(n=>{const v=n/255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;});return .2126*rgb[0]+.7152*rgb[1]+.0722*rgb[2];};
 for(const row of rows){const a=luminance(row.fg),b=luminance(row.bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);assert.ok(ratio>=4.5,'low menu contrast: '+row.text+' '+ratio);}
 return rows.length;
}
async function main(){
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const url='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,chromiumSandbox:true,executablePath:process.env.DONINO_CHROMIUM||'/usr/bin/google-chrome'});const errors=[],results=[];
 try{
  for(const role of ['iran','foreign'])for(const mobile of [true,false]){
   const context=await browser.newContext({viewport:{width:mobile?390:1440,height:mobile?844:1000},isMobile:mobile,hasTouch:mobile,reducedMotion:'reduce',userAgent:mobile?'Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0'});
   const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
   await page.goto(url+'/?role='+role);await page.locator('#password').fill('responsive-fixture-password');await page.locator('#login-form button').click();await page.locator('#detected-panel').waitFor({state:'visible'});
   for(const theme of ['light','dark']){
    await page.evaluate(theme=>setTheme(theme),theme);
    const widths=mobile?[320,360,390,412,768,844]:[1024,1280,1440,1920];
    for(const width of widths){
     await page.setViewportSize({width,height:mobile&&width===844?390:mobile?844:1000});await overflow(page,role+' '+theme+' '+width);
     if(mobile){
      await page.locator('#menu-toggle').tap();await page.waitForFunction(()=>document.querySelector('#menu-toggle').getAttribute('aria-expanded')==='true');
      assert.equal(await page.locator('#sidebar').getAttribute('aria-modal'),'true');assert.equal(await page.locator('#main-content').evaluate(n=>n.inert),true);
      await contrast(page);const box=await page.locator('#menu-close').boundingBox();assert.ok(box.width>=44&&box.height>=44);
      if(width===390)await page.screenshot({path:path.join(out,'ux-'+role+'-'+theme+'-mobile-menu.png')});
      for(let n=0;n<12;n++){await page.keyboard.press('Tab');assert.equal(await page.evaluate(()=>document.querySelector('#sidebar').contains(document.activeElement)),true,'focus escaped drawer');}
      await page.keyboard.press('Escape');assert.equal(await page.locator('#main-content').evaluate(n=>n.inert),false);assert.equal(await page.evaluate(()=>document.activeElement.id),'menu-toggle');
      await page.locator('#menu-toggle').tap();await page.locator('#nav-backdrop').tap({position:{x:8,y:100}});assert.equal(await page.locator('#menu-toggle').getAttribute('aria-expanded'),'false');
      await page.locator('#menu-toggle').tap();await page.locator('#nav-detected').tap();assert.equal(await page.locator('#menu-toggle').getAttribute('aria-expanded'),'false');
     }else{assert.equal(await page.locator('#sidebar').evaluate(n=>n.inert),false);await contrast(page);}
     results.push({role,theme,width,mode:mobile?'Android touch emulation':'Windows desktop UA',overflow:false,menu_contrast_aa:true});
    }
    await page.setViewportSize({width:mobile?390:1440,height:mobile?844:1000});await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(out,'ux-'+role+'-'+theme+'-'+(mobile?'mobile':'desktop')+'.png')});
    const card=page.locator('.detected-service').filter({hasText:role==='iran'?'vendor-edge.service':'vendor-exit.service'}).getByRole('button');await card.click();await card.focus();
    await page.evaluate(async role=>role==='iran'?await pollSetup():await refresh(),role);assert.equal(await card.evaluate(n=>n===document.activeElement),true,'polling stole service-button focus');
    if(!await page.locator('#detected-config-details').evaluate(n=>n.open))await page.locator('#detected-config-details summary').click();
    const draft=(await page.locator('#detected-config').inputValue())+'\n';await page.locator('#detected-config').fill(draft);await page.evaluate(async role=>role==='iran'?await pollSetup():await refresh(),role);assert.equal(await page.locator('#detected-config').inputValue(),draft,'polling overwrote a draft');
    await overflow(page,'expanded config '+role+' '+theme);await page.locator('#detected-detail').screenshot({path:path.join(out,'ux-'+role+'-'+theme+'-'+(mobile?'mobile':'desktop')+'-workspace.png')});
    await page.locator('#detected-expand-logs').click();await page.locator('#inspector-dialog').waitFor({state:'visible'});const before=await page.locator('#inspector-content').inputValue();
    await page.waitForFunction(previous=>document.querySelector('#inspector-content').value!==previous,before);assert.equal(await page.locator('#inspector-content').evaluate(n=>n.readOnly),true);
    const bounds=await page.locator('#inspector-dialog').boundingBox(),size=page.viewportSize();assert.ok(bounds.x>=0&&bounds.y>=0&&bounds.x+bounds.width<=size.width&&bounds.y+bounds.height<=size.height);
    await overflow(page,'log dialog');await page.screenshot({path:path.join(out,'ux-'+role+'-'+theme+'-'+(mobile?'mobile':'desktop')+'-dialog.png')});
    await page.keyboard.press('Escape');assert.equal(await page.locator('#inspector-dialog').evaluate(n=>n.open),false);assert.equal(await page.locator('#inspector-content').inputValue(),'');
    await page.locator('#detected-expand-config').click();assert.equal(await page.locator('#inspector-content').inputValue(),draft);await page.locator('#inspector-close').click();
    if(role==='iran'){
     if(mobile){await page.locator('#menu-toggle').tap();await page.locator('#nav-setup').tap();}else await page.locator('#nav-setup').click();
     assert.equal(await page.locator('#setup-details').evaluate(n=>n.open),true);await page.locator('#setup-transports input[value="paqet"]').check();if(!await page.locator('#paqet-options').evaluate(n=>n.open))await page.locator('#paqet-options summary').click();
     for(const width of mobile?[320,390,844]:[1024,1440]){await page.setViewportSize({width,height:mobile?844:1000});await overflow(page,'advanced forms '+width);}
     await page.setViewportSize({width:mobile?390:1440,height:mobile?844:1000});await page.locator('#setup-details summary').first().click();
    }
   }
   // A resize from an open touch drawer to desktop must remove inert/scroll lock.
   if(mobile){await page.locator('#menu-toggle').tap();await page.setViewportSize({width:1440,height:1000});await page.waitForFunction(()=>!document.body.classList.contains('drawer-open'));assert.equal(await page.locator('#main-content').evaluate(n=>n.inert),false);assert.equal(await page.locator('#sidebar').evaluate(n=>n.inert),false);}
   await context.close();
  }
  assert.deepEqual(errors,[]);assert.deepEqual(mutations,[],'layout/navigation triggered a service mutation');
  fs.writeFileSync(path.join(out,'responsive-ui-results.json'),JSON.stringify({scope:'Actual UI in Chromium; declared public API fixture, Android touch and Windows desktop UA; no OS/device or VPS certification',results,focus_trap:true,escape_and_backdrop:true,resize_unlocks_content:true,polling_preserves_focus_and_draft:true,live_log_dialog:true,advanced_forms_no_overflow:true,no_service_mutations:true,js_errors:errors},null,2));
  console.log(JSON.stringify({responsive_scenarios:results.length,contrast_aa:true,drawer_keyboard_and_touch:true,live_dialog:true,stable_polling_focus:true,draft_preserved:true,no_service_mutations:true,js_errors:errors}));
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(e=>{console.error(e);server.close();process.exitCode=1;});
