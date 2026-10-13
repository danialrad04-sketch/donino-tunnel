'use strict';
// Real browser and actual product assets; API fixtures are declared, not VPS evidence.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const http=require('node:http');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'..'),out=path.join(root,'ui-results');
const a='a'.repeat(24),b='b'.repeat(24),c='c'.repeat(24),profile={id:'d'.repeat(32),name:'خارج آزمایشی',host:'198.51.100.20',port:22};
const mutations=[],errors=[];let cursor=0;
function inventory(role){
 const cfg={role:role==='iran'?'client':'server',log:{level:'info'},network:{interface:'eth0',ipv4:{addr:role==='iran'?'192.0.2.10:0':'198.51.100.20:6589',router_mac:'02:00:00:00:00:01'}},transport:{protocol:'kcp',conn:1,kcp:{mode:'normal',block:'twofish',mtu:1350,key:'[redacted]'}}};
 if(role==='iran'){cfg.server={addr:'198.51.100.20:6589'};cfg.forward=[{listen:'0.0.0.0:443',target:'127.0.0.1:443',protocol:'tcp'}];}else cfg.listen={addr:':6589'};
 const health={tcp_ok:null,udp_ok:null,time:Date.now()/1000,revision:'1'.repeat(64),verification:'diagnostics-only',config_match:true,local_listeners:[{listen:'0.0.0.0:443',target:'127.0.0.1:443',tcp_accepting:true}],origin_targets:[{target:'127.0.0.1:443',reachable:true}]};
 return {services:[{id:a,unit:'paqet-game.service',engine:'paqet',role:cfg.role,active:true,state:'active',management_enabled:true,editable:true,config_path:'/etc/paqet/game.yaml',config:cfg,revision:'1'.repeat(64),health,history:[],memory:10000000,restarts:0,capabilities:{category:'tunnel',control:true,edit:true,logs:true,signed_probe:false,protocol:'KCP / raw TCP'}},
  {id:b,unit:'backpack-monitor.service',engine:'backpack',active:true,state:'active',management_enabled:false,editable:false,config:{},health:null,memory:16000000,restarts:0,capabilities:{category:'auxiliary',control:true,edit:false,logs:true}},
  {id:c,unit:'frpc-custom-name-with-a-long-description-for-mobile-layout.service',engine:'frp',active:true,state:'active',management_enabled:false,editable:false,config:{auth:{token:'[redacted]'}},health:null,memory:2000000,restarts:1,capabilities:{category:'tunnel',control:true,edit:false,logs:true}}],checked_at:Date.now()/1000,error:'',mode:'passive'};
}
function paqet(role){const inv=inventory(role);return {installed:true,managed_installation:false,instances:inv.services.filter(r=>r.engine==='paqet')};}
const protocol={connected_lanes:2,recovering_sessions:0,recoveries:3,expired:0,replayed_bytes:16384,pending_bytes:0,recovery_seconds:30,endpoint_changes:2,connect_attempts:6,connect_failures:1};
function status(role,managed){return {role,bootstrap:!managed,time:Date.now()/1000,uptime:300,paused:false,preferred:null,selected:managed?'donino-continuum':null,active:managed?2:null,accepted:2,rejected:0,route_changes:0,routing_strategy:'static',paths:managed?[{id:'donino-continuum',transport:'donino-continuum',mode:'enabled',healthy:true,latency_ms:12,active:2,bytes_up:1024,bytes_down:1024,history:[{time:Date.now()/1000,ok:true,latency:12}],continuum:protocol,observation:'fresh'}]:[],units:[],services:[],targets:{},host:{load:[.1],memory_total:2**30,memory_used:2**28},events:[],foreign:{available:true,agent_port:9444,paired:[],actions:[],inventory:inventory('foreign'),paqet:paqet('foreign')},metrics:null,telemetry_fresh:managed};}
function setup(){return {available:true,busy:false,public_key:'ssh-ed25519 AAAA-public-fixture',profiles:[profile],iran_address:'192.0.2.10',jobs:[],transports:['frp-wss','frp-quic','paqet','donino-continuum'].map(id=>({id,experimental:!id.startsWith('frp')})),inventory:inventory('iran'),paqet:paqet('iran')};}
const server=http.createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,'http://fixture'),role=req.headers.cookie?.includes('fixture_role=foreign')?'foreign':'iran',managed=req.headers.cookie?.includes('fixture_managed=1');
  const json=(body,code=200)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(body));};
  if(url.pathname==='/'){res.writeHead(200,{'Content-Type':'text/html','Set-Cookie':['fixture_role='+ (url.searchParams.get('role')==='foreign'?'foreign':'iran')+'; Path=/','fixture_managed='+(url.searchParams.get('managed')==='1'?'1':'0')+'; Path=/']});return res.end(fs.readFileSync(path.join(root,'donino_link/web/index.html')));}
  if(['/app.js','/workspace.js','/style.css','/Vazirmatn.woff2'].includes(url.pathname)){res.setHeader('Content-Type',url.pathname.endsWith('.js')?'text/javascript':url.pathname.endsWith('.css')?'text/css':'font/woff2');return res.end(fs.readFileSync(path.join(root,'donino_link/web',url.pathname.slice(1))));}
  let raw='';for await(const chunk of req)raw+=chunk;const body=raw?JSON.parse(raw):null;
  if(url.pathname==='/api/session'||url.pathname==='/api/login')return json({csrf:'workspace-fixture'});
  if(url.pathname==='/api/status')return json(status(role,managed));
  if(url.pathname==='/api/provision/state')return json(setup());
  if(url.pathname==='/api/foreign/state')return json(status('foreign',managed).foreign);
  if(url.pathname.endsWith('/imported-action')){
   if(body.action==='logs')return json({ok:true,cursor:'s=fixture;i='+ ++cursor,lines:[{time:String(Date.now()*1000),message:'[live '+cursor+'] Existing vendor service operational'}]});
   if(body.action==='inspect')return json(inventory(role));
   if(body.action==='test')return json(inventory(role).services[0].health);
   mutations.push(body);return json({ok:true});
  }
  if(url.pathname==='/api/logout')return json({ok:true});
  return json({error:'unexpected fixture request '+url.pathname},404);
 }catch(error){res.writeHead(500);res.end(String(error));}
});
async function navigate(page,hash){await page.evaluate(hash=>navigateWorkspace(hash),hash);await page.waitForFunction(()=>document.querySelectorAll('.workspace-page:not([hidden])').length===1);}
async function overflow(page,label){assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,label+' horizontal overflow');}
async function main(){
 fs.mkdirSync(out,{recursive:true});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
 const launch={headless:true,chromiumSandbox:process.env.DONINO_UI_SANDBOX!=='0'};if(process.env.DONINO_CHROMIUM)launch.executablePath=process.env.DONINO_CHROMIUM;
 const browser=await chromium.launch(launch);let checks=0;
 try{
  for(const role of ['iran','foreign'])for(const managed of [false,true]){
   const page=await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'});page.on('pageerror',e=>{errors.push(e.message);console.error('PAGE ERROR:',e.stack);});page.on('console',m=>{if(m.type()==='error')console.error('BROWSER:',m.text());});
   await page.goto(base+'/?role='+role+'&managed='+(managed?'1':'0'));await page.locator('#dashboard').waitFor({state:'visible'});await page.waitForFunction(()=>typeof detectedState!=='undefined'&&detectedState?.services?.length===3);
   const routes=['#overview','#detected-panel','#pairing','#paths','#monitor','#events','#engines','#engine/paqet','#resilience','#settings','#guide',role==='iran'?'#setup':'#foreign-node',...(role==='foreign'?['#targets']:[])];
   for(const theme of ['light','dark'])for(const width of [320,390,768,1440]){
    await page.setViewportSize({width,height:width<1024?844:1000});await page.evaluate(theme=>setTheme(theme),theme);
    for(const route of routes){await navigate(page,route);await overflow(page,role+' '+theme+' '+width+' '+route);checks++;}
    await navigate(page,'#detected-panel');await page.locator('.detected-service').filter({hasText:'paqet-game.service'}).getByRole('button').click();
    assert.equal(await page.locator('.workspace-page:visible').getAttribute('data-page'),'service');
    for(const tab of ['health','config','logs','overview']){
     await navigate(page,'#service/'+a+'/'+tab);await overflow(page,'service '+tab);
     assert.equal(await page.locator('[data-service-tab]:visible').count(),1);
     if(tab==='health'){assert.match(await page.locator('#service-diagnostics').textContent(),/فوروارد/);assert.match(await page.locator('#detected-health').textContent(),/تأیید نشده/);}
     if(tab==='config'){const draft=(await page.locator('#detected-config').inputValue())+'\n';await page.locator('#detected-config').fill(draft);await page.evaluate(()=>workspaceRefresh());assert.equal(await page.locator('#detected-config').inputValue(),draft);assert.ok(draft.includes('[redacted]'));}
     if(tab==='logs'){await page.waitForFunction(()=>document.querySelector('#detected-logs').textContent.includes('[live'));const before=await page.locator('#detected-logs').textContent();await page.locator('#detected-expand-logs').click();await page.waitForFunction(previous=>document.querySelector('#inspector-content').value!==previous,before);await page.locator('#inspector-close').click();}
     checks++;
    }
    await navigate(page,'#service/'+b+'/logs');await page.waitForFunction(()=>document.querySelector('#detected-logs').textContent.includes('[live'));
    await navigate(page,'#service/'+c+'/config');assert.equal(await page.locator('#detected-config').evaluate(n=>n.readOnly),true);assert.equal(await page.locator('#detected-save').isDisabled(),true);
    await navigate(page,'#paqet-manager');assert.ok((await page.locator('#paqet-summary').textContent()).includes('paqet-game.service'));
    if(managed){await navigate(page,'#paths');await page.locator('a[href="#path/donino-continuum"]').click();assert.equal(await page.locator('.workspace-page:visible').getAttribute('data-page'),'path');await navigate(page,'#resilience');assert.match(await page.locator('#resilience-metrics').textContent(),/بازیابی موفق/);}
    if(width===390||width===1440){await page.screenshot({path:path.join(out,'workspace-'+role+'-'+(managed?'managed':'existing')+'-'+theme+'-'+width+'.png')});}
   }
   await navigate(page,'#service/'+a+'/logs');await page.reload();await page.locator('[data-service-tab=logs]').waitFor({state:'visible'});assert.equal(await page.locator('.workspace-page:visible').count(),1);
   await navigate(page,'#events');await page.goBack();assert.ok(page.url().includes('/logs'));await page.goForward();assert.ok(page.url().endsWith('#events'));
   await page.close();
  }
  assert.deepEqual(errors,[]);assert.deepEqual(mutations,[],'navigation caused a service change');
  fs.writeFileSync(path.join(out,'workspace-ui-results.json'),JSON.stringify({scope:'Real Chromium with declared fixture APIs; both roles, existing-only and managed-path states',checks,distinct_pages:true,service_subpages:true,forward_only_health_honest:true,generic_vendor_logs:true,drafts_preserved:true,deep_links_and_history:true,no_service_mutations:true,js_errors:errors},null,2));
  console.log(JSON.stringify({checks,js_errors:errors,no_service_mutations:true}));
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(e=>{console.error(e);server.close();process.exitCode=1;});
