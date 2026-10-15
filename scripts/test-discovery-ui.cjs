'use strict';
// Real browsers and APIs, before any Donino-managed carrier is installed.
const fs=require('node:fs');
const {chromium}=require('playwright');
async function clickAction(page,action){
 const response=page.waitForResponse(r=>r.url().endsWith('/imported-action')&&r.request().postDataJSON()?.action===action);
 await page.locator('#detected-'+(action==='edit'?'save':action)).click();
 const reply=await response;const result=await reply.json();
 if(!reply.ok())throw Error(action+' rejected: '+JSON.stringify(result));
 // A response is received before the follow-up inventory refresh is finished.
 await page.waitForFunction(()=>!document.querySelector('#detected-test').disabled);
 return result;
}
async function signedHealth(page){
 await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/health'));
 // An active systemd unit may still be reconnecting after an explicit restart.
 // Repeat only the read-only probe; never restart or edit to make it pass.
 let last;
 for(let attempt=0;attempt<12;attempt++){
  last=await clickAction(page,'test');
  if(last.tcp_ok===true&&last.udp_ok===true){
   await page.waitForFunction(()=>document.querySelector('#detected-result').textContent.includes('UDP: true'));
   return;
  }
  await page.waitForTimeout(1000);
 }
 throw Error('signed round trips did not recover: '+JSON.stringify(last));
}
async function main(){
 const browser=await chromium.launch({headless:true,chromiumSandbox:true,executablePath:process.env.DONINO_CHROMIUM||'/usr/bin/google-chrome'});
 const errors=[];fs.mkdirSync('ui-role-results',{recursive:true});
 try{
  const pages={};
  for(const role of ['iran','foreign']){
   const page=await browser.newPage({viewport:{width:1440,height:1000}});pages[role]=page;page.on('pageerror',e=>errors.push(e.message));
   await page.goto(process.env[role==='iran'?'DONINO_IRAN_URL':'DONINO_FOREIGN_URL']);
   await page.locator('#password').fill('systemd-fixture-password-123');await page.locator('#login-form button').click();
   await page.evaluate(()=>navigateWorkspace('#detected-panel'));await page.locator('#detected-panel').waitFor({state:'visible'});
   if(await page.locator('#selected').textContent()!=='پایش نصب موجود'||await page.locator('#active').textContent()!=='—'||await page.locator('#traffic').textContent()!=='—')throw Error('bootstrap falsely reports imported tunnel failure or traffic');
   const unit=role==='iran'?'vendor-edge.service':'vendor-exit.service';
   await page.locator('.detected-service').filter({hasText:unit}).getByRole('button').click();
   await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/health'));await page.waitForFunction(()=>document.querySelector('#detected-health').textContent.includes('UDP: رفت‌وبرگشت امضاشده سالم'));
   await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/logs'));await page.waitForFunction(()=>document.querySelector('#detected-logs').textContent.length>40&&!document.querySelector('#detected-logs').textContent.includes('در انتظار'));
   await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/config'));
   const raw=await page.locator('#detected-config').inputValue();if(raw.includes('external-fixture-key-')||raw.includes('external-socks-password')||!raw.includes('[redacted]'))throw Error('secrets leaked into editor');
   if(!await page.locator('#detected-save').isDisabled())throw Error('save needs explicit restart acknowledgement');
   if(await page.locator('#detected-auto-test').isChecked())throw Error('automatic active probing unexpectedly enabled');
   await page.locator('#service-page').screenshot({path:'ui-role-results/existing-'+role+'-desktop.png'});
   await page.setViewportSize({width:390,height:844});
   if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error(role+' mobile overflow');
   await page.locator('#service-page').screenshot({path:'ui-role-results/existing-'+role+'-mobile.png'});
  }
  const page=pages.iran;
  await signedHealth(page);
  // Detaching the existing process must leave it running and gate controls.
  await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/overview'));await page.locator('#detected-manage').click();
  await page.waitForFunction(()=>document.querySelector('#detected-stop').disabled&&document.querySelector('#detected-title').textContent.includes('روشن'));
  await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/overview'));await page.locator('#detected-manage').click();
  await page.waitForFunction(()=>!document.querySelector('#detected-stop').disabled);
  // Edit a local, non-peer setting through the real browser.
  for(const level of ['info','warn']){
   await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/config'));const beforeRevision=await page.locator('#detected-config').getAttribute('data-revision');
   const cfg=JSON.parse(await page.locator('#detected-config').inputValue());cfg.log.level=level;
   await page.locator('#detected-config').fill(JSON.stringify(cfg,null,2));await page.locator('#detected-confirm').check();
   const saved=await clickAction(page,'edit');
   if(saved.revision===beforeRevision)throw Error('save did not commit a fresh revision');
   await page.waitForFunction(revision=>document.querySelector('#detected-config').dataset.revision===revision,saved.revision);
   const raw=await page.locator('#detected-config').inputValue();
   if(raw.includes('external-fixture-key-')||raw.includes('external-socks-password')||!raw.includes('[redacted]'))throw Error('save response leaked secrets');
   await signedHealth(page);
  }
  // Force a new engine event, then observe cursor-based live log updates.
  await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/logs'));const before=await page.locator('#detected-logs').textContent();
  await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/overview'));await clickAction(page,'restart');await page.evaluate(()=>navigateWorkspace('#service/'+detectedSelected+'/logs'));
  await page.waitForFunction(previous=>document.querySelector('#detected-logs').textContent!==previous,before,{timeout:20000});
  // Manage the foreign fixture through Iran's pinned HTTPS channel, with root
  // SSH disabled by the parent fixture. Await both mutation and fresh inventory.
  await page.evaluate(()=>navigateWorkspace('#pairing'));
  await page.locator('#peer-management-check').click();
  await page.waitForFunction(()=>!document.querySelector('#peer-management-check').disabled&&document.querySelector('#peer-management-result').textContent.includes('نسخه‌های دو طرف یکسان است'));
  const remote=page.locator('#peer-management-services details').filter({hasText:'vendor-exit.service'});
  await remote.locator('summary').click();
  await remote.getByRole('button',{name:'دریافت لاگ',exact:true}).click();
  await remote.locator('pre').filter({hasText:/./}).waitFor();
  await page.waitForFunction(()=>!peerManagementBusy);
  const editor=remote.locator('textarea');const foreignConfig=JSON.parse(await editor.inputValue());
  if(!JSON.stringify(foreignConfig).includes('[redacted]'))throw Error('foreign secrets are not redacted');
  const newForeignLevel=foreignConfig.log.level==='warn'?'info':'warn';
  foreignConfig.log.level=newForeignLevel;await editor.fill(JSON.stringify(foreignConfig,null,2));
  await remote.getByRole('checkbox').check();
  const remoteReply=page.waitForResponse(r=>r.url().endsWith('/remote-action')&&r.request().postDataJSON()?.body?.action==='edit');
  await remote.getByRole('button',{name:'ذخیرهٔ تنظیمات روی خارج',exact:true}).click();
  const remoteSaved=await remoteReply;const remoteResult=await remoteSaved.json();
  if(!remoteSaved.ok()||!remoteResult.backup_saved||!remoteResult.restarted)throw Error('foreign edit failed: '+JSON.stringify(remoteResult));
  await page.waitForFunction(()=>!peerManagementBusy);
  const committed=await remote.locator('textarea').inputValue();
  if(JSON.parse(committed).log.level!==newForeignLevel||committed.includes('external-fixture-key-')||committed.includes('external-socks-password'))throw Error('foreign edit was not safely refreshed');
  if(errors.length)throw Error(JSON.stringify(errors));
  console.log(JSON.stringify({existing_roles_detected:true,live_logs:true,fresh_signed_health_visible_both_roles:true,opt_in_detach_keeps_running:true,browser_edit_and_restart:true,two_consecutive_saves_with_current_revision:true,https_foreign_edit_from_iran:true,secret_safe_editor:true,mobile_overflow:false,js_errors:errors}));
 }finally{await browser.close();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
