'use strict';
// Real browsers and APIs, before any Donino-managed carrier is installed.
const fs=require('node:fs');
const {chromium}=require('playwright');
async function main(){
 const browser=await chromium.launch({headless:true,chromiumSandbox:true,executablePath:process.env.DONINO_CHROMIUM||'/usr/bin/google-chrome'});
 const errors=[];fs.mkdirSync('ui-role-results',{recursive:true});
 try{
  const pages={};
  for(const role of ['iran','foreign']){
   const page=await browser.newPage({viewport:{width:1440,height:1000}});pages[role]=page;page.on('pageerror',e=>errors.push(e.message));
   await page.goto(process.env[role==='iran'?'DONINO_IRAN_URL':'DONINO_FOREIGN_URL']);
   await page.locator('#password').fill('systemd-fixture-password-123');await page.locator('#login-form button').click();
   await page.locator('#detected-panel').waitFor({state:'visible'});
   const unit=role==='iran'?'vendor-edge.service':'vendor-exit.service';
   await page.locator('.detected-service').filter({hasText:unit}).getByRole('button').click();
   await page.waitForFunction(()=>document.querySelector('#detected-health').textContent.includes('UDP: رفت‌وبرگشت امضاشده سالم'));
   await page.waitForFunction(()=>document.querySelector('#detected-logs').textContent.length>40&&!document.querySelector('#detected-logs').textContent.includes('در انتظار'));
   await page.locator('#detected-config-details summary').click();
   const raw=await page.locator('#detected-config').inputValue();if(raw.includes('external-fixture-key-')||raw.includes('external-socks-password')||!raw.includes('[redacted]'))throw Error('secrets leaked into editor');
   if(!await page.locator('#detected-save').isDisabled())throw Error('save needs explicit restart acknowledgement');
   if(await page.locator('#detected-auto-test').isChecked())throw Error('automatic active probing unexpectedly enabled');
   await page.locator('#detected-panel').screenshot({path:'ui-role-results/existing-'+role+'-desktop.png'});
   await page.setViewportSize({width:390,height:844});
   if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error(role+' mobile overflow');
   await page.locator('#detected-panel').screenshot({path:'ui-role-results/existing-'+role+'-mobile.png'});
  }
  const page=pages.iran;
  await page.locator('#detected-test').click();
  await page.waitForFunction(()=>document.querySelector('#detected-result').textContent.includes('UDP: true'));
  // Detaching the existing process must leave it running and gate controls.
  await page.locator('#detected-manage').click();
  await page.waitForFunction(()=>document.querySelector('#detected-stop').disabled&&document.querySelector('#detected-title').textContent.includes('روشن'));
  await page.locator('#detected-manage').click();
  await page.waitForFunction(()=>!document.querySelector('#detected-stop').disabled);
  // Edit a local, non-peer setting through the real browser.
  const cfg=JSON.parse(await page.locator('#detected-config').inputValue());cfg.log.level='info';
  await page.locator('#detected-config').fill(JSON.stringify(cfg,null,2));await page.locator('#detected-confirm').check();
  await page.locator('#detected-save').click();
  await page.waitForFunction(()=>document.querySelector('#detected-result').textContent.includes('انجام شد'));
  await page.locator('#detected-test').click();await page.waitForFunction(()=>document.querySelector('#detected-result').textContent.includes('UDP: true'));
  // Force a new engine event, then observe cursor-based live log updates.
  const before=await page.locator('#detected-logs').textContent();
  await page.locator('#detected-restart').click();
  await page.waitForFunction(previous=>document.querySelector('#detected-logs').textContent!==previous,before,{timeout:20000});
  if(errors.length)throw Error(JSON.stringify(errors));
  console.log(JSON.stringify({existing_roles_detected:true,live_logs:true,fresh_signed_health_visible_both_roles:true,opt_in_detach_keeps_running:true,browser_edit_and_restart:true,secret_safe_editor:true,mobile_overflow:false,js_errors:errors}));
 }finally{await browser.close();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
