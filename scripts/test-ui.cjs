'use strict';
// Runs against real loopback engines and the actual admin panel.
const {spawn}=require('node:child_process');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('playwright');
async function main(){
  const args=['scripts/test-engines.py','--serve-panel'];
  if(process.env.DONINO_BINARY_DIR)args.push('--binary-dir',process.env.DONINO_BINARY_DIR);
  const child=spawn('python',args,{stdio:['ignore','pipe','inherit']});
  let browser;
  try{
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(Error('panel startup timeout')),120000);
      child.on('exit',code=>{clearTimeout(timer);reject(Error('engine fixture exited '+code));});
      child.stdout.on('data',b=>{if(b.toString().includes('LOCAL INTEGRATION PANEL READY')){clearTimeout(timer);resolve();}});
    });
    browser=await chromium.launch({headless:true,chromiumSandbox:true,executablePath:process.env.DONINO_CHROMIUM||'/usr/bin/google-chrome'});
    const page=await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto('http://127.0.0.1:18090');
    fs.mkdirSync('ui-results',{recursive:true});
    await page.screenshot({path:'ui-results/login.png',fullPage:true});
    await page.locator('#password').fill('integration-only-password-123');
    await page.locator('#login-form button').click();
    await page.locator('#dashboard').waitFor({state:'visible'});
    await page.waitForFunction(()=>document.querySelectorAll('.path-card').length===4);
    await page.locator('#pause').click();
    await page.waitForFunction(()=>document.querySelector('#pause').textContent.includes('ادامه'));
    await page.locator('#pause').click();
    await page.waitForFunction(()=>document.querySelector('#pause').textContent.includes('توقف'));
    const cards=page.locator('.path-card');
    await cards.filter({hasText:'frp-quic'}).locator('select').selectOption('prefer');
    await page.waitForFunction(()=>document.querySelector('#hero-description').textContent.includes('frp-quic'));
    fs.mkdirSync('ui-results',{recursive:true});
    await page.screenshot({path:'ui-results/desktop.png',fullPage:true});
    const desktopOverflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    await page.locator('#theme').click();
    await page.waitForFunction(()=>document.documentElement.dataset.theme==='dark');
    await page.screenshot({path:'ui-results/dark.png',fullPage:true});
    await page.reload();
    await page.locator('#dashboard').waitFor({state:'visible'});
    await page.waitForFunction(()=>document.documentElement.dataset.theme==='dark');
    await page.locator('#theme').click();
    await page.waitForFunction(()=>document.documentElement.dataset.theme==='light');
    await page.locator('#refresh').click();
    // Form interactions use a declared installer API fixture. Actual privileged
    // provisioning is exercised separately by test-provision.py with systemd.
    let fixtureJob=null;const profile={id:'a'.repeat(32),name:'سرور آزمایشی',host:'198.51.100.20',port:22};
    await page.route('**/api/provision/**',async route=>{
      const url=new URL(route.request().url());let result;
      if(url.pathname.endsWith('/state'))result={available:true,busy:!!fixtureJob,public_key:'ssh-ed25519 AAAA fixture-public-key',profiles:[profile],transports:['frp-wss','frp-quic','backpack-wss','paqet','backhaul-wss','browser-wss'].map(id=>({id,experimental:!id.startsWith('frp-')})),jobs:fixtureJob?[fixtureJob]:[]};
      else if(url.pathname.endsWith('/preview')){const body=route.request().postDataJSON();if(body.services[0].target!=='127.0.0.1:8443'||!body.transports.includes('backpack-wss')||!body.experimental)throw Error('incorrect installer request');result={id:'b'.repeat(32),summary:{iran:body.iran,foreign:profile.host,transports:body.transports,services:body.services,firewall:{iran:{tcp:[24443,24445,443],udp:[24444]},foreign:{tcp:[],udp:[]}}}};}
      else if(url.pathname.endsWith('/start')){const body=route.request().postDataJSON();if(!body.confirm_replace)throw Error('unreviewed start');fixtureJob={id:'c'.repeat(32),status:'running',stage:'prepare-foreign',created:Date.now()/1000,events:[{stage:'preflight',status:'done'},{stage:'prepare-foreign',status:'running'}],probes:[]};result=fixtureJob;}
      else result=profile;
      await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(result)});
    });
    await page.locator('#setup-details summary').first().click();
    await page.waitForFunction(()=>document.querySelector('#setup-public-key').value.includes('fixture'));
    await page.locator('#setup-profile').selectOption(profile.id);
    await page.locator('#setup-iran').fill('192.0.2.10');
    await page.locator('#setup-transports input[value="backpack-wss"]').check();
    await page.locator('#setup-experimental').check();
    await page.locator('#setup-preview').click();
    await page.locator('#setup-review').waitFor({state:'visible'});
    if(!await page.locator('#setup-start').isDisabled())throw Error('start must wait for review');
    await page.locator('#setup').screenshot({path:'ui-results/setup.png'});
    await page.locator('#setup-confirm').check();await page.locator('#setup-start').click();
    await page.locator('#setup-job').waitFor({state:'visible'});
    await page.waitForFunction(()=>document.querySelector('#setup-job-status').textContent.includes('در حال'));
    await page.locator('#setup-details summary').first().click();

    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:'ui-results/mobile.png',fullPage:true});
    const mobileOverflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    await page.locator('#mobile-logout').click();await page.locator('#login').waitFor({state:'visible'});
    if(errors.length||desktopOverflow||mobileOverflow)throw Error(JSON.stringify({errors,desktopOverflow,mobileOverflow}));
    console.log(JSON.stringify({login:true,pause_resume:true,prefer:true,mobile_logout:true,dark_light_theme_persists:true,manual_refresh:true,installer_form_fixture:true,review_required:true,job_progress:true,js_errors:errors,horizontal_overflow:false}));
    if(process.env.DONINO_EMIT_SCREENSHOT==='1')for(const name of ['desktop','mobile','dark','login','setup'])console.log('DONINO_SCREENSHOT_'+name+':'+fs.readFileSync('ui-results/'+name+'.png').toString('base64'));
  }finally{
    if(browser)await browser.close();
    child.kill('SIGTERM');
    await new Promise(resolve=>{if(child.exitCode!==null)return resolve();child.once('exit',resolve);setTimeout(()=>{child.kill('SIGKILL');resolve();},10000).unref();});
  }
}
main().catch(e=>{console.error(e);process.exitCode=1;});
