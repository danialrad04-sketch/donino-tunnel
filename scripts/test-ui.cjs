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
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:'ui-results/mobile.png',fullPage:true});
    const mobileOverflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    await page.locator('#mobile-logout').click();await page.locator('#login').waitFor({state:'visible'});
    if(errors.length||desktopOverflow||mobileOverflow)throw Error(JSON.stringify({errors,desktopOverflow,mobileOverflow}));
    console.log(JSON.stringify({login:true,pause_resume:true,prefer:true,mobile_logout:true,dark_light_theme_persists:true,manual_refresh:true,js_errors:errors,horizontal_overflow:false}));
    if(process.env.DONINO_EMIT_SCREENSHOT==='1')for(const name of ['desktop','mobile','dark','login'])console.log('DONINO_SCREENSHOT_'+name+':'+fs.readFileSync('ui-results/'+name+'.png').toString('base64'));
  }finally{
    if(browser)await browser.close();
    child.kill('SIGTERM');
    await new Promise(resolve=>{if(child.exitCode!==null)return resolve();child.once('exit',resolve);setTimeout(()=>{child.kill('SIGKILL');resolve();},10000).unref();});
  }
}
main().catch(e=>{console.error(e);process.exitCode=1;});
