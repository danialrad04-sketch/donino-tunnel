'use strict';
// Native browser against BOTH disposable systemd panels. No API route mocks.
const fs=require('node:fs');
const {chromium}=require('playwright');
async function main(){
  const browser=await chromium.launch({headless:true,chromiumSandbox:true,executablePath:process.env.DONINO_CHROMIUM||'/usr/bin/google-chrome'});
  const errors=[];fs.mkdirSync('ui-role-results',{recursive:true});
  let outside;
  try{
    outside=await browser.newPage({viewport:{width:1440,height:1000}});
    outside.on('pageerror',e=>errors.push(e.message));
    await outside.goto(process.env.DONINO_FOREIGN_URL);
    await outside.locator('#password').fill('systemd-fixture-password-123');
    await outside.locator('#login-form button').click();
    await outside.locator('#foreign-node').waitFor({state:'visible'});
    if(await outside.locator('#setup').isVisible())throw Error('foreign must have its own role panel');
    await outside.waitForFunction(()=>document.querySelectorAll('.path-card').length===6&&document.querySelectorAll('.foreign-unit').length>=7);
    if(process.env.DONINO_EXPECT_UNKNOWN==='1'){
      await outside.waitForFunction(()=>[...document.querySelectorAll('.path-status')].length===6&&[...document.querySelectorAll('.path-status')].every(e=>e.textContent==='نامشخص'));
      await outside.screenshot({path:'ui-role-results/foreign-unknown.png',fullPage:true});
      if(errors.length)throw Error(JSON.stringify(errors));
      console.log(JSON.stringify({revoked_peer_no_fresh_health:true,unknown_paths_render:true,js_errors:errors}));
      if(process.env.DONINO_EMIT_SCREENSHOT==='1')console.log('DONINO_ROLE_SCREENSHOT_foreign-unknown:'+fs.readFileSync('ui-role-results/foreign-unknown.png').toString('base64'));
      return;
    }
    await outside.locator('#foreign-test').click();
    await outside.waitForFunction(()=>document.querySelector('#foreign-action-history').textContent.includes('موفق'),{},{timeout:45000});
    const quic=outside.locator('.foreign-unit').filter({hasText:'donino-link-frp-quic.service'});
    await quic.getByRole('button',{name:'توقف',exact:true}).click();
    await outside.waitForFunction(()=>[...document.querySelectorAll('.foreign-unit')].find(e=>e.textContent.includes('donino-link-frp-quic.service'))?.querySelector('.badge').textContent==='inactive',{},{timeout:45000});
    await outside.waitForFunction(()=>[...document.querySelectorAll('.path-card')].find(e=>e.querySelector('h3').textContent==='frp-quic')?.querySelector('.path-status').textContent!=='سالم');
    await quic.getByRole('button',{name:'شروع',exact:true}).click();
    await outside.waitForFunction(()=>[...document.querySelectorAll('.path-status')].length===6&&[...document.querySelectorAll('.path-status')].every(e=>e.textContent==='سالم'),{},{timeout:60000});
    const panelUnit=outside.locator('.foreign-unit').filter({hasText:/donino-link\.service/});
    if(!await panelUnit.getByRole('button',{name:'توقف',exact:true}).isDisabled())throw Error('panel must not stop itself');
    await outside.locator('#foreign-new-code').click();
    await outside.waitForFunction(()=>document.querySelector('#foreign-code-value').value.startsWith('donino1.'));
    // Do not publish a still-valid fixture pairing code in screenshots/logs.
    await outside.locator('#foreign-code-value').evaluate(e=>e.value='');
    await outside.locator('#foreign-code-expiry').evaluate(e=>e.textContent='کد یک‌بارمصرف ساخته شد · برای پیش‌نمایش پنهان شده');
    await outside.screenshot({path:'ui-role-results/foreign-desktop.png',fullPage:true});
    await outside.locator('#theme').click();
    await outside.waitForFunction(()=>document.documentElement.dataset.theme==='dark');
    await outside.waitForFunction(()=>getComputedStyle(document.querySelector('#refresh')).backgroundColor==='rgb(24, 32, 51)');
    await outside.screenshot({path:'ui-role-results/foreign-dark.png',fullPage:true});
    await outside.setViewportSize({width:390,height:844});
    await outside.locator('#theme').click();
    await outside.waitForFunction(()=>document.documentElement.dataset.theme==='light');
    await outside.waitForFunction(()=>getComputedStyle(document.querySelector('#refresh')).backgroundColor==='rgb(255, 255, 255)');
    await outside.screenshot({path:'ui-role-results/foreign-mobile.png',fullPage:true});
    const foreignOverflow=await outside.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    const iran=await browser.newPage({viewport:{width:1440,height:1000}});iran.on('pageerror',e=>errors.push(e.message));
    await iran.goto(process.env.DONINO_IRAN_URL);
    await iran.locator('#password').fill('systemd-fixture-password-123');await iran.locator('#login-form button').click();
    await iran.locator('#setup').waitFor({state:'visible'});await iran.locator('#setup-details summary').first().click();
    await iran.waitForFunction(()=>document.querySelector('#setup-profile').options.length>=2&&document.querySelector('#setup-iran').value.length>0);
    if(await iran.locator('#foreign-node').isVisible()||!await iran.locator('#connection-code').isVisible()||await iran.locator('#connection-pin').isVisible())throw Error('wrong Iran pairing flow');
    await iran.locator('#setup').screenshot({path:'ui-role-results/iran-setup.png'});
    await iran.setViewportSize({width:390,height:844});
    await iran.locator('#setup').screenshot({path:'ui-role-results/iran-setup-mobile.png'});
    const iranOverflow=await iran.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    if(errors.length||foreignOverflow||iranOverflow)throw Error(JSON.stringify({errors,foreignOverflow,iranOverflow}));
    console.log(JSON.stringify({real_role_panels:true,foreign_actual_health_test:true,foreign_code_generation:true,foreign_stop_start_actual_quic:true,prevent_panel_self_stop:true,role_specific_controls:true,automatic_pairing_form:true,mobile_overflow:false,js_errors:errors}));
    if(process.env.DONINO_EMIT_SCREENSHOT==='1')for(const name of ['foreign-desktop','foreign-dark','foreign-mobile','iran-setup','iran-setup-mobile'])console.log('DONINO_ROLE_SCREENSHOT_'+name+':'+fs.readFileSync('ui-role-results/'+name+'.png').toString('base64'));
  }catch(error){
    if(outside)console.error('ROLE UI DIAGNOSTICS: '+JSON.stringify({errors,dom:await outside.evaluate(()=>({labels:[...document.querySelectorAll('.path-status')].map(e=>e.textContent),notice:document.querySelector('#notice').textContent,live:document.querySelector('#live').textContent})),status:await outside.evaluate(async()=>{const d=await (await fetch('/api/status')).json();return {role:d.role,telemetry_fresh:d.telemetry_fresh,paths:d.paths?.map(p=>({id:p.id,healthy:p.healthy,observation:p.observation}))};})}));
    throw error;
  }finally{await browser.close();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
