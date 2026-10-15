'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {chromium}=require('playwright');
const out=path.resolve('ui-results');fs.mkdirSync(out,{recursive:true});
async function main(){
 const browser=await chromium.launch({headless:true,chromiumSandbox:process.env.DONINO_UI_SANDBOX!=='0',executablePath:process.env.DONINO_CHROMIUM||'/usr/bin/google-chrome'});
 const page=await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'}),errors=[];page.on('pageerror',e=>errors.push(e.message));let checks=0;
 async function route(hash){await page.evaluate(hash=>navigateWorkspace(hash),hash);await page.waitForFunction(hash=>document.querySelector('.workspace-page:not([hidden])').dataset.page===hash.slice(1),hash);}
 try{
  await page.goto(process.env.DONINO_ECO_UI_URL);await page.locator('#password').fill('ecosystem-browser-password');await page.locator('#login-form button').click();await page.locator('#dashboard').waitFor({state:'visible'});
  await route('#ecosystem');await page.waitForFunction(()=>ecoState!==null);assert.equal(await page.locator('.eco-flow').count(),4);checks++;
  await route('#providers');await page.locator('#eco-eco-connect-name').fill('Europe Workspace');await page.locator('#eco-eco-connect-url').fill(process.env.DONINO_ECO_VENDOR_URL);await page.locator('#eco-eco-connect-token').fill('wrong-token');await page.locator('#eco-connect button[type=submit]').click();await page.waitForFunction(()=>document.querySelector('#eco-connect-result').textContent.includes('HTTP 401'));assert.equal(await page.locator('#eco-connections .eco-provider-card').count(),0);checks++;
  await page.locator('#eco-eco-connect-token').fill('fixture-vendor-token');await page.locator('#eco-connect details').evaluate(n=>n.open=true);await page.locator('input[name=writable]').check();await page.locator('#eco-connect button[type=submit]').click();await page.waitForFunction(()=>ecoState?.connections.length===1);assert.equal(await page.locator('#eco-eco-connect-token').inputValue(),'');checks++;
  await route('#accounts');await page.getByText('alice',{exact:true}).waitFor();assert.equal(await page.locator('.eco-user-table tbody tr').count(),1);checks++;
  await page.getByRole('button',{name:'کاربر جدید',exact:true}).click();await page.locator('#eco-account-username').fill('bob');await page.locator('#eco-account-limit').fill('3');await page.locator('#eco-account-note').fill('<img src=x onerror=alert(1)>');await page.locator('#eco-dialog button[type=submit]').click();await page.getByText('bob',{exact:true}).waitFor();assert.equal(await page.locator('.eco-user-table img').count(),0);checks++;
  const bob=page.locator('.eco-user-table tbody tr').filter({hasText:'bob'});await bob.getByRole('button',{name:'مدیریت',exact:true}).click();await page.locator('#eco-account-limit').fill('5');await page.evaluate(()=>workspaceRefresh());assert.equal(await page.locator('#eco-account-limit').inputValue(),'5');await page.locator('#eco-dialog button[type=submit]').click();await page.waitForFunction(()=>ecoUsers.find(u=>u.username==='bob')?.limit===5*2**30);checks++;
  await bob.getByRole('button',{name:'اشتراک',exact:true}).click();await page.locator('#eco-dialog textarea').waitFor();assert.match(await page.locator('#eco-dialog textarea').inputValue(),/sub\/fixture-private/);await page.locator('#eco-dialog').getByRole('button',{name:'بستن',exact:true}).click();assert.equal(await page.locator('#eco-dialog textarea').count(),0);checks++;
  await page.locator('#eco-user-query').fill('bob');await page.locator('#eco-user-query').press('Enter');await page.waitForFunction(()=>ecoUsers.length===1&&ecoUsers[0].username==='bob');checks++;
  for(const theme of ['light','dark'])for(const width of [320,390,768,1440]){
   await page.setViewportSize({width,height:width<1024?844:1000});await page.evaluate(t=>setTheme(t),theme);
   for(const hash of ['#ecosystem','#providers','#accounts','#catalog']){await route(hash);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,theme+' '+width+' '+hash);checks++;if(width===390||width===1440)await page.screenshot({path:path.join(out,'ecosystem-'+hash.slice(1)+'-'+theme+'-'+width+'.png')});}
  }
  await route('#catalog');await page.getByRole('button',{name:'هسته‌های VPN',exact:true}).click();assert.equal(await page.locator('#eco-catalog .eco-engine').count(),5);assert.equal(await page.locator('#eco-catalog .eco-engine').filter({hasText:'Hysteria'}).getByRole('button').count(),0);checks++;
  await route('#providers');await page.getByRole('button',{name:'نصب backend و اتصال به Donino',exact:true}).click();assert.equal(await page.locator('#eco-dialog').isVisible(),true);await page.keyboard.press('Escape');checks++;
  await page.evaluate(()=>loggedOut());assert.equal(await page.locator('#eco-account-list').textContent(),'');assert.equal(await page.locator('#eco-connections').textContent(),'');assert.equal(await page.evaluate(()=>JSON.stringify(localStorage).includes('fixture-vendor-token')),false);checks++;
  assert.deepEqual(errors,[]);const result={checks,js_errors:errors,real_panel:true,vendor:'declared fixture',themes:2,widths:[320,390,768,1440],result:'passed'};fs.writeFileSync(path.join(out,'ecosystem-browser.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
 }finally{await browser.close();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
