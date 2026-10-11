'use strict';
// Native browser owns TLS and WebSocket. This IPC bridge never emits tunnel
// payload over CDP's debugging socket: Chromium uses anonymous inherited pipes.
const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
let chrome, profile, cdpBuffer='', sequence=0, session, initialized=false;
const pending=new Map();
const emit = value => process.stdout.write(JSON.stringify(value)+'\n');
function cdp(method, params={}, scoped=true) {
  if (pending.size>128) return Promise.reject(Error('CDP queue limit'));
  const id=++sequence;
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout'));},15000);
    pending.set(id,{resolve,reject,timer});
    chrome.stdio[3].write(JSON.stringify({id,method,params,...(scoped&&session?{sessionId:session}:{})})+'\0');
  });
}
async function initialize(config) {
  if (initialized) throw Error('already initialized');
  initialized=true;
  profile=fs.mkdtempSync(path.join(os.tmpdir(),'donino-browser-'));
  const flags=['--headless=new','--remote-debugging-pipe',`--user-data-dir=${profile}`,
    '--disable-setuid-sandbox','--no-first-run','--no-default-browser-check','--disable-background-networking',
    '--disable-component-update','--disable-sync','--disable-extensions','--disable-dev-shm-usage'];
  // NoNewPrivileges in the service prevents the legacy setuid helper. Use
  // Chromium's unprivileged namespace + seccomp sandbox, never --no-sandbox.
  if (config.spki) flags.push(`--ignore-certificate-errors-spki-list=${config.spki}`);
  // Explicit root-only local integration fixture. Production does not set it.
  if (config.test_no_sandbox===true) {
    if (process.getuid()!==0 || process.env.DONINO_TEST!=='1') throw Error('test sandbox exception forbidden');
    flags.push('--no-sandbox');
  }
  chrome=spawn(config.chromium||'/usr/bin/chromium',flags,{stdio:['ignore','ignore','pipe','pipe','pipe'],
    env:{...process.env,XDG_CONFIG_HOME:path.join(profile,'config'),XDG_CACHE_HOME:path.join(profile,'cache')}});
  chrome.on('error',()=>shutdown(1));
  let startupDiagnostics='';
  chrome.on('exit',()=>{if(!session&&startupDiagnostics)process.stderr.write('Chromium startup: '+startupDiagnostics+'\n');shutdown(1);});
  // Collect only bounded pre-session launch diagnostics, before credentials or
  // a target page enter the browser. Normal platform warnings stay quiet.
  chrome.stderr.on('data',chunk=>{if(!session)startupDiagnostics=(startupDiagnostics+chunk.toString()).slice(-4096);});
  chrome.stdio[3].on('error',()=>shutdown(1));
  chrome.stdio[4].on('error',()=>shutdown(1));
  chrome.stdio[4].on('data',chunk=>{
    cdpBuffer+=chunk.toString();
    if(cdpBuffer.length>4*1024*1024) return shutdown(1);
    let offset;
    while((offset=cdpBuffer.indexOf('\0'))>=0) {
      const message=JSON.parse(cdpBuffer.slice(0,offset));cdpBuffer=cdpBuffer.slice(offset+1);
      if(message.id) {
        const waiter=pending.get(message.id);
        if(waiter){clearTimeout(waiter.timer);pending.delete(message.id);message.error?waiter.reject(Error(message.error.message)):waiter.resolve(message.result);}
      } else if(message.method==='Runtime.bindingCalled'&&message.sessionId===session&&message.params.name==='donino_bridge') {
        emit(JSON.parse(message.params.payload));
      }
    }
  });
  const target=await cdp('Target.createTarget',{url:'about:blank'},false);
  session=(await cdp('Target.attachToTarget',{targetId:target.targetId,flatten:true},false)).sessionId;
  await cdp('Runtime.enable');await cdp('Page.enable');await cdp('Network.enable');
  await cdp('Runtime.addBinding',{name:'donino_bridge'});
  const cookie=await cdp('Network.setCookie',{name:'donino_session',value:config.token,url:config.origin+'/',secure:true,httpOnly:true,sameSite:'Strict'});
  if(!cookie.success) throw Error('cookie rejected');
  const navigation=await cdp('Page.navigate',{url:config.origin+'/'});
  if(navigation.errorText) throw Error('TLS or navigation failed');
  // Load a real page and refuse certificate interstitials or cross-origin redirects.
  let loaded=false;
  for(let i=0;i<100;i++) {
    const state=await cdp('Runtime.evaluate',{expression:'JSON.stringify({origin:location.origin,ready:document.readyState,title:document.title})',returnByValue:true});
    const page=JSON.parse(state.result.value||'{}');
    if(page.origin===config.origin&&page.ready==='complete'&&page.title==='Donino Workspace'){loaded=true;break;}
    await new Promise(resolve=>setTimeout(resolve,50));
  }
  if(!loaded) throw Error('owned portal did not load');
  const injected=await cdp('Runtime.evaluate',{expression:`(()=>{
    const streams=new Map();
    const report=(event,id,extra={})=>donino_bridge(JSON.stringify({event,id,...extra}));
    window.doninoTransport={
      open(id,service){
        if(streams.size>=32||!/^[a-z][a-z0-9-]{0,31}$/.test(service))throw Error('stream limit or name');
        const ws=new WebSocket(location.origin.replace(/^https:/,'wss:')+'/api/stream/'+service);
        ws.binaryType='arraybuffer';streams.set(id,ws);
        ws.onmessage=e=>{
          if(typeof e.data==='string'){if(e.data==='ready')report('open',id);else ws.close(1002);return;}
          const b=new Uint8Array(e.data);
          if(b[0]===0&&b.length>1&&b.length<=32769){let s='';for(let i=1;i<b.length;i++)s+=String.fromCharCode(b[i]);report('data',id,{data:btoa(s)});}
          else if(b.length===1&&b[0]===1)report('eof',id);
          else if(b.length===1&&b[0]===3)report('ack',id);
          else ws.close(1002);
        };
        ws.onclose=()=>{streams.delete(id);report('close',id);};
        ws.onerror=()=>ws.close();
      },
      data(id,value){const ws=streams.get(id);if(!ws||ws.readyState!==1)throw Error('stream closed');const s=atob(value);if(s.length>32768||ws.bufferedAmount>1048576)throw Error('buffer limit');const b=new Uint8Array(s.length+1);for(let i=0;i<s.length;i++)b[i+1]=s.charCodeAt(i);ws.send(b);},
      eof(id){const ws=streams.get(id);if(ws&&ws.readyState===1)ws.send(new Uint8Array([1]));},
      ack(id){const ws=streams.get(id);if(ws&&ws.readyState===1)ws.send(new Uint8Array([2]));},
      close(id){const ws=streams.get(id);if(ws)ws.close();}
    };
  })()`,returnByValue:true});
  if(injected.exceptionDetails) throw Error('bridge initialization failed');
  emit({event:'ready'});
}
async function command(message) {
  if(message.op==='init') return initialize(message.config);
  if(!session) throw Error('not initialized');
  if(!['open','data','eof','ack','close'].includes(message.op)) throw Error('invalid operation');
  const args=[message.id];
  if(message.op==='open')args.push(message.service);
  if(message.op==='data')args.push(message.data);
  const result=await cdp('Runtime.evaluate',{expression:`window.doninoTransport[${JSON.stringify(message.op)}](...${JSON.stringify(args)})`,returnByValue:true});
  if(result.exceptionDetails)emit({event:'close',id:message.id});
}
let stopping=false;
function shutdown(code=0) {
  if(stopping)return;stopping=true;
  if(chrome)chrome.kill('SIGTERM');
  for(const waiter of pending.values())clearTimeout(waiter.timer);
  setTimeout(()=>{
    if(chrome)chrome.kill('SIGKILL');
    if(profile) {
      if(fs.rmSync)fs.rmSync(profile,{recursive:true,force:true});
      else fs.rmdirSync(profile,{recursive:true}); // Ubuntu 22.04's Node 12.
    }
    process.exit(code);
  },300).unref();
}
process.on('SIGTERM',()=>shutdown());process.on('SIGINT',()=>shutdown());
const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
let chain=Promise.resolve();
lines.on('line',line=>{
  if(line.length>131072)return shutdown(1);
  chain=chain.then(()=>command(JSON.parse(line))).catch(error=>{process.stderr.write('BrowserLink: '+error.message+'\n');shutdown(1);});
});
lines.on('close',()=>shutdown());
