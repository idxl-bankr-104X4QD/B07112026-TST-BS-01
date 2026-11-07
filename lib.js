/* Общая библиотека: шифрование данных (AES-GCM, ключ из пароля через PBKDF2) и окно входа. */
(function(G){
var enc=new TextEncoder(),dec=new TextDecoder(),ITER=300000;
function b64d(s){var b=atob(s.replace(/\s+/g,'')),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
function b64e(u){var s='';for(var i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s)}
async function pipe(data,T){var s=new Blob([data]).stream().pipeThrough(new T('gzip'));return new Uint8Array(await new Response(s).arrayBuffer())}
async function deriveKey(pw,salt){
  var base=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:salt,iterations:ITER,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function encryptJson(key,obj){
  var iv=crypto.getRandomValues(new Uint8Array(12)),gz=await pipe(enc.encode(JSON.stringify(obj)),CompressionStream);
  var ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv},key,gz)),out=new Uint8Array(12+ct.length);
  out.set(iv);out.set(ct,12);return out;
}
async function decryptJson(key,buf){
  var u=new Uint8Array(buf),pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:u.slice(0,12)},key,u.slice(12));
  return JSON.parse(dec.decode(await pipe(pt,DecompressionStream)));
}
async function getBuf(url){var r=await fetch(url,{cache:'no-store'});if(!r.ok)throw new Error(url+': '+r.status);return r.arrayBuffer()}

/* Окно ввода пароля. Возвращает {key, idx} после успешной расшифровки data/index.enc */
async function gate(){
  var salt=b64d(dec.decode(await getBuf('data/salt.txt'))),idxBuf=await getBuf('data/index.enc');
  async function attempt(pw){var k=await deriveKey(pw,salt);try{return {key:k,idx:await decryptJson(k,idxBuf),pw:pw}}catch(e){return null}}
  var saved=null;try{saved=localStorage.getItem('nb-pw')}catch(e){}
  if(saved){var r0=await attempt(saved);if(r0)return r0}
  return new Promise(function(resolve){
    var st=document.createElement('style');
    st.textContent='.nbg{position:fixed;inset:0;z-index:99;background:var(--bg,#eef0f3);display:flex;align-items:center;justify-content:center;padding:16px}.nbg form{background:var(--panel,#fff);color:var(--ink,#1b2230);border:1px solid var(--line,#d9dde4);border-radius:8px;padding:24px;width:min(360px,100%);display:grid;gap:12px;font:15px var(--ui,system-ui,sans-serif)}.nbg h2{margin:0;font:600 18px var(--ui,system-ui,sans-serif)}.nbg input[type=password]{font:16px var(--ui,system-ui,sans-serif);padding:10px 12px;border:1px solid var(--line,#d9dde4);border-radius:6px;background:var(--bg,#fff);color:var(--ink,#1b2230)}.nbg button{font:600 15px var(--ui,system-ui,sans-serif);padding:10px;border:0;border-radius:6px;background:var(--accent,#1d4f8f);color:var(--panel,#fff);cursor:pointer}.nbg label{font-size:13px;color:var(--muted,#5d6879);display:flex;gap:8px;align-items:center}.nbg .err{color:#c0392b;font-size:13px;min-height:1.2em}';
    document.head.appendChild(st);
    var d=document.createElement('div');d.className='nbg';
    d.innerHTML='<form><h2>Нормативна база</h2><div>Введите пароль для доступа</div><input type="password" id="nbp" autocomplete="current-password" aria-label="Пароль"><label><input type="checkbox" id="nbr" checked> Запомнить на этом устройстве</label><div class="err" id="nbe" role="alert"></div><button type="submit">Войти</button></form>';
    document.body.appendChild(d);
    var f=d.querySelector('form'),inp=d.querySelector('#nbp'),err=d.querySelector('#nbe');inp.focus();
    f.addEventListener('submit',async function(e){
      e.preventDefault();err.textContent='Проверяю…';
      var r=await attempt(inp.value.trim());
      if(!r){err.textContent='Неверный пароль.';inp.select();return}
      try{if(d.querySelector('#nbr').checked)localStorage.setItem('nb-pw',r.pw)}catch(x){}
      d.remove();st.remove();resolve(r);
    });
  });
}
G.NBLib={b64d:b64d,b64e:b64e,deriveKey:deriveKey,encryptJson:encryptJson,decryptJson:decryptJson,gate:gate,ITER:ITER};
})(typeof window!=='undefined'?window:globalThis);
