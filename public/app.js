let csrfToken = '';
const $ = id => document.getElementById(id);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function msg(id, text, kind='') { $(id).innerHTML = text ? `<div class="alert ${kind}">${esc(text)}</div>` : ''; }
async function api(url, opts={}) {
  const headers = { ...(opts.body ? {'Content-Type':'application/json'} : {}), ...(opts.headers || {}) };
  if (csrfToken && opts.method && opts.method !== 'GET') headers['X-CSRF-Token'] = csrfToken;
  const r = await fetch(url, { credentials:'same-origin', ...opts, headers });
  let data = {}; try { data = await r.json(); } catch (_) {}
  if (r.status === 401 && !url.includes('/auth/login')) showLogin();
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}
function showLogin() { $('appScreen').classList.add('hidden'); $('loginScreen').classList.remove('hidden'); csrfToken=''; }
function showApp() { $('loginScreen').classList.add('hidden'); $('appScreen').classList.remove('hidden'); loadDashboard(); }
$('loginForm').addEventListener('submit', async e => {
  e.preventDefault(); msg('loginMsg','');
  try { const d = await api('/auth/login',{method:'POST',body:JSON.stringify({username:$('username').value,password:$('password').value})}); csrfToken=d.csrfToken; $('password').value=''; showApp(); }
  catch(err) { msg('loginMsg',err.message,'error'); }
});
$('logoutBtn').addEventListener('click', async () => { try { await api('/auth/logout',{method:'POST',body:'{}'}); } catch(_){} showLogin(); });
function goto(tab) {
  document.querySelectorAll('.nav').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
  document.querySelectorAll('.tabpage').forEach(p=>p.classList.toggle('active',p.id===`tab-${tab}`));
  if(tab==='keys') loadKeys(); if(tab==='audit') loadAudit(); if(tab==='database') loadPreview();
}
document.querySelectorAll('.nav').forEach(b=>b.addEventListener('click',()=>goto(b.dataset.tab)));
document.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>goto(b.dataset.goto)));
function fmtDate(s) { if(!s)return '—'; const d=new Date(s); return Number.isNaN(d.getTime())?'—':d.toLocaleString(); }
function statusBadge(s) { return `<span class="status ${esc(s)}">${esc(String(s).replace('_',' '))}</span>`; }
function keyRows(keys, compact=false) {
  if(!keys.length) return '<div class="empty">No API keys yet. Create one to get started.</div>';
  return `<div class="tablewrap"><table><thead><tr><th>Key</th><th>Status</th><th>Created</th><th>Expires</th><th>Usage</th>${compact?'':'<th>Actions</th>'}</tr></thead><tbody>${keys.map(k=>`<tr><td><div class="keyname">${esc(k.name)}</div><div class="mono">${esc(k.prefix)}••••••</div></td><td>${statusBadge(k.status)}</td><td>${esc(fmtDate(k.createdAt))}</td><td>${esc(fmtDate(k.expiresAt))}</td><td>${esc(k.used)} / ${esc(k.limit)}</td>${compact?'':`<td><div class="row">${k.status==='active'?`<button class="btn secondary" data-revoke="${esc(k.id)}">Revoke</button>`:''}<button class="btn danger" data-delete="${esc(k.id)}">Delete</button></div></td>`}</tr>`).join('')}</tbody></table></div>`;
}
async function loadDashboard() {
  try { const d=await api('/api/dashboard'); $('statRecords').textContent=d.records.toLocaleString(); $('statKeys').textContent=d.activeKeys.toLocaleString(); $('statTotal').textContent=`${d.totalKeys} total keys`; $('statRequests').textContent=d.requests.toLocaleString(); $('statFields').textContent=d.fields.length; $('healthRecords').textContent=d.records.toLocaleString(); $('healthFields').textContent=d.fields.length; renderSources(d.sources || []); $('recentKeys').innerHTML=keyRows(d.keys.slice(0,5),true); $('fieldList').innerHTML=d.fields.length?d.fields.map(f=>`<span class="pill">${esc(f)}</span>`).join(''):'<span class="muted tiny">No fields detected yet.</span>'; }
  catch(e) { if(e.message!=='Authentication required') console.error(e); }
}
async function loadKeys() { try { const d=await api('/api/dashboard'); $('keysTable').innerHTML=keyRows(d.keys); $('keysTable').querySelectorAll('[data-revoke]').forEach(b=>b.addEventListener('click',()=>revokeKey(b.dataset.revoke))); $('keysTable').querySelectorAll('[data-delete]').forEach(b=>b.addEventListener('click',()=>deleteKey(b.dataset.delete))); } catch(e){ $('keysTable').innerHTML=`<div class="alert error">${esc(e.message)}</div>`; } }
async function revokeKey(id) { if(!confirm('Revoke this API key immediately? This cannot be undone.'))return; try { await api(`/api/keys/${encodeURIComponent(id)}/revoke`,{method:'POST',body:'{}'}); await loadKeys(); await loadDashboard(); } catch(e){alert(e.message);} }
async function deleteKey(id) { if(!confirm('Permanently delete this key and its usage history?'))return; try { await api(`/api/keys/${encodeURIComponent(id)}`,{method:'DELETE'}); await loadKeys(); await loadDashboard(); } catch(e){alert(e.message);} }
$('createKeyForm').addEventListener('submit',async e=>{
  e.preventDefault(); $('newKeyResult').innerHTML='';
  try { const d=await api('/api/keys',{method:'POST',body:JSON.stringify({name:$('keyName').value,days:Number($('keyDays').value),limit:Number($('keyLimit').value)})});
    $('newKeyResult').innerHTML=`<div class="alert success">API key created. Copy it now; the complete token is only shown once.</div><div class="tokenbox" id="newToken">${esc(d.token)}</div><button id="copyToken" class="btn secondary" style="margin-top:9px">Copy key</button><p class="tiny">Expires ${esc(fmtDate(d.key.expiresAt))} · Quota ${esc(d.key.limit)} requests</p>`;
    $('copyToken').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(d.token);$('copyToken').textContent='Copied ✓';}catch(_){$('copyToken').textContent='Select and copy the token above';}});
    $('keyName').value=''; await loadKeys(); await loadDashboard();
  } catch(err){ $('newKeyResult').innerHTML=`<div class="alert error">${esc(err.message)}</div>`; }
});
$('refreshKeys').addEventListener('click',loadKeys);
$('importBtn').addEventListener('click',async()=>{
  const files=Array.from($('jsonFile').files || []); msg('importMsg','');
  if(!files.length){msg('importMsg','Choose at least one JSON file first.','error');return;}
  if(files.reduce((n,f)=>n+f.size,0)>100*1024*1024){msg('importMsg','Combined file size must be 100 MB or less per import.','error');return;}
  try {
    const parsedFiles=[];
    for(const file of files){ parsedFiles.push({name:file.name,records:JSON.parse(await file.text())}); }
    const d=await api('/api/records/import',{method:'POST',body:JSON.stringify({files:parsedFiles})});
    msg('importMsg',`Indexed ${d.files} JSON files and ${d.count.toLocaleString()} records successfully.`,'success');
    $('fieldList').innerHTML=d.fields.map(f=>`<span class="pill">${esc(f)}</span>`).join('');
    renderSources(d.sources || []);
    await loadDashboard(); await loadPreview();
  } catch(e){msg('importMsg',e.message,'error');}
});
function renderSources(sources){
  if(!$('sourcesTable')) return;
  if(!sources.length){$('sourcesTable').innerHTML='<div class="empty">No JSON sources indexed yet.</div>';return;}
  $('sourcesTable').innerHTML=`<div class="tablewrap"><table><thead><tr><th>File</th><th>Records</th><th>Detected fields</th><th>Imported</th></tr></thead><tbody>${sources.map(s=>`<tr><td><b>${esc(s.name)}</b></td><td>${esc(s.count)}</td><td>${(s.fields||[]).map(f=>`<span class="pill">${esc(f)}</span>`).join(' ')}</td><td>${esc(fmtDate(s.importedAt))}</td></tr>`).join('')}</tbody></table></div>`;
}
async function loadPreview(){try{const d=await api('/api/records/preview?limit=10');$('recordPreview').textContent=JSON.stringify(d.records,null,2);}catch(e){$('recordPreview').textContent=e.message;}}
$('refreshPreview').addEventListener('click',loadPreview);
$('testApiBtn').addEventListener('click',async()=>{
  msg('apiTestMsg',''); $('apiTestResult').textContent='Sending request…';
  const q=$('testQuery').value.trim(), token=$('testToken').value.trim();
  if(!q||!token){msg('apiTestMsg','Enter both an exact lookup value and API key.','error');$('apiTestResult').textContent='';return;}
  try { const r=await fetch(`/v1/lookup?q=${encodeURIComponent(q)}`,{headers:{'X-API-Key':token}}); const d=await r.json(); $('apiTestResult').textContent=JSON.stringify(d,null,2); if(!r.ok)msg('apiTestMsg',`HTTP ${r.status}`,'error'); else msg('apiTestMsg',`HTTP ${r.status} · Request completed`,'success'); }
  catch(e){$('apiTestResult').textContent=e.message;}
});
async function loadAudit(){
  try {
    const d=await api('/api/audit');
    if(!d.events.length){ $('auditTable').innerHTML='<div class="empty">No audit events yet.</div>'; return; }
    const rows=d.events.map(e=>{
      const details=Object.fromEntries(Object.entries(e).filter(([k])=>!['id','at','action'].includes(k)));
      return `<tr><td>${esc(fmtDate(e.at))}</td><td><b>${esc(e.action)}</b></td><td class="mono">${esc(JSON.stringify(details))}</td></tr>`;
    }).join('');
    $('auditTable').innerHTML=`<div class="tablewrap"><table><thead><tr><th>Time</th><th>Event</th><th>Details</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  } catch(e) { $('auditTable').innerHTML=`<div class="alert error">${esc(e.message)}</div>`; }
}
$('refreshAudit').addEventListener('click',loadAudit);
(async()=>{try{const d=await api('/api/auth/me');if(d.authenticated){csrfToken=d.csrfToken;showApp();}}catch(_){} })();
