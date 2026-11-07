import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createApp } from '../src/server.mjs';
import { hashPassword } from '../src/security.mjs';

let app; let server; let origin; let temporaryDirectory; let user; let admin;
const testPassword='TestingPassword123';

async function call(path, { method='GET', body, cookie='', csrf='', redirect='follow', extraHeaders={} }={}) {
  const headers={};
  if(body!==undefined)headers['content-type']='application/json';
  if(cookie)headers.cookie=cookie;
  if(csrf)headers['x-csrf-token']=csrf;
  Object.assign(headers,extraHeaders);
  const response=await fetch(`${origin}/api/v1${path}`,{method,headers,body:body!==undefined?JSON.stringify(body):undefined,redirect});
  const type=response.headers.get('content-type')||'';
  const data=type.includes('application/json')?await response.json():await response.text();
  return {response,data};
}

async function createAccount({email,role='user',status='active'}) {
  const id=randomUUID();
  app.db.prepare(`INSERT INTO users(id,email,password_hash,display_name,role,status,referral_code,verified_at)
    VALUES (?,?,?,?,?,?,?,datetime('now'))`).run(id,email,await hashPassword(testPassword),email.split('@')[0],role,status,randomUUID().slice(0,8));
  const login=await call('/auth/login',{method:'POST',body:{email,password:testPassword}});
  assert.equal(login.response.status,200);
  const cookies=login.response.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
  return {id,email,cookie:cookies,csrf:login.data.csrfToken};
}

before(async () => {
  temporaryDirectory=mkdtempSync(join(tmpdir(),'verdant-links-test-'));
  app=createApp({env:{NODE_ENV:'test',DATABASE_PATH:join(temporaryDirectory,'test.sqlite'),SESSION_SECRET:'a'.repeat(48),DATA_ENCRYPTION_KEY:'b'.repeat(48),APP_URL:'http://127.0.0.1:0',MINIMUM_WITHDRAWAL_PAISE:'50000',AD_CALLBACK_SECRET:'callback-test-secret'}});
  server=createServer(app.handler);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  origin=`http://127.0.0.1:${server.address().port}`; app.config.appUrl=origin;
  admin=await createAccount({email:'admin@example.test',role:'super_admin'});
  // First ordinary user is registered through the real verification route below.
});

after(async () => {
  if(server){server.closeAllConnections?.();await new Promise(resolve=>server.close(resolve));}
  app?.db.close();
  if(temporaryDirectory)rmSync(temporaryDirectory,{recursive:true,force:true});
});

test('registration, email verification, login, and session identity', async () => {
  const bad=await call('/auth/register',{method:'POST',body:{email:'not-an-email',displayName:'A',password:'weak'}});
  assert.equal(bad.response.status,400);
  let verificationUrl=''; const original=console.info;
  console.info=(message)=>{if(String(message).includes('Development email verification link:'))verificationUrl=String(message).split(': ').slice(1).join(': ');};
  const registered=await call('/auth/register',{method:'POST',body:{email:'owner@example.test',displayName:'Link Owner',password:testPassword}});
  console.info=original;
  assert.equal(registered.response.status,201);
  assert.match(verificationUrl,/\/verify\?token=/);
  const token=new URL(verificationUrl).searchParams.get('token');
  const verify=await call('/auth/verify-email',{method:'POST',body:{token}});
  assert.equal(verify.response.status,200);
  const login=await call('/auth/login',{method:'POST',body:{email:'owner@example.test',password:testPassword}});
  assert.equal(login.response.status,200);
  user={id:app.db.prepare('SELECT id FROM users WHERE email=?').get('owner@example.test').id,email:'owner@example.test',csrf:login.data.csrfToken,cookie:login.response.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ')};
  const me=await call('/auth/me',{cookie:user.cookie});
  assert.equal(me.data.user.email,user.email);
  const duplicate=await call('/auth/register',{method:'POST',body:{email:'owner@example.test',displayName:'Duplicate',password:testPassword}});
  assert.equal(duplicate.response.status,409);
});

test('link ownership, validation, five-step unlock, and one-time final redirect', async () => {
  const invalid=await call('/links',{method:'POST',cookie:user.cookie,csrf:user.csrf,body:{destinationUrl:'javascript:alert(1)'}});
  assert.equal(invalid.response.status,400);
  const created=await call('/links',{method:'POST',cookie:user.cookie,csrf:user.csrf,body:{destinationUrl:'https://example.com/private?x=1',title:'Private destination',alias:'test-link'}});
  assert.equal(created.response.status,201);
  const link=created.data.link;
  assert.equal(link.destination_url,'https://example.com/private?x=1');
  const other=await createAccount({email:'other@example.test'});
  const notOwner=await call(`/links/${link.id}`,{cookie:other.cookie});
  assert.equal(notOwner.response.status,404);
  const noCsrf=await call('/links',{method:'POST',cookie:user.cookie,body:{destinationUrl:'https://example.com'}});
  assert.equal(noCsrf.response.status,403);

  const started=await call('/unlock/sessions',{method:'POST',body:{code:link.code}});
  assert.equal(started.response.status,200);
  assert.equal(JSON.stringify(started.data).includes('https://example.com/private?x=1'),false);
  let unlockCookie=started.response.headers.getSetCookie().map(c=>c.split(';')[0]).find(c=>c.startsWith('unlock_sid='));
  const cookie=[user.cookie,unlockCookie].filter(Boolean).join('; ');
  const bypass=await call(`/unlock/sessions/${link.code}/redeem`,{method:'POST',cookie,body:{}});
  assert.equal(bypass.response.status,409);
  const wrongOrder=await call(`/unlock/sessions/${link.code}/steps/2/activate`,{method:'POST',cookie,body:{}});
  assert.equal(wrongOrder.response.status,409);
  const incomplete=await call(`/unlock/sessions/${link.code}/steps/1/complete`,{method:'POST',cookie,body:{}});
  assert.equal(incomplete.response.status,409);
  for(let step=1;step<=5;step++){
    const activate=await call(`/unlock/sessions/${link.code}/steps/${step}/activate`,{method:'POST',cookie,body:{}});
    assert.equal(activate.response.status,200);
    assert.equal(activate.data.destinationUrl,'');
    const complete=await call(`/unlock/sessions/${link.code}/steps/${step}/complete`,{method:'POST',cookie,body:{}});
    assert.equal(complete.response.status,200);
  }
  const redeem=await call(`/unlock/sessions/${link.code}/redeem`,{method:'POST',cookie,body:{}});
  assert.equal(redeem.response.status,200);
  assert.ok(redeem.data.redirectPath.startsWith('/r/'));
  assert.equal(JSON.stringify(redeem.data).includes('https://example.com/private?x=1'),false);
  const redirect=await fetch(`${origin}${redeem.data.redirectPath}`,{redirect:'manual'});
  assert.equal(redirect.status,302);
  assert.equal(redirect.headers.get('location'),'https://example.com/private?x=1');
  const replay=await fetch(`${origin}${redeem.data.redirectPath}`,{redirect:'manual'});
  assert.equal(replay.status,410);
  assert.equal(app.db.prepare("SELECT COUNT(*) n FROM click_events WHERE short_link_id=? AND event_type='visit'").get(link.id).n,1);
  assert.equal(app.db.prepare("SELECT COUNT(*) n FROM click_events WHERE short_link_id=? AND event_type='redirect_success'").get(link.id).n,1);
  assert.equal(app.db.prepare("SELECT COUNT(*) n FROM earning_ledger WHERE link_id=?").get(link.id).n,0,'click-through only is not payable');
});

test('admin authorization, protected callback policy, and safe payout lifecycle', async () => {
  const forbidden=await call('/admin/dashboard',{cookie:user.cookie});
  assert.equal(forbidden.response.status,403);
  const dashboard=await call('/admin/dashboard',{cookie:admin.cookie});
  assert.equal(dashboard.response.status,200);

  const integration=await call('/admin/integrations',{method:'POST',cookie:admin.cookie,csrf:admin.csrf,body:{name:'Test provider',provider:'Custom',callbackEnabled:true}});
  assert.equal(integration.response.status,201);
  const settings=await call('/admin/settings',{cookie:admin.cookie});
  const steps=settings.data.steps.map(s=>({...s,position:Number(s.position),displayOrder:Number(s.display_order),retryLimit:3,timeoutSeconds:0,enabled:true,destinationUrl:s.position===1?'https://partner.example/go?event={event_id}':'',title:s.title,buttonLabel:s.button_label,instruction:s.instruction,policy:s.position===1?'provider_callback':'clickthrough',integrationId:s.position===1?integration.data.id:''}));
  const saved=await call('/admin/unlock-steps',{method:'PATCH',cookie:admin.cookie,csrf:admin.csrf,body:{steps}});
  assert.equal(saved.response.status,200);
  const noCallbacks=await call('/admin/integrations',{method:'POST',cookie:admin.cookie,csrf:admin.csrf,body:{name:'Bad provider',provider:'Custom',callbackEnabled:false}});
  assert.equal(noCallbacks.response.status,201);
  const stepCheck=await call('/admin/settings',{cookie:admin.cookie});
  assert.equal(stepCheck.data.steps[0].policy,'provider_callback');
  const settingUpdate=await call('/admin/settings',{method:'PATCH',cookie:admin.cookie,csrf:admin.csrf,body:{siteName:'Verdant Test',unlockEnabled:true,referralsEnabled:true,earningRatePaisePerThousand:2000,minimumWithdrawalPaise:50000,unlockTtlMinutes:60,reason:'Configure test rate'}});
  assert.equal(settingUpdate.response.status,200);

  const monetizedLink=await call('/links',{method:'POST',cookie:user.cookie,csrf:user.csrf,body:{destinationUrl:'https://example.com/callback-test',alias:'callback-link',password:'Private123'}});
  assert.equal(monetizedLink.response.status,201);
  assert.equal('password_hash' in monetizedLink.data.link,false);
  const protectedAttempt=await call('/unlock/sessions',{method:'POST',body:{code:monetizedLink.data.link.code}});
  assert.equal(protectedAttempt.response.status,401);
  const protectedStart=await call('/unlock/sessions',{method:'POST',body:{code:monetizedLink.data.link.code,password:'Private123'}});
  assert.equal(protectedStart.response.status,200);
  const unlockCookie=protectedStart.response.headers.getSetCookie().map(c=>c.split(';')[0]).find(c=>c.startsWith('unlock_sid='));
  const unlockCookies=[user.cookie,unlockCookie].filter(Boolean).join('; ');
  const activated=await call(`/unlock/sessions/${monetizedLink.data.link.code}/steps/1/activate`,{method:'POST',cookie:unlockCookies,body:{}});
  assert.equal(activated.response.status,200);
  assert.match(activated.data.destinationUrl,/event=/);
  const noCallback=await call(`/unlock/sessions/${monetizedLink.data.link.code}/steps/1/complete`,{method:'POST',cookie:unlockCookies,body:{}});
  assert.equal(noCallback.response.status,409);
  const callbackBody={eventId:activated.data.eventId,providerEventId:'provider-event-1',eligible:true};
  const callbackSignature=createHmac('sha256','callback-test-secret').update(JSON.stringify(callbackBody)).digest('hex');
  const badSignature=await call('/integrations/callback',{method:'POST',body:callbackBody});
  assert.equal(badSignature.response.status,401);
  const callback=await call('/integrations/callback',{method:'POST',body:callbackBody,extraHeaders:{'x-provider-signature':callbackSignature}});
  assert.equal(callback.response.status,200);
  const duplicateCallback=await call('/integrations/callback',{method:'POST',body:callbackBody,extraHeaders:{'x-provider-signature':callbackSignature}});
  assert.equal(duplicateCallback.data.duplicate,true);
  for(let step=1;step<=5;step++){
    if(step>1)assert.equal((await call(`/unlock/sessions/${monetizedLink.data.link.code}/steps/${step}/activate`,{method:'POST',cookie:unlockCookies,body:{}})).response.status,200);
    const complete=await call(`/unlock/sessions/${monetizedLink.data.link.code}/steps/${step}/complete`,{method:'POST',cookie:unlockCookies,body:{}});
    assert.equal(complete.response.status,200);
  }
  const callbackRedeem=await call(`/unlock/sessions/${monetizedLink.data.link.code}/redeem`,{method:'POST',cookie:unlockCookies,body:{}});
  assert.equal(callbackRedeem.response.status,200);
  const pendingEarning=app.db.prepare("SELECT * FROM earning_ledger WHERE link_id=? AND status='pending'").get(monetizedLink.data.link.id);
  assert.equal(pendingEarning.amount_paise,2);
  assert.equal(pendingEarning.rate_paise_per_1000,2000);

  app.db.prepare(`INSERT INTO earning_ledger(id,user_id,type,status,amount_paise,currency,reason,created_by)
    VALUES (?,?, 'adjustment','approved',100000,'INR','Test approved balance',?)`).run(randomUUID(),user.id,admin.id);
  const request=await call('/withdrawals',{method:'POST',cookie:user.cookie,csrf:user.csrf,body:{amountPaise:50000,payoutMethod:'UPI',payoutDetails:'owner@example@upi'}});
  assert.equal(request.response.status,201);
  const over=await call('/withdrawals',{method:'POST',cookie:user.cookie,csrf:user.csrf,body:{amountPaise:60000,payoutMethod:'UPI',payoutDetails:'owner@example@upi'}});
  assert.equal(over.response.status,400);
  const details=await call(`/admin/withdrawals/${request.data.id}/payout-details`,{cookie:admin.cookie});
  assert.equal(details.response.status,200);
  assert.equal(details.data.details,'owner@example@upi');
  const approve=await call(`/admin/withdrawals/${request.data.id}/approve`,{method:'POST',cookie:admin.cookie,csrf:admin.csrf,body:{reason:''}});
  assert.equal(approve.response.status,200);
  const paid=await call(`/admin/withdrawals/${request.data.id}/paid`,{method:'POST',cookie:admin.cookie,csrf:admin.csrf,body:{reference:'TXN-123'}});
  assert.equal(paid.response.status,200);
  const duplicate=await call(`/admin/withdrawals/${request.data.id}/paid`,{method:'POST',cookie:admin.cookie,csrf:admin.csrf,body:{reference:'TXN-123'}});
  assert.equal(duplicate.response.status,409);
  const summary=await call('/earnings/summary',{cookie:user.cookie});
  assert.equal(summary.data.withdrawablePaise,50000);
});
