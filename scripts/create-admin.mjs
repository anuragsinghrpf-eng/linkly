import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { randomUUID } from 'node:crypto';
import { openDatabase, createPublicUserId } from '../src/db.mjs';
import { loadConfig } from '../src/config.mjs';
import { hashPassword } from '../src/security.mjs';
import { normalizeEmail, randomToken, validateEmail, validatePassword, passwordLooksCompromised, cleanText } from '../src/domain.mjs';

const config = loadConfig();
const rl = createInterface({ input, output });
function hiddenPrompt(prompt) {
  if (!input.isTTY || !input.setRawMode) throw new Error('Run this command in an interactive terminal to enter the password without echo.');
  return new Promise((resolve,reject)=>{
    let value='';
    output.write(prompt);
    input.setRawMode(true);input.resume();
    const onData=chunk=>{
      for(const byte of chunk){
        if(byte===3){input.setRawMode(false);input.off('data',onData);output.write('\n');reject(new Error('Cancelled.'));return;}
        if(byte===13||byte===10){input.setRawMode(false);input.off('data',onData);output.write('\n');resolve(value);return;}
        if(byte===8||byte===127){value=value.slice(0,-1);continue;}
        if(byte>=32)value+=String.fromCharCode(byte);
      }
    };
    input.on('data',onData);
  });
}
try {
  const email = normalizeEmail(await rl.question('Admin email: '));
  const displayName = cleanText(await rl.question('Display name: '), 80);
  rl.close();
  const password = await hiddenPrompt('Password: ');
  const confirmation = await hiddenPrompt('Confirm password: ');
  if (!validateEmail(email)) throw new Error('Enter a valid email address.');
  if (!displayName) throw new Error('Display name is required.');
  if (password !== confirmation) throw new Error('Passwords do not match.');
  if (!validatePassword(password) || passwordLooksCompromised(password)) throw new Error('Password must be at least 10 characters and include upper case, lower case, and a number.');
  const db = openDatabase(config.databasePath);
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) {
    db.close();
    throw new Error('That email already exists. Provision the first admin with a new email.');
  }
  const id = randomUUID();
  const passwordHash = await hashPassword(password);
  const publicId = createPublicUserId(db);
  db.prepare(`INSERT INTO users(id,email,password_hash,display_name,public_id,role,status,referral_code,verified_at)
    VALUES (?,?,?,?,?,'super_admin','active',?,datetime('now'))`).run(id,email,passwordHash,displayName,publicId,randomToken(7).slice(0,10).toUpperCase());
  db.prepare("INSERT INTO audit_logs(id,actor_id,action,resource_type,resource_id,reason) VALUES (?,?,'admin_provisioned','user',?,'Secure CLI provisioning')").run(randomUUID(),id,id);
  db.close();
  console.info(`Super admin provisioned for ${email}.`);
} finally {
  rl.close();
}
