import tls from 'node:tls';
import { createInterface } from 'node:readline';

function cleanHeader(value) {
  const text=String(value??'');
  if(/[\r\n]/.test(text))throw new Error('Invalid email header.');
  return text;
}

export async function sendMail({ smtpUrl, emailFrom }, to, subject, text) {
  if(!smtpUrl||!emailFrom)throw new Error('Email transport is not configured.');
  const address=cleanHeader(to); const from=cleanHeader(emailFrom);
  const url=new URL(smtpUrl);
  if(url.protocol!=='smtps:')throw new Error('Only implicit TLS SMTP URLs (smtps://) are supported.');
  const socket=tls.connect({host:url.hostname,port:Number(url.port||465),servername:url.hostname,rejectUnauthorized:true});
  const lines=[];const waiters=[];
  const rl=createInterface({input:socket,crlfDelay:Infinity});
  rl.on('line',line=>{const waiter=waiters.shift();if(waiter)waiter(line);else lines.push(line);});
  const nextLine=()=>lines.length?Promise.resolve(lines.shift()):new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('SMTP response timed out.')),15000);
    waiters.push(line=>{clearTimeout(timer);resolve(line);});
    socket.once('error',error=>{clearTimeout(timer);reject(error);});
  });
  const expect=async code=>{
    let line;
    do{line=await nextLine();}while(line.length>=4&&line[3]==='-');
    const accepted=Array.isArray(code)?code:[code];
    if(!accepted.some(value=>line.startsWith(String(value))))throw new Error(`SMTP server returned ${line.slice(0,3)}.`);
  };
  const command=async(text,code)=>{socket.write(`${text}\r\n`);await expect(code);};
  try{
    await new Promise((resolve,reject)=>{socket.once('secureConnect',resolve);socket.once('error',reject);});
    await expect(220);
    await command(`EHLO ${url.hostname}`,250);
    await command('AUTH LOGIN',334);
    await command(Buffer.from(decodeURIComponent(url.username)).toString('base64'),334);
    await command(Buffer.from(decodeURIComponent(url.password)).toString('base64'),235);
    await command(`MAIL FROM:<${from}>`,250);
    await command(`RCPT TO:<${address}>`,[250,251]);
    await command('DATA',354);
    const encodedSubject=Buffer.from(String(subject),'utf8').toString('base64');
    const body=String(text).replace(/\r?\n/g,'\r\n').split('\r\n').map(line=>line.startsWith('.')?`.${line}`:line).join('\r\n');
    const message=[`From: Verdant Links <${from}>`,`To: <${address}>`,`Subject: =?UTF-8?B?${encodedSubject}?=`,`Date: ${new Date().toUTCString()}`,'MIME-Version: 1.0','Content-Type: text/plain; charset=UTF-8','Content-Transfer-Encoding: 8bit','','',body,'.'].join('\r\n');
    socket.write(`${message}\r\n`);await expect(250);
    await command('QUIT',221);
  } finally {
    rl.close();socket.end();
  }
}
