#!/usr/bin/env node
// Cross-language receipt verifier (JCS canonical JSON + Ed25519)
import fs from 'node:fs';
import crypto from 'node:crypto';

function canonicalize(v){
  if(v===null||typeof v!=='object') return JSON.stringify(v);
  if(Array.isArray(v)) return '['+v.map(canonicalize).join(',')+']';
  const keys=Object.keys(v).sort();
  return '{'+keys.map(k=>JSON.stringify(k)+':'+canonicalize(v[k])).join(',')+'}';
}

if(process.argv.length<3){
  console.error('Usage: node verify-receipt-node.mjs <receipt.json>');
  process.exit(2);
}
const p=process.argv[2];
let receipt;try{receipt=JSON.parse(fs.readFileSync(p,'utf8'));}catch(e){
  console.error('Read/parse error:',e.message);process.exit(2);
}
const signatureB64=receipt.signature_b64; if(!signatureB64){console.error('missing signature_b64');process.exit(2);} 
const pubB64=receipt.signer_pubkey_b64||receipt.signing_pubkey_b64; if(!pubB64){console.error('missing public key');process.exit(2);} 
const {signature_b64, ...body}=receipt;
const message=canonicalize(body);
const sig=Buffer.from(signatureB64,'base64');
const pkRaw=Buffer.from(pubB64,'base64');

let ok=false;
try {
  // Construct a SubjectPublicKeyInfo DER wrapper if raw 32 bytes supplied
  let pubKeyObj;
  if(pkRaw.length===32){
    const oidEd25519=Buffer.from([0x30,0x05,0x06,0x03,0x2B,0x65,0x70]);
    const pubKeyBitString=Buffer.concat([Buffer.from([0x03,0x21,0x00]), pkRaw]);
    const spki=Buffer.concat([Buffer.from([0x30, oidEd25519.length+pubKeyBitString.length]), oidEd25519, pubKeyBitString]);
    pubKeyObj=crypto.createPublicKey({key:spki, format:'der', type:'spki'});
  } else {
    pubKeyObj=crypto.createPublicKey(pkRaw);
  }
  ok = crypto.verify(null, Buffer.from(message,'utf8'), pubKeyObj, sig);
} catch(e){
  console.error('Verification failure:', e.message);
  process.exit(3);
}
if(!ok){console.error('Signature verify: FAIL');process.exit(1);} 
console.log('Signature verify: OK');