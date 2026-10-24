import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
const v=JSON.parse(readFileSync('/tmp/vm.json','utf8')).vm;
const b64d=s=>Uint8Array.from(Buffer.from(s,'base64'));
const rd32=(b,o)=>((b[o]<<24)|(b[o+1]<<16)|(b[o+2]<<8)|b[o+3])>>>0;
const rd32le=(b,o)=>(b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0;
const mul32=(a,b)=>Math.imul(a,b)>>>0;
const rotl32=(x,r)=>{r&=31;return r?(((x<<r)|(x>>>(32-r)))>>>0):(x>>>0);};
function vmX(data,seed,prog,rounds){
  const s=new Array(8); for(let i=0;i<8;i++)s[i]=rd32le(seed,i*4);
  const plen=prog.length>>1, out=new Uint8Array(data.length);
  const nBlocks=Math.ceil(data.length/32), word=new Uint8Array(32);
  for(let n=0;n<nBlocks;n++){
    s[0]=(s[0]^n)>>>0; s[6]=(s[6]+n)>>>0;
    for(let r=0;r<rounds;r++)for(let p=0;p<plen;p++){
      const ins=prog[p*2]|(prog[p*2+1]<<8), op=ins&7, a=(ins>>3)&7, bb=(ins>>6)&7;
      if(op===0)s[a]=(s[a]+s[bb])>>>0;
      else if(op===1)s[a]=(s[a]^s[bb])>>>0;
      else if(op===2)s[a]=rotl32(s[a],1+(bb%31));
      else if(op===3)s[a]=mul32(s[a],(2*s[bb]+1)>>>0);
      else if(op===4){const t=s[a];s[a]=s[bb];s[bb]=t;}
      else if(op===5)s[a]=(s[a]+0x9E3779B9+n)>>>0;
      else if(op===6)s[a]=(s[a]^mul32(n,0x85EBCA6B))>>>0;
      else s[a]=(s[a]+(s[(a+1)&7]^n))>>>0;
    }
    for(let i=0;i<8;i++){const w=s[i];word[i*4]=w&255;word[i*4+1]=(w>>>8)&255;word[i*4+2]=(w>>>16)&255;word[i*4+3]=(w>>>24)&255;}
    for(let i=0;i<32;i++){const pos=n*32+i;if(pos<data.length)out[pos]=data[pos]^word[i];}
  }
  return out;
}
const key=b64d(v.key), nonce=b64d(v.nonce), prog=b64d(v.prog), data=b64d(v.data);
const seed=new Uint8Array(await webcrypto.subtle.digest('SHA-256', Buffer.concat([Buffer.from(key),Buffer.from(nonce)])));
const enc=vmX(data,seed,prog,2);
const got=Buffer.from(enc).toString('base64');
console.log('match', got===v.enc);
console.log('php', v.enc.slice(0,60));
console.log('js ', got.slice(0,60));
