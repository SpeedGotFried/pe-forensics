"use strict";
function entropy(bytes) {
  if (!bytes.length) return null;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte]++;
  let bits = 0;
  for (const count of counts) if (count) bits -= count / bytes.length * Math.log2(count / bytes.length);
  return bits;
}
function parsePE(buffer) {
  const bytes = new Uint8Array(buffer), view = new DataView(buffer);
  function check(ok, message) { if (!ok) throw Error(message); }
  const u16 = i => view.getUint16(i,true), u32 = i => view.getUint32(i,true);
  check(bytes.length >= 64 && u16(0) === 0x5a4d, "Select a Windows PE executable or DLL with a valid DOS header.");
  const pe = u32(60), opt = pe+24;
  check(pe >= 64 && opt <= bytes.length && u32(pe) === 0x4550, "Missing or truncated PE signature.");
  const count=u16(pe+6), optSize=u16(pe+20), table=opt+optSize;
  check(count>0 && count<=96 && optSize>=2 && table+40*count<=bytes.length, "Invalid section table or optional header.");
  const magic=u16(opt), wide=magic===0x20b, directory=wide?112:96;
  check((wide || magic===0x10b) && optSize>=directory, "Unsupported PE optional header.");
  const dirCount=u32(opt+directory-4);
  check(dirCount<=Math.floor((optSize-directory)/8), "Data directories exceed the header.");
  const headers=u32(opt+60);
  check(headers>=table+40*count && headers<=bytes.length, "Invalid header size.");
  const fields={NumberOfSections:count,MajorLinkerVersion:bytes[opt+2],MinorLinkerVersion:bytes[opt+3],
    SizeOfCode:u32(opt+4),SizeOfInitializedData:u32(opt+8),SizeOfUninitializedData:u32(opt+12),
    AddressOfEntryPoint:u32(opt+16),SectionAlignment:u32(opt+32),FileAlignment:u32(opt+36),
    MajorOperatingSystemVersion:u16(opt+40),MajorSubsystemVersion:u16(opt+48),SizeOfImage:u32(opt+56),
    SizeOfHeaders:headers,Subsystem:u16(opt+68),DllCharacteristics:u16(opt+70)};
  const sections=[], warnings=[];
  for(let i=0;i<count;i++){
    const start=table+40*i, length=u32(start+16), raw=u32(start+20), flags=u32(start+36);
    check(!length || (raw>=headers && raw+length<=bytes.length),"Section data falls outside the file.");
    check(!length || !sections.some(s=>s.rawSize && raw<s.offset+s.rawSize && s.offset<raw+length),"Overlapping raw section data.");
    sections.push({name:new TextDecoder().decode(bytes.subarray(start,start+8)).split("\0")[0],
      rawSize:length, virtualSize:u32(start+8),rva:u32(start+12),offset:raw,
      entropy:entropy(bytes.subarray(raw,raw+length)), permissions:
      ((flags&0x40000000)?"R":"-")+((flags&0x80000000)?"W":"-")+((flags&0x20000000)?"X":"-")});
  }
  function fileOffset(rva,size) {
    if(rva<headers && rva+size<=headers) return rva;
    const s=sections.find(s=>rva>=s.rva && rva+size<=s.rva+s.rawSize);
    return s ? s.offset+rva-s.rva : null;
  }
  const imports=[];
  if(dirCount>1){
    const rva=u32(opt+directory+8), size=u32(opt+directory+12);
    if(rva || size){
      let ended=false;
      for(let i=0;rva && i<Math.min(Math.floor(size/20),512);i++){
        const off=fileOffset(rva+20*i,20);
        if(off===null) break;
        if([0,4,8,12,16].every(k=>u32(off+k)===0)){ended=true;break;}
        const nameRva=u32(off+12), idx=fileOffset(nameRva,1);
        if(!nameRva || idx===null) break;
        let len=0;
        while(len<256 && fileOffset(nameRva,len+1)!==null && bytes[idx+len]) len++;
        if(!len || len===256 || fileOffset(nameRva,len+1)===null) break;
        imports.push(new TextDecoder().decode(bytes.subarray(idx,idx+len)));
      }
      if(!ended) warnings.push("Import directory incomplete or exceeds the inspection limit.");
    }
  }
  const indicators=[];
  for(const s of sections){
    if(s.rawSize>=512 && s.entropy>=7.2) indicators.push(s.name+" has high byte entropy ("+s.entropy.toFixed(2)+" bits/byte).");
    if(s.permissions.endsWith("WX")) indicators.push(s.name+" permits both writes and execution.");
    if(/^UPX[0-9]/i.test(s.name)) indicators.push(s.name+" resembles a UPX section name.");
  }
  return {format:wide?"PE32+":"PE32",machine:"0x"+u16(pe+4).toString(16),headerTimestamp:u32(pe+8),
    fields,sections,imports,warnings,indicators,fileEntropy:entropy(bytes)};
}
function score(values) {
  const contributions=values.map((x,i)=>({feature:MODEL.features[i],value:x,
    impact:MODEL.weights[i]*(Math.log1p(x)-MODEL.mean[i])/MODEL.scale[i]}));
  const logOdds=contributions.reduce((a,c)=>a+c.impact,MODEL.base);
  const probability=1/(1+Math.exp(-logOdds));
  return {label:probability>=0.5?"Malicious-like":"Benign-like",score:probability,logOdds,
    baselineLogOdds:MODEL.base,contributions:contributions.sort((a,b)=>Math.abs(b.impact)-Math.abs(a.impact))};
}

