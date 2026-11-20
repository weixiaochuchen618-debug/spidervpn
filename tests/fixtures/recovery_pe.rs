//! Test-only bounded PE32+ import-directory reader for the four actual held
//! recovery fixtures. No tool download, loader emulation or recursive graph.
use std::convert::TryInto;
type Res<T>=Result<T,&'static str>;
fn bytes(b:&[u8],p:usize,n:usize)->Res<&[u8]>{
    b.get(p..p.checked_add(n).ok_or("offset overflow")?).ok_or("truncated")
}
fn u16at(b:&[u8],p:usize)->Res<u16>{Ok(u16::from_le_bytes(bytes(b,p,2)?.try_into().unwrap()))}
fn u32at(b:&[u8],p:usize)->Res<u32>{Ok(u32::from_le_bytes(bytes(b,p,4)?.try_into().unwrap()))}
fn u64at(b:&[u8],p:usize)->Res<u64>{Ok(u64::from_le_bytes(bytes(b,p,8)?.try_into().unwrap()))}
#[derive(Debug)]
pub(super) struct Imports{pub machine:u16,pub image_base:u64,pub normal:Option<Vec<String>>,pub delay:Option<Vec<String>>}
struct Section{va:u32,virtual_size:u32,raw:u32,size:u32}
struct Pe<'a>{b:&'a[u8],headers:u32,sections:Vec<Section>,base:u64,opt:usize,dirs:usize}
impl<'a> Pe<'a>{
    fn mapped(&self,rva:u32,n:usize)->Res<&'a[u8]>{
        if rva==0{return Err("null RVA")}
        if rva<self.headers{
            if u64::from(rva)+n as u64>u64::from(self.headers){return Err("header RVA range")}
            return bytes(self.b,rva as usize,n);
        }
        let mut found=None;
        for s in &self.sections{
            let span=s.virtual_size.max(s.size);
            if let Some(d)=rva.checked_sub(s.va).filter(|d|*d<span){
                if found.is_some(){return Err("ambiguous RVA")}
                if u64::from(d)+n as u64>u64::from(s.size){return Err("RVA beyond raw section")}
                found=Some(bytes(self.b,s.raw.checked_add(d).ok_or("raw overflow")? as usize,n)?);
            }
        }
        found.ok_or("unmapped RVA")
    }
    fn name(&self,rva:u32)->Res<String>{
        let mut v=Vec::new();
        for i in 0..260u32{
            let c=self.mapped(rva.checked_add(i).ok_or("name overflow")?,1)?[0];
            if c==0{
                let name=String::from_utf8(v).map_err(|_|"non ASCII import")?;
                if name.len()<5||!name.to_ascii_lowercase().ends_with(".dll"){return Err("invalid import name")}
                return Ok(name);
            }
            if !(c.is_ascii_alphanumeric()||matches!(c,b'.'|b'_'|b'-')){return Err("invalid import character")}
            v.push(c);
        }
        Err("unterminated import name")
    }
    fn table(&self,index:usize,delay:bool)->Res<Option<Vec<String>>>{
        if index>=self.dirs{return Ok(None)}
        let at=self.opt+112+index*8;
        let rva=u32at(self.b,at)?;let size=u32at(self.b,at+4)? as usize;
        if rva==0&&size==0{return Ok(None)}
        let stride=if delay{32}else{20};
        if rva==0||size<stride||size>1024*1024{return Err("invalid directory size")}
        let table=self.mapped(rva,size)?;
        let mut names=Vec::new();
        for d in table.chunks_exact(stride).take(4096){
            if d.iter().all(|b|*b==0){return Ok(Some(names))}
            let name=if delay{
                let flags=u32at(d,0)?;
                let value=u32at(d,4)?;
                match flags{
                    1=>value,
                    0=>u32::try_from(u64::from(value).checked_sub(self.base).ok_or("delay VA underflow")?).map_err(|_|"delay VA overflow")?,
                    _=>return Err("unsupported delay attributes"),
                }
            }else{u32at(d,12)?};
            names.push(self.name(name)?);
        }
        Err("missing import terminator")
    }
}
pub(super) fn parse(b:&[u8])->Res<Imports>{
    if b.len()>128*1024*1024||bytes(b,0,2)?!=b"MZ"{return Err("invalid DOS header")}
    let pe=u32at(b,0x3c)? as usize;
    if pe<64||bytes(b,pe,4)?!=b"PE\0\0"{return Err("invalid PE header")}
    let coff=pe+4;let machine=u16at(b,coff)?;let count=u16at(b,coff+2)? as usize;
    if machine!=0x8664||count==0||count>96{return Err("unexpected machine/sections")}
    let opt_len=u16at(b,coff+16)? as usize;let opt=coff+20;
    bytes(b,opt,opt_len)?;
    if opt_len<112||u16at(b,opt)?!=0x20b{return Err("expected PE32+")}
    let base=u64at(b,opt+24)?;let headers=u32at(b,opt+60)?;
    let dirs=u32at(b,opt+108)? as usize;
    if dirs>16||112+dirs*8>opt_len||headers as usize>b.len(){return Err("directory/header bounds")}
    let start=opt+opt_len;
    bytes(b,start,count*40)?;
    if start+count*40>headers as usize{return Err("section table outside headers")}
    let mut sections:Vec<Section>=Vec::new();
    for i in 0..count{
        let p=start+i*40;
        let s=Section{virtual_size:u32at(b,p+8)?,va:u32at(b,p+12)?,size:u32at(b,p+16)?,raw:u32at(b,p+20)?};
        let end=s.va.checked_add(s.virtual_size.max(s.size)).ok_or("section RVA overflow")?;
        if s.va<headers{return Err("section overlaps headers")}
        if s.size!=0{bytes(b,s.raw as usize,s.size as usize)?;if s.raw<headers{return Err("section raw overlaps headers")}}
        for old in &sections{
            let old_end=old.va.checked_add(old.virtual_size.max(old.size)).ok_or("section RVA overflow")?;
            if s.va<old_end&&old.va<end{return Err("overlapping virtual sections")}
            if s.size!=0&&old.size!=0&&u64::from(s.raw)<u64::from(old.raw)+u64::from(old.size)
                &&u64::from(old.raw)<u64::from(s.raw)+u64::from(s.size){return Err("overlapping raw sections")}
        }
        sections.push(s);
    }
    let p=Pe{b,headers,sections,base,opt,dirs};
    Ok(Imports{machine,image_base:base,normal:p.table(1,false)?,delay:p.table(13,true)?})
}
