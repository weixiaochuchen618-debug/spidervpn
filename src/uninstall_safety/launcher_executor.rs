//! Private same-object disposal core. No production caller is authorized yet.
//!
//! Scope is a caller-selected launcher directory and the existing installation
//! root policy, with only the two built-in names/templates. A future trusted
//! maintenance transaction must authenticate that scope, hold its real
//! lifecycle exclusion and establish recovery before calling this module.
//! Observed ACLs, a matching template, or a successful disposal are NOT that
//! authorization. User-owned folders can be writable; ACL observation is not
//! a claim of isolation against the same SID, administrators or old mappings.
#![allow(dead_code)]
use super::{launcher_handle_info, launcher_handle_path, launcher_path_parts,
    launcher_size, launcher_template, read_launcher_bounded, safe_local_root,
    owned_launcher_bytes, MAX_LAUNCHER_BYTES};
use std::{fs::{self, File, OpenOptions}, io::{self, Seek, SeekFrom},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf}, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, LocalFree},
    Security::{ACL, ACE_HEADER, GetAce, GetSecurityDescriptorDacl, IsValidSid,
        OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION},
    Security::Authorization::{GetSecurityInfo, ConvertSecurityDescriptorToStringSecurityDescriptorW,
        SE_FILE_OBJECT, SDDL_REVISION_1},
    Storage::FileSystem::{GetDriveTypeW, GetFileInformationByHandleEx, SetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, FILE_STANDARD_INFO, FILE_DISPOSITION_INFO,
        FileStandardInfo, FileDispositionInfo, FileStreamInfo, DELETE, FILE_READ_ATTRIBUTES,
        FILE_LIST_DIRECTORY, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT},
};
const FLAGS:u32=FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS;
const READ_CONTROL:u32=0x20000;
const ALL_SHARES:u32=FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE;
type Info=BY_HANDLE_FILE_INFORMATION;
type Id=(u32,u32,u32);
type Result<T>=std::result::Result<T,Fault>;

#[derive(Clone,Copy,Debug)]
enum Launcher { Start, Uninstall }
impl Launcher {
    fn parse(name:&str)->Result<Self> {
        if name.eq_ignore_ascii_case("启动SpiderVPN.cmd"){Ok(Self::Start)}
        else if name.eq_ignore_ascii_case("卸载SpiderVPN.cmd"){Ok(Self::Uninstall)}
        else {Err(Fault::before("NAME_NOT_ALLOWED",name))}
    }
    fn name(self)->&'static str {
        match self {Self::Start=>"启动SpiderVPN.cmd",Self::Uninstall=>"卸载SpiderVPN.cmd"}
    }
}
// Do not collapse a successful disposition with uncertain completion into a
// pre-mutation error. In that state no caller may retry by pathname.
#[derive(Debug,PartialEq,Eq)]
enum Mutation { None, DispositionFailed{pending:Option<bool>}, PendingOrUnknown }
#[derive(Debug)]
struct Fault { phase:&'static str, win32:Option<i32>, detail:String, mutation:Mutation }
impl Fault {
    fn before(phase:&'static str,detail:impl Into<String>)->Self{
        Self{phase,win32:None,detail:detail.into(),mutation:Mutation::None}
    }
    fn os(phase:&'static str,e:io::Error)->Self{
        Self{phase,win32:e.raw_os_error(),detail:e.to_string(),mutation:Mutation::None}
    }
    fn after(mut self)->Self{self.mutation=Mutation::PendingOrUnknown;self}
}
fn id(i:&Info)->Id{(i.dwVolumeSerialNumber,i.nFileIndexHigh,i.nFileIndexLow)}
fn same(a:&Info,b:&Info)->bool{
    id(a)==id(b)&&a.dwFileAttributes==b.dwFileAttributes&&a.nNumberOfLinks==b.nNumberOfLinks
        &&launcher_size(a)==launcher_size(b)
        &&a.ftLastWriteTime.dwHighDateTime==b.ftLastWriteTime.dwHighDateTime
        &&a.ftLastWriteTime.dwLowDateTime==b.ftLastWriteTime.dwLowDateTime
}
fn parts(path:&Path)->Result<Vec<PathBuf>> {
    let text=path.to_str().ok_or_else(||Fault::before("PATH_TEXT","invalid UTF-16"))?;
    if text.contains('/')||text.encode_utf16().count()>240 {
        return Err(Fault::before("PATH_FORM","noncanonical or oversized DOS path"));
    }
    let p=launcher_path_parts(path).map_err(|e|Fault::before("PATH_FORM",e))?;
    let drive:Vec<u16>=p[0].as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe{GetDriveTypeW(drive.as_ptr())}!=3 {return Err(Fault::before("DRIVE","not fixed local disk"));}
    Ok(p)
}
struct Local(*mut core::ffi::c_void);
impl Drop for Local {fn drop(&mut self){if !self.0.is_null(){unsafe{LocalFree(self.0);}}}}
// Snapshot actual same-object owner and DACL. Null/unreadable descriptors or
// unsupported ACE formats fail closed; writable user ACLs are not trusted
// authorization. Recheck exact descriptor against the first observation.
fn acl(file:&File)->Result<String>{
    let mut owner=null_mut();let mut dacl:*mut ACL=null_mut();let mut sd=null_mut();
    let rc=unsafe{GetSecurityInfo(file.as_raw_handle(),SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,null_mut(),
        &mut dacl,null_mut(),&mut sd)};
    let _sd=Local(sd.cast());
    if rc!=0{return Err(Fault::os("ACL_QUERY",io::Error::from_raw_os_error(rc as i32)));}
    if sd.is_null()||owner.is_null()||dacl.is_null()||unsafe{IsValidSid(owner)}==0{
        return Err(Fault::before("ACL_UNKNOWN","missing/invalid owner or DACL"));
    }
    let mut present=0;let mut defaulted=0;let mut returned=null_mut();
    if unsafe{GetSecurityDescriptorDacl(sd,&mut present,&mut returned,&mut defaulted)}==0{
        return Err(Fault::os("ACL_QUERY",io::Error::last_os_error()));
    }
    let count=unsafe{(*dacl).AceCount};
    if present==0||returned!=dacl||count==0||count>128{
        return Err(Fault::before("ACL_UNKNOWN","empty/unreadable DACL"));
    }
    for n in 0..u32::from(count){
        let mut ace=null_mut();
        if unsafe{GetAce(dacl,n,&mut ace)}==0{return Err(Fault::os("ACL_ACE",io::Error::last_os_error()));}
        if ace.is_null(){return Err(Fault::before("ACL_UNKNOWN","null ACE"));}
        let head=unsafe{&*ace.cast::<ACE_HEADER>()};
        if !matches!(head.AceType,0|1)||head.AceSize<16{
            return Err(Fault::before("ACL_UNKNOWN","unsupported ACE"));
        }
    }
    let mut text=null_mut();let mut n=0;
    if unsafe{ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut text,&mut n)}==0{
        return Err(Fault::os("ACL_STRING",io::Error::last_os_error()));
    }
    let _text=Local(text.cast());
    if text.is_null()||n==0||n>65536{return Err(Fault::before("ACL_UNKNOWN","invalid descriptor length"));}
    String::from_utf16(unsafe{std::slice::from_raw_parts(text,n as usize)})
        .map_err(|_|Fault::before("ACL_UNKNOWN","invalid descriptor text"))
}
fn streams(file:&File,dir:bool)->Result<()>{
    let mut aligned=vec![0u64;8192];
    let bytes=unsafe{std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(),aligned.len()*8)};
    if unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),FileStreamInfo,
        bytes.as_mut_ptr().cast(),bytes.len() as u32)}==0{
        let e=io::Error::last_os_error();
        if dir&&e.raw_os_error()==Some(38){return Ok(());}
        return Err(Fault::os("STREAM_QUERY",e));
    }
    let next=u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let len=u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let wanted:Vec<u8>="::$DATA".encode_utf16().flat_map(u16::to_le_bytes).collect();
    if next!=0||len!=wanted.len()||bytes[24..24+wanted.len()]!=wanted{
        return Err(Fault::before("ALTERNATE_STREAM","unexpected named or unknown stream"));
    }
    Ok(())
}
fn inspect(file:&File,path:&Path,dir:bool)->Result<Info>{
    let i=launcher_handle_info(file,dir).map_err(|e|Fault::before("OBJECT_TYPE_OR_ID",e))?;
    if (i.nFileIndexHigh,i.nFileIndexLow)==(0,0){return Err(Fault::before("OBJECT_TYPE_OR_ID","zero ID"));}
    launcher_handle_path(file,path).map_err(|e|Fault::before("CANONICAL_PATH",e))?;
    streams(file,dir)?;
    Ok(i)
}
struct Directory {path:PathBuf,file:File,info:Info,acl:String}
impl Directory{
    fn open(path:&Path)->Result<Self>{
        let file=OpenOptions::new().access_mode(FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL)
            .share_mode(FILE_SHARE_READ).custom_flags(FLAGS).open(path)
            .map_err(|e|Fault::os("PARENT_OPEN",e))?;
        let info=inspect(&file,path,true)?;
        let acl=acl(&file)?;
        Ok(Self{path:path.to_owned(),file,info,acl})
    }
    fn check(&self)->Result<()>{
        let now=inspect(&self.file,&self.path,true)?;
        if id(&now)!=id(&self.info)||now.dwFileAttributes!=self.info.dwFileAttributes||acl(&self.file)?!=self.acl{
            return Err(Fault::before("PARENT_CHANGED",format!("{:?}",self.path)));
        }
        Ok(())
    }
}
fn hold(path:&Path)->Result<Vec<Directory>>{parts(path)?.iter().map(|p|Directory::open(p)).collect()}
fn check(dirs:&[Directory])->Result<()>{for d in dirs{d.check()?;}Ok(())}
fn matching_entries(parent:&Path,which:Launcher)->Result<usize>{
    let mut n=0;
    for e in fs::read_dir(parent).map_err(|e|Fault::os("ENUM_PARENT",e))?{
        let name=e.map_err(|e|Fault::os("ENUM_PARENT",e))?.file_name();
        if name.to_str().is_some_and(|s|s.eq_ignore_ascii_case(which.name())){n+=1;}
    }
    Ok(n)
}
fn independent(path:&Path)->io::Result<File>{
    OpenOptions::new().read(true).share_mode(ALL_SHARES).custom_flags(FLAGS).open(path)
}
fn pending(file:&File)->io::Result<bool>{
    let mut i:FILE_STANDARD_INFO=unsafe{std::mem::zeroed()};
    if unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),FileStandardInfo,
        (&mut i as *mut FILE_STANDARD_INFO).cast(),std::mem::size_of::<FILE_STANDARD_INFO>() as u32)}==0{
        return Err(io::Error::last_os_error());
    }
    Ok(i.DeletePending as u8!=0)
}
fn disposition(file:&File)->io::Result<()>{
    let i=FILE_DISPOSITION_INFO{DeleteFile:true as _};
    if unsafe{SetFileInformationByHandle(file.as_raw_handle(),FileDispositionInfo,
        (&i as *const FILE_DISPOSITION_INFO).cast(),std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32)}==0{
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
enum Admission { Missing, NotOwned, Verified(Verified) }
// Private module, no public constructor, no caller-provided bytes or list.
// No production callers. The root/parent pair is NOT authenticated by this
// function; that remains the future trusted maintenance caller's obligation.
struct Verified {
    root:PathBuf,parent:PathBuf,which:Launcher,path:PathBuf,
    install_dirs:Vec<Directory>,parents:Vec<Directory>,file:File,before:Info,acl:String,
}
impl Verified{
    fn open(root:&Path,parent:&Path,name:&str)->Result<Admission>{
        let which=Launcher::parse(name)?;
        safe_local_root(root).map_err(|e|Fault::before("INSTALL_SCOPE",e))?;
        let path=parent.join(which.name());
        parts(&path)?;
        let install_dirs=hold(root)?;
        let parents=hold(parent)?;
        let mut file=match OpenOptions::new().access_mode(GENERIC_READ|DELETE|READ_CONTROL)
            .share_mode(FILE_SHARE_READ).custom_flags(FLAGS).open(&path){
            Ok(f)=>f,
            Err(e) if e.raw_os_error()==Some(2)=>{
                check(&install_dirs)?;check(&parents)?;
                if matching_entries(parent,which)?==0 {
                    check(&install_dirs)?;check(&parents)?;
                    return Ok(Admission::Missing);
                }
                return Err(Fault::os("MISSING_BUT_ENUMERATED",e));
            }
            Err(e)=>return Err(Fault::os("LEAF_OPEN",e)),
        };
        let before=inspect(&file,&path,false)?;
        let security=acl(&file)?;
        if launcher_size(&before)>MAX_LAUNCHER_BYTES{return Ok(Admission::NotOwned);}
        let bytes=read_launcher_bounded(&mut file).map_err(|e|Fault::os("LEAF_READ",e))?;
        if bytes.len() as u64!=launcher_size(&before)||!same(&before,&inspect(&file,&path,false)?)
            ||acl(&file)?!=security{return Err(Fault::before("LEAF_CHANGED","initial read"));}
        if !owned_launcher_bytes(&bytes,root,which.name()){return Ok(Admission::NotOwned);}
        let mut v=Self{root:root.to_owned(),parent:parent.to_owned(),which,path,install_dirs,parents,
            file,before,acl:security};
        v.recheck()?;
        Ok(Admission::Verified(v))
    }
    fn recheck(&mut self)->Result<()>{
        check(&self.install_dirs)?;check(&self.parents)?;
        let a=inspect(&self.file,&self.path,false)?;
        if !same(&a,&self.before)||acl(&self.file)?!=self.acl{
            return Err(Fault::before("LEAF_CHANGED","identity, attributes or DACL"));
        }
        if pending(&self.file).map_err(|e|Fault::os("PENDING_QUERY",e))?{
            return Err(Fault::before("ALREADY_PENDING","cannot adopt"));
        }
        self.file.seek(SeekFrom::Start(0)).map_err(|e|Fault::os("LEAF_SEEK",e))?;
        let bytes=read_launcher_bounded(&mut self.file).map_err(|e|Fault::os("LEAF_READ",e))?;
        let b=inspect(&self.file,&self.path,false)?;
        if bytes.len() as u64>MAX_LAUNCHER_BYTES||bytes.len() as u64!=launcher_size(&b)||!same(&a,&b)
            ||acl(&self.file)?!=self.acl||!owned_launcher_bytes(&bytes,&self.root,self.which.name()){
            return Err(Fault::before("LEAF_CHANGED","template or identity changed"));
        }
        if matching_entries(&self.parent,self.which)?!=1{return Err(Fault::before("NAME_AMBIGUOUS","parent enumeration"));}
        check(&self.install_dirs)?;check(&self.parents)?;
        Ok(())
    }
    // Consume the verified value. No retry or path-based fallback following
    // any attempted disposition. A successful kernel call immediately changes
    // the error boundary, even if pending readback itself fails.
    fn mark(mut self)->Result<Marked>{
        self.recheck()?;
        if let Err(e)=disposition(&self.file){
            let mut fault=Fault::os("DISPOSITION_FAILED",e);
            fault.mutation=Mutation::DispositionFailed{pending:pending(&self.file).ok()};
            return Err(fault);
        }
        if !pending(&self.file).map_err(|e|Fault::os("PENDING_QUERY",e).after())?{
            return Err(Fault::before("PENDING_NOT_CONFIRMED","disposition returned success").after());
        }
        Ok(Marked(self))
    }
}
struct Marked(Verified);
#[derive(Debug,PartialEq,Eq)]
enum Completion { Removed }
impl Marked{
    fn finish(self)->Result<Completion>{
        let Verified{file,path,parent,which,install_dirs,parents,..}=self.0;
        if !pending(&file).map_err(|e|Fault::os("PENDING_QUERY",e).after())?{
            return Err(Fault::before("PENDING_NOT_CONFIRMED","before close").after());
        }
        drop(file);
        // Original ancestor handles remain live during independent absence
        // and exact parent enumeration. Not a promise of future absence:
        // a user-writable parent can create new names after this observation.
        check(&install_dirs).map_err(Fault::after)?;check(&parents).map_err(Fault::after)?;
        match independent(&path){
            Err(e) if e.raw_os_error()==Some(2)=>{},
            Err(e)=>return Err(Fault::os("ABSENCE_UNKNOWN",e).after()),
            Ok(_)=>return Err(Fault::before("NAME_STILL_EXISTS","after disposition").after()),
        }
        if matching_entries(&parent,which).map_err(Fault::after)?!=0{
            return Err(Fault::before("NAME_STILL_ENUMERATED","after disposition").after());
        }
        check(&install_dirs).map_err(Fault::after)?;check(&parents).map_err(Fault::after)?;
        Ok(Completion::Removed)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{SecureRandom,SystemRandom};
    use std::io::Write;
    use windows_sys::Win32::Security::{PROTECTED_DACL_SECURITY_INFORMATION};
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW,SetSecurityInfo};

    struct Fixture{base:PathBuf,root:PathBuf,parent:PathBuf,neighbor:PathBuf}
    impl Fixture{
        fn new()->Self{
            // Normalize only the fixture location, never a candidate. Verify
            // both spellings of every ancestor against retained object IDs.
            let raw=std::env::temp_dir();
            let mut lexical=launcher_path_parts(&raw.join("not-opened")).unwrap();lexical.pop();
            let mut held=Vec::new();let mut names=Vec::new();
            for p in &lexical{
                let f=OpenOptions::new().access_mode(FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL)
                    .share_mode(FILE_SHARE_READ).custom_flags(FLAGS).open(p).unwrap();
                let i=launcher_handle_info(&f,true).unwrap();
                let mut buf=vec![0u16;32768];
                let n=unsafe{windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(
                    f.as_raw_handle(),buf.as_mut_ptr(),buf.len() as u32,0)} as usize;
                assert!(n>0&&n<buf.len());
                let actual=String::from_utf16(&buf[..n]).unwrap();
                let p=PathBuf::from(actual.strip_prefix(r"\\?\").unwrap());
                names.push(p.clone());held.push((f,i));
            }
            let canonical=names.last().unwrap();
            let canonical_dirs=hold(canonical).unwrap();
            assert_eq!(canonical_dirs.len(),held.len());
            for ((d,(f,i)),name) in canonical_dirs.iter().zip(&held).zip(&names){
                assert_eq!(&d.path,name);assert_eq!(id(&d.info),id(i));
                assert_eq!(id(&launcher_handle_info(f,true).unwrap()),id(i));
            }
            let mut nonce=[0u8;16];SystemRandom::new().fill(&mut nonce).unwrap();
            let suffix:String=nonce.iter().map(|b|format!("{b:02x}")).collect();
            let base=canonical.join(format!("spider-d2-core-{suffix}"));
            fs::create_dir(&base).unwrap();
            check(&canonical_dirs).unwrap();
            drop(canonical_dirs);drop(held);
            let root=base.join("installation");let parent=base.join("fixture-launchers");let neighbor=base.join("neighbor");
            for d in [&root,&parent,&neighbor]{fs::create_dir(d).unwrap();}
            let f=Self{base,root,parent,neighbor};
            fs::write(f.neighbor.join("sentinel"),b"unrelated user data").unwrap();
            println!("D2_CORE_FIXTURE path={:?} fixed_disk=true nonreparse=true normalized_same_ids=true",f.base);
            f
        }
        fn path(&self,w:Launcher)->PathBuf{self.parent.join(w.name())}
        fn bytes(&self,w:Launcher)->Vec<u8>{launcher_template(&self.root,w.name()).unwrap().into_bytes()}
        fn seed(&self,w:Launcher){fs::write(self.path(w),self.bytes(w)).unwrap();}
        fn admit(&self,w:Launcher)->Result<Admission>{Verified::open(&self.root,&self.parent,w.name())}
        fn ready(&self,w:Launcher)->Verified{
            match self.admit(w){Ok(Admission::Verified(v))=>v,Err(e)=>panic!("unexpected fault {e:?}"),_=>panic!("expected verified")}
        }
        fn cleanup(self){
            assert_eq!(fs::read(self.neighbor.join("sentinel")).unwrap(),b"unrelated user data");
            // No recursive cleanup. All test-created leaves must be removed
            // by their owning case, and no unknown object is ever deleted.
            fs::remove_file(self.neighbor.join("sentinel")).unwrap();
            for d in [&self.root,&self.parent,&self.neighbor,&self.base]{fs::remove_dir(d).unwrap();}
        }
    }
    fn fault<T>(r:Result<T>,phase:&str,rc:Option<i32>)->Fault{
        match r {
            Err(e)=>{assert_eq!(e.phase,phase,"{e:?}");assert_eq!(e.win32,rc,"{e:?}");e},
            Ok(_)=>panic!("unexpected acceptance {phase}"),
        }
    }
    fn rc<T>(r:io::Result<T>,label:&str,codes:&[i32])->i32{
        let e=match r {Err(e)=>e,Ok(_)=>panic!("{label}: unexpected success")};
        let n=e.raw_os_error().unwrap();assert!(codes.contains(&n),"{label}: {e}");n
    }
    fn snapshot(path:&Path)->(Id,Vec<u8>){
        let mut f=independent(path).unwrap();
        let i=inspect(&f,path,false).unwrap();
        let b=read_launcher_bounded(&mut f).unwrap();
        assert!(same(&i,&inspect(&f,path,false).unwrap()));
        assert_eq!(launcher_size(&i),b.len() as u64);
        (id(&i),b)
    }
    fn unowned(r:Result<Admission>){
        match r{Ok(Admission::NotOwned)=>{},Err(e)=>panic!("expected not-owned: {e:?}"),_=>panic!("expected not-owned")}
    }
    fn remove_own(path:&Path){fs::remove_file(path).unwrap();}
    #[test]
    fn d2_core_actual_same_object_executor(){
        let f=Fixture::new();
        let neighbor=f.neighbor.join(Launcher::Start.name());
        fs::write(&neighbor,f.bytes(Launcher::Start)).unwrap();
        let neighbor_before=snapshot(&neighbor);
        let unknown=f.parent.join("custom.cmd");fs::write(&unknown,b"unrelated launcher").unwrap();
        let unknown_before=snapshot(&unknown);

        for w in [Launcher::Start,Launcher::Uninstall]{
            assert!(matches!(f.admit(w),Ok(Admission::Missing)));
            f.seed(w);let p=f.path(w);let before=snapshot(&p);
            let v=f.ready(w);
            let observer=independent(&p).unwrap();
            assert_eq!(id(&v.before),before.0);
            assert_eq!(id(&inspect(&observer,&p,false).unwrap()),before.0);
            assert!(!pending(&observer).unwrap());
            let m=v.mark().unwrap();
            assert!(pending(&observer).unwrap());
            let pending_rc=rc(independent(&p),"pending reopen",&[5,32,303]);
            drop(observer);
            assert_eq!(m.finish().unwrap(),Completion::Removed);
            assert_eq!(rc(independent(&p),"independent absence",&[2]),2);
            assert_eq!(matching_entries(&f.parent,w).unwrap(),0);
            assert_eq!(snapshot(&neighbor),neighbor_before);assert_eq!(snapshot(&unknown),unknown_before);
            println!("D2_CORE_REMOVED name={} id={:?} pending=true pending_reopen={pending_rc} absence=2 enum_absent=true neighbor_preserved=true",w.name(),before.0);
        }

        let w=Launcher::Start;let p=f.path(w);f.seed(w);let original=snapshot(&p);
        let writer=OpenOptions::new().write(true).share_mode(ALL_SHARES).open(&p).unwrap();
        assert_eq!(fault(f.admit(w),"LEAF_OPEN",Some(32)).mutation,Mutation::None);drop(writer);
        let reader=OpenOptions::new().read(true).share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE).open(&p).unwrap();
        fault(f.admit(w),"LEAF_OPEN",Some(32));drop(reader);
        assert_eq!(snapshot(&p),original);
        // Actual read-only access handle lacks DELETE; not a substitute for
        // the separate fully validated DELETE handle disposition failure.
        let reader=independent(&p).unwrap();
        assert_eq!(rc(disposition(&reader),"no DELETE access",&[5]),5);
        assert!(!pending(&reader).unwrap());drop(reader);
        let mut permissions=fs::metadata(&p).unwrap().permissions();permissions.set_readonly(true);
        fs::set_permissions(&p,permissions).unwrap();
        let before=snapshot(&p);let v=f.ready(w);
        let observer=independent(&p).unwrap();
        let error=fault(v.mark(),"DISPOSITION_FAILED",Some(5));
        assert_eq!(error.mutation,Mutation::DispositionFailed{pending:Some(false)});
        assert!(!pending(&observer).unwrap());drop(observer);
        assert_eq!(snapshot(&p),before);assert!(fs::metadata(&p).unwrap().permissions().readonly());
        let mut permissions=fs::metadata(&p).unwrap().permissions();permissions.set_readonly(false);
        fs::set_permissions(&p,permissions).unwrap();assert_eq!(snapshot(&p),original);
        println!("D2_CORE_ACCESS old_writer=32 no_delete_share=32 no_delete_access=5 readonly_disposition=5 pending=false same_id_bytes=true");

        // Independent scoped thread runs while the real Verified object owns
        // the handles. No sleeps, fabricated kernel errors or timing guesses.
        let replacement=f.parent.join("replacement.cmd");fs::write(&replacement,b"replacement sentinel").unwrap();
        let replacement_before=snapshot(&replacement);
        let mut v=f.ready(w);
        let codes=std::thread::scope(|s|s.spawn(||{
            let write=rc(OpenOptions::new().write(true).share_mode(ALL_SHARES).open(&p),"write",&[32]);
            let rename=rc(fs::rename(&p,f.parent.join("moved.cmd")),"rename",&[5,32]);
            let replace=rc(fs::rename(&replacement,&p),"replace",&[5,32]);
            let parent=rc(fs::rename(&f.parent,f.base.join("moved-parent")),"parent",&[5,32]);
            let ancestor=rc(fs::rename(&f.base,f.base.with_extension("moved")),"ancestor",&[5,32]);
            (write,rename,replace,parent,ancestor)
        }).join().unwrap());
        v.recheck().unwrap();assert_eq!(snapshot(&p),original);assert_eq!(snapshot(&replacement),replacement_before);
        assert_eq!(v.mark().unwrap().finish().unwrap(),Completion::Removed);
        assert_eq!(snapshot(&replacement),replacement_before);
        println!("D2_CORE_COMPETITION write={} rename={} replace={} parent={} ancestor={} same_id_bytes=true replacement_preserved=true",codes.0,codes.1,codes.2,codes.3,codes.4);
        remove_own(&replacement);

        // An extra independently retained handle can postpone final absence.
        // The result must report indeterminate completion, not Removed.
        f.seed(w);let v=f.ready(w);let observer=independent(&p).unwrap();
        let m=v.mark().unwrap();assert!(pending(&observer).unwrap());
        let uncertain=match m.finish(){Err(e)=>e,Ok(_)=>panic!("pending handle misreported as removed")};
        assert_eq!(uncertain.mutation,Mutation::PendingOrUnknown);
        assert!(matches!(uncertain.phase,"ABSENCE_UNKNOWN"|"NAME_STILL_EXISTS"|"NAME_STILL_ENUMERATED"),"{uncertain:?}");
        if uncertain.phase=="ABSENCE_UNKNOWN"{assert!(matches!(uncertain.win32,Some(5|32|303)));}
        assert!(pending(&observer).unwrap());drop(observer);
        assert_eq!(rc(independent(&p),"final observer closed",&[2]),2);
        println!("D2_CORE_PENDING_UNKNOWN actual={uncertain:?} observer_pending=true no_path_retry=true");

        // All unknown/other-install candidates survive. Only known fixture
        // artifacts are cleaned by the test, never by the production core.
        for bytes in [launcher_template(&f.neighbor,w.name()).unwrap().into_bytes(),
            b"@echo off\r\nrem custom user command\r\n".to_vec(),
            {let mut b=f.bytes(w);b.extend_from_slice(b"rem near match\r\n");b}]{
            fs::write(&p,&bytes).unwrap();let keep=snapshot(&p);unowned(f.admit(w));assert_eq!(snapshot(&p),keep);
        }
        fs::write(&p,vec![b'x';(MAX_LAUNCHER_BYTES+1) as usize]).unwrap();
        unowned(f.admit(w));assert_eq!(fs::metadata(&p).unwrap().len(),MAX_LAUNCHER_BYTES+1);
        remove_own(&p);
        fault(Verified::open(&f.root,&f.parent,"custom.cmd"),"NAME_NOT_ALLOWED",None);
        assert_eq!(snapshot(&unknown),unknown_before);
        fs::create_dir(&p).unwrap();fault(f.admit(w),"OBJECT_TYPE_OR_ID",None);fs::remove_dir(&p).unwrap();
        f.seed(w);let original=snapshot(&p);
        let link=f.neighbor.join("hardlink.cmd");fs::hard_link(&p,&link).unwrap();
        fault(f.admit(w),"OBJECT_TYPE_OR_ID",None);
        assert_eq!(fs::read(&link).unwrap(),original.1);assert_eq!(fs::read(&p).unwrap(),original.1);
        remove_own(&link);assert_eq!(snapshot(&p),original);
        let ads=PathBuf::from(format!("{}:extra",p.display()));fs::write(&ads,b"named stream").unwrap();
        fault(f.admit(w),"ALTERNATE_STREAM",None);
        assert_eq!(fs::read(&ads).unwrap(),b"named stream");remove_own(&ads);
        let dir_ads=PathBuf::from(format!("{}:extra",f.parent.display()));fs::write(&dir_ads,b"directory stream").unwrap();
        fault(f.admit(w),"ALTERNATE_STREAM",None);
        assert_eq!(fs::read(&dir_ads).unwrap(),b"directory stream");remove_own(&dir_ads);
        let alias=f.parent.join("..").join("fixture-launchers");
        fault(Verified::open(&f.root,&alias,w.name()),"PATH_FORM",None);
        let target=f.neighbor.join(Launcher::Uninstall.name());
        fs::write(&target,f.bytes(Launcher::Uninstall)).unwrap();let target_before=snapshot(&target);
        let leaf=f.path(Launcher::Uninstall);
        std::os::windows::fs::symlink_file(&target,&leaf).unwrap();
        fault(f.admit(Launcher::Uninstall),"OBJECT_TYPE_OR_ID",None);
        assert_eq!(snapshot(&target),target_before);remove_own(&leaf);
        let real=f.base.join("saved-parent");fs::rename(&f.parent,&real).unwrap();
        let cmd=PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("cmd.exe");
        let out=std::process::Command::new(cmd).args(["/D","/C","mklink","/J"])
            .arg(&f.parent).arg(&f.neighbor).output().unwrap();
        assert!(out.status.success(),"{out:?}");
        fault(f.admit(w),"OBJECT_TYPE_OR_ID",None);
        assert_eq!(snapshot(&neighbor),neighbor_before);
        fs::remove_dir(&f.parent).unwrap();fs::rename(&real,&f.parent).unwrap();
        assert_eq!(snapshot(&p),original);
        println!("D2_CORE_NONOWNED other_install=true custom=true near_template=true oversize=true name=true directory=true hardlink=true symlink=true junction=true leaf_ads=true parent_ads=true traversal=true preserved=true");

        // Same-account descriptor mutation on this new isolated object.
        // A random unmapped SID does not grant a real account access.
        // Metadata-only WRITE_DAC opens are NOT fenced by share mode; the
        // actual descriptor recheck must stop before disposition.
        let metadata=OpenOptions::new().access_mode(READ_CONTROL|0x40000|FILE_READ_ATTRIBUTES)
            .share_mode(ALL_SHARES).custom_flags(FLAGS).open(&p).unwrap();
        let old=acl(&metadata).unwrap();let v=f.ready(w);
        let mut nonce=[0u8;16];SystemRandom::new().fill(&mut nonce).unwrap();
        let ns:Vec<_>=nonce.chunks_exact(4).map(|b|u32::from_le_bytes(b.try_into().unwrap())).collect();
        let sid=format!("S-1-5-21-{}-{}-{}-{}",ns[0],ns[1],ns[2],ns[3]);
        // Explicit protected DACL for known fixture only, retains Admin/SYSTEM
        // access and adds one synthetic ACE; no real OS/desktop ACL touched.
        let widened=format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})");
        let wide:Vec<u16>=widened.encode_utf16().chain(Some(0)).collect();
        let mut sd=null_mut();
        assert_ne!(unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(),SDDL_REVISION_1,&mut sd,null_mut())},0);
        let _sd=Local(sd.cast());let mut present=0;let mut defaulted=0;let mut dacl=null_mut();
        assert_ne!(unsafe{GetSecurityDescriptorDacl(sd,&mut present,&mut dacl,&mut defaulted)},0);
        assert_ne!(present,0);assert!(!dacl.is_null());
        let apply=|dacl|unsafe{SetSecurityInfo(metadata.as_raw_handle(),SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),null_mut(),dacl,null_mut())};
        let code=apply(dacl);
        assert_eq!(code,0);
        let actual=acl(&metadata).unwrap();assert_ne!(actual,old);assert!(actual.contains(&sid));
        let error=fault(v.mark(),"LEAF_CHANGED",None);assert_eq!(error.mutation,Mutation::None);
        assert!(!pending(&metadata).unwrap());
        assert_eq!(snapshot(&p),original);
        let no_control=OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).share_mode(ALL_SHARES).custom_flags(FLAGS).open(&p).unwrap();
        let e=fault(acl(&no_control),"ACL_QUERY",Some(5));assert_eq!(e.mutation,Mutation::None);drop(no_control);
        // An OWNER RIGHTS ACE removes the owner's implicit READ_CONTROL;
        // deny that access explicitly for this test file. Keep the original
        // WRITE_DAC handle so the exact fixture can be restored without
        // exercising a privileged ACL repair pathway in the core.
        let restrict:Vec<u16>="D:P(D;;RC;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
            .encode_utf16().chain(Some(0)).collect();
        let mut restricted_sd=null_mut();
        assert_ne!(unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(restrict.as_ptr(),
            SDDL_REVISION_1,&mut restricted_sd,null_mut())},0);
        let _restricted=Local(restricted_sd.cast());
        let mut restricted_acl=null_mut();
        assert_ne!(unsafe{GetSecurityDescriptorDacl(restricted_sd,&mut present,&mut restricted_acl,&mut defaulted)},0);
        assert_ne!(present,0);assert!(!restricted_acl.is_null());
        assert_eq!(apply(restricted_acl),0);
        let restricted_actual=acl(&metadata).unwrap();
        assert_ne!(restricted_actual,actual);
        let denied=fault(f.admit(w),"LEAF_OPEN",Some(5));
        assert_eq!(denied.mutation,Mutation::None);
        assert!(!pending(&metadata).unwrap());
        assert_eq!(apply(dacl),0);assert_eq!(acl(&metadata).unwrap(),actual);drop(metadata);
        assert_eq!(snapshot(&p),original);
        println!("D2_CORE_ACL actual_changed=true old={old:?} changed={actual:?} restricted={restricted_actual:?} same_id_bytes=true pending=false no_read_control=5 restricted_open=5 same_admin_only=true");
        remove_own(&p);remove_own(&unknown);remove_own(&neighbor);remove_own(&target);
        f.cleanup();
        writeln!(std::io::stdout().lock(),"D2_CORE_COMPLETE real_core=true fixed_launchers=2 same_object_disposition=true independent_absence=true readonly_failure=true pending_unknown=true source_competition=true acl_change_rejected=true no_production_caller=true maintenance_authorized=false recovery_proven=false cross_sid_not_run=true").unwrap();
    }
}
