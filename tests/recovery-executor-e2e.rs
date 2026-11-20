//! Independent controller for the actual standalone candidate builder.
//! All executable fixtures are locally compiled from checked-in benign Rust.
//! This is neither a production supply-chain check nor a real product restore.
#![cfg(all(windows,feature="recovery-core"))]
use std::{
    collections::{BTreeMap,BTreeSet},ffi::OsStr,fs::{self,File,OpenOptions},
    io::{self,BufRead,BufReader,Read,Write},
    os::windows::{ffi::OsStrExt,fs::OpenOptionsExt,io::{AsRawHandle,FromRawHandle}},
    path::{Path,PathBuf},process::{Child,Command,ExitStatus,Stdio},
    sync::mpsc,thread::{self,JoinHandle},time::{Duration,Instant},ptr::null_mut,
};
use ring::rand::{SecureRandom,SystemRandom};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use windows_sys::Win32::{
    Foundation::{LocalFree,INVALID_HANDLE_VALUE,GENERIC_READ,GENERIC_WRITE},
    Security::{SECURITY_ATTRIBUTES,OWNER_SECURITY_INFORMATION,DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,GetSecurityDescriptorDacl},
    Security::Authorization::{GetSecurityInfo,SetSecurityInfo,SE_FILE_OBJECT,
        ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertSecurityDescriptorToStringSecurityDescriptorW,SDDL_REVISION_1},
    Storage::FileSystem::{CreateDirectoryW,CreateFileW,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,
        GetFileInformationByHandle,GetFinalPathNameByHandleW,GetFileType,FILE_TYPE_DISK,
        BY_HANDLE_FILE_INFORMATION,FILE_READ_ATTRIBUTES,DELETE,FILE_SHARE_READ,
        FILE_FLAG_BACKUP_SEMANTICS,FILE_FLAG_OPEN_REPARSE_POINT},
    System::{Com::CoTaskMemFree,Threading::WaitForSingleObject},
    UI::Shell::{SHGetKnownFolderPath,FOLDERID_ProgramFiles},
};
const NAMES:[&str;4]=["spidervpn.exe","WebView2Loader.dll","sing-box.exe","sing-box.LICENSE.txt"];
const MANIFEST:&str="manifest.json";
const ACL:&str="O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
const FLAGS:u32=FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT;
const READ_CONTROL:u32=0x20000;
const ALL_SHARES:u32=7;
type Id=(u32,u32,u32);
type Expected=BTreeMap<&'static str,Vec<u8>>;
fn hash(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn wide(s:&OsStr)->Vec<u16>{s.encode_wide().chain(Some(0)).collect()}
fn nonce()->String{let mut b=[0u8;16];SystemRandom::new().fill(&mut b).unwrap();b.iter().map(|x|format!("{x:02x}")).collect()}
fn program_files()->PathBuf{
    let mut p=null_mut();
    let hr=unsafe{SHGetKnownFolderPath(&FOLDERID_ProgramFiles,0,null_mut(),&mut p)};
    assert!(hr>=0&&!p.is_null(),"known folder {hr:#x}");
    let mut n=0;while n<32768&&unsafe{*p.add(n)}!=0{n+=1;}
    assert!(n<32768);
    let path=PathBuf::from(String::from_utf16(unsafe{std::slice::from_raw_parts(p,n)}).unwrap());
    unsafe{CoTaskMemFree(p.cast());}path
}
struct Local(*mut core::ffi::c_void);
impl Drop for Local{fn drop(&mut self){if !self.0.is_null(){unsafe{LocalFree(self.0);}}}}
fn with_sd<T>(s:&str,f:impl FnOnce(&SECURITY_ATTRIBUTES)->T)->T{
    let mut sd=null_mut();
    assert_ne!(unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(OsStr::new(s)).as_ptr(),
        SDDL_REVISION_1,&mut sd,null_mut())},0,"{}",io::Error::last_os_error());
    let _guard=Local(sd.cast());
    f(&SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor:sd,bInheritHandle:0})
}
fn new_dir(p:&Path){
    let ok=with_sd(ACL,|sa|unsafe{CreateDirectoryW(wide(p.as_os_str()).as_ptr(),sa)});
    assert_ne!(ok,0,"atomic test dir {p:?}: {}",io::Error::last_os_error());
    dir_id(p);
}
fn new_file(p:&Path,b:&[u8]){
    let h=with_sd(ACL,|sa|unsafe{CreateFileW(wide(p.as_os_str()).as_ptr(),
        GENERIC_READ|GENERIC_WRITE|READ_CONTROL,FILE_SHARE_READ,sa,CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,null_mut())});
    assert_ne!(h,INVALID_HANDLE_VALUE,"atomic test file {p:?}: {}",io::Error::last_os_error());
    let mut f=unsafe{File::from_raw_handle(h)};
    f.write_all(b).unwrap();f.sync_all().unwrap();
    assert_eq!(info(&f,p,false).1,b.len() as u64);exact_acl(&f);
}
fn open(p:&Path)->File{OpenOptions::new().read(true).share_mode(FILE_SHARE_READ)
    .custom_flags(FLAGS).open(p).unwrap_or_else(|e|panic!("open {p:?}: {e}"))}
fn info(f:&File,p:&Path,dir:bool)->(Id,u64){
    let mut i:BY_HANDLE_FILE_INFORMATION=unsafe{std::mem::zeroed()};
    assert_eq!(unsafe{GetFileType(f.as_raw_handle())},FILE_TYPE_DISK);
    assert_ne!(unsafe{GetFileInformationByHandle(f.as_raw_handle(),&mut i)},0);
    assert_eq!(i.dwFileAttributes&0x440,0,"no reparse or device {p:?}");
    assert_eq!(i.dwFileAttributes&0x10!=0,dir);
    if !dir{assert_eq!(i.nNumberOfLinks,1);}
    assert_ne!((i.nFileIndexHigh,i.nFileIndexLow),(0,0));
    let mut b=vec![0u16;32768];
    let n=unsafe{GetFinalPathNameByHandleW(f.as_raw_handle(),b.as_mut_ptr(),b.len() as u32,0)} as usize;
    assert!(n>0&&n<b.len());
    let actual=String::from_utf16(&b[..n]).unwrap();
    assert!(actual.strip_prefix(r"\\?\").unwrap().eq_ignore_ascii_case(p.to_str().unwrap()),"{actual:?} != {p:?}");
    ((i.dwVolumeSerialNumber,i.nFileIndexHigh,i.nFileIndexLow),(u64::from(i.nFileSizeHigh)<<32)|u64::from(i.nFileSizeLow))
}
fn sddl(f:&File)->String{
    let mut sd=null_mut();let mut text=null_mut();let mut n=0;
    assert_eq!(unsafe{GetSecurityInfo(f.as_raw_handle(),SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,null_mut(),null_mut(),null_mut(),null_mut(),&mut sd)},0);
    assert!(!sd.is_null());let _sd=Local(sd.cast());
    assert_ne!(unsafe{ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut text,&mut n)},0);
    assert!(!text.is_null()&&n>0&&n<=65536);let _text=Local(text.cast());
    let mut b=Vec::new();
    for j in 0..n as usize{
        let c=unsafe{*text.add(j)};
        if c==0{return String::from_utf16(&b).unwrap();}
        b.push(c);
    }
    panic!("SDDL missing terminator")
}
fn exact_acl(f:&File){let s=sddl(f);assert!(s==ACL||s==ACL.replace("D:P","D:PAI"),"{s:?}");}
fn dir_id(p:&Path)->Id{let f=open(p);exact_acl(&f);info(&f,p,true).0}
fn names(p:&Path)->BTreeSet<String>{
    fs::read_dir(p).unwrap().map(|e|e.unwrap().file_name().into_string().unwrap()).collect()
}
#[derive(Debug,PartialEq,Eq,Clone)]
struct Snap{id:Id,len:u64,sha:String}
fn readback(p:&Path,expected:&[u8],protected:bool)->Snap{
    let mut f=open(p);
    let (id,len)=info(&f,p,false);assert_eq!(len,expected.len() as u64,"{p:?}");
    if protected{exact_acl(&f);}
    let mut h=Sha256::new();
    let mut buf=[0u8;65536];
    for chunk in expected.chunks(buf.len()){
        f.read_exact(&mut buf[..chunk.len()]).unwrap();
        assert!(&buf[..chunk.len()]==chunk,"independent bytes mismatch {p:?}");
        h.update(&buf[..chunk.len()]);
    }
    assert_eq!(f.read(&mut buf[..1]).unwrap(),0);
    assert_eq!(info(&f,p,false),(id,len));
    if protected{exact_acl(&f);}
    Snap{id,len,sha:format!("{:x}",h.finalize())}
}
fn set_dacl(p:&Path,new:&str){
    let f=OpenOptions::new().access_mode(READ_CONTROL|0x40000)
        .share_mode(ALL_SHARES).custom_flags(FLAGS).open(p).unwrap();
    with_sd(new,|sa|{
        let mut present=0;let mut defaulted=0;let mut dacl=null_mut();
        assert_ne!(unsafe{GetSecurityDescriptorDacl(sa.lpSecurityDescriptor,&mut present,&mut dacl,&mut defaulted)},0);
        assert_ne!(present,0);assert!(!dacl.is_null());
        let rc=unsafe{SetSecurityInfo(f.as_raw_handle(),SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),null_mut(),dacl,null_mut())};
        assert_eq!(rc,0);
    });
}
fn manifest(e:&Expected,sha:&str)->Value{
    let entries:Vec<_>=NAMES.iter().map(|n|json!({"path":n,"size":e[n].len(),"sha256":hash(&e[n])})).collect();
    json!({"schema":1,"kind":"unapproved-recovery-candidate","sourceSha":sha,"files":entries})
}
fn replace_known(p:&Path,old:&[u8],new:&[u8]){
    // Controller only edits its own explicitly verified fixture files.
    let snap=readback(p,old,true);
    let mut f=OpenOptions::new().write(true).share_mode(FILE_SHARE_READ).custom_flags(FLAGS).open(p).unwrap();
    assert_eq!(info(&f,p,false).0,snap.id);exact_acl(&f);
    f.set_len(0).unwrap();f.write_all(new).unwrap();f.sync_all().unwrap();
    drop(f);assert_eq!(readback(p,new,true).id,snap.id);
}
fn verify_vault(vault:&Path,e:&Expected,raw:&[u8])->BTreeMap<String,Snap>{
    let mut out=BTreeMap::new();
    for n in NAMES.into_iter().chain([MANIFEST]){
        let expected=if n==MANIFEST{raw}else{&e[n]};
        let s=readback(&vault.join(n),expected,true);
        println!("D3_VAULT_READBACK name={n} id={:?} size={} sha256={} exact_acl=true independent_expected=true",s.id,s.len,s.sha);
        out.insert(n.to_string(),s);
    }
    assert_eq!(names(vault),out.keys().cloned().collect());
    out
}
fn remove_known(p:&Path,expected:&[u8],s:&Snap){
    assert_eq!(&readback(p,expected,true),s);
    fs::remove_file(p).unwrap();
}
fn rc<T>(res:io::Result<T>,label:&str,wants:&[i32])->i32{
    let e=match res{Ok(_)=>panic!("{label} unexpected success"),Err(e)=>e};
    let code=e.raw_os_error().unwrap();assert!(wants.contains(&code),"{label}: {e}");code
}
struct Proc{
    child:Child,pid:u32,lines:mpsc::Receiver<String>,
    stdout:Option<JoinHandle<String>>,stderr:Option<JoinHandle<String>>,
}
struct Run{pid:u32,status:ExitStatus,out:String,err:String}
impl Run{fn all(&self)->String{format!("{}\n{}",self.out,self.err)}}
impl Drop for Proc{fn drop(&mut self){
    if !matches!(self.child.try_wait(),Ok(Some(_))){let _=self.child.kill();let _=self.child.wait();}
}}
impl Proc{
    fn start(c:&mut Command)->Self{
        let mut child=c.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let pid=child.id();let reader=child.stdout.take().unwrap();let errors=child.stderr.take().unwrap();
        let (tx,lines)=mpsc::channel();
        let stdout=thread::spawn(move||{
            let mut s=String::new();
            for line in BufReader::new(reader).lines(){
                let line=line.unwrap();assert!(s.len()+line.len()<512*1024);
                let _=tx.send(line.clone());s.push_str(&line);s.push('\n');
            }
            s
        });
        let stderr=thread::spawn(move||{
            let mut b=Vec::new();errors.take(256*1024+1).read_to_end(&mut b).unwrap();
            assert!(b.len()<=256*1024);String::from_utf8_lossy(&b).into_owned()
        });
        Self{child,pid,lines,stdout:Some(stdout),stderr:Some(stderr)}
    }
    fn collect(mut self)->Run{
        let status=self.child.wait().unwrap();
        let out=self.stdout.take().unwrap().join().unwrap();
        let err=self.stderr.take().unwrap().join().unwrap();
        Run{pid:self.pid,status,out,err}
    }
    fn wait_code(&self,ms:u32)->u32{unsafe{WaitForSingleObject(self.child.as_raw_handle(),ms)}}
    fn finish(mut self,ms:u32)->Run{
        let code=self.wait_code(ms);
        if code!=0{
            let e=if code==u32::MAX{Some(io::Error::last_os_error())}else{None};
            self.child.kill().unwrap();let killed=self.collect();
            panic!("child timeout/failure wait={code} native={e:?} pid={} exit={:?} {}",killed.pid,killed.status.code(),killed.all());
        }
        self.collect()
    }
    fn kill(mut self)->Run{self.child.kill().unwrap();self.collect()}
}
fn run(c:&mut Command,ms:u32)->Run{Proc::start(c).finish(ms)}
fn recovery(exe:&Path,digest:&str,sha:&str,cwd:&Path)->Command{
    let mut c=Command::new(exe);
    c.args(["--manifest-sha256",digest,"--source-sha",sha]).current_dir(cwd)
        .env_remove("SPIDERVPN_ROOT").stdin(Stdio::null());c
}
fn gen_from(run:&Run,work:&Path)->PathBuf{
    let prefix=format!("RECOVERY_GENERATION_UNREADY pid={} path=",run.pid);
    let p=PathBuf::from(run.out.lines().find_map(|l|l.strip_prefix(&prefix)).expect("real generation marker"));
    assert_eq!(p.parent(),Some(work));
    let n=p.file_name().unwrap().to_str().unwrap().strip_prefix("unready-").unwrap();
    assert_eq!(n.len(),32);assert!(n.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)));
    p
}
fn recover(exe:&Path,raw:&[u8],sha:&str,work:&Path,cwd:&Path)->PathBuf{
    let result=run(&mut recovery(exe,&hash(raw),sha,cwd),120000);
    assert_eq!(result.status.code(),Some(0),"{}",result.all());
    assert!(result.out.contains(&format!("RECOVERY_CONTENT_MATCH files=4 pid={} source_sha={sha} manifest_sha256={}",result.pid,hash(raw))));
    assert!(result.out.contains("source_authenticated=false production_recovery_proven=false maintenance_authorized=false"));
    let p=gen_from(&result,work);
    println!("D3_RECOVERY_PROCESS pid={} exit=0 sha={sha} independent_exe={exe:?} generation={p:?}",result.pid);
    p
}
fn refuse(exe:&Path,digest:&str,sha:&str,cwd:&Path,work:&Path,want:&str){
    let before=if work.exists(){Some(names(work))}else{None};
    let result=run(&mut recovery(exe,digest,sha,cwd),120000);
    assert_eq!(result.status.code(),Some(1),"{}",result.all());
    let msg=result.err.lines().find(|l|l.contains("RECOVERY_REFUSED")).unwrap();
    assert!(msg.contains(want),"expected {want}: {msg}");
    assert!(!result.out.contains("RECOVERY_CONTENT_MATCH")&&!result.out.contains("RECOVERY_GENERATION_UNREADY"));
    assert_eq!(before,if work.exists(){Some(names(work))}else{None});
    println!("D3_REFUSED pid={} exit=1 expected={want} actual={msg}",result.pid);
}
struct Group{path:PathBuf,id:Id,files:BTreeMap<String,Snap>}
fn check_group(path:&Path,e:&Expected,source:&BTreeMap<String,Snap>)->Group{
    let id=dir_id(path);
    let mut files=BTreeMap::new();let mut seen=BTreeSet::from([id]);
    for n in NAMES{
        let s=readback(&path.join(n),&e[n],true);
        let src=&source[n];
        assert!(!source.values().any(|v|v.id==s.id));assert_eq!(s.id.0,src.id.0);assert!(seen.insert(s.id));
        assert_eq!(s.sha,src.sha);assert_eq!(s.len,src.len);
        println!("D3_READBACK name={n} source_id={:?} target_id={:?} size={} sha256={} exact_acl=true independent_expected=true",src.id,s.id,s.len,s.sha);
        files.insert(n.to_string(),s);
    }
    assert_eq!(names(path),files.keys().cloned().collect());
    Group{path:path.to_owned(),id,files}
}
fn check_preserved(g:&Group,e:&Expected){
    assert_eq!(dir_id(&g.path),g.id);assert_eq!(names(&g.path),g.files.keys().cloned().collect());
    for (n,s) in &g.files{assert_eq!(&readback(&g.path.join(n),&e[n.as_str()],true),s);}
}
fn clean_group(g:Group,e:&Expected){
    check_preserved(&g,e);
    for (n,s) in &g.files{remove_known(&g.path.join(n),&e[n.as_str()],s);}
    assert_eq!(dir_id(&g.path),g.id);fs::remove_dir(g.path).unwrap();
}
fn run_group(g:&Group,e:&Expected,cwd:&Path,broken:bool){
    check_preserved(g,e);
    // Keep authenticated candidate files open with no write/delete share
    // while running. The fixtures never consult the old group or PATH.
    let _held:Vec<_>=g.files.keys().map(|n|open(&g.path.join(n))).collect();
    let client=g.path.join(NAMES[0]);
    let c=run(Command::new(&client).current_dir(cwd).stdin(Stdio::null()),20000);
    if broken{
        assert_eq!(c.status.code(),Some(41),"{}",c.all());
        assert!(c.err.contains(&format!("D3_CLIENT_DLL_FAILED pid={} win32=Some(126)",c.pid)),"{}",c.all());
        println!("D3_ACTUAL_DLL_FAILURE pid={} exit=41 {}",c.pid,c.err.trim());
    }else{
        assert_eq!(c.status.code(),Some(0),"{}",c.all());
        assert!(c.out.contains(&format!("D3_CLIENT_DLL_OK pid={} value=0x53504433 exe={} loaded={}",c.pid,client.display(),g.path.join(NAMES[1]).display())),"{}",c.all());
        println!("D3_ACTUAL_CLIENT pid={} exit=0 {}",c.pid,c.out.trim());
    }
    let engine=g.path.join(NAMES[2]);
    let p=run(Command::new(&engine).current_dir(cwd).stdin(Stdio::null()),20000);
    assert_eq!(p.status.code(),Some(0),"{}",p.all());
    assert!(p.out.contains(&format!("D3_ENGINE_OK pid={} fixture=0x454e4733 exe={}",p.pid,engine.display())),"{}",p.all());
    println!("D3_ACTUAL_ENGINE pid={} exit=0 {}",p.pid,p.out.trim());
}
fn compile_fixtures(out:&Path)->Expected{
    let rustc=PathBuf::from(std::env::var_os("SPIDER_RECOVERY_TEST_RUSTC").expect("explicit workflow rustc"));
    let target=std::env::var("SPIDER_RECOVERY_TEST_TARGET").unwrap();
    assert!(rustc.is_absolute()&&matches!(target.as_str(),"x86_64-pc-windows-msvc"|"x86_64-pc-windows-gnu"));
    let v=Command::new(&rustc).arg("-vV").output().unwrap();
    assert!(v.status.success());println!("D3_FIXTURE_TOOLCHAIN target={target} {}",String::from_utf8_lossy(&v.stdout));
    let src=Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut result=Expected::new();
    for (file,name,kind) in [("recovery_client.rs",NAMES[0],"bin"),("recovery_dll.rs",NAMES[1],"cdylib"),("recovery_engine.rs",NAMES[2],"bin")]{
        let p=out.join(name);
        let o=Command::new(&rustc).arg(src.join(file)).args(["--edition=2021","--crate-type",kind,"--target",&target,"-C","opt-level=1","-C","debuginfo=0"])
            .arg("-o").arg(&p).output().unwrap();
        assert!(o.status.success(),"fixture compile {}: {}",name,String::from_utf8_lossy(&o.stderr));
        let bytes=fs::read(&p).unwrap();assert!(bytes.starts_with(b"MZ"));println!("D3_FIXTURE_COMPILED name={name} sha256={}",hash(&bytes));
        result.insert(name,bytes);
    }
    result.insert(NAMES[3],b"CI-only harmless engine fixture license sentinel\n".to_vec());
    result
}

fn raw_manifest(v:&Value)->Vec<u8>{serde_json::to_vec(v).unwrap()}
fn partial_group(path:&Path,e:&Expected)->Group{
    let id=dir_id(path);let mut files=BTreeMap::new();
    for n in names(path){
        assert!(NAMES.contains(&n.as_str()),"unexpected interrupted output {n}");
        let p=path.join(&n);let len=fs::metadata(&p).unwrap().len() as usize;
        assert!(len<=e[n.as_str()].len());
        let snap=readback(&p,&e[n.as_str()][..len],true);
        println!("D3_INTERRUPTED_READBACK name={n} id={:?} len={} hash={} expected_prefix=true",snap.id,snap.len,snap.sha);
        files.insert(n,snap);
    }
    Group{path:path.to_owned(),id,files}
}
fn partial_preserved(g:&Group,e:&Expected){
    assert_eq!(dir_id(&g.path),g.id);assert_eq!(names(&g.path),g.files.keys().cloned().collect());
    for(n,s)in &g.files{assert_eq!(&readback(&g.path.join(n),&e[n.as_str()][..s.len as usize],true),s);}
}
fn clean_partial(g:Group,e:&Expected){
    partial_preserved(&g,e);
    for(n,s)in &g.files{remove_known(&g.path.join(n),&e[n.as_str()][..s.len as usize],s);}
    assert_eq!(dir_id(&g.path),g.id);fs::remove_dir(g.path).unwrap();
}
// Real copy progress, independent metadata observation, active source
// competition, then interruption. No production wait or fault-injection flag.
fn interrupt(exe:&Path,raw:&[u8],sha:&str,work:&Path,vault:&Path,cwd:&Path,e:&Expected,
    neighbor:&Path,neighbor_expected:&[u8])->(Group,bool){
    let mut child=Proc::start(&mut recovery(exe,&hash(raw),sha,cwd));
    let pid=child.pid;let start=Instant::now();let limit=Duration::from_secs(120);
    let gen_prefix=format!("RECOVERY_GENERATION_UNREADY pid={pid} path=");
    let target_marker=format!("RECOVERY_COPY_TARGET name={} pid={pid}",NAMES[3]);
    let copy_prefix=format!("RECOVERY_COPY_STARTED pid={pid} ");
    let mut generation=None;
    let mut license=false;
    let mut observed=None;
    loop{
        let line=match child.lines.recv_timeout(limit.saturating_sub(start.elapsed())){
            Ok(l)=>l,
            Err(mpsc::RecvTimeoutError::Disconnected)=>break,
            Err(mpsc::RecvTimeoutError::Timeout)=>{
                let killed=child.kill();panic!("copy observation timed out; reaped pid={} exit={:?} {}",killed.pid,killed.status.code(),killed.all());
            }
        };
        if let Some(p)=line.strip_prefix(&gen_prefix){
            let p=PathBuf::from(p);assert_eq!(p.parent(),Some(work));
            let n=p.file_name().unwrap().to_str().unwrap().strip_prefix("unready-").unwrap();
            assert_eq!(n.len(),32);assert!(n.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)));
            generation=Some(p);
        }
        if line==target_marker{license=true;}
        if license&&line.starts_with(&copy_prefix){
            let path=generation.as_ref().unwrap().join(NAMES[3]);
            // Metadata-only query of actual open destination; check child
            // still running, never treat a progress log alone as partial I/O.
            if child.child.try_wait().unwrap().is_none(){
                let metadata=OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES)
                    .share_mode(ALL_SHARES).custom_flags(FLAGS).open(&path);
                if let Ok(f)=metadata{
                    let (_,len)=info(&f,&path,false);
                    if len>0&&len<e[NAMES[3]].len() as u64{
                        observed=Some(len);drop(f);
                        break;
                    }
                }
            }
        }
    }
    let p=generation.expect("actual generation was created");
    let result;
    if let Some(len)=observed{
        // Still in live copy; use actual source operations while original
        // verified source handles are held by the independent process.
        assert!(child.child.try_wait().unwrap().is_none());
        let target=vault.join(NAMES[0]);
        let write=rc(OpenOptions::new().write(true).share_mode(ALL_SHARES).open(&target),"active write",&[32]);
        let rename=rc(fs::rename(&target,vault.join("moved-client.exe")),"active rename",&[32,5]);
        let replace=rc(fs::rename(neighbor,&target),"active replace",&[32,5]);
        let parent=rc(fs::rename(vault,vault.with_extension("moved")),"active parent rename",&[32,5]);
        assert!(child.child.try_wait().unwrap().is_none(),"copy finished before controlled interruption");
        println!("D3_ACTIVE_COMPETITION pid={pid} observed_partial_bytes={len} write={write} rename={rename} replace={replace} parent={parent}");
        result=child.kill();assert!(!result.status.success());
    }else{
        // No invented evidence: this runner may finish before observation.
        result=child.finish(120000);
        assert!(result.status.success(),"{}",result.all());
    }
    assert_eq!(gen_from(&result,work),p);
    let g=partial_group(&p,e);
    assert_eq!(fs::read(neighbor).unwrap(),neighbor_expected);
    let actual_partial=g.files.get(NAMES[3]).is_some_and(|s|s.len>0&&s.len<e[NAMES[3]].len() as u64);
    let real=observed.is_some()&&actual_partial&&!result.status.success()&&!result.out.contains("RECOVERY_CONTENT_MATCH");
    if real{
        println!("D3_ACTUAL_INTERRUPT pid={pid} exit={:?} observed_bytes={} retained_partial_bytes={} generation={p:?} child_reaped=true no_content_match=true",
            result.status.code(),observed.unwrap(),g.files[NAMES[3]].len);
    }else{
        println!("D3_ACTUAL_INTERRUPT NOT_RUN pid={pid} exit={:?} observed={observed:?} retained_partial={actual_partial} reason=unable_to_capture_incomplete_generation",result.status.code());
    }
    (g,real)
}
#[test]
fn real_independent_recovery_executor(){
    let sha=std::env::var("SPIDER_RECOVERY_TEST_SOURCE_SHA").expect("workflow external source SHA");
    assert_eq!(sha.len(),40);assert!(sha.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)));
    // Independently check fixed manifest names against production allowlist,
    // without importing or changing the production module.
    let src=include_str!("../src/install_trust.rs");
    let body=src.split("pub(crate) const BIN_FILES: &[&str] = &[").nth(1).unwrap().split("];").next().unwrap();
    let declared:BTreeSet<_>=body.lines().filter_map(|l|l.trim().strip_prefix('"'))
        .map(|l|l.split('"').next().unwrap()).collect();
    assert_eq!(declared,NAMES.into_iter().collect());
    let parent=program_files();let vault=parent.join("SpiderVPN-Recovery-Candidate");let work=parent.join("SpiderVPN-Recovery-Work");
    // Never adopt, modify or clean any preexisting fixed root.
    for p in [&vault,&work]{
        match fs::symlink_metadata(p){
            Err(e) if e.raw_os_error()==Some(2)=>{},
            other=>panic!("refuse pre-existing or unknown fixed test root {p:?}: {other:?}"),
        }
    }
    let runner=parent.join(format!("SpiderVPN-Recovery-Runner-{}",nonce()));
    let builder=parent.join(format!("SpiderVPN-Recovery-FixtureBuild-{}",nonce()));
    new_dir(&runner);let runner_id=dir_id(&runner);
    new_dir(&builder);let builder_id=dir_id(&builder);
    let mut expected=compile_fixtures(&builder);
    // Third-party binaries are intentionally not involved. Authenticate
    // locally compiled fixture bytes in this separate controller before
    // materializing the vault, and record the independently derived digest.
    let m=manifest(&expected,&sha);let mut raw=raw_manifest(&m);
    let original_exe=fs::read(env!("CARGO_BIN_EXE_spidervpn-recovery")).unwrap();
    assert!(original_exe.starts_with(b"MZ"));
    let exe=runner.join("spidervpn-recovery.exe");new_file(&exe,&original_exe);
    let exe_guard=open(&exe);
    let runner_exe=readback(&exe,&original_exe,true);
    assert_eq!(info(&exe_guard,&exe,false).0,runner_exe.id);exact_acl(&exe_guard);
    assert_eq!(runner_exe.sha,hash(&original_exe));
    let sentinel=runner.join("neighbor.bin");let sent=b"unrelated known sentinel";
    new_file(&sentinel,sent);let neighbor_before=readback(&sentinel,sent,true);
    assert_eq!(names(&runner),["spidervpn-recovery.exe","neighbor.bin"].into_iter().map(String::from).collect());
    println!("D3_EXTERNAL_FIXTURE_AUTH source_sha={sha} manifest_sha256={} recovery_exe_sha256={} isolated_exe_dir={runner:?} no_product_dependencies=true fixture_only=true",
        hash(&raw),runner_exe.sha);
    // Compiler-created outputs in our own fresh build directory: verify
    // known names/extensions and exact identities; no recursive cleanup.
    for n in names(&builder){
        assert!(["spidervpn","WebView2Loader","libWebView2Loader","sing-box"].iter().any(|prefix|n.starts_with(prefix)),
            "unknown compiler output preserved: {n}");
        let p=builder.join(n);
        let bytes=fs::read(&p).unwrap();
        let snap=readback(&p,&bytes,false);
        assert_eq!(readback(&p,&bytes,false),snap);fs::remove_file(p).unwrap();
    }
    assert_eq!(dir_id(&builder),builder_id);fs::remove_dir(&builder).unwrap();

    let noargs=run(Command::new(&exe).current_dir(&runner),20000);
    assert_eq!(noargs.status.code(),Some(1));assert!(noargs.err.contains("RECOVERY_REFUSED USAGE"));
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"OBJECT_OPEN");
    new_dir(&vault);let vault_id=dir_id(&vault);
    for n in NAMES{new_file(&vault.join(n),&expected[n]);}
    new_file(&vault.join(MANIFEST),&raw);
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"OBJECT_OPEN");
    new_dir(&work);let work_id=dir_id(&work);
    let source=verify_vault(&vault,&expected,&raw);
    // Existing bad generation + file (not a forced nonce collision) must
    // never be adopted/overwritten; preserve exact ID/bytes throughout.
    let stale=work.join("unready-00000000000000000000000000000000");
    new_dir(&stale);let stale_id=dir_id(&stale);
    let stale_file=stale.join(NAMES[0]);let stale_bytes=b"old unready neighbor sentinel";
    new_file(&stale_file,stale_bytes);let stale_before=readback(&stale_file,stale_bytes,true);
    refuse(&exe,"x",&sha,&runner,&work,"ARG_EXTERNAL_ANCHOR_FORMAT");
    refuse(&exe,&"0".repeat(64),&sha,&runner,&work,"MANIFEST_DIGEST");
    let wrong_sha=if sha=="a".repeat(40){"b".repeat(40)}else{"a".repeat(40)};
    refuse(&exe,&hash(&raw),&wrong_sha,&runner,&work,"SOURCE_SHA_MISMATCH");
    for (key,value) in [("schema",json!(2)),("kind",json!("approved")),("unknown",json!(true))]{
        let mut v=m.clone();v[key]=value;let bad=raw_manifest(&v);
        replace_known(&vault.join(MANIFEST),&raw,&bad);
        refuse(&exe,&hash(&bad),&sha,&runner,&work,"MANIFEST_SCHEMA");
        replace_known(&vault.join(MANIFEST),&bad,&raw);
    }
    let duplicate=String::from_utf8(raw.clone()).unwrap().replace("\"schema\":1","\"schema\":1,\"schema\":1").into_bytes();
    assert_ne!(duplicate,raw);
    replace_known(&vault.join(MANIFEST),&raw,&duplicate);
    refuse(&exe,&hash(&duplicate),&sha,&runner,&work,"MANIFEST_SCHEMA");
    replace_known(&vault.join(MANIFEST),&duplicate,&raw);
    let mut v=m.clone();v["files"].as_array_mut().unwrap().pop();
    let missing_entry=raw_manifest(&v);
    replace_known(&vault.join(MANIFEST),&raw,&missing_entry);
    refuse(&exe,&hash(&missing_entry),&sha,&runner,&work,"MANIFEST_COUNT");
    replace_known(&vault.join(MANIFEST),&missing_entry,&raw);
    let mut v=m.clone();v["files"][0]["unexpected"]=json!(true);
    let unknown_entry=raw_manifest(&v);
    replace_known(&vault.join(MANIFEST),&raw,&unknown_entry);
    refuse(&exe,&hash(&unknown_entry),&sha,&runner,&work,"MANIFEST_SCHEMA");
    replace_known(&vault.join(MANIFEST),&unknown_entry,&raw);
    for bad_name in [NAMES[1],"SPIDERVPN.EXE","../spidervpn.exe","spidervpn.exe:ads"]{
        let mut v=m.clone();v["files"][0]["path"]=json!(bad_name);let bad=raw_manifest(&v);
        replace_known(&vault.join(MANIFEST),&raw,&bad);
        refuse(&exe,&hash(&bad),&sha,&runner,&work,"MANIFEST_NAME_OR_DUPLICATE");
        replace_known(&vault.join(MANIFEST),&bad,&raw);
    }
    for (field,value,want) in [("size",json!(536870913u64),"MANIFEST_ENTRY_BOUNDS"),
        ("size",json!(1),"FILE_SIZE"),("sha256",json!("0".repeat(64)),"FILE_DIGEST")]{
        let mut v=m.clone();v["files"][0][field]=value;let bad=raw_manifest(&v);
        replace_known(&vault.join(MANIFEST),&raw,&bad);
        refuse(&exe,&hash(&bad),&sha,&runner,&work,want);
        replace_known(&vault.join(MANIFEST),&bad,&raw);
    }
    let leaf=vault.join(NAMES[0]);
    let moved=runner.join("known-quarantine.exe");
    fs::rename(&leaf,&moved).unwrap();
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"SET_MISSING");
    assert_eq!(readback(&moved,&expected[NAMES[0]],true),source[NAMES[0]]);
    fs::rename(&moved,&leaf).unwrap();
    let extra=vault.join("unexpected.txt");new_file(&extra,b"extra");let extra_id=readback(&extra,b"extra",true);
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"SET_UNKNOWN_OR_TYPE");
    remove_known(&extra,b"extra",&extra_id);
    let mut bad=expected[NAMES[0]].clone();bad[0]^=1;
    replace_known(&leaf,&expected[NAMES[0]],&bad);
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"FILE_DIGEST");
    replace_known(&leaf,&bad,&expected[NAMES[0]]);
    // Real kernel sharing failures, not a parser rejection.
    let writer=OpenOptions::new().write(true).share_mode(ALL_SHARES).open(&leaf).unwrap();
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"win32=Some(32)");drop(writer);
    let old_delete=OpenOptions::new().access_mode(DELETE|FILE_READ_ATTRIBUTES).share_mode(ALL_SHARES).open(&leaf).unwrap();
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"win32=Some(32)");drop(old_delete);
    for p in [&vault,&work]{
        let old_parent=OpenOptions::new().access_mode(DELETE|FILE_READ_ATTRIBUTES).share_mode(ALL_SHARES)
            .custom_flags(FLAGS).open(p).unwrap();
        refuse(&exe,&hash(&raw),&sha,&runner,&work,"win32=Some(32)");drop(old_parent);
    }
    // A deliberately wider actual ACL with an unmapped test SID (not a
    // real account) is still refused. Restore only our own test ACL.
    let mut b=[0u8;16];SystemRandom::new().fill(&mut b).unwrap();
    let ns:Vec<_>=b.chunks_exact(4).map(|v|u32::from_le_bytes(v.try_into().unwrap())).collect();
    let sid=format!("S-1-5-21-{}-{}-{}-{}",ns[0],ns[1],ns[2],ns[3]);
    let wide_acl=format!("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})");
    for p in [&leaf,&vault,&work]{
        set_dacl(p,&wide_acl);
        let descriptor=sddl(&open(p));assert!(descriptor.contains(&sid));
        refuse(&exe,&hash(&raw),&sha,&runner,&work,"ACL_COUNT");
        assert_eq!(sddl(&open(p)),descriptor);set_dacl(p,ACL);exact_acl(&open(p));
    }
    let link=runner.join("known-hardlink.exe");
    fs::hard_link(&leaf,&link).unwrap();
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"OBJECT_TYPE_OR_LINK");
    assert_eq!(fs::read(&link).unwrap(),expected[NAMES[0]]);assert_eq!(fs::read(&leaf).unwrap(),expected[NAMES[0]]);
    fs::remove_file(&link).unwrap();
    for p in [&leaf,&vault,&work]{
        let ads=PathBuf::from(format!("{}:fixture",p.display()));
        fs::write(&ads,b"named stream").unwrap();
        refuse(&exe,&hash(&raw),&sha,&runner,&work,"OBJECT_ALTERNATE_STREAM");
        assert_eq!(fs::read(&ads).unwrap(),b"named stream");fs::remove_file(&ads).unwrap();
    }
    let saved=runner.join("saved-vault");
    fs::rename(&vault,&saved).unwrap();
    let cmd=PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("cmd.exe");
    let out=Command::new(cmd).args(["/D","/C","mklink","/J"]).arg(&vault).arg(&saved).output().unwrap();
    assert!(out.status.success(),"{out:?}");
    refuse(&exe,&hash(&raw),&sha,&runner,&work,"OBJECT_TYPE_OR_LINK");
    assert_eq!(dir_id(&saved),vault_id);assert_eq!(verify_vault(&saved,&expected,&raw),source);
    fs::remove_dir(&vault).unwrap();fs::rename(&saved,&vault).unwrap();
    assert_eq!(dir_id(&vault),vault_id);assert_eq!(dir_id(&work),work_id);
    assert_eq!(verify_vault(&vault,&expected,&raw),source);
    assert_eq!(readback(&stale_file,stale_bytes,true),stale_before);
    assert_eq!(readback(&sentinel,sent,true),neighbor_before);
    println!("D3_NEGATIVE_MATRIX actual_sharing=true exact_acl=true reparse=true hardlink=true ads=true external_anchor=true source_preserved=true stale_generation_preserved=true");

    let p1=recover(&exe,&raw,&sha,&work,&runner);let mut first=check_group(&p1,&expected,&source);
    run_group(&first,&expected,&runner,false);
    // Only a known, independently verified fixture working group is damaged.
    // Delete its actual adjacent DLL, then prove another dependency cannot
    // be deleted while a real reader denies delete sharing.
    let dll=first.files.remove(NAMES[1]).unwrap();
    remove_known(&first.path.join(NAMES[1]),&expected[NAMES[1]],&dll);
    assert_eq!(rc(fs::symlink_metadata(first.path.join(NAMES[1])),"deleted dependency absence",&[2]),2);
    let eng=first.path.join(NAMES[2]);let blocker=open(&eng);
    let denied=rc(fs::remove_file(&eng),"held engine deletion",&[32,5]);
    drop(blocker);check_preserved(&first,&expected);
    assert_eq!(readback(&sentinel,sent,true),neighbor_before);
    println!("D3_DEPENDENCY_DAMAGE dll_removed_id={:?} dll_absence=2 engine_delete_win32={denied} engine_id={:?} engine_hash={} neighbors_preserved=true",
        dll.id,first.files[NAMES[2]].id,first.files[NAMES[2]].sha);
    run_group(&first,&expected,&runner,true);
    // Separate executable and PID rebuild a NEW group from unchanged vault.
    assert_eq!(readback(&exe,&original_exe,true),runner_exe);
    let p2=recover(&exe,&raw,&sha,&work,&runner);let second=check_group(&p2,&expected,&source);
    assert_ne!(first.id,second.id);assert_ne!(p1,p2);
    for(n,s)in &first.files{assert_ne!(s.id,second.files[n].id);}
    check_preserved(&first,&expected);assert!(!first.path.join(NAMES[1]).exists());
    run_group(&second,&expected,&runner,false);
    println!("D3_NEW_GROUP old={p1:?} new={p2:?} old_broken_unchanged=true actual_client_dll_engine=true");

    // Native timeout on a benign independent fixture process that has
    // explicitly signalled readiness and is waiting on a live stdin pipe.
    let _hold_engine=open(&second.path.join(NAMES[2]));
    let waiting=Proc::start(Command::new(second.path.join(NAMES[2])).arg("--wait-fixture").current_dir(&runner).stdin(Stdio::piped()));
    let pid=waiting.pid;let start=Instant::now();let ready=format!("D3_ENGINE_WAIT_READY pid={pid}");
    loop{
        let line=waiting.lines.recv_timeout(Duration::from_secs(10).saturating_sub(start.elapsed())).expect("real wait child ready");
        if line==ready{break;}
    }
    assert!(waiting.child.stdin.is_some());
    let clock=Instant::now();assert_eq!(waiting.wait_code(100),258);
    let killed=waiting.kill();assert!(!killed.status.success());drop(_hold_engine);
    check_preserved(&second,&expected);
    println!("D3_TIMEOUT_ACTUAL pid={pid} wait_rc=258 requested_ms=100 elapsed_ms={} exit={:?} child_reaped=true original_group_unchanged=true",clock.elapsed().as_millis(),killed.status.code());

    // Cleanup the two complete/broken known outputs before the larger copy
    // experiment. Their independent verified recovery evidence is retained.
    clean_group(first,&expected);clean_group(second,&expected);
    let mut large=vec![0x5au8;256*1024*1024];
    large[..64].copy_from_slice(&[0x51;64]);
    replace_known(&vault.join(NAMES[3]),&expected[NAMES[3]],&large);
    expected.insert(NAMES[3],large);
    let new_raw=raw_manifest(&manifest(&expected,&sha));
    replace_known(&vault.join(MANIFEST),&raw,&new_raw);raw=new_raw;
    let large_source=verify_vault(&vault,&expected,&raw);
    let (interrupted,actual_interrupted)=interrupt(&exe,&raw,&sha,&work,&vault,&runner,&expected,&sentinel,sent);
    assert_eq!(verify_vault(&vault,&expected,&raw),large_source);
    assert_eq!(readback(&sentinel,sent,true),neighbor_before);
    let new_path=recover(&exe,&raw,&sha,&work,&runner);
    let rebuilt=check_group(&new_path,&expected,&large_source);
    assert_ne!(interrupted.path,rebuilt.path);assert_ne!(interrupted.id,rebuilt.id);
    for(n,s)in &interrupted.files{assert_ne!(s.id,rebuilt.files[n].id);}
    partial_preserved(&interrupted,&expected);
    run_group(&rebuilt,&expected,&runner,false);
    assert_eq!(readback(&stale_file,stale_bytes,true),stale_before);
    assert_eq!(dir_id(&stale),stale_id);
    clean_partial(interrupted,&expected);clean_group(rebuilt,&expected);
    remove_known(&stale_file,stale_bytes,&stale_before);fs::remove_dir(&stale).unwrap();
    assert_eq!(verify_vault(&vault,&expected,&raw),large_source);
    for n in NAMES.into_iter().chain([MANIFEST]){
        remove_known(&vault.join(n),if n==MANIFEST{&raw}else{&expected[n]},&large_source[n]);
    }
    assert_eq!(dir_id(&vault),vault_id);assert_eq!(dir_id(&work),work_id);
    fs::remove_dir(&vault).unwrap();fs::remove_dir(&work).unwrap();
    remove_known(&sentinel,sent,&neighbor_before);drop(exe_guard);remove_known(&exe,&original_exe,&runner_exe);
    assert_eq!(dir_id(&runner),runner_id);fs::remove_dir(&runner).unwrap();
    println!("D3_RECOVERY_COMPLETE source_sha={sha} fixture_client_dll=true fixture_engine=true dependency_failure=true independent_recovery=true fixed_vault=true generation_preserved=true actual_timeout=true actual_interrupt={actual_interrupted} production_product_not_run=true source_authenticated=false production_recovery_proven=false maintenance_authorized=false r2_not_run=true d2_timeout_not_run=true");
}
