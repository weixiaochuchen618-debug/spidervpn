//! Actual standalone process + filesystem regressions, not a package release.
//! The default-off feature is exercised explicitly on both Windows ABIs.
#![cfg(all(windows, feature = "bootstrap-stage"))]
use std::{
    ffi::OsStr, fs::{self, File, OpenOptions}, io::{BufRead, BufReader, Read, Write},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf}, process::{Command, Output, Stdio}, ptr::null_mut,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{SECURITY_ATTRIBUTES, OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION},
    Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT,
        ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1},
    Storage::FileSystem::{CreateDirectoryW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT},
    UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramFiles},
    System::Com::CoTaskMemFree,
};
const NAMES: [&str;12]=["spidervpn.exe","WebView2Loader.dll","sing-box.exe",
    "sing-box.LICENSE.txt","一键安装.cmd","一键卸载.cmd","直接运行（免安装）.cmd",
    "install/install.ps1","install/uninstall.ps1","install/expected.sha256","INSTALL.txt","用户速查.md"];
const SOURCE_SHA:&str="1234567890123456789012345678901234567890";
const SLOT:&str="SpiderVPN-Bootstrap-Staging";
const ACL:&str="O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
const BROAD:&str="O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)";
fn wide(s:&OsStr)->Vec<u16>{s.encode_wide().chain(Some(0)).collect()}
fn hash(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn nonce()->String {
    let mut b=[0u8;16]; SystemRandom::new().fill(&mut b).unwrap();
    b.iter().map(|b|format!("{b:02x}")).collect()
}
fn canonical(path:&Path)->PathBuf {
    let p=fs::canonicalize(path).unwrap();
    PathBuf::from(p.to_str().unwrap().strip_prefix(r"\\?\").unwrap())
}
fn program_files()->PathBuf {
    let mut p=null_mut();
    let hr=unsafe{SHGetKnownFolderPath(&FOLDERID_ProgramFiles,0,null_mut(),&mut p)};
    assert!(hr>=0&&!p.is_null(),"known folder hr={hr:#x}");
    let mut n=0;
    while n<32768&&unsafe{*p.add(n)}!=0 {n+=1;}
    assert!(n<32768);
    let s=String::from_utf16(unsafe{std::slice::from_raw_parts(p,n)}).unwrap();
    unsafe{CoTaskMemFree(p.cast());}
    PathBuf::from(s)
}
fn slot()->PathBuf {program_files().join(SLOT)}
fn path(root:&Path,name:&str)->PathBuf {root.join(name.replace('/',"\\"))}
struct Fixture{root:PathBuf, source:PathBuf}
impl Fixture {
    fn new()->Self {
        let root=canonical(&std::env::temp_dir()).join(format!("spider-bootstrap-e2e-{}",nonce()));
        fs::create_dir(&root).unwrap();
        let source=root.join("source");fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("install")).unwrap();
        for n in NAMES { fs::write(path(&source,n),format!("NONEXECUTABLE FIXTURE {n}\n")).unwrap(); }
        fs::write(root.join("neighbor.txt"),b"unrelated sentinel").unwrap();
        let fixture=Self{root,source}; fixture.restore_manifest();fixture
    }
    fn manifest(&self)->Value {
        let files:Vec<_>=NAMES.iter().map(|n|{
            let b=fs::read(path(&self.source,n)).unwrap();
            json!({"path":n,"size":b.len(),"sha256":hash(&b)})
        }).collect();
        json!({"schema":1,"kind":"unapproved-client-candidate","sourceSha":SOURCE_SHA,"files":files})
    }
    fn set_manifest(&self,v:&Value)->String {
        self.raw_manifest(&serde_json::to_vec(v).unwrap())
    }
    fn raw_manifest(&self,b:&[u8])->String {
        let mut raw=vec![0xef,0xbb,0xbf];raw.extend_from_slice(b);
        fs::write(self.source.join("manifest.json"),&raw).unwrap();hash(&raw)
    }
    fn restore_manifest(&self)->String { self.set_manifest(&self.manifest()) }
    fn digest(&self)->String {hash(&fs::read(self.source.join("manifest.json")).unwrap())}
    fn neighbor(&self) {assert_eq!(fs::read(self.root.join("neighbor.txt")).unwrap(),b"unrelated sentinel");}
}
impl Drop for Fixture {fn drop(&mut self){let _=fs::remove_dir_all(&self.root);}}

fn command(source:&Path,digest:&str,sha:&str)->Command {
    let mut c=Command::new(env!("CARGO_BIN_EXE_spidervpn-bootstrap"));
    c.arg("--source").arg(source).arg("--manifest-sha256").arg(digest).arg("--source-sha").arg(sha);
    c
}
fn log(o:&Output)->String {
    format!("{}\n{}",String::from_utf8_lossy(&o.stdout),String::from_utf8_lossy(&o.stderr))
}
fn refuse(source:&Path,digest:&str,sha:&str,want:&str) -> String {
    let out=command(source,digest,sha).output().unwrap();let msg=log(&out);
    assert_eq!(out.status.code(),Some(1),"{msg}");
    assert!(msg.contains(&format!("BOOTSTRAP_REFUSED {want}")),"expected {want}: {msg}");
    assert!(!msg.contains("BOOTSTRAP_CONTENT_MATCH"),"{msg}");
    assert!(!slot().exists(),"source rejection must precede stage creation: {msg}");
    println!("BOOTSTRAP_E2E_REFUSED expected={want} actual={}",msg.lines().find(|l|l.contains("BOOTSTRAP_REFUSED")).unwrap());
    msg
}
fn open(path:&Path)->File {
    OpenOptions::new().read(true).share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT).open(path).unwrap()
}
fn identity(file:&File)->(u32,u32,u32) {
    let mut info:BY_HANDLE_FILE_INFORMATION=unsafe{std::mem::zeroed()};
    assert_ne!(unsafe{GetFileInformationByHandle(file.as_raw_handle(),&mut info)},0);
    assert_eq!(info.dwFileAttributes&0x400,0,"no reparse");
    if info.dwFileAttributes&0x10==0 {assert_eq!(info.nNumberOfLinks,1);}
    assert_ne!((info.nFileIndexHigh,info.nFileIndexLow),(0,0));
    (info.dwVolumeSerialNumber,info.nFileIndexHigh,info.nFileIndexLow)
}
fn sddl(file:&File)->String {
    let mut sd=null_mut();let mut text=null_mut();let mut n=0;
    assert_eq!(unsafe{GetSecurityInfo(file.as_raw_handle(),SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,null_mut(),null_mut(),
        null_mut(),null_mut(),&mut sd)},0);
    assert!(!sd.is_null());
    assert_ne!(unsafe{ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut text,&mut n)},0);
    assert!(!text.is_null());
    let result=String::from_utf16(unsafe{std::slice::from_raw_parts(text,n as usize)}).unwrap()
        .trim_end_matches('\0').to_owned();
    unsafe{LocalFree(text.cast());LocalFree(sd.cast());}
    result
}
fn exact_acl(file:&File) {
    let actual=sddl(file);
    assert!(actual==ACL||actual==ACL.replace("D:P","D:PAI"),"independent ACL: {actual}");
}
fn create_slot(s:&str) {
    let mut sd=null_mut();
    assert_ne!(unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(
        wide(OsStr::new(s)).as_ptr(),SDDL_REVISION_1,&mut sd,null_mut())},0);
    let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor:sd,bInheritHandle:0};
    let ok=unsafe{CreateDirectoryW(wide(slot().as_os_str()).as_ptr(),&sa)};
    unsafe{LocalFree(sd.cast());}
    assert_ne!(ok,0,"test precreation failed: {}",std::io::Error::last_os_error());
}
fn checked_stage(line:&str)->PathBuf {
    let p=PathBuf::from(line.strip_prefix("BOOTSTRAP_STAGE_UNREADY path=").unwrap().trim_end());
    assert_eq!(p.parent(),Some(slot().as_path()));
    let name=p.file_name().unwrap().to_str().unwrap().strip_prefix("unready-").unwrap();
    assert_eq!(name.len(),32);
    assert!(name.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)));
    p
}
fn cleanup_stage(p:&Path) {
    assert_eq!(p.parent(),Some(slot().as_path()));
    // Never recursively delete unknown objects in the fixed slot.
    for n in NAMES.into_iter().chain(["manifest.json"]) {
        match fs::remove_file(path(p,n)) {
            Ok(())=>{},Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
            Err(e)=>panic!("test cleanup {n}: {e}"),
        }
    }
    fs::remove_dir(p.join("install")).unwrap();
    fs::remove_dir(p).unwrap();fs::remove_dir(slot()).unwrap();
}
fn verify_stage(f:&Fixture,p:&Path) {
    let mut dirs=Vec::new();
    for d in [slot(),p.to_owned(),p.join("install")] {
        let dir=open(&d);exact_acl(&dir);dirs.push(identity(&dir));
    }
    assert_eq!(dirs.iter().collect::<std::collections::BTreeSet<_>>().len(),3);
    let mut ids=std::collections::BTreeSet::new();
    for n in NAMES.into_iter().chain(["manifest.json"]) {
        let original=path(&f.source,n);let target=path(p,n);
        let mut s=open(&original);let mut d=open(&target);
        let a=identity(&s);let b=identity(&d);
        assert_ne!(a,b,"no source object reuse");assert!(ids.insert(b),"no target object reuse");
        let mut src=Vec::new();let mut dst=Vec::new();
        s.read_to_end(&mut src).unwrap();d.read_to_end(&mut dst).unwrap();
        assert_eq!(hash(&src),hash(&dst));assert_eq!(src,dst);
        exact_acl(&d);
        println!("BOOTSTRAP_E2E_READBACK name={n} source_id={a:?} target_id={b:?} sha256={} owner_acl=true",hash(&dst));
    }
    assert_eq!(fs::read_dir(p).unwrap().count(),11);
    assert_eq!(fs::read_dir(p.join("install")).unwrap().count(),3);
    assert_eq!(fs::read_dir(slot()).unwrap().count(),1);
}
#[test]
fn real_bootstrap_content_and_object_boundaries() {
    assert!(!slot().exists(),"never use or delete a pre-existing staging slot");
    let f=Fixture::new();
    let m=f.manifest();
    let missing=Command::new(env!("CARGO_BIN_EXE_spidervpn-bootstrap")).output().unwrap();
    assert_eq!(missing.status.code(),Some(1));
    assert!(log(&missing).contains("BOOTSTRAP_REFUSED USAGE"));
    assert!(!slot().exists());
    println!("BOOTSTRAP_E2E_REFUSED expected=USAGE no_external_anchor=true");
    refuse(&f.source,"x",SOURCE_SHA,"ARG_EXTERNAL_ANCHOR_FORMAT");
    refuse(&f.source,&"0".repeat(64),SOURCE_SHA,"MANIFEST_DIGEST");
    refuse(&f.source,&f.digest(),&"a".repeat(40),"SOURCE_SHA_MISMATCH");
    for (key,value) in [("schema",json!(2)),("kind",json!("approved")),("unknown",json!(true))] {
        let mut v=m.clone();v[key]=value;let d=f.set_manifest(&v);
        refuse(&f.source,&d,SOURCE_SHA,"MANIFEST_SCHEMA");
    }
    let raw=serde_json::to_string(&m).unwrap().replace("\"schema\":1","\"schema\":1,\"schema\":1");
    let d=f.raw_manifest(raw.as_bytes());refuse(&f.source,&d,SOURCE_SHA,"MANIFEST_SCHEMA");
    let raw=serde_json::to_string(&m).unwrap().replacen("\"size\":","\"size\":1,\"size\":",1);
    let d=f.raw_manifest(raw.as_bytes());refuse(&f.source,&d,SOURCE_SHA,"MANIFEST_SCHEMA");
    let mut v=m.clone();v["files"][0]["unexpected"]=json!(1);
    let d=f.set_manifest(&v);refuse(&f.source,&d,SOURCE_SHA,"MANIFEST_SCHEMA");
    let mut v=m.clone();v["files"].as_array_mut().unwrap().pop();
    let d=f.set_manifest(&v);refuse(&f.source,&d,SOURCE_SHA,"MANIFEST_COUNT");
    for name in ["WebView2Loader.dll","SPIDERVPN.EXE","../spidervpn.exe","C:/spidervpn.exe",
        "spidervpn.exe:payload","install//install.ps1","evil.dll"] {
        let mut v=m.clone();v["files"][0]["path"]=json!(name);
        let d=f.set_manifest(&v);refuse(&f.source,&d,SOURCE_SHA,"MANIFEST_NAME_OR_DUPLICATE");
    }
    let mut v=m.clone();v["files"][0]["size"]=json!(536870913u64);
    let d=f.set_manifest(&v);refuse(&f.source,&d,SOURCE_SHA,"MANIFEST_ENTRY_BOUNDS");
    let mut v=m.clone();v["files"][0]["size"]=json!(0);
    let d=f.set_manifest(&v);refuse(&f.source,&d,SOURCE_SHA,"FILE_SIZE");
    let mut v=m.clone();v["files"][0]["sha256"]=json!("0".repeat(64));
    let d=f.set_manifest(&v);refuse(&f.source,&d,SOURCE_SHA,"FILE_DIGEST");
    let digest=f.restore_manifest();
    let p=path(&f.source,NAMES[0]);let original=fs::read(&p).unwrap();
    let mut bad=original.clone();bad[0]^=1;fs::write(&p,&bad).unwrap();
    refuse(&f.source,&digest,SOURCE_SHA,"FILE_DIGEST");fs::write(&p,&original).unwrap();
    fs::remove_file(&p).unwrap();assert!(refuse(&f.source,&digest,SOURCE_SHA,"OBJECT_OPEN").contains("Some(2)"));
    fs::write(&p,&original).unwrap();
    let extra=f.source.join("extra.dll");fs::write(&extra,b"unknown").unwrap();
    refuse(&f.source,&digest,SOURCE_SHA,"SET_UNKNOWN_OR_TYPE");fs::remove_file(&extra).unwrap();
    let case=f.source.join("SPIDERVPN.EXE");let temp=f.source.join("rename.tmp");
    fs::rename(&p,&temp).unwrap();fs::rename(&temp,&case).unwrap();
    refuse(&f.source,&digest,SOURCE_SHA,"SET_UNKNOWN_OR_TYPE");
    fs::rename(&case,&temp).unwrap();fs::rename(&temp,&p).unwrap();

    for access in [0x40000000u32,0x10000] {
        let old=OpenOptions::new().access_mode(access).share_mode(7).open(&p).unwrap();
        let denied=refuse(&f.source,&digest,SOURCE_SHA,"OBJECT_OPEN");
        assert!(denied.contains("Some(32)"),"{denied}");
        drop(old);assert_eq!(fs::read(&p).unwrap(),original);
        println!("BOOTSTRAP_E2E_OLD_ACCESS mask={access:#x} original_preserved=true");
    }
    let neighbor=f.root.join("neighbor.txt");
    fs::remove_file(&p).unwrap();fs::hard_link(&neighbor,&p).unwrap();
    refuse(&f.source,&digest,SOURCE_SHA,"OBJECT_TYPE_OR_LINK");fs::remove_file(&p).unwrap();
    std::os::windows::fs::symlink_file(&neighbor,&p).unwrap();
    refuse(&f.source,&digest,SOURCE_SHA,"OBJECT_TYPE_OR_LINK");fs::remove_file(&p).unwrap();
    fs::write(&p,&original).unwrap();
    let stream=PathBuf::from(format!("{}:hidden",p.display()));
    fs::write(&stream,b"alternate stream").unwrap();
    refuse(&f.source,&digest,SOURCE_SHA,"OBJECT_ALTERNATE_STREAM");fs::remove_file(&stream).unwrap();
    let junction=f.root.join("junction");
    let output=Command::new("cmd.exe").args(["/D","/C","mklink","/J"])
        .arg(&junction).arg(&f.source).output().unwrap();
    assert!(output.status.success(),"{}",log(&output));
    refuse(&junction,&digest,SOURCE_SHA,"OBJECT_TYPE_OR_LINK");fs::remove_dir(&junction).unwrap();
    let install=f.source.join("install");let saved=f.source.join("saved-install");
    fs::rename(&install,&saved).unwrap();
    let output=Command::new("cmd.exe").args(["/D","/C","mklink","/J"])
        .arg(&install).arg(&saved).output().unwrap();
    assert!(output.status.success(),"{}",log(&output));
    refuse(&f.source,&digest,SOURCE_SHA,"OBJECT_TYPE_OR_LINK");
    fs::remove_dir(&install).unwrap();fs::rename(&saved,&install).unwrap();
    let alias=f.source.join("..").join("source");
    refuse(&alias,&digest,SOURCE_SHA,"PATH_ALIAS_OR_TRAVERSAL");
    f.neighbor();

    // Actual fixed target creation collision, both wide and seemingly exact
    // security descriptor. The bootstrap never adopts either prior object.
    for acl in [BROAD,ACL] {
        create_slot(acl);
        let sentinel=slot().join("preexisting-sentinel");fs::write(&sentinel,b"do not delete or overwrite").unwrap();
        let before=open(&slot());let before_id=identity(&before);let before_acl=sddl(&before);assert!(before_acl==acl||before_acl==acl.replace("D:P","D:PAI"),"{before_acl}");drop(before);
        let out=command(&f.source,&digest,SOURCE_SHA).output().unwrap();let msg=log(&out);
        assert_eq!(out.status.code(),Some(1),"{msg}");
        assert!(msg.contains("BOOTSTRAP_REFUSED STAGE_DIR_CREATE")&&msg.contains("Some(183)"),"{msg}");
        assert!(!msg.contains("BOOTSTRAP_CONTENT_MATCH"),"{msg}");
        let after=open(&slot());assert_eq!(identity(&after),before_id);assert_eq!(sddl(&after),before_acl);drop(after);
        assert_eq!(fs::read(&sentinel).unwrap(),b"do not delete or overwrite");
        println!("BOOTSTRAP_E2E_SLOT_COLLISION acl={before_acl} win32=183 untouched=true");
        fs::remove_file(sentinel).unwrap();fs::remove_dir(slot()).unwrap();
    }

    let out=command(&f.source,&digest,SOURCE_SHA).output().unwrap();let msg=log(&out);
    assert!(out.status.success(),"{msg}");println!("{msg}");
    assert!(msg.contains("BOOTSTRAP_CONTENT_MATCH files=13"));
    assert!(msg.contains("install_authorized=false zip_origin_verified=false"));
    let p1=checked_stage(msg.lines().find(|l|l.starts_with("BOOTSTRAP_STAGE_UNREADY path=")).unwrap());
    verify_stage(&f,&p1);let first_id=identity(&open(&p1));cleanup_stage(&p1);
    let out=command(&f.source,&digest,SOURCE_SHA).output().unwrap();let msg=log(&out);
    assert!(out.status.success(),"{msg}");
    let p2=checked_stage(msg.lines().find(|l|l.starts_with("BOOTSTRAP_STAGE_UNREADY path=")).unwrap());
    assert_ne!(p1,p2);assert_ne!(first_id,identity(&open(&p2)));verify_stage(&f,&p2);cleanup_stage(&p2);
    f.neighbor();

    // Real competing create during staging. The next file is the manifest
    // (last), while the first payload is large. No production fault switch,
    // no untrusted executable, same elevated test account only.
    let mut large=File::create(path(&f.source,NAMES[0])).unwrap();
    let block=vec![0x5au8;1024*1024];
    for _ in 0..32 {large.write_all(&block).unwrap();}
    large.sync_all().unwrap();drop(large);let digest=f.restore_manifest();
    let mut child=command(&f.source,&digest,SOURCE_SHA).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut reader=BufReader::new(child.stdout.take().unwrap());let mut observed=String::new();
    let stage=loop {
        let mut line=String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(),0,"{observed}");
        observed.push_str(&line);
        if line.starts_with("BOOTSTRAP_STAGE_UNREADY path="){break checked_stage(&line);}
    };
    let mut reserved=OpenOptions::new().write(true).create_new(true).open(stage.join("manifest.json")).unwrap();
    reserved.write_all(b"competing object sentinel").unwrap();drop(reserved);
    reader.read_to_string(&mut observed).unwrap();drop(reader);
    let out=child.wait_with_output().unwrap();observed.push_str(&log(&out));
    assert_eq!(out.status.code(),Some(1),"{observed}");
    assert!(observed.contains("BOOTSTRAP_REFUSED STAGE_FILE_CREATE")&&(observed.contains("Some(80)")||observed.contains("Some(183)")),"{observed}");
    assert!(!observed.contains("BOOTSTRAP_CONTENT_MATCH"));
    assert_eq!(fs::read(stage.join("manifest.json")).unwrap(),b"competing object sentinel");
    println!("BOOTSTRAP_E2E_STAGE_FILE_COLLISION {}",observed.lines().find(|l|l.contains("BOOTSTRAP_REFUSED")).unwrap());
    cleanup_stage(&stage);f.neighbor();
    println!("BOOTSTRAP_E2E_COMPLETE real_exe=true files=13 same_object_readback=true stage_acl=true slot_collision=true file_collision=true fixture_executed=false release=false install=false cross_sid_not_run=true");
}
