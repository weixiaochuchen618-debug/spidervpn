//! Test-only module observation: actual child handle + Toolhelp snapshot.
use super::{io,Path,PathBuf,Command,Proc,Snap,readback};
use std::{os::windows::{ffi::OsStringExt,io::{AsRawHandle,FromRawHandle,OwnedHandle}},ffi::OsString};
use windows_sys::Win32::{
    Foundation::{FILETIME,INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,Module32FirstW,Module32NextW,
            MODULEENTRY32W,TH32CS_SNAPMODULE,TH32CS_SNAPMODULE32},
        Threading::{GetProcessId,GetProcessTimes,QueryFullProcessImageNameW},
    },
};
#[link(name="kernel32")]
extern "system"{
    fn GetSystemDirectoryW(buffer:*mut u16,size:u32)->u32;
    fn GetWindowsDirectoryW(buffer:*mut u16,size:u32)->u32;
}
fn os_dir(f:unsafe extern "system" fn(*mut u16,u32)->u32)->PathBuf{
    let mut b=vec![0u16;32768];let n=unsafe{f(b.as_mut_ptr(),b.len() as u32)} as usize;
    assert!(n>0&&n<b.len(),"OS directory query: {}",io::Error::last_os_error());
    let p=PathBuf::from(OsString::from_wide(&b[..n]));
    assert!(p.is_absolute());p
}
fn system32()->PathBuf{os_dir(GetSystemDirectoryW)}
fn windows()->PathBuf{os_dir(GetWindowsDirectoryW)}
fn same(a:&Path,b:&Path)->bool{
    a.to_str().zip(b.to_str()).is_some_and(|(x,y)|x.eq_ignore_ascii_case(y))
}
pub(super) fn isolate(c:&mut Command){
    let sys=system32();let win=windows();
    assert!(same(sys.parent().unwrap(),&win));
    // Do not inherit the toolchain PATH into any actual fixture process.
    // The compiler itself is separately invoked by explicit rustc path.
    let path=std::env::join_paths([&sys,&win]).unwrap();
    c.env("PATH",&path).env("SystemRoot",&win).env("WINDIR",&win)
        .env_remove("SPIDERVPN_ROOT");
    let cwd=c.get_current_dir().expect("fixture must use isolated cwd");
    println!("D3_EXEC_ENV cwd={cwd:?} path={path:?} os_api=true inherited_toolchain_path=false");
}
fn stamp(p:&Proc,exe:&Path)->u64{
    assert_eq!(p.wait_code(0),258,"child not live");
    let h=p.child.as_raw_handle();
    assert_eq!(unsafe{GetProcessId(h)},p.pid);
    let mut created:FILETIME=unsafe{std::mem::zeroed()};
    let mut exited=created;let mut kernel=created;let mut user=created;
    assert_ne!(unsafe{GetProcessTimes(h,&mut created,&mut exited,&mut kernel,&mut user)},0,
        "GetProcessTimes: {}",io::Error::last_os_error());
    let mut b=vec![0u16;32768];let mut n=b.len() as u32;
    assert_ne!(unsafe{QueryFullProcessImageNameW(h,0,b.as_mut_ptr(),&mut n)},0,
        "QueryFullProcessImageNameW: {}",io::Error::last_os_error());
    assert!(n>0&&(n as usize)<b.len());
    let actual=PathBuf::from(OsString::from_wide(&b[..n as usize]));
    assert!(same(&actual,exe),"actual child image {actual:?} != {exe:?}");
    let time=(u64::from(created.dwHighDateTime)<<32)|u64::from(created.dwLowDateTime);
    assert_ne!(time,0);time
}
pub(super) fn snapshot(p:&Proc,exe:&Path,known:&[(&Path,&Snap,&[u8])],role:&str){
    let created=stamp(p,exe);
    let mut snapshot=None;
    for _ in 0..8{
        let h=unsafe{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,p.pid)};
        if h!=INVALID_HANDLE_VALUE{snapshot=Some(unsafe{OwnedHandle::from_raw_handle(h)});break;}
        let e=io::Error::last_os_error();
        assert_eq!(e.raw_os_error(),Some(24),"Toolhelp snapshot UNKNOWN: {e}");
    }
    let snapshot=snapshot.expect("Toolhelp ERROR_BAD_LENGTH retry limit UNKNOWN");
    let mut entry:MODULEENTRY32W=unsafe{std::mem::zeroed()};
    entry.dwSize=std::mem::size_of::<MODULEENTRY32W>() as u32;
    assert_ne!(unsafe{Module32FirstW(snapshot.as_raw_handle(),&mut entry)},0,
        "Module32FirstW UNKNOWN: {}",io::Error::last_os_error());
    let sys=system32();let win=windows();
    let mut seen=std::collections::BTreeSet::new();let mut count=0usize;
    loop{
        count+=1;assert!(count<=512,"module snapshot bound");
        assert_eq!(entry.th32ProcessID,p.pid);
        let n=entry.szExePath.iter().position(|c|*c==0).expect("module path terminator");
        assert!(n>0&&n<entry.szExePath.len()-1,"module path truncated/empty");
        let path=PathBuf::from(OsString::from_wide(&entry.szExePath[..n]));
        assert!(path.is_absolute()&&path.to_str().is_some());
        if let Some((wanted,snap,expected))=known.iter().find(|(w,_,_)|same(w,&path)){
            let observed=readback(&path,expected,true);
            assert_eq!(&observed,*snap,"actual module path object changed");
            assert!(seen.insert(wanted.to_string_lossy().to_ascii_lowercase()));
            println!("D3_EXEC_MODULE role={role} pid={} creation={created} base={:p} path={path:?} source=authenticated_fixture id={:?} sha256={}",p.pid,entry.modBaseAddr,observed.id,observed.sha);
        }else{
            // Only immediate, OS-located System32 or Windows files.
            // No recursive trust for arbitrary writable children. This
            // observes location, NOT a Microsoft signature/trust proof.
            let parent=path.parent().expect("module parent");
            assert!(same(parent,&sys)||same(parent,&win),"UNKNOWN non-OS module, report to coordinator: {path:?}");
            let canonical=std::fs::canonicalize(&path).unwrap();
            let canonical=canonical.to_str().unwrap().strip_prefix(r"\\?\").expect("local OS DOS path");
            assert!(canonical.eq_ignore_ascii_case(path.to_str().unwrap()),"OS module alias UNKNOWN");
            println!("D3_EXEC_MODULE role={role} pid={} creation={created} base={:p} path={path:?} source=os_directory_observed",p.pid,entry.modBaseAddr);
        }
        entry.dwSize=std::mem::size_of::<MODULEENTRY32W>() as u32;
        if unsafe{Module32NextW(snapshot.as_raw_handle(),&mut entry)}==0{
            let e=io::Error::last_os_error();
            assert_eq!(e.raw_os_error(),Some(18),"Module32NextW UNKNOWN: {e}");break;
        }
    }
    assert!(known.iter().all(|(w,_,_)|seen.contains(&w.to_string_lossy().to_ascii_lowercase())),
        "expected actual executable/DLL absent from snapshot");
    assert_eq!(stamp(p,exe),created);
    println!("D3_EXEC_MODULES_COMPLETE role={role} pid={} creation={created} image={exe:?} modules={count} fixture_modules={} path_os_only=true snapshot_only=true signature_verified=false",p.pid,known.len());
}
