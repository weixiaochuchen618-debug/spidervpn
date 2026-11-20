// CI-only fixture: no VPN, no networking and no access to product data.
use std::{ffi::c_void, os::windows::ffi::OsStrExt, path::PathBuf};
#[link(name="kernel32")]
extern "system" {
    fn LoadLibraryExW(name:*const u16,file:*mut c_void,flags:u32)->*mut c_void;
    fn GetProcAddress(module:*mut c_void,name:*const u8)->*mut c_void;
    fn GetModuleFileNameW(module:*mut c_void,buffer:*mut u16,len:u32)->u32;
    fn FreeLibrary(module:*mut c_void)->i32;
}
fn main(){
    let exe=std::env::current_exe().unwrap();
    let wanted=exe.parent().unwrap().join("WebView2Loader.dll");
    let wide:Vec<u16>=wanted.as_os_str().encode_wide().chain(Some(0)).collect();
    // Absolute adjacent path, only its own directory and System32 for
    // dependent OS DLLs; no PATH/current-directory fallback for loader.
    let module=unsafe{LoadLibraryExW(wide.as_ptr(),std::ptr::null_mut(),0x100|0x800)};
    if module.is_null(){
        eprintln!("D3_CLIENT_DLL_FAILED pid={} win32={:?} path={}",std::process::id(),
            std::io::Error::last_os_error().raw_os_error(),wanted.display());
        std::process::exit(41);
    }
    let mut buf=vec![0u16;32768];
    let n=unsafe{GetModuleFileNameW(module,buf.as_mut_ptr(),buf.len() as u32)} as usize;
    assert!(n>0&&n<buf.len());
    let actual=PathBuf::from(String::from_utf16(&buf[..n]).unwrap());
    assert!(actual.to_str().unwrap().eq_ignore_ascii_case(wanted.to_str().unwrap()));
    let proc=unsafe{GetProcAddress(module,b"spider_recovery_fixture_v1\0".as_ptr())};
    assert!(!proc.is_null());
    let entry:unsafe extern "system" fn()->u32=unsafe{std::mem::transmute(proc)};
    let mark=unsafe{entry()};
    assert_eq!(mark,0x5350_4433);
    println!("D3_CLIENT_DLL_OK pid={} value={mark:#x} exe={} loaded={}",std::process::id(),exe.display(),actual.display());
    // Test-only module observation: the real adjacent DLL and called
    // export remain loaded until the independent controller releases us.
    if std::env::args().nth(1).as_deref()==Some("--observe-fixture"){
        use std::io::{BufRead,Write};
        println!("D3_CLIENT_OBSERVE_READY pid={}",std::process::id());
        std::io::stdout().flush().unwrap();
        let mut go=String::new();std::io::stdin().lock().read_line(&mut go).unwrap();
        assert_eq!(go.trim_end_matches(['\r','\n']),"G");
    }
    assert_ne!(unsafe{FreeLibrary(module)},0);
}
