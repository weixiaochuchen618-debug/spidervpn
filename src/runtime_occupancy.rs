//! G2 cooperative runtime occupancy. This is deliberately NOT a trusted
//! deployment, a machine-history proof or a maintenance authorization.
//! Existing installations without a verifiable anchor keep compatibility.
//! Once a stable protected object is verified, actual lock contention must
//! never be converted to that compatibility path.
#![allow(dead_code)]

#[cfg(windows)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use std::path::{Path, PathBuf};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    use windows_sys::Win32::System::Threading::*;
    use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramFiles};

    const DIRECTORY: &str = "SpiderVPN-Lifecycle";
    const LEAF: &str = "occupancy.lock";
    const BA: &str = "S-1-5-32-544";
    const SY: &str = "S-1-5-18";
    const TI: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    const AU: &str = "S-1-5-11";
    const FULL: u32 = 0x001f01ff;
    const DIR_READ: u32 = 0x001200a9;
    const FILE_READ: u32 = 0x00120089;
    const OPEN_FLAGS: u32 = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    const READ_CONTROL_RIGHT: u32 = 0x00020000;
    const SYNC_RIGHT: u32 = 0x00100000;
    const LOCK_LEN: u32 = 1; // offset 0, same range for every participant

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().chain(Some(0)).collect()
    }
    fn last(label: &str) -> String {
        format!("{label} win32={}", unsafe { GetLastError() })
    }
    struct Local(*mut core::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { LocalFree(self.0); } }
        }
    }
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0); }
            }
        }
    }

    // No SPIDERVPN_ROOT, ProgramFiles environment variable, registry override
    // or user-configured path is used to select the machine anchor.
    fn program_files() -> Result<PathBuf, String> {
        let mut p = null_mut();
        let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, null_mut(), &mut p) };
        if hr < 0 || p.is_null() { return Err(format!("G2_KNOWN_FOLDER hr={hr:#x}")); }
        let mut n = 0;
        while n < 32768 && unsafe { *p.add(n) } != 0 { n += 1; }
        let result = if n == 32768 { Err("G2_KNOWN_FOLDER_LENGTH".into()) }
        else { String::from_utf16(unsafe { std::slice::from_raw_parts(p, n) })
            .map(PathBuf::from).map_err(|_| "G2_KNOWN_FOLDER_UTF16".into()) };
        unsafe { CoTaskMemFree(p.cast()); }
        result
    }

    fn parts(path: &Path) -> Result<Vec<PathBuf>, String> {
        let s = path.to_str().ok_or("G2_PATH_UTF16")?;
        let b = s.as_bytes();
        if b.len() < 4 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\'
            || s.len() > 240 { return Err("G2_PATH_DOS_REQUIRED".into()); }
        let mut result = vec![PathBuf::from(&s[..3])];
        for name in s[3..].split('\\') {
            let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
            let device = matches!(stem.as_str(), "CON"|"PRN"|"AUX"|"NUL"|"CONIN$"|"CONOUT$"|"CLOCK$")
                || stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT"))
                    .is_some_and(|n| matches!(n,"1"|"2"|"3"|"4"|"5"|"6"|"7"|"8"|"9"|"¹"|"²"|"³"));
            if name.is_empty() || name.ends_with(['.', ' ']) || device
                || name.chars().any(|c| c.is_control() || ":*?\"<>|/".contains(c)) {
                return Err("G2_PATH_ALIAS_OR_TRAVERSAL".into());
            }
            result.push(result.last().unwrap().join(name));
        }
        if unsafe { GetDriveTypeW(wide(result[0].as_os_str()).as_ptr()) } != 3 {
            return Err("G2_PATH_NOT_FIXED_DRIVE".into());
        }
        Ok(result)
    }

    fn sid_text(sid: *mut core::ffi::c_void) -> Result<String, String> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 { return Err("G2_INVALID_SID".into()); }
        let mut p = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut p) } == 0 || p.is_null() {
            return Err(last("G2_SID_TEXT"));
        }
        let _p = Local(p.cast());
        let mut n = 0;
        while n < 256 && unsafe { *p.add(n) } != 0 { n += 1; }
        if n == 256 { return Err("G2_SID_LENGTH".into()); }
        String::from_utf16(unsafe { std::slice::from_raw_parts(p,n) })
            .map_err(|_| "G2_SID_UTF16".into())
    }
    fn trusted_owner(s: &str) -> bool { matches!(s, BA | SY | TI) }

    // Read back the actual descriptor of the held handle. Ancestors follow
    // the existing protected-ancestor policy, not a blanket ACL rewrite.
    // Dedicated objects have exact protected SY/BA/AU ACLs, no inherited
    // ACE, no untrusted write/delete/WRITE_DAC/WRITE_OWNER grant.
    fn acl(file: &File, path: &Path, exact: Option<u32>, immediate: bool) -> Result<(), String> {
        let mut owner = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut sd = null_mut();
        let rc = unsafe { GetSecurityInfo(file.as_raw_handle(), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner, null_mut(), &mut dacl, null_mut(), &mut sd) };
        let _sd = Local(sd.cast());
        if rc != 0 || sd.is_null() || owner.is_null() || dacl.is_null() {
            return Err(format!("G2_ACL_QUERY path={path:?} win32={rc}"));
        }
        let who = sid_text(owner)?;
        if if exact.is_some() { who != BA && who != SY } else { !trusted_owner(&who) } {
            return Err(format!("G2_ACL_OWNER path={path:?} owner={who}"));
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut returned = null_mut();
        let mut control = 0u16;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorDacl(sd,&mut present,&mut returned,&mut defaulted) } == 0
            || unsafe { GetSecurityDescriptorControl(sd,&mut control,&mut revision) } == 0
            || present == 0 || returned != dacl
            || (exact.is_some() && (control & 0x1000 == 0 || defaulted != 0)) {
            return Err(format!("G2_ACL_CONTROL path={path:?} control={control:#x}"));
        }
        let count = unsafe { (*dacl).AceCount };
        if count == 0 || count > 128 || (exact.is_some() && count != 3) {
            return Err(format!("G2_ACL_COUNT path={path:?} count={count}"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for n in 0..u32::from(count) {
            let mut p = null_mut();
            if unsafe { GetAce(dacl,n,&mut p) } == 0 || p.is_null() {
                return Err(last("G2_ACE_READ"));
            }
            let header = unsafe { &*p.cast::<ACE_HEADER>() };
            if !matches!(header.AceType,0|1) || header.AceSize < 16 {
                return Err(format!("G2_ACE_FORMAT path={path:?} type={}",header.AceType));
            }
            let a = unsafe { &*p.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = std::ptr::addr_of!(a.SidStart).cast_mut().cast::<core::ffi::c_void>();
            let prefix = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(),8) };
            let len = 8+usize::from(prefix[1])*4;
            if len != usize::from(header.AceSize)-8 || unsafe { IsValidSid(sid) } == 0
                || unsafe { GetLengthSid(sid) } as usize != len {
                return Err("G2_ACE_SID_BOUNDS".into());
            }
            let trustee = sid_text(sid)?;
            if let Some(read) = exact {
                let mask = match trustee.as_str() {
                    BA|SY => FULL, AU => read, _ => return Err("G2_ACE_UNTRUSTED".into()),
                };
                if header.AceType != 0 || header.AceFlags != 0 || a.Mask != mask
                    || !seen.insert(trustee) {
                    return Err(format!("G2_ACE_EXACT path={path:?} mask={:#x}",a.Mask));
                }
            } else if header.AceType == 0 && header.AceFlags & 0x08 == 0 && !trusted_owner(&trustee) {
                let forbidden = 0x500d0150u32 | if immediate { 0x6 } else { 0 };
                if a.Mask & forbidden != 0 {
                    return Err(format!("G2_ACL_ANCESTOR_WRITE path={path:?} sid={trustee} mask={:#x}",a.Mask));
                }
            }
        }
        if exact.is_some() && seen.len() != 3 { return Err("G2_ACE_MISSING".into()); }
        #[cfg(test)]
        if let Some(read) = exact {
            println!("G2_ACL path={path:?} owner={who} ace_count={count} control={control:#x} read_mask={read:#x} read_rc={rc}");
        }
        Ok(())
    }
    type ObjectId = (u32,u32,u32);
    fn id(i: &BY_HANDLE_FILE_INFORMATION) -> ObjectId {
        (i.dwVolumeSerialNumber,i.nFileIndexHigh,i.nFileIndexLow)
    }
    fn raw_info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION,String> {
        let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
            || unsafe { GetFileInformationByHandle(file.as_raw_handle(),&mut i) } == 0 {
            return Err(last("G2_OBJECT_INFO"));
        }
        Ok(i)
    }
    fn unnamed_stream_only(file: &File, dir: bool) -> Result<(), String> {
        let mut data = vec![0u64;8192];
        let bytes = unsafe { std::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<u8>(), data.len()*8) };
        if unsafe { GetFileInformationByHandleEx(file.as_raw_handle(),FileStreamInfo,
            bytes.as_mut_ptr().cast(),bytes.len() as u32) } == 0 {
            let rc = unsafe { GetLastError() };
            if dir && rc == ERROR_HANDLE_EOF { return Ok(()); }
            return Err(format!("G2_STREAM_INFO win32={rc}"));
        }
        let next = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let wanted: Vec<u8> = "::$DATA".encode_utf16().flat_map(u16::to_le_bytes).collect();
        if next != 0 || len != wanted.len() || bytes[24..24+wanted.len()] != wanted {
            return Err("G2_ALTERNATE_STREAM".into());
        }
        Ok(())
    }
    fn checked_info(file: &File, path: &Path, dir: bool, dedicated: bool)
        -> Result<BY_HANDLE_FILE_INFORMATION,String> {
        let i = raw_info(file)?;
        if i.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DEVICE) != 0
            || (i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != dir
            || i.nFileIndexHigh == 0 && i.nFileIndexLow == 0
            || !dir && i.nNumberOfLinks != 1 {
            return Err(format!("G2_OBJECT_TYPE_OR_LINK path={path:?} attrs={:#x} links={}",i.dwFileAttributes,i.nNumberOfLinks));
        }
        let mut buffer = vec![0u16;32768];
        let n = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(),buffer.as_mut_ptr(),buffer.len() as u32,0) } as usize;
        if n == 0 || n >= buffer.len() { return Err(last("G2_FINAL_PATH")); }
        let actual = String::from_utf16(&buffer[..n]).map_err(|_| "G2_FINAL_UTF16")?;
        if !actual.strip_prefix(r"\\?\").is_some_and(|s| path.to_str().is_some_and(|p| s.eq_ignore_ascii_case(p))) {
            return Err(format!("G2_PATH_ALIAS expected={path:?} actual={actual:?}"));
        }
        if dedicated { unnamed_stream_only(file,dir)?; }
        Ok(i)
    }

    struct Object {
        path: PathBuf,
        file: File,
        before: BY_HANDLE_FILE_INFORMATION,
        dir: bool,
        exact: Option<u32>,
        immediate: bool,
    }
    impl Object {
        fn open(path: &Path, dir: bool, exact: Option<u32>, immediate: bool) -> Result<Self,String> {
            let mut op = OpenOptions::new();
            if dir { op.access_mode(FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL_RIGHT|SYNC_RIGHT); }
            else { op.read(true); } // GENERIC_READ, no write/delete, sufficient for LockFileEx
            // Retain OS ancestors without denying normal unrelated writes to
            // their contents, but prohibit rename/delete of the held objects.
            // Dedicated directory and leaf also deny write-sharing.
            let share = if exact.is_some() { FILE_SHARE_READ } else { FILE_SHARE_READ|FILE_SHARE_WRITE };
            let file = op.share_mode(share).custom_flags(OPEN_FLAGS).open(path)
                .map_err(|e| format!("G2_OBJECT_OPEN path={path:?} win32={:?}",e.raw_os_error()))?;
            let before = checked_info(&file,path,dir,exact.is_some())?;
            acl(&file,path,exact,immediate)?;
            Ok(Self{path:path.to_owned(),file,before,dir,exact,immediate})
        }
        fn recheck(&self) -> Result<(),String> {
            let now = checked_info(&self.file,&self.path,self.dir,self.exact.is_some())?;
            if id(&now) != id(&self.before)
                || now.dwFileAttributes != self.before.dwFileAttributes
                || (!self.dir && (now.nNumberOfLinks != self.before.nNumberOfLinks
                    || now.nFileSizeHigh != self.before.nFileSizeHigh || now.nFileSizeLow != self.before.nFileSizeLow
                    || now.ftLastWriteTime.dwHighDateTime != self.before.ftLastWriteTime.dwHighDateTime
                    || now.ftLastWriteTime.dwLowDateTime != self.before.ftLastWriteTime.dwLowDateTime)) {
                return Err(format!("G2_OBJECT_CHANGED path={:?}",self.path));
            }
            acl(&self.file,&self.path,self.exact,self.immediate)
        }
    }
    struct Anchor {
        // The complete ancestor chain and exact leaf remain open for the
        // entire lock lifetime; no path re-resolution substitutes an object.
        ancestors: Vec<Object>,
        leaf: Object,
    }
    impl Anchor {
        fn open() -> Result<Self,String> {
            let pf = program_files()?;
            let paths = parts(&pf)?;
            let dir = pf.join(DIRECTORY);
            // Cheap negative-only check for the ordinary unprovisioned
            // legacy installation. It never authorizes a lock or claims
            // an absence of other writers. Positive paths still use the
            // full held-object chain below.
            let attributes = unsafe { GetFileAttributesW(wide(dir.as_os_str()).as_ptr()) };
            if attributes == INVALID_FILE_ATTRIBUTES {
                let rc = unsafe { GetLastError() };
                if matches!(rc, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
                    return Err(format!("G2_OBJECT_OPEN path={dir:?} win32=Some({rc})"));
                }
            }
            let mut ancestors = Vec::new();
            for (n,p) in paths.iter().enumerate() {
                ancestors.push(Object::open(p,true,None,n+1==paths.len())?);
            }
            ancestors.push(Object::open(&dir,true,Some(DIR_READ),false)?);
            let leaf = Object::open(&dir.join(LEAF),false,Some(FILE_READ),false)?;
            let anchor = Self{ancestors,leaf};
            anchor.recheck()?;
            Ok(anchor)
        }
        fn recheck(&self) -> Result<(),String> {
            for obj in &self.ancestors { obj.recheck()?; }
            self.leaf.recheck()?;
            let volume = self.leaf.before.dwVolumeSerialNumber;
            if self.ancestors.iter().any(|x| x.before.dwVolumeSerialNumber != volume) {
                return Err("G2_DIFFERENT_VOLUME".into());
            }
            Ok(())
        }
    }
    struct AnchorLock { anchor: Anchor, exclusive: bool }
    enum Acquire {
        Held(AnchorLock),
        Unknown(String),
        Refused(String),
    }
    fn acquire(exclusive: bool) -> Acquire {
        let anchor = match Anchor::open() {
            Ok(a) => a,
            Err(e) => return Acquire::Unknown(e),
        };
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        let flags = LOCKFILE_FAIL_IMMEDIATELY | if exclusive { LOCKFILE_EXCLUSIVE_LOCK } else { 0 };
        if unsafe { LockFileEx(anchor.leaf.file.as_raw_handle(),flags,0,LOCK_LEN,0,&mut ov) } == 0 {
            let rc = unsafe { GetLastError() };
            let check = anchor.recheck();
            // Once a protected object is verified, even a subsequently
            // failed readback cannot turn real contention into legacy admission.
            return Acquire::Refused(format!("G2_{} win32={rc} recheck={check:?}",
                if rc == ERROR_LOCK_VIOLATION {"LOCK_CONFLICT"} else {"LOCK_ERROR"}));
        }
        let held = AnchorLock{anchor,exclusive};
        if let Err(e) = held.anchor.recheck() {
            return Acquire::Refused(format!("G2_LOCK_RECHECK {e}"));
        }
        #[cfg(test)]
        println!("G2_LOCK_HELD exclusive={exclusive} pid={} id={:?} source_authenticated=false",
            std::process::id(),id(&held.anchor.leaf.before));
        Acquire::Held(held)
    }
    impl Drop for AnchorLock {
        fn drop(&mut self) {
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            if unsafe { UnlockFileEx(self.anchor.leaf.file.as_raw_handle(),0,LOCK_LEN,0,&mut ov) } == 0 {
                eprintln!("{}",last("G2_UNLOCK"));
            }
            // Closing the same non-inheritable file handle is the final
            // kernel cleanup, including process termination.
        }
    }

    pub(crate) struct RuntimeAdmission {
        _registered: Option<AnchorLock>,
        // Unknown is deliberately visible, not an affirmative credential.
        _unknown: Option<String>,
    }
    pub(crate) fn admit() -> Result<RuntimeAdmission,String> {
        match acquire(false) {
            Acquire::Held(lock) => Ok(RuntimeAdmission{_registered:Some(lock),_unknown:None}),
            Acquire::Unknown(reason) => {
                eprintln!("G2_RUNTIME_UNREGISTERED: {reason} (maintenance not authorized)");
                Ok(RuntimeAdmission{_registered:None,_unknown:Some(reason)})
            }
            Acquire::Refused(reason) => Err(format!("运行准入拒绝：{reason}")),
        }
    }

    // Independent process occupancy: name is only a conservative hint.
    // A candidate is never accepted on PID/name alone. Keep the same actual
    // process handle while checking creation stamp, image and token.
    struct ProcessIdentity {
        _handle: Handle,
        pid: u32,
        created: u64,
        image: PathBuf,
        sid: String,
        session: u32,
        elevated: bool,
    }
    fn times(h: HANDLE) -> Result<u64,String> {
        let mut c: FILETIME = unsafe { std::mem::zeroed() };
        let mut e = c;
        let mut k = c;
        let mut u = c;
        if unsafe { GetProcessTimes(h,&mut c,&mut e,&mut k,&mut u) } == 0 {
            return Err(last("G2_PROCESS_TIMES"));
        }
        let stamp = (u64::from(c.dwHighDateTime)<<32)|u64::from(c.dwLowDateTime);
        if stamp == 0 { return Err("G2_PROCESS_CREATION_ZERO".into()); }
        Ok(stamp)
    }
    fn live(h: HANDLE, pid: u32) -> Result<(),String> {
        if unsafe { GetProcessId(h) } != pid
            || unsafe { WaitForSingleObject(h,0) } != WAIT_TIMEOUT {
            return Err(format!("G2_PROCESS_GONE_OR_CHANGED pid={pid}"));
        }
        Ok(())
    }
    fn image_path(h: HANDLE) -> Result<PathBuf,String> {
        let mut p = vec![0u16;32768];
        let mut n = p.len() as u32;
        if unsafe { QueryFullProcessImageNameW(h,0,p.as_mut_ptr(),&mut n) } == 0
            || n == 0 || n as usize >= p.len() {
            return Err(last("G2_PROCESS_IMAGE"));
        }
        String::from_utf16(&p[..n as usize]).map(PathBuf::from).map_err(|_| "G2_PROCESS_IMAGE_UTF16".into())
    }
    fn token_identity(h: HANDLE) -> Result<(String,u32,bool),String> {
        let mut t = null_mut();
        if unsafe { OpenProcessToken(h,TOKEN_QUERY,&mut t) } == 0 || t.is_null() {
            return Err(last("G2_PROCESS_TOKEN"));
        }
        let token = Handle(t);
        let mut len = 0u32;
        unsafe { GetTokenInformation(token.0,TokenUser,null_mut(),0,&mut len); }
        if len < std::mem::size_of::<TOKEN_USER>() as u32 || len > 65536 {
            return Err("G2_PROCESS_TOKEN_SIZE".into());
        }
        let mut buf = vec![0usize;(len as usize).div_ceil(std::mem::size_of::<usize>())];
        let mut actual = len;
        if unsafe { GetTokenInformation(token.0,TokenUser,buf.as_mut_ptr().cast(),len,&mut actual) } == 0
            || actual < std::mem::size_of::<TOKEN_USER>() as u32 || actual > len {
            return Err(last("G2_PROCESS_TOKEN_USER"));
        }
        let sid = sid_text(unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
        let mut session = 0u32;
        let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
        if unsafe { GetTokenInformation(token.0,TokenSessionId,(&mut session as *mut u32).cast(),4,&mut actual) } == 0 || actual != 4 {
            return Err(last("G2_PROCESS_TOKEN_SESSION"));
        }
        if unsafe { GetTokenInformation(token.0,TokenElevation,(&mut elevation as *mut TOKEN_ELEVATION).cast(),4,&mut actual) } == 0
            || actual != 4 || elevation.TokenIsElevated > 1 {
            return Err(last("G2_PROCESS_TOKEN_ELEVATION"));
        }
        Ok((sid,session,elevation.TokenIsElevated==1))
    }
    fn process(pid: u32, hint: &str, extra_images: &[PathBuf]) -> Result<Option<ProcessIdentity>,String> {
        let h = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNC_RIGHT,0,pid) });
        if h.0.is_null() { return Err(last("G2_PROCESS_OPEN")); }
        live(h.0,pid)?;
        let created = times(h.0)?;
        let image = image_path(h.0)?;
        let actual_name = image.file_name().and_then(|x| x.to_str()).ok_or("G2_PROCESS_NAME")?;
        if !actual_name.eq_ignore_ascii_case(hint) { return Err("G2_PROCESS_SNAPSHOT_MISMATCH".into()); }
        let image_text = image.to_str().ok_or("G2_PROCESS_IMAGE_UTF16")?.to_ascii_lowercase();
        let known_root = format!("{}\\",crate::isolation::Rewrite::INSTALL_DIR.to_ascii_lowercase());
        // A same-name outsider is deliberately a blocker, not a trusted
        // SpiderVPN identity. Extra paths can only increase blocking.
        let relevant = matches!(actual_name.to_ascii_lowercase().as_str(),
            "spidervpn.exe"|"spidervpn-bootstrap.exe"|"sing-box.exe")
            || image_text.starts_with(&known_root)
            || extra_images.iter().any(|p| p.to_str().is_some_and(|s| s.eq_ignore_ascii_case(&image_text)));
        if !relevant {
            live(h.0,pid)?;
            if times(h.0)? != created { return Err("G2_PROCESS_CREATION_CHANGED".into()); }
            return Ok(None);
        }
        let (sid,session,elevated) = token_identity(h.0)?;
        live(h.0,pid)?;
        if times(h.0)? != created || image_path(h.0)? != image {
            return Err("G2_PROCESS_IDENTITY_CHANGED".into());
        }
        Ok(Some(ProcessIdentity{_handle:h,pid,created,image,sid,session,elevated}))
    }
    struct Scan { active: Vec<ProcessIdentity>, unknown: Vec<(u32,String)> }
    fn scan(extra_images: &[PathBuf]) -> Scan {
        let mut result = Scan{active:Vec::new(),unknown:Vec::new()};
        let snap = Handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0) });
        if snap.0 == INVALID_HANDLE_VALUE {
            result.unknown.push((0,last("G2_SNAPSHOT")));
            return result;
        }
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if unsafe { Process32FirstW(snap.0,&mut entry) } == 0 {
            result.unknown.push((0,last("G2_SNAPSHOT_FIRST")));
            return result;
        }
        loop {
            let n = entry.szExeFile.iter().position(|v| *v==0).unwrap_or(entry.szExeFile.len());
            let pid = entry.th32ProcessID;
            match String::from_utf16(&entry.szExeFile[..n]) {
                Ok(hint) => match process(pid,&hint,extra_images) {
                    Ok(Some(identity)) => result.active.push(identity),
                    Ok(None) => {}
                    Err(reason) => result.unknown.push((pid,reason)),
                },
                Err(_) => result.unknown.push((pid,"G2_SNAPSHOT_NAME_UTF16".into())),
            }
            if unsafe { Process32NextW(snap.0,&mut entry) } == 0 {
                let rc = unsafe { GetLastError() };
                if rc != ERROR_NO_MORE_FILES { result.unknown.push((0,format!("G2_SNAPSHOT_NEXT win32={rc}"))); }
                break;
            }
        }
        result
    }
    #[derive(Debug,PartialEq,Eq)]
    enum Occupancy { Active, Unknown, NoKnownOccupancy }
    impl Scan {
        fn classification(&self) -> Occupancy {
            if !self.active.is_empty() { Occupancy::Active }
            else if !self.unknown.is_empty() { Occupancy::Unknown }
            else { Occupancy::NoKnownOccupancy }
        }
    }
    // The exclusive lock is private and cannot escape as an authorization
    // ticket. While it is held, inspect actual processes; even the empty
    // result cannot prove authenticated anchor deployment or old writers.
    fn maintenance_check(extra_images: &[PathBuf]) -> (Occupancy,String) {
        match acquire(true) {
            Acquire::Held(_held) => {
                let observed = scan(extra_images);
                (observed.classification(),"G2_NOT_READY: source/history/maintenance not authorized".into())
            }
            Acquire::Unknown(reason) | Acquire::Refused(reason) =>
                (Occupancy::Unknown,format!("G2_NOT_READY: {reason}")),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::os::windows::io::FromRawHandle;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};
        const TEST: &str = "runtime_occupancy::imp::tests::g2_runtime_occupancy";
        const ROLE: &str = "SPIDERVPN_G2_TEST_ROLE";
        const ROOT: &str = "SPIDERVPN_G2_TEST_ROOT";
        const LIMIT: Duration = Duration::from_secs(20);
        const DIR_SD: &str = "O:BAD:P(A;;0x001f01ff;;;SY)(A;;0x001f01ff;;;BA)(A;;0x001200a9;;;AU)";
        const FILE_SD: &str = "O:BAD:P(A;;0x001f01ff;;;SY)(A;;0x001f01ff;;;BA)(A;;0x00120089;;;AU)";
        const DELETE_RIGHT: u32 = 0x00010000;

        fn attributes<T>(sddl:&str, f:impl FnOnce(&SECURITY_ATTRIBUTES)->T) -> T {
            let mut sd = null_mut();
            assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(std::ffi::OsStr::new(sddl)).as_ptr(),SDDL_REVISION_1,&mut sd,null_mut()) },0);
            assert!(!sd.is_null());
            let _sd = Local(sd.cast());
            f(&SECURITY_ATTRIBUTES {
                nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor:sd,bInheritHandle:0,
            })
        }
        fn raw_open(path:&Path, access:u32, share:u32) -> Result<File,String> {
            let h=unsafe { CreateFileW(wide(path.as_os_str()).as_ptr(),access,share,null_mut(),
                OPEN_EXISTING,OPEN_FLAGS,null_mut()) };
            if h==INVALID_HANDLE_VALUE { Err(last("G2_TEST_OPEN")) }
            else { Ok(unsafe { File::from_raw_handle(h) }) }
        }
        fn absence(path:&Path) {
            let a=unsafe { GetFileAttributesW(wide(path.as_os_str()).as_ptr()) };
            let rc=unsafe { GetLastError() };
            assert_eq!(a,INVALID_FILE_ATTRIBUTES,"refuse to adopt pre-existing object {path:?}");
            assert!(matches!(rc,ERROR_FILE_NOT_FOUND|ERROR_PATH_NOT_FOUND),"unknown absence rc={rc}");
        }
        // Only the test creates the reserved directory; exact CREATE_NEW
        // or CreateDirectoryW, then record its own kernel object identity.
        // Never adopt or recursively remove a pre-existing directory.
        struct Fixture { dir:PathBuf, owned:Vec<(PathBuf,ObjectId)> }
        impl Fixture {
            fn new(sd:&str)->Self {
                let pf=program_files().unwrap();
                let ps=parts(&pf).unwrap();
                let _parents:Vec<_>=ps.iter().enumerate().map(|(n,p)|
                    Object::open(p,true,None,n+1==ps.len()).unwrap()).collect();
                let dir=pf.join(DIRECTORY);
                absence(&dir);
                assert_ne!(attributes(sd,|sa|unsafe { CreateDirectoryW(wide(dir.as_os_str()).as_ptr(),sa) }),0,
                    "{}",last("G2_FIXTURE_DIR_NEW"));
                let mut f=Self{dir:dir.clone(),owned:Vec::new()};
                f.remember(&dir);
                f
            }
            fn remember(&mut self,path:&Path) {
                let file=raw_open(path,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE).unwrap();
                self.owned.push((path.to_owned(),id(&raw_info(&file).unwrap())));
            }
            fn leaf(&self)->PathBuf { self.dir.join(LEAF) }
            fn file(&mut self,sd:&str) {
                let path=self.leaf();
                let h=attributes(sd,|sa|unsafe { CreateFileW(wide(path.as_os_str()).as_ptr(),
                    GENERIC_READ|GENERIC_WRITE,0,sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,null_mut()) });
                assert_ne!(h,INVALID_HANDLE_VALUE,"{}",last("G2_FIXTURE_FILE_NEW"));
                let file=unsafe { File::from_raw_handle(h) };
                self.owned.push((path,id(&raw_info(&file).unwrap())));
            }
            fn checked()->Self {
                let mut f=Self::new(DIR_SD); f.file(FILE_SD);
                let a=Anchor::open().unwrap();
                assert_eq!(id(&a.leaf.before),f.owned[1].1);
                assert_eq!(id(&a.ancestors.last().unwrap().before),f.owned[0].1);
                println!("G2_FIXTURE_READY same_volume=true leaf_id={:?} dir_id={:?} source_authenticated=false",f.owned[1].1,f.owned[0].1);
                f
            }
            fn cleanup(&mut self)->Result<(),String> {
                while let Some((path,expected))=self.owned.last() {
                    // Delete only our exact recorded object, on the same
                    // DELETE handle. A replacement or unknown child stops
                    // cleanup rather than deleting by name/recursive tree.
                    let file=raw_open(path,DELETE_RIGHT|FILE_READ_ATTRIBUTES,0)?;
                    if id(&raw_info(&file)?)!=*expected { return Err("G2_FIXTURE_CLEANUP_ID_CHANGED".into()); }
                    let d=FILE_DISPOSITION_INFO{DeleteFile:true as _};
                    if unsafe { SetFileInformationByHandle(file.as_raw_handle(),FileDispositionInfo,
                        (&d as *const FILE_DISPOSITION_INFO).cast(),std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32) }==0 {
                        return Err(last("G2_FIXTURE_DISPOSITION"));
                    }
                    drop(file);
                    absence(path);
                    self.owned.pop();
                }
                Ok(())
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                if let Err(e)=self.cleanup() {
                    eprintln!("G2_FIXTURE_CLEANUP_STOPPED {e}");
                    if !std::thread::panicking() { panic!("{e}"); }
                }
            }
        }
        fn held(exclusive:bool)->AnchorLock {
            match acquire(exclusive) {
                Acquire::Held(h)=>h,
                Acquire::Unknown(e)|Acquire::Refused(e)=>panic!("expected actual lock: {e}"),
            }
        }
        fn busy(exclusive:bool) {
            match acquire(exclusive) {
                Acquire::Refused(e)=>assert!(e.contains("G2_LOCK_CONFLICT win32=33 recheck=Ok(())"),"{e}"),
                Acquire::Unknown(e)=>panic!("contention became unknown: {e}"),
                Acquire::Held(_)=>panic!("incompatible lock admitted"),
            }
        }
        fn unknown(label:&str,reason:&str) {
            match acquire(false) {
                Acquire::Unknown(e)=> {
                    assert!(e.contains(reason),"{label}: {e}");
                    println!("G2_UNKNOWN case={label} reason={e}");
                }
                _=>panic!("{label}: unverified anchor accepted"),
            }
            let a=admit().expect("legacy runtime remains compatible");
            assert!(a._registered.is_none() && a._unknown.is_some());
            let (class,note)=maintenance_check(&[]);
            assert_eq!(class,Occupancy::Unknown);
            assert!(note.starts_with("G2_NOT_READY"));
        }
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _=self.0.kill(); let _=self.0.wait();
                }
            }
        }
        fn wait(child:&mut ChildGuard)->i32 {
            let deadline=Instant::now()+LIMIT;
            loop {
                if let Some(status)=child.0.try_wait().unwrap() { return status.code().unwrap(); }
                if Instant::now()>=deadline {
                    let _=child.0.kill(); let _=child.0.wait();
                    panic!("G2 subprocess timeout 20s");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        fn ready(path:&Path, child:&mut ChildGuard)->String {
            let deadline=Instant::now()+LIMIT;
            loop {
                assert!(child.0.try_wait().unwrap().is_none(),"holder exited before ready");
                if let Ok(s)=std::fs::read_to_string(path) {
                    if s.starts_with(&format!("{} ",child.0.id())) { return s; }
                }
                assert!(Instant::now()<deadline,"G2 holder handshake timeout");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        fn worker(exe:&Path,root:&Path,role:&str)->Command {
            let mut c=Command::new(exe);
            c.args(["--ignored","--exact",TEST,"--nocapture"]).env(ROLE,role).env(ROOT,root);
            c
        }
        fn holder(root:&Path,role:&str,expected:ObjectId)->ChildGuard {
            std::fs::create_dir(root).unwrap();
            let mut c=ChildGuard(worker(&std::env::current_exe().unwrap(),root,role)
                .stdin(Stdio::piped()).spawn().unwrap());
            let result=ready(&root.join("ready"),&mut c);
            assert_eq!(result,format!("{} {:?}",c.0.id(),expected));
            println!("G2_LOCK_PEER role={role} pid={} id={expected:?} same_object=true",c.0.id());
            c
        }
        fn release(mut c:ChildGuard,abnormal:bool) {
            if abnormal {
                c.0.kill().unwrap(); assert_ne!(wait(&mut c),0);
            } else {
                drop(c.0.stdin.take()); assert_eq!(wait(&mut c),0);
            }
        }
        fn run_worker(exe:&Path,root:&Path,role:&str) {
            std::fs::create_dir(root).unwrap();
            let mut c=ChildGuard(worker(exe,root,role)
                .env("SPIDERVPN_G2_FIXTURE_MARKER",root.join("engine-marker"))
                .stdin(Stdio::null()).spawn().unwrap());
            assert_eq!(wait(&mut c),0);
        }

        #[test]
        #[ignore = "explicit isolated elevated Windows CI; creates only its own fixed protected fixture"]
        fn g2_runtime_occupancy() {
            if let Ok(role)=std::env::var(ROLE) {
                let root=PathBuf::from(std::env::var_os(ROOT).unwrap());
                assert!(root.starts_with(std::env::temp_dir()) && root.is_dir());
                if matches!(role.as_str(),"shared"|"exclusive") {
                    let h=held(role=="exclusive");
                    std::fs::write(root.join("ready"),format!("{} {:?}",std::process::id(),id(&h.anchor.leaf.before))).unwrap();
                    assert_eq!(std::io::stdin().read(&mut [0u8;1]).unwrap(),0);
                    return;
                }
                let exe=std::env::current_exe().unwrap();
                let engine=exe.parent().unwrap().join("sing-box.exe");
                assert!(exe.starts_with(std::env::temp_dir()) && engine.is_file());
                match role.as_str() {
                    "start-ok"|"start-denied" => {
                        let cfg=crate::engine::EngineConfig{binary:engine.to_string_lossy().into_owned(),args:vec!["hold".into()]};
                        let h=crate::engine::start(&cfg,&root.join("logs"));
                        if role=="start-denied" {
                            assert!(h.err().unwrap().contains("G2_LOCK_CONFLICT win32=33"));
                            assert!(!root.join("logs").exists());
                            assert!(!root.join("engine-marker").exists());
                        } else {
                            let pid=h.unwrap().pid;
                            assert!(pid>0);
                            std::fs::write(root.join("child-pid"),pid.to_string()).unwrap();
                        }
                    }
                    "version-ok"|"version-denied" => {
                        let v=crate::ipc::probe_engine_binary(&engine);
                        if role=="version-denied" {
                            assert!(v.unwrap_err().contains("G2_LOCK_CONFLICT win32=33"));
                            assert!(!root.join("engine-marker").exists());
                        } else {
                            assert_eq!(v.unwrap(),"sing-box G2 isolated fixture");
                            assert!(root.join("engine-marker").is_file());
                        }
                    }
                    _=>panic!("unknown G2 test role"),
                }
                println!("G2_REAL_ENGINE_ENTRY role={role} pid={} actual_original_function=true",std::process::id());
                return;
            }
            assert!(token_identity(unsafe { GetCurrentProcess() }).unwrap().2,"isolated elevated runner required");
            let random={
                use ring::rand::{SecureRandom,SystemRandom};
                let mut b=[0u8;16];SystemRandom::new().fill(&mut b).unwrap();
                b.iter().map(|x|format!("{x:02x}")).collect::<String>()
            };
            let root=std::env::temp_dir().join(format!("spidervpn-g2-{random}"));
            std::fs::create_dir(&root).unwrap();
            struct Temp(PathBuf);
            impl Drop for Temp {
                fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}
            }
            let _tmp=Temp(root.clone());
            let dir=program_files().unwrap().join(DIRECTORY);
            absence(&dir); // abort on ANY prior object; no production anchor adoption
            unknown("missing","G2_OBJECT_OPEN");
            {
                let _f=Fixture::new(DIR_SD);
                unknown("precreated_directory_missing_leaf","G2_OBJECT_OPEN");
            }
            {
                let mut f=Fixture::new(DIR_SD);
                f.file(&format!("{FILE_SD}(A;;0x001f01ff;;;WD)"));
                unknown("broad_acl","G2_ACL_COUNT");
            }
            {
                let own=token_identity(unsafe { GetCurrentProcess() }).unwrap().0;
                assert!(!matches!(own.as_str(),BA|SY),"wrong-owner test needs actual distinct account SID");
                let mut f=Fixture::new(DIR_SD);
                f.file(&FILE_SD.replace("O:BA",&format!("O:{own}")));
                unknown("wrong_owner","G2_ACL_OWNER");
            }
            {
                let mut f=Fixture::new(DIR_SD);
                let p=f.leaf();
                assert_ne!(attributes(DIR_SD,|sa|unsafe{CreateDirectoryW(wide(p.as_os_str()).as_ptr(),sa)}),0);
                f.remember(&p);
                unknown("wrong_type","G2_OBJECT_TYPE_OR_LINK");
            }
            {
                let mut f=Fixture::new(DIR_SD);
                f.file(FILE_SD);
                let alias=f.dir.join("extra-link");
                std::fs::hard_link(f.leaf(),&alias).unwrap();
                f.remember(&alias);
                unknown("hard_link","G2_OBJECT_TYPE_OR_LINK");
            }
            {
                let mut f=Fixture::new(DIR_SD);
                f.file(FILE_SD);
                let stream=PathBuf::from(format!("{}:fixture",f.leaf().display()));
                std::fs::write(stream,b"alternate stream").unwrap();
                unknown("alternate_stream","G2_ALTERNATE_STREAM");
            }
            {
                let mut f=Fixture::new(DIR_SD);
                f.file(FILE_SD);
                let stream=PathBuf::from(format!("{}:fixture",f.dir.display()));
                std::fs::write(stream,b"directory alternate stream").unwrap();
                unknown("directory_stream","G2_ALTERNATE_STREAM");
            }
            {
                let mut f=Fixture::new(DIR_SD);
                let target=root.join("junction-target");
                std::fs::create_dir(&target).unwrap();
                let p=f.leaf();
                let output=Command::new(r"C:\Windows\System32\cmd.exe").args(["/D","/C","mklink","/J"])
                    .arg(&p).arg(&target).output().unwrap();
                assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
                f.remember(&p);
                unknown("reparse","G2_OBJECT_TYPE_OR_LINK");
                assert!(target.is_dir());
            }
            {
                let f=Fixture::checked();
                let writer=raw_open(&f.leaf(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE).unwrap();
                unknown("existing_writer","win32=Some(32)");
                drop(writer);
                drop(held(false));
            }
            {
                let target=root.join("ancestor-junction-target");
                std::fs::create_dir(&target).unwrap();
                absence(&dir);
                let output=Command::new(r"C:\Windows\System32\cmd.exe").args(["/D","/C","mklink","/J"])
                    .arg(&dir).arg(&target).output().unwrap();
                assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
                let mut f=Fixture{dir:dir.clone(),owned:Vec::new()};
                f.remember(&dir);
                unknown("anchor_directory_reparse","G2_OBJECT_TYPE_OR_LINK");
                assert!(target.is_dir());
            }
            let product=PathBuf::from(std::env::var_os("SPIDERVPN_G2_PRODUCT_EXE").unwrap());
            let fixture_exe=PathBuf::from(std::env::var_os("SPIDERVPN_G2_FIXTURE_EXE").unwrap());
            assert!(product.is_absolute() && product.is_file() && fixture_exe.is_absolute() && fixture_exe.is_file());
            let work=root.join("worker");
            std::fs::create_dir(&work).unwrap();
            let worker_exe=work.join("g2-test-worker.exe");
            let engine=work.join("sing-box.exe");
            std::fs::copy(std::env::current_exe().unwrap(),&worker_exe).unwrap();
            std::fs::copy(&fixture_exe,&engine).unwrap();

            // Actual debug product with an isolated configuration and HKCU
            // test proxy key. All positive proxy writes target only that key.
            let app=root.join("product");
            std::fs::create_dir_all(app.join("data")).unwrap();
            let app_exe=app.join("spidervpn.exe");
            std::fs::copy(&product,&app_exe).unwrap();
            std::fs::copy(&fixture_exe,app.join("sing-box.exe")).unwrap();
            let profile=root.join("profile.json");
            std::fs::write(&profile,r#"{"inbounds":[{"type":"tun","tag":"trade-tun","mtu":1380,"stack":"gvisor","auto_route":true}],"route":{"rules":[],"final":"direct"},"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"trade-exit","outbounds":["direct"],"default":"direct"}]}"#).unwrap();
            use winreg::{RegKey,enums::HKEY_CURRENT_USER};
            let key=format!(r"Software\SpiderVPN\tests\G2-{random}");
            let run_key=format!(r"Software\SpiderVPN\tests\G2-run-{random}");
            let hkcu=RegKey::predef(HKEY_CURRENT_USER);
            let (reg,_)=hkcu.create_subkey(&key).unwrap();
            reg.set_value("ProxyEnable",&0u32).unwrap();
            reg.set_value("ProxyServer",&"127.0.0.1:7897".to_string()).unwrap();
            reg.set_value("ProxyOverride",&"localhost".to_string()).unwrap();
            #[cfg(test)]
            struct RegistryCleanup(String,String);
            impl Drop for RegistryCleanup {
                fn drop(&mut self) {
                    let h=RegKey::predef(HKEY_CURRENT_USER);
                    let _=h.delete_subkey_all(&self.0);let _=h.delete_subkey_all(&self.1);
                }
            }
            let _reg_cleanup=RegistryCleanup(key.clone(),run_key.clone());
            let proxy_state=|| (reg.get_value::<u32,_>("ProxyEnable").unwrap_or(0),
                reg.get_value::<String,_>("ProxyServer").ok(),
                reg.get_value::<String,_>("ProxyOverride").ok());
            let before=proxy_state();
            let product_cmd=|| {
                let mut cmd=Command::new(&app_exe);
                cmd.env("SPIDERVPN_ROOT",&app).env("SPIDERVPN_PROXY_KEY",&key)
                    .env("SPIDERVPN_RUN_KEY",&run_key).stdin(Stdio::null());
                cmd
            };
            let run=|args:&[&str]|{
                // Redirect to actual files, avoiding a blocked pipe while
                // waiting; preserve both stdout and stderr on failure.
                let out=root.join("cli-stdout");
                let err=root.join("cli-stderr");
                let mut c=ChildGuard(product_cmd().args(args)
                    .stdout(Stdio::from(File::create(&out).unwrap()))
                    .stderr(Stdio::from(File::create(&err).unwrap())).spawn().unwrap());
                let pid=c.0.id();
                let code=wait(&mut c);
                let stdout=String::from_utf8_lossy(&std::fs::read(&out).unwrap()).into_owned();
                let stderr=String::from_utf8_lossy(&std::fs::read(&err).unwrap()).into_owned();
                println!("G2_PRODUCT_CLI args={args:?} pid={pid} exit={code} stderr={stderr:?}");
                (code,format!("{stdout}\n{stderr}"))
            };
            let import=run(&["--import",profile.to_str().unwrap(),"--engine",app.join("sing-box.exe").to_str().unwrap(),
                "--port","17996","--line-name","G2-fixture"]);
            assert_eq!(import.0,0,"{}",import.1);
            let config=app.join("data/config.json");
            let config_before=std::fs::read(&config).unwrap();
            let parsed:serde_json::Value=serde_json::from_slice(&config_before).unwrap();
            assert_eq!(parsed["lines"].as_array().unwrap().len(),1);
            let headless=run(&["--headless"]);
            assert_eq!(headless.0,0,"{}",headless.1);
            assert!(headless.1.contains("G2_RUNTIME_UNREGISTERED"),"missing anchor must be reported");
            println!("G2_PRODUCT_MISSING_COMPAT config_valid=true headless_exit=0 maintenance_not_ready=true");

            // Start a real legacy-compatible controller before the fixture
            // exists: it is live but has no cooperative occupancy handle.
            let mut old_gui=ChildGuard(product_cmd().stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
            let pipe=crate::ipc::name_for(&app.join("data").to_string_lossy());
            assert!(crate::ipc::wait_ready(&pipe,15000),"actual product controller not ready");
            assert!(old_gui.0.try_wait().unwrap().is_none());
            let fixture=Fixture::checked();
            let object=fixture.owned[1].1;
            // Exact ACL is not authenticated provenance; even a readable
            // pre-created fixture must never grant maintenance authorization.
            let (_,note)=maintenance_check(&[]);
            assert!(note.starts_with("G2_NOT_READY"));
            let mut old_exclusion=holder(&root.join("old-exclusive"),"exclusive",object);
            assert!(crate::ipc::ping(&pipe,1000),"read-only ping cannot depend on occupancy gate");
            // The real IPC handler serves an actual named-pipe connect
            // request; the original valid config is already present.
            let n=pipe.clone();
            let (tx,rx)=std::sync::mpsc::channel();
            std::thread::spawn(move||{
                use interprocess::local_socket::prelude::*;
                use interprocess::local_socket::GenericNamespaced;
                let v=(||{
                    let ns=n.to_ns_name::<GenericNamespaced>().ok()?;
                    let mut s=LocalSocketStream::connect(ns).ok()?;
                    s.write_all(b"{\"cmd\":\"connect\"}\n").ok()?;
                    s.flush().ok()?;
                    let mut buf=String::new();
                    use std::io::BufRead;
                    std::io::BufReader::new(&mut s).read_line(&mut buf).ok()?;
                    Some(buf)
                })();
                let _=tx.send(v);
            });
            let reply=rx.recv_timeout(LIMIT).unwrap().unwrap();
            assert!(reply.contains("G2_LOCK_CONFLICT"),"{reply}");
            let observation=scan(&[]);
            let live_gui=observation.active.iter().find(|p|p.pid==old_gui.0.id()).expect("actual unregistered product process");
            assert!(live_gui.created>0 && !live_gui.sid.is_empty());
            assert_eq!(live_gui.image,app_exe);
            assert_eq!(observation.classification(),Occupancy::Active);
            assert_eq!(proxy_state(),before);
            assert!(!app.join("data/proxy-journal.json").exists());
            assert!(!app.join("data/runtime-engine.json").exists());
            println!("G2_IPC_REAL pid={} actual_active=true ping_ok=true connect_conflict=true no_journal=true no_proxy_change=true",live_gui.pid);
            assert!(old_exclusion.0.try_wait().unwrap().is_none());
            release(old_exclusion,false);
            release(old_gui,true);
            drop(observation);

            // Multiple real holders share one exact file; maintenance
            // exclusion fails until every shared handle is gone.
            let own=held(false);
            let a=holder(&root.join("shared-a"),"shared",object);
            let b=holder(&root.join("shared-b"),"shared",object);
            busy(true);
            drop(own);
            release(a,false);
            busy(true);
            release(b,true);
            drop(held(true));
            println!("G2_SHARED_COMPLETE independent_holders=2 exclusive_refused=true normal_release=true abnormal_release=true");

            let mut gui=ChildGuard(product_cmd().stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
            assert!(crate::ipc::wait_ready(&pipe,15000));
            assert!(gui.0.try_wait().unwrap().is_none());
            busy(true);
            assert!(crate::ipc::ping(&pipe,1000));
            println!("G2_PRODUCT_CONTROLLER pid={} shared_lifetime=true exclusive_refused=true ping_ok=true",gui.0.id());
            release(gui,true);
            drop(held(true));

            // True competing exclusive process: all new network write
            // entry points reject, but status and cleanup remain callable.
            let exclusion=holder(&root.join("exclusive"),"exclusive",object);
            busy(false);
            assert!(admit().err().unwrap().contains("G2_LOCK_CONFLICT win32=33"));
            run_worker(&worker_exe,&root.join("start-denied"),"start-denied");
            run_worker(&worker_exe,&root.join("version-denied"),"version-denied");
            for arg in ["--connect","--apply"] {
                let (code,log)=run(&[arg]);
                assert_eq!(code,6,"{log}");
                assert!(log.contains("G2_LOCK_CONFLICT win32=33"),"{log}");
                assert_eq!(std::fs::read(&config).unwrap(),config_before);
                assert_eq!(proxy_state(),before);
                for name in ["proxy-journal.json","runtime.json","runtime-engine.json","logs/engine.log"] {
                    assert!(!app.join("data").join(name).exists(),"{name}");
                }
            }
            assert_eq!(run(&["--status"]).0,0);
            assert_eq!(run(&["--headless"]).0,0);
            // Stable handles actively prevent replacement, not just a
            // path-based "exists" check. Only known fixture objects tested.
            for path in [fixture.leaf(),fixture.dir.clone()] {
                let e=raw_open(&path,DELETE_RIGHT|FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE).err().unwrap();
                assert!(e.contains("win32=32"),"{e}");
                println!("G2_REPLACE_REFUSED path={path:?} native_rc=32");
            }
            release(exclusion,true);
            drop(held(false));

            run_worker(&worker_exe,&root.join("version-ok"),"version-ok");
            run_worker(&worker_exe,&root.join("start-ok"),"start-ok");
            let pid=std::fs::read_to_string(root.join("start-ok/child-pid")).unwrap().parse::<u32>().unwrap();
            // Child process from engine::start outlives the finished
            // controller. Retain an actual handle to just our disposable
            // fixture for cleanup even if a later assertion fails.
            struct Orphan(Handle);
            impl Drop for Orphan {
                fn drop(&mut self) {
                    if unsafe{WaitForSingleObject(self.0.0,0)}==WAIT_TIMEOUT {
                        unsafe{TerminateProcess(self.0.0,1);WaitForSingleObject(self.0.0,5000);}
                    }
                }
            }
            let h=Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNC_RIGHT|PROCESS_TERMINATE,0,pid) });
            assert!(!h.0.is_null());
            assert_eq!(image_path(h.0).unwrap(),engine);
            let orphan=Orphan(h);
            live(orphan.0.0,pid).unwrap();
            let stamp=times(orphan.0.0).unwrap();
            let deadline=Instant::now()+LIMIT;
            loop {
                if let Ok(s)=std::fs::read_to_string(root.join("start-ok/engine-marker")) {
                    if s.trim()==pid.to_string(){break}
                }
                assert!(Instant::now()<deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            let x=held(true); // no cooperating holder remains
            let s=scan(&[]);
            let p=s.active.iter().find(|p|p.pid==pid).expect("live orphan engine in actual scan");
            assert_eq!(p.created,stamp);
            assert_eq!(p.image,engine);
            assert!(!p.sid.is_empty());
            assert_eq!(s.classification(),Occupancy::Active);
            assert!(process(pid,"wrong-image.exe",&[]).err().unwrap().contains("G2_PROCESS_SNAPSHOT_MISMATCH"));
            assert!(process(0,"unknown",&[]).is_err());
            println!("G2_ORPHAN_ACTIVE pid={pid} creation={stamp} image={:?} sid={} session={} elevated={} exclusive_held=true unknown_count={} maintenance_not_ready=true",
                p.image,p.sid,p.session,p.elevated,s.unknown.len());
            // Existing engine shutdown has no admission check and must
            // work while exclusive is held. No arbitrary process is killed.
            crate::engine::stop(pid as i64,1000).unwrap();
            assert_eq!(unsafe{WaitForSingleObject(orphan.0.0,5000)},WAIT_OBJECT_0);
            drop(s);drop(x);drop(orphan);
            let check=maintenance_check(&[]);
            assert!(check.1.starts_with("G2_NOT_READY"));
            println!("G2_ORPHAN_CLEANUP actual_exit=true exclusive_independent=true later_class={:?}",check.0);

            let (code,log)=run(&["--apply"]);
            assert_eq!(code,0,"{log}");
            assert_eq!(proxy_state().0,1);
            assert!(app.join("data/proxy-journal.json").exists());
            let cleanup_holder=holder(&root.join("cleanup-exclusive"),"exclusive",object);
            // The original owner-only startup heal and explicit restore
            // remain independent of the new gate, against isolated HKCU.
            let (code,log)=run(&["--restore-apply"]);
            assert_eq!(code,0,"{log}");
            assert_eq!(proxy_state(),before);
            assert!(!app.join("data/proxy-journal.json").exists());
            release(cleanup_holder,false);
            println!("G2_PROXY_CLEANUP isolated_hkcu=true apply_real=true restore_while_exclusive=true original_state=true");
            drop(fixture);
            absence(&dir);
            unknown("after_fixture_cleanup","G2_OBJECT_OPEN");
            println!("G2_RUNTIME_OCCUPANCY_COMPLETE fixed_anchor=true shared_and_exclusive=true actual_product=true actual_engine_and_version=true orphan_detected=true cleanup_independent=true missing_compatible=true maintenance_authorized=false source_authenticated=false standard_token_not_run=true cross_sid_not_run=true");
        }
    }

}
#[cfg(windows)]
pub(crate) use imp::{admit,RuntimeAdmission};
#[cfg(not(windows))]
pub(crate) struct RuntimeAdmission;
#[cfg(not(windows))]
pub(crate) fn admit() -> Result<RuntimeAdmission,String> { Ok(RuntimeAdmission) }
