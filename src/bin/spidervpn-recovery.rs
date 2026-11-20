//! Independent recovery candidate builder. No installation, deletion or execution.
//! The caller must authenticate this EXE and the external manifest digest/commit
//! independently. Content matching does not confer maintenance authorization.
//! Fixed protected vault and work roots must already exist; never consume B1.
#![cfg_attr(not(windows), allow(dead_code))]
#[cfg(not(windows))]
fn main() { std::process::exit(1); }

#[cfg(windows)]
mod recovery {
    use std::{collections::BTreeSet, ffi::OsStr, fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write}, os::windows::{ffi::OsStrExt, fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle}}, path::{Path, PathBuf}, ptr::null_mut};
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use ring::rand::{SecureRandom, SystemRandom};
    use windows_sys::Win32::{
        Foundation::{LocalFree, SetLastError, INVALID_HANDLE_VALUE, GENERIC_READ, GENERIC_WRITE},
        Security::{ACL, ACE_HEADER, ACCESS_ALLOWED_ACE, SECURITY_ATTRIBUTES,
            GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            IsValidSid, GetLengthSid, OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION},
        Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT, ConvertSidToStringSidW,
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        Storage::FileSystem::{CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
            GetDriveTypeW, GetFileType, GetFileInformationByHandle, GetFinalPathNameByHandleW,
            GetFileInformationByHandleEx, FileStreamInfo,
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_DEVICE, FILE_TYPE_DISK, FILE_TYPE_UNKNOWN, FILE_READ_ATTRIBUTES, FILE_LIST_DIRECTORY, FILE_SHARE_READ,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS},
        UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramFiles},
        System::Com::CoTaskMemFree,
    };

    const NAMES: [&str; 4] = ["spidervpn.exe", "WebView2Loader.dll", "sing-box.exe", "sing-box.LICENSE.txt"];
    const MANIFEST: &str = "manifest.json";
    const VAULT: &str = "SpiderVPN-Recovery-Candidate";
    const WORK: &str = "SpiderVPN-Recovery-Work";
    const SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
    const BA: &str = "S-1-5-32-544";
    const SY: &str = "S-1-5-18";
    // The Windows servicing account, not an arbitrary service or local user.
    const TI: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    const FLAGS: u32 = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    const READ_CONTROL: u32 = 0x0002_0000;
    const FULL_ACCESS: u32 = 0x001f_01ff;
    const MAX_MANIFEST: u64 = 64 * 1024;
    const MAX_FILE: u64 = 512 * 1024 * 1024;
    const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
    type Result<T> = std::result::Result<T, String>;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        schema: u32,
        kind: String,
        #[serde(rename = "sourceSha")]
        source_sha: String,
        files: Vec<Entry>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry { path: String, size: u64, sha256: String }

    fn hex(s: &str, n: usize) -> bool {
        s.len() == n && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn hash(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
    fn parse_manifest(raw: &[u8], expected: &str, source: &str) -> Result<Manifest> {
        if hash(raw) != expected { return Err("MANIFEST_DIGEST".into()); }
        // PowerShell 5 writes a UTF-8 BOM. Hash the original bytes including it.
        let body = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw);
        let m: Manifest = serde_json::from_slice(body).map_err(|e| format!("MANIFEST_SCHEMA {e}"))?;
        if m.schema != 1 || m.kind != "unapproved-recovery-candidate" {
            return Err("MANIFEST_SCHEMA kind/version".into());
        }
        if !hex(&m.source_sha, 40) || m.source_sha != source { return Err("SOURCE_SHA_MISMATCH".into()); }
        if m.files.len() != NAMES.len() { return Err("MANIFEST_COUNT".into()); }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for e in &m.files {
            if !NAMES.contains(&e.path.as_str()) || !seen.insert(e.path.as_str()) {
                return Err("MANIFEST_NAME_OR_DUPLICATE".into());
            }
            if !hex(&e.sha256, 64) || e.size == 0 || e.size > MAX_FILE { return Err("MANIFEST_ENTRY_BOUNDS".into()); }
            total = total.checked_add(e.size).ok_or("MANIFEST_TOTAL")?;
        }
        if total > MAX_TOTAL { return Err("MANIFEST_TOTAL".into()); }
        Ok(m)
    }
    fn err(label: &str, path: &Path, e: std::io::Error) -> String {
        format!("{label} path={path:?} win32={:?} {e}", e.raw_os_error())
    }
    fn last(label: &str, path: &Path) -> String { err(label, path, std::io::Error::last_os_error()) }
    fn wide(s: &OsStr) -> Vec<u16> { s.encode_wide().chain(Some(0)).collect() }
    fn trusted_sid(sid: &str) -> bool { matches!(sid, BA | SY | TI) }
    struct Local(*mut core::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) { if !self.0.is_null() { unsafe { LocalFree(self.0); } } }
    }
    fn sid_text(sid: *mut core::ffi::c_void) -> Result<String> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 { return Err("ACL_INVALID_SID".into()); }
        let mut p = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut p) } == 0 {
            return Err(format!("ACL_SID_STRING win32={:?}",std::io::Error::last_os_error().raw_os_error()));
        }
        if p.is_null() {return Err("ACL_SID_STRING_NULL".into());}
        let _p = Local(p.cast());
        let mut n = 0;
        while n < 256 && unsafe { *p.add(n) } != 0 { n += 1; }
        if n == 256 { return Err("ACL_SID_LENGTH".into()); }
        String::from_utf16(unsafe { std::slice::from_raw_parts(p, n) }).map_err(|_| "ACL_SID_UTF16".into())
    }
    // Inspect the actual descriptor on the held object. For ancestors, reject
    // any effective nontrusted ACE granting object replacement or ACL control.
    // Only the immediate Program Files parent must additionally forbid creation
    // of children by nontrusted users; normal volume roots may allow new siblings.
    // Unknown ACE formats are a refusal, not a permissive parser.
    fn acl(file: &File, path: &Path, exact: bool, immediate: bool) -> Result<()> {
        let mut owner = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut sd = null_mut();
        let rc = unsafe { GetSecurityInfo(file.as_raw_handle(), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &mut owner,
            null_mut(), &mut dacl, null_mut(), &mut sd) };
        let _sd = Local(sd.cast());
        if rc != 0 {return Err(format!("ACL_QUERY path={path:?} win32={rc}"));}
        if sd.is_null() || dacl.is_null() || owner.is_null() {return Err(format!("ACL_NULL path={path:?}"));}
        let owner = sid_text(owner)?;
        if (exact && owner != BA) || (!exact && !trusted_sid(&owner)) {
            return Err(format!("ACL_OWNER path={path:?} owner={owner}"));
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut returned = null_mut();
        let mut control = 0u16;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut returned, &mut defaulted) } == 0 {
            return Err(last("ACL_DACL_QUERY",path));
        }
        if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0 {
            return Err(last("ACL_CONTROL_QUERY",path));
        }
        if present == 0 || returned != dacl || (exact && control & 0x1000 == 0) {
            return Err(format!("ACL_CONTROL path={path:?}"));
        }
        let count = unsafe { (*dacl).AceCount };
        if count == 0 || count > 128 || (exact && count != 2) {
            return Err(format!("ACL_COUNT path={path:?} count={count}"));
        }
        let mut stage_sids = BTreeSet::new();
        for i in 0..u32::from(count) {
            let mut p = null_mut();
            if unsafe { GetAce(dacl, i, &mut p) } == 0 { return Err(last("ACL_ACE_READ",path)); }
            if p.is_null() {return Err("ACL_ACE_NULL".into());}
            let header = unsafe { &*p.cast::<ACE_HEADER>() };
            if !matches!(header.AceType, 0 | 1) || (header.AceSize as usize) < 16 {
                return Err(format!("ACL_ACE_FORMAT path={path:?} type={}", header.AceType));
            }
            let ace = unsafe { &*p.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<core::ffi::c_void>();
            // A standard SID starts at byte 8 of an allow/deny ACE. Bound
            // its subauthority count before invoking SID helpers.
            let sid_bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
            let sid_len = 8 + usize::from(sid_bytes[1]) * 4;
            if sid_len > usize::from(header.AceSize) - 8 || unsafe { IsValidSid(sid) } == 0
                || unsafe { GetLengthSid(sid) } as usize != sid_len
            { return Err("ACL_ACE_SID_BOUNDS".into()); }
            let who = sid_text(sid)?;
            if exact {
                if header.AceType != 0 || header.AceFlags != 0 || ace.Mask != FULL_ACCESS
                    || !matches!(who.as_str(), BA | SY) || !stage_sids.insert(who)
                { return Err(format!("ACL_RECOVERY_ACE path={path:?}")); }
            } else if header.AceType == 0 && header.AceFlags & 0x08 == 0 && !trusted_sid(&who) {
                // DELETE/DELETE_CHILD/WRITE_DAC/WRITE_OWNER/WRITE_EA/
                // WRITE_ATTRIBUTES/GENERIC_WRITE/GENERIC_ALL are disallowed.
                // For Program Files, also deny add-file/add-subdirectory.
                let forbidden = 0x500d_0150u32 | if immediate { 0x6 } else { 0 };
                if ace.Mask & forbidden != 0 {
                    return Err(format!("ACL_ANCESTOR_WRITE path={path:?} sid={who} mask={:#x}", ace.Mask));
                }
            }
        }
        println!("RECOVERY_ACL path={path:?} owner={owner} ace_count={count} protected_recovery={exact} control={control:#x}");
        Ok(())
    }

    fn parts(path: &Path) -> Result<Vec<PathBuf>> {
        let s = path.to_str().ok_or("PATH_UTF16")?;
        let b = s.as_bytes();
        if b.len() < 4 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
            return Err("PATH_LOCAL_DOS_REQUIRED".into());
        }
        if s.len() > 240 { return Err("PATH_LENGTH".into()); }
        let mut out = vec![PathBuf::from(&s[..3])];
        for name in s[3..].split('\\') {
            let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
            let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$")
                || stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT"))
                    .is_some_and(|n| matches!(n, "1"|"2"|"3"|"4"|"5"|"6"|"7"|"8"|"9"|"¹"|"²"|"³"));
            if name.is_empty() || name.ends_with(['.', ' ']) || device
                || name.chars().any(|c| c.is_control() || ":*?\"<>|/".contains(c))
            { return Err("PATH_ALIAS_OR_TRAVERSAL".into()); }
            out.push(out.last().unwrap().join(name));
        }
        if unsafe { GetDriveTypeW(wide(out[0].as_os_str()).as_ptr()) } != 3 {
            return Err("PATH_NOT_FIXED_DRIVE".into());
        }
        Ok(out)
    }
    fn size(info: &BY_HANDLE_FILE_INFORMATION) -> u64 {
        (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow)
    }
    fn id(info: &BY_HANDLE_FILE_INFORMATION) -> (u32,u32,u32) {
        (info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow)
    }
    // Reject named alternate data streams from the actual leaf handle.
    // FILE_STREAM_INFO has a 24-byte fixed prefix followed by UTF-16 name.
    // Only a single unnamed $DATA stream is allowed; unknown FS is a refusal.
    fn unnamed_stream_only(file: &File, path: &Path, dir: bool) -> Result<()> {
        let mut aligned = vec![0u64; 8192];
        let bytes = unsafe { std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), aligned.len()*8) };
        if unsafe { GetFileInformationByHandleEx(file.as_raw_handle(), FileStreamInfo,
            bytes.as_mut_ptr().cast(), bytes.len() as u32) } == 0 {
            let e = std::io::Error::last_os_error();
            // NTFS directories without a named $DATA stream can report EOF.
            // Do not accept any other error as evidence of an empty stream set.
            if dir && e.raw_os_error() == Some(38) { return Ok(()); }
            return Err(err("STREAM_INFO", path, e));
        }
        let next = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let wanted: Vec<u8> = "::$DATA".encode_utf16().flat_map(u16::to_le_bytes).collect();
        if next != 0 || len != wanted.len() || bytes[24..24+wanted.len()] != wanted {
            return Err(format!("OBJECT_ALTERNATE_STREAM path={path:?}"));
        }
        Ok(())
    }
    fn info(file: &File, path: &Path, dir: bool) -> Result<BY_HANDLE_FILE_INFORMATION> {
        let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        unsafe{SetLastError(0);}
        let kind=unsafe{GetFileType(file.as_raw_handle())};
        if kind==FILE_TYPE_UNKNOWN {
            let e=std::io::Error::last_os_error();
            if e.raw_os_error()!=Some(0){return Err(err("OBJECT_TYPE_QUERY",path,e));}
        }
        if kind!=FILE_TYPE_DISK{return Err(format!("OBJECT_NOT_DISK path={path:?}"));}
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut i) } == 0 {
            return Err(last("OBJECT_READ",path));
        }
        if i.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0
            || (i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != dir
            || (i.nFileIndexHigh == 0 && i.nFileIndexLow == 0)
            || (!dir && i.nNumberOfLinks != 1)
        { return Err(format!("OBJECT_TYPE_OR_LINK path={path:?} attrs={:#x} links={}", i.dwFileAttributes,i.nNumberOfLinks)); }
        let mut buffer = vec![0u16; 32768];
        let n = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(), buffer.len() as u32, 0) } as usize;
        if n == 0 { return Err(last("OBJECT_FINAL_PATH", path)); }
        if n>=buffer.len(){return Err("OBJECT_PATH_LENGTH".into());}
        let actual = String::from_utf16(&buffer[..n]).map_err(|_| "OBJECT_PATH_UTF16")?;
        if !actual.strip_prefix(r"\\?\").is_some_and(|s| path.to_str().is_some_and(|p| s.eq_ignore_ascii_case(p))) {
            return Err(format!("OBJECT_PATH_ALIAS expected={path:?} actual={actual:?}"));
        }
        unnamed_stream_only(file,path,dir)?;
        Ok(i)
    }
    fn unchanged(a: &BY_HANDLE_FILE_INFORMATION,b:&BY_HANDLE_FILE_INFORMATION) -> bool {
        id(a)==id(b) && size(a)==size(b) && a.dwFileAttributes==b.dwFileAttributes
            && a.nNumberOfLinks==b.nNumberOfLinks
            && a.ftLastWriteTime.dwHighDateTime==b.ftLastWriteTime.dwHighDateTime
            && a.ftLastWriteTime.dwLowDateTime==b.ftLastWriteTime.dwLowDateTime
    }
    struct Object { path: PathBuf, file: File, before: BY_HANDLE_FILE_INFORMATION, dir: bool }
    impl Object {
        fn open(path: &Path, dir: bool, security: bool) -> Result<Self> {
            let mut op = OpenOptions::new();
            // Attribute-only opens do not reliably participate in Windows
            // sharing checks. LIST_DIRECTORY requests actual read access so
            // the held handle fences competing write/delete opens as well.
            if dir { op.access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | if security { READ_CONTROL } else { 0 }); }
            else { op.read(true); }
            let f=op.share_mode(FILE_SHARE_READ).custom_flags(FLAGS).open(path)
                .map_err(|e| err("OBJECT_OPEN",path,e))?;
            Self::from_file(path, f, dir)
        }
        fn from_file(path: &Path, file: File, dir: bool) -> Result<Self> {
            let before=info(&file,path,dir)?;
            Ok(Self { path:path.to_owned(),file,before,dir })
        }
        fn check_dir_streams(&self) -> Result<()> {
            if !self.dir { return Err("EXPECTED_DIRECTORY".into()); }
            unnamed_stream_only(&self.file, &self.path, true)
        }
        fn check(&self) -> Result<()> {
            let now=info(&self.file,&self.path,self.dir)?;
            if if self.dir { id(&now)!=id(&self.before) || now.dwFileAttributes!=self.before.dwFileAttributes } else { !unchanged(&self.before,&now) } {
                return Err(format!("OBJECT_CHANGED path={:?}",self.path));
            }
            Ok(())
        }
    }
    fn chain(path: &Path, protected: bool) -> Result<Vec<Object>> {
        let p=parts(path)?;
        let mut held=Vec::new();
        for (n, x) in p.iter().enumerate() {
            let o=Object::open(x,true,protected)?;
            if protected { acl(&o.file,x,false,n+1==p.len())?; }
            held.push(o);
        }
        Ok(held)
    }
    fn check_chain(c:&[Object]) -> Result<()> {
        for o in c { o.check()?; }
        Ok(())
    }
    fn file_set(root:&Path,manifest:bool)->Result<()> {
        let expected:BTreeSet<_>=NAMES.iter().copied().chain(if manifest{Some(MANIFEST)}else{None})
            .map(OsStr::new).map(|x|x.to_os_string()).collect();
        let mut seen=BTreeSet::new();
        for entry in fs::read_dir(root).map_err(|e|err("SET_ENUM",root,e))?{
            let entry=entry.map_err(|e|err("SET_ENUM",root,e))?;
            let name=entry.file_name();
            if !expected.contains(&name)||!seen.insert(name.clone())
                ||!entry.file_type().map_err(|e|err("SET_TYPE",root,e))?.is_file(){
                return Err(format!("SET_UNKNOWN_OR_TYPE path={root:?} name={name:?}"));
            }
        }
        if seen!=expected{return Err(format!("SET_MISSING path={root:?}"));}
        Ok(())
    }
    fn program_files() -> Result<PathBuf> {
        let mut p=null_mut();
        let rc=unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles,0,null_mut(),&mut p) };
        if rc<0 || p.is_null() { return Err(format!("KNOWN_FOLDER hr={rc:#x}")); }
        let mut n=0usize;
        while n<32768 && unsafe{*p.add(n)}!=0 { n+=1; }
        let result=if n==32768 {Err("KNOWN_FOLDER_LENGTH".into())} else {
            String::from_utf16(unsafe{std::slice::from_raw_parts(p,n)}).map(PathBuf::from).map_err(|_|"KNOWN_FOLDER_UTF16".into())
        };
        unsafe{CoTaskMemFree(p.cast());}
        result
    }
    fn with_sd<T>(f:impl FnOnce(&SECURITY_ATTRIBUTES)->Result<T>)->Result<T> {
        let mut sd=null_mut();
        if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(OsStr::new(SDDL)).as_ptr(),SDDL_REVISION_1,&mut sd,null_mut())}==0
            {return Err(format!("RECOVERY_SD_CREATE win32={:?}",std::io::Error::last_os_error().raw_os_error()));}
        if sd.is_null(){return Err("RECOVERY_SD_NULL".into());}
        let _sd=Local(sd.cast());
        f(&SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor:sd,bInheritHandle:0})
    }
    fn create_dir(path:&Path)->Result<Object> {
        with_sd(|sa|{
            if unsafe{CreateDirectoryW(wide(path.as_os_str()).as_ptr(),sa)}==0 {
                return Err(last("RECOVERY_DIR_CREATE",path));
            }
            Ok(())
        })?;
        // Never adopt a pre-existing object. The protected parent and atomic
        // create are necessary; ACL readback on the new handle is separate.
        let o=Object::open(path,true,true)?;
        acl(&o.file,path,true,false)?;
        o.check_dir_streams()?;
        Ok(o)
    }
    fn create_file(path:&Path)->Result<File> {
        with_sd(|sa|{
            let handle=unsafe{CreateFileW(wide(path.as_os_str()).as_ptr(),
                GENERIC_READ|GENERIC_WRITE|READ_CONTROL,FILE_SHARE_READ,sa,CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,null_mut())};
            if handle==INVALID_HANDLE_VALUE {return Err(last("RECOVERY_FILE_CREATE",path));}
            Ok(unsafe{File::from_raw_handle(handle)})
        })
    }
    // Read only the declared byte count plus an EOF check. When copying,
    // the digest is of the actual bytes read from the already-held source.
    fn stream(file:&mut File, mut out:Option<&mut File>, n:u64)->Result<String> {
        file.seek(SeekFrom::Start(0)).map_err(|e|format!("STREAM_SEEK win32={:?} {e}",e.raw_os_error()))?;
        let mut rest=n;
        let mut digest=Sha256::new();
        let mut buf=[0u8;64*1024];
        while rest!=0 {
            let chunk=rest.min(buf.len() as u64) as usize;
            let got=file.read(&mut buf[..chunk]).map_err(|e|format!("STREAM_READ win32={:?} {e}",e.raw_os_error()))?;
            if got==0 {return Err("STREAM_TOO_SHORT".into());}
            digest.update(&buf[..got]);
            if let Some(f)=out.as_deref_mut() {
                f.write_all(&buf[..got]).map_err(|e|format!("RECOVERY_COPY win32={:?} {e}",e.raw_os_error()))?;
                if rest==n {
                    println!("RECOVERY_COPY_STARTED pid={} bytes_written={got} total={n}",std::process::id());
                    std::io::stdout().flush().map_err(|e|format!("RECOVERY_LOG win32={:?} {e}",e.raw_os_error()))?;
                }
            }
            rest-=got as u64;
        }
        if file.read(&mut buf[..1]).map_err(|e|format!("STREAM_EOF win32={:?} {e}",e.raw_os_error()))?!=0 {return Err("STREAM_TOO_LONG".into());}
        Ok(format!("{:x}",digest.finalize()))
    }
    fn copy(src:&mut Object,target:&Path,n:u64,expected:&str)->Result<Object> {
        src.check()?;acl(&src.file,&src.path,true,false)?;
        if size(&src.before)!=n {return Err(format!("FILE_SIZE path={:?}",src.path));}
        let mut dst=create_file(target)?;
        // Check type/path/identity immediately after creation, then keep that
        // exact handle through copy, sync, digest and security readback.
        let initial=info(&dst,target,false)?;
        acl(&dst,target,true,false)?;
        if stream(&mut src.file,Some(&mut dst),n)?!=expected {return Err(format!("FILE_DIGEST path={:?}",src.path));}
        src.check()?;
        dst.sync_all().map_err(|e|err("RECOVERY_SYNC",target,e))?;
        let before=info(&dst,target,false)?;
        if id(&initial)!=id(&before) || size(&before)!=n {return Err("RECOVERY_ID_OR_SIZE".into());}
        if stream(&mut dst,None,n)?!=expected {return Err("RECOVERY_READBACK_DIGEST".into());}
        let after=info(&dst,target,false)?;
        if !unchanged(&before,&after) {return Err("RECOVERY_READBACK_CHANGED".into());}
        acl(&dst,target,true,false)?;
        println!("RECOVERY_FILE path={target:?} bytes={n} source_id={:?} target_id={:?} sha256={expected} same_handle_readback=true",id(&src.before),id(&after));
        Ok(Object{path:target.to_owned(),file:dst,before:after,dir:false})
    }

    fn protected(path:&Path,dir:bool,volume:u32)->Result<Object>{
        let o=Object::open(path,dir,true)?;
        acl(&o.file,path,true,false)?;
        if o.before.dwVolumeSerialNumber!=volume{return Err(format!("VOLUME_MISMATCH path={path:?}"));}
        Ok(o)
    }
    fn recheck_protected(o:&Object,volume:u32)->Result<()>{
        o.check()?;acl(&o.file,&o.path,true,false)?;
        if o.before.dwVolumeSerialNumber!=volume{return Err("VOLUME_MISMATCH".into());}
        Ok(())
    }
    pub fn run()->Result<()> {
        let args:Vec<_>=std::env::args_os().skip(1).collect();
        if args.len()!=4||args[0]!="--manifest-sha256"||args[2]!="--source-sha"{
            return Err("USAGE --manifest-sha256 <external-digest> --source-sha <external-commit>".into());
        }
        let expected=args[1].to_str().ok_or("ARG_DIGEST")?;
        let source_sha=args[3].to_str().ok_or("ARG_SOURCE_SHA")?;
        if !hex(expected,64)||!hex(source_sha,40){return Err("ARG_EXTERNAL_ANCHOR_FORMAT".into());}
        let parent=program_files()?;
        let trusted=chain(&parent,true)?;
        let volume=trusted.last().ok_or("PARENT_MISSING")?.before.dwVolumeSerialNumber;
        for o in &trusted{if o.before.dwVolumeSerialNumber!=volume{return Err("ANCESTOR_VOLUME".into());}}
        let root=parent.join(VAULT);let work_path=parent.join(WORK);
        parts(&root)?;parts(&work_path)?;
        let vault=protected(&root,true,volume)?;
        let work=protected(&work_path,true,volume)?;
        if id(&vault.before)==id(&work.before){return Err("ROOT_ID_COLLISION".into());}
        file_set(&root,true)?;
        let mut mf=protected(&root.join(MANIFEST),false,volume)?;
        if size(&mf.before)>MAX_MANIFEST{return Err("MANIFEST_LENGTH".into());}
        let mut raw=Vec::new();
        (&mut mf.file).take(MAX_MANIFEST+1).read_to_end(&mut raw).map_err(|e|err("MANIFEST_READ",&mf.path,e))?;
        recheck_protected(&mf,volume)?;
        if raw.len() as u64!=size(&mf.before)||raw.len() as u64>MAX_MANIFEST{return Err("MANIFEST_LENGTH".into());}
        let manifest=parse_manifest(&raw,expected,source_sha)?;
        let mut files=Vec::new();
        let mut ids=BTreeSet::from([id(&mf.before),id(&vault.before),id(&work.before)]);
        for e in &manifest.files{
            let mut obj=protected(&root.join(&e.path),false,volume)?;
            if !ids.insert(id(&obj.before)){return Err("SOURCE_ID_COLLISION".into());}
            if size(&obj.before)!=e.size{return Err(format!("FILE_SIZE path={:?}",obj.path));}
            if stream(&mut obj.file,None,e.size)?!=e.sha256{return Err(format!("FILE_DIGEST path={:?}",obj.path));}
            recheck_protected(&obj,volume)?;files.push(obj);
        }
        let check_roots=||->Result<()>{
            check_chain(&trusted)?;
            for (i,o) in trusted.iter().enumerate(){acl(&o.file,&o.path,false,i+1==trusted.len())?;}
            recheck_protected(&vault,volume)?;recheck_protected(&work,volume)?;
            file_set(&root,true)
        };
        check_roots()?;
        let mut nonce=[0u8;16];SystemRandom::new().fill(&mut nonce).map_err(|_|"RECOVERY_RANDOM")?;
        let suffix:String=nonce.iter().map(|b|format!("{b:02x}")).collect();
        let generation=work_path.join(format!("unready-{suffix}"));
        parts(&generation)?;
        let stage=create_dir(&generation)?;
        recheck_protected(&stage,volume)?;
        if !ids.insert(id(&stage.before)){return Err("GENERATION_ID_COLLISION".into());}
        println!("RECOVERY_GENERATION_UNREADY pid={} path={}",std::process::id(),generation.display());
        std::io::stdout().flush().map_err(|e|err("RECOVERY_LOG",&generation,e))?;
        let mut targets=Vec::new();
        for (entry,src) in manifest.files.iter().zip(&mut files){
            let target=generation.join(&entry.path);
            parts(&target)?;
            println!("RECOVERY_COPY_TARGET name={} pid={}",entry.path,std::process::id());
            std::io::stdout().flush().map_err(|e|err("RECOVERY_LOG",&generation,e))?;
            let o=copy(src,&target,entry.size,&entry.sha256)?;
            recheck_protected(&o,volume)?;
            if !ids.insert(id(&o.before)){return Err("TARGET_ID_COLLISION".into());}
            targets.push(o);
        }
        check_roots()?;recheck_protected(&stage,volume)?;
        if stream(&mut mf.file,None,raw.len() as u64)?!=expected{return Err("MANIFEST_FINAL_DIGEST".into());}
        recheck_protected(&mf,volume)?;
        for ((entry,src),dst) in manifest.files.iter().zip(&mut files).zip(&mut targets){
            recheck_protected(src,volume)?;recheck_protected(dst,volume)?;
            if stream(&mut src.file,None,entry.size)?!=entry.sha256
                ||stream(&mut dst.file,None,entry.size)?!=entry.sha256{return Err("RECOVERY_FINAL_DIGEST".into());}
            recheck_protected(src,volume)?;recheck_protected(dst,volume)?;
        }
        file_set(&generation,false)?;check_roots()?;recheck_protected(&stage,volume)?;
        // No activation or persistent READY marker. A separate authenticated
        // controller may read the original expected bytes and test a candidate.
        println!("RECOVERY_CONTENT_MATCH files=4 pid={} source_sha={source_sha} manifest_sha256={expected} source_authenticated=false production_recovery_proven=false maintenance_authorized=false",std::process::id());
        Ok(())
    }
}
#[cfg(windows)]
fn main(){
    if let Err(e)=recovery::run(){
        eprintln!("RECOVERY_REFUSED {e}; any generation remains UNREADY");
        std::process::exit(1);
    }
}
