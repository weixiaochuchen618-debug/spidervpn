//! Standalone, externally authenticated content staging. No install or execution.
//! A successful invocation is NOT an installation authorization or evidence of
//! bootstrap/ZIP provenance. The caller must establish both outside the package.
#![cfg_attr(not(windows), allow(dead_code))]
#[cfg(not(windows))]
fn main() { std::process::exit(1); }

#[cfg(windows)]
mod stage {
    use std::{collections::BTreeSet, ffi::OsStr, fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write}, os::windows::{ffi::OsStrExt, fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle}}, path::{Path, PathBuf}, ptr::null_mut};
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use ring::rand::{SecureRandom, SystemRandom};
    use windows_sys::Win32::{
        Foundation::{LocalFree, INVALID_HANDLE_VALUE, GENERIC_READ, GENERIC_WRITE},
        Security::{ACL, ACE_HEADER, ACCESS_ALLOWED_ACE, SECURITY_ATTRIBUTES,
            GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            IsValidSid, GetLengthSid, OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION},
        Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT, ConvertSidToStringSidW,
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        Storage::FileSystem::{CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
            GetDriveTypeW, GetFileType, GetFileInformationByHandle, GetFinalPathNameByHandleW,
            GetFileInformationByHandleEx, FileStreamInfo,
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_DEVICE, FILE_TYPE_DISK, FILE_READ_ATTRIBUTES, FILE_LIST_DIRECTORY, FILE_SHARE_READ,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS},
        UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramFiles},
        System::Com::CoTaskMemFree,
    };

    const NAMES: [&str; 12] = ["spidervpn.exe", "WebView2Loader.dll", "sing-box.exe",
        "sing-box.LICENSE.txt", "一键安装.cmd", "一键卸载.cmd", "直接运行（免安装）.cmd",
        "install/install.ps1", "install/uninstall.ps1", "install/expected.sha256",
        "INSTALL.txt", "用户速查.md"];
    const MANIFEST: &str = "manifest.json";
    const SLOT: &str = "SpiderVPN-Bootstrap-Staging";
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
        if m.schema != 1 || m.kind != "unapproved-client-candidate" {
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
            if !hex(&e.sha256, 64) || e.size > MAX_FILE { return Err("MANIFEST_ENTRY_BOUNDS".into()); }
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
        if unsafe { ConvertSidToStringSidW(sid, &mut p) } == 0 || p.is_null() {
            return Err("ACL_SID_STRING".into());
        }
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
        if rc != 0 || sd.is_null() || dacl.is_null() || owner.is_null() {
            return Err(format!("ACL_QUERY path={path:?} win32={rc}"));
        }
        let owner = sid_text(owner)?;
        if (exact && owner != BA) || (!exact && !trusted_sid(&owner)) {
            return Err(format!("ACL_OWNER path={path:?} owner={owner}"));
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut returned = null_mut();
        let mut control = 0u16;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut returned, &mut defaulted) } == 0
            || unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
            || present == 0 || returned != dacl || (exact && control & 0x1000 == 0)
        { return Err(format!("ACL_CONTROL path={path:?}")); }
        let count = unsafe { (*dacl).AceCount };
        if count == 0 || count > 128 || (exact && count != 2) {
            return Err(format!("ACL_COUNT path={path:?} count={count}"));
        }
        let mut stage_sids = BTreeSet::new();
        for i in 0..u32::from(count) {
            let mut p = null_mut();
            if unsafe { GetAce(dacl, i, &mut p) } == 0 || p.is_null() { return Err("ACL_ACE_READ".into()); }
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
                { return Err(format!("ACL_STAGE_ACE path={path:?}")); }
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
        println!("BOOTSTRAP_ACL path={path:?} owner={owner} ace_count={count} protected_stage={exact} control={control:#x}");
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
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
            || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut i) } == 0
        { return Err(last("OBJECT_READ", path)); }
        if i.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0
            || (i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != dir
            || (i.nFileIndexHigh == 0 && i.nFileIndexLow == 0)
            || (!dir && i.nNumberOfLinks != 1)
        { return Err(format!("OBJECT_TYPE_OR_LINK path={path:?} attrs={:#x} links={}", i.dwFileAttributes,i.nNumberOfLinks)); }
        let mut buffer = vec![0u16; 32768];
        let n = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(), buffer.len() as u32, 0) } as usize;
        if n == 0 || n >= buffer.len() { return Err(last("OBJECT_FINAL_PATH", path)); }
        let actual = String::from_utf16(&buffer[..n]).map_err(|_| "OBJECT_PATH_UTF16")?;
        if !actual.strip_prefix(r"\\?\").is_some_and(|s| path.to_str().is_some_and(|p| s.eq_ignore_ascii_case(p))) {
            return Err(format!("OBJECT_PATH_ALIAS expected={path:?} actual={actual:?}"));
        }
        if !dir { unnamed_stream_only(file,path,false)?; }
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
            if if self.dir { id(&now)!=id(&self.before) } else { !unchanged(&self.before,&now) } {
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
    fn file_set(root:&Path) -> Result<()> {
        let top:BTreeSet<_>=NAMES.iter().filter(|n| !n.contains('/')).copied()
            .chain([MANIFEST,"install"]).map(OsStr::new).map(|x|x.to_os_string()).collect();
        let inner:BTreeSet<_>=NAMES.iter().filter_map(|n| n.strip_prefix("install/"))
            .map(OsStr::new).map(|x|x.to_os_string()).collect();
        for (dir,expected) in [(root.to_owned(),top),(root.join("install"),inner)] {
            let mut seen=BTreeSet::new();
            for entry in fs::read_dir(&dir).map_err(|e|err("SET_ENUM",&dir,e))? {
                let entry=entry.map_err(|e|err("SET_ENUM",&dir,e))?;
                let name=entry.file_name();
                let ty=entry.file_type().map_err(|e|err("SET_TYPE",&dir,e))?;
                if !expected.contains(&name) || !seen.insert(name.clone())
                    || (name==OsStr::new("install") && dir==root && !ty.is_dir())
                    || (!(name==OsStr::new("install") && dir==root) && !ty.is_file())
                { return Err(format!("SET_UNKNOWN_OR_TYPE dir={dir:?} name={name:?}")); }
            }
            if seen!=expected { return Err(format!("SET_MISSING dir={dir:?}")); }
        }
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
            || sd.is_null() {return Err("STAGE_SD_CREATE".into());}
        let _sd=Local(sd.cast());
        f(&SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor:sd,bInheritHandle:0})
    }
    fn create_dir(path:&Path)->Result<Object> {
        with_sd(|sa|{
            if unsafe{CreateDirectoryW(wide(path.as_os_str()).as_ptr(),sa)}==0 {
                return Err(last("STAGE_DIR_CREATE",path));
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
            if handle==INVALID_HANDLE_VALUE {return Err(last("STAGE_FILE_CREATE",path));}
            Ok(unsafe{File::from_raw_handle(handle)})
        })
    }
    // Read only the declared byte count plus an EOF check. When copying,
    // the digest is of the actual bytes read from the already-held source.
    fn stream(file:&mut File, mut out:Option<&mut File>, n:u64)->Result<String> {
        file.seek(SeekFrom::Start(0)).map_err(|e|format!("STREAM_SEEK {e}"))?;
        let mut rest=n;
        let mut digest=Sha256::new();
        let mut buf=[0u8;64*1024];
        while rest!=0 {
            let chunk=rest.min(buf.len() as u64) as usize;
            let got=file.read(&mut buf[..chunk]).map_err(|e|format!("STREAM_READ {e}"))?;
            if got==0 {return Err("STREAM_TOO_SHORT".into());}
            digest.update(&buf[..got]);
            if let Some(f)=out.as_deref_mut() {f.write_all(&buf[..got]).map_err(|e|format!("STAGE_COPY win32={:?} {e}",e.raw_os_error()))?;}
            rest-=got as u64;
        }
        if file.read(&mut buf[..1]).map_err(|e|format!("STREAM_EOF {e}"))?!=0 {return Err("STREAM_TOO_LONG".into());}
        Ok(format!("{:x}",digest.finalize()))
    }
    fn copy(src:&mut Object,target:&Path,n:u64,expected:&str)->Result<Object> {
        src.check()?;
        if size(&src.before)!=n {return Err(format!("FILE_SIZE path={:?}",src.path));}
        let mut dst=create_file(target)?;
        // Check type/path/identity immediately after creation, then keep that
        // exact handle through copy, sync, digest and security readback.
        let initial=info(&dst,target,false)?;
        acl(&dst,target,true,false)?;
        if stream(&mut src.file,Some(&mut dst),n)?!=expected {return Err(format!("FILE_DIGEST path={:?}",src.path));}
        src.check()?;
        dst.sync_all().map_err(|e|err("STAGE_SYNC",target,e))?;
        let before=info(&dst,target,false)?;
        if id(&initial)!=id(&before) || size(&before)!=n {return Err("STAGE_ID_OR_SIZE".into());}
        if stream(&mut dst,None,n)?!=expected {return Err("STAGE_READBACK_DIGEST".into());}
        let after=info(&dst,target,false)?;
        if !unchanged(&before,&after) {return Err("STAGE_READBACK_CHANGED".into());}
        acl(&dst,target,true,false)?;
        println!("BOOTSTRAP_FILE path={target:?} bytes={n} source_id={:?} target_id={:?} sha256={expected} same_handle_readback=true",id(&src.before),id(&after));
        Ok(Object{path:target.to_owned(),file:dst,before:after,dir:false})
    }

    pub fn run()->Result<()> {
        let args:Vec<_>=std::env::args_os().skip(1).collect();
        // No stage override, no package executable, no env/receipt trust.
        if args.len()!=6 || args[0]!="--source" || args[2]!="--manifest-sha256" || args[4]!="--source-sha" {
            return Err("USAGE --source <canonical-local-directory> --manifest-sha256 <authenticated-lowercase-hex> --source-sha <authenticated-commit>".into());
        }
        let expected=args[3].to_str().ok_or("ARG_DIGEST")?;
        let source_sha=args[5].to_str().ok_or("ARG_SOURCE_SHA")?;
        if !hex(expected,64)||!hex(source_sha,40) {return Err("ARG_EXTERNAL_ANCHOR_FORMAT".into());}
        let root=PathBuf::from(args[1].as_os_str());
        let source_dirs=chain(&root,false)?;
        let install=Object::open(&root.join("install"),true,false)?;
        // Only package-owned directories are part of the manifest boundary.
        // OS ancestors are held and validated but their streams are not imported.
        source_dirs.last().ok_or("SOURCE_ROOT_MISSING")?.check_dir_streams()?;
        install.check_dir_streams()?;
        let mut mf=Object::open(&root.join(MANIFEST),false,false)?;
        if size(&mf.before)>MAX_MANIFEST {return Err("MANIFEST_LENGTH".into());}
        let mut raw=Vec::new();
        (&mut mf.file).take(MAX_MANIFEST+1).read_to_end(&mut raw).map_err(|e|format!("MANIFEST_READ {e}"))?;
        mf.check()?;
        if raw.len() as u64!=size(&mf.before) || raw.len() as u64>MAX_MANIFEST {return Err("MANIFEST_LENGTH".into());}
        let manifest=parse_manifest(&raw,expected,source_sha)?;
        // Authenticate every source file before creating any stage. All
        // source handles stay open; every copy rechecks the digest again.
        let mut files=Vec::new();
        for e in &manifest.files {
            let mut obj=Object::open(&root.join(e.path.replace('/',"\\")),false,false)?;
            if size(&obj.before)!=e.size {return Err(format!("FILE_SIZE path={:?}",obj.path));}
            if stream(&mut obj.file,None,e.size)?!=e.sha256 {return Err(format!("FILE_DIGEST path={:?}",obj.path));}
            obj.check()?;
            files.push(obj);
        }
        check_chain(&source_dirs)?; install.check()?;
        source_dirs.last().ok_or("SOURCE_ROOT_MISSING")?.check_dir_streams()?;
        install.check_dir_streams()?; file_set(&root)?;
        let parent=program_files()?;
        let trusted=chain(&parent,true)?;
        // Fixed, exclusive staging slot: an existing slot (even with a
        // seemingly correct ACL) is refused, never reused. A trustworthy
        // future maintenance transaction must decide cleanup or consumption.
        let slot_path=parent.join(SLOT);
        let slot=create_dir(&slot_path)?;
        println!("BOOTSTRAP_SLOT_UNREADY path={slot_path:?}");
        let mut nonce=[0u8;16];
        SystemRandom::new().fill(&mut nonce).map_err(|_|"STAGE_RANDOM")?;
        let suffix:String=nonce.iter().map(|b|format!("{b:02x}")).collect();
        let stage_path=slot_path.join(format!("unready-{suffix}"));
        let stage=create_dir(&stage_path)?;
        let stage_install=create_dir(&stage_path.join("install"))?;
        println!("BOOTSTRAP_STAGE_UNREADY path={}",stage_path.display());
        std::io::stdout().flush().map_err(|e|format!("STAGE_LOG {e}"))?;
        let mut targets=Vec::new();
        for (entry,src) in manifest.files.iter().zip(&mut files) {
            targets.push(copy(src,&stage_path.join(entry.path.replace('/',"\\")),entry.size,&entry.sha256)?);
        }
        targets.push(copy(&mut mf,&stage_path.join(MANIFEST),raw.len() as u64,expected)?);
        check_chain(&source_dirs)?; install.check()?; mf.check()?;
        source_dirs.last().ok_or("SOURCE_ROOT_MISSING")?.check_dir_streams()?;
        install.check_dir_streams()?;
        for src in &files {src.check()?;}
        file_set(&root)?;
        check_chain(&trusted)?;
        for (i,o) in trusted.iter().enumerate() {acl(&o.file,&o.path,false,i+1==trusted.len())?;}
        for o in [&slot,&stage,&stage_install] {o.check()?;acl(&o.file,&o.path,true,false)?;o.check_dir_streams()?;}
        for (i,o) in targets.iter_mut().enumerate() {
            o.check()?;
            let (n,digest)=if i<manifest.files.len() {
                (manifest.files[i].size,manifest.files[i].sha256.as_str())
            } else {(raw.len() as u64,expected)};
            if stream(&mut o.file,None,n)?!=digest {return Err("STAGE_FINAL_DIGEST".into());}
            o.check()?; acl(&o.file,&o.path,true,false)?;
        }
        file_set(&stage_path)?;
        let children: Vec<_> = fs::read_dir(&slot_path).map_err(|e|err("STAGE_SLOT_ENUM",&slot_path,e))?
            .collect::<std::io::Result<Vec<_>>>().map_err(|e|err("STAGE_SLOT_ENUM",&slot_path,e))?;
        if children.len()!=1 || children[0].path()!=stage_path
            || !children[0].file_type().map_err(|e|err("STAGE_SLOT_TYPE",&slot_path,e))?.is_dir() {
            return Err("STAGE_SLOT_UNKNOWN_OBJECT".into());
        }
        // Even the success path is unready for installation; no ticket,
        // no durable success flag and no execution of any package file.
        println!("BOOTSTRAP_CONTENT_MATCH files=13 source_sha={source_sha} manifest_sha256={expected} install_authorized=false zip_origin_verified=false");
        Ok(())
    }
}
#[cfg(windows)]
fn main() {
    if let Err(e)=stage::run() {
        eprintln!("BOOTSTRAP_REFUSED {e}; any created stage remains UNREADY");
        std::process::exit(1);
    }
}
