//! G1: a short, fresh machine-global transaction, not a machine-history
//! certificate. Never adopt an existing object (even with matching ACL).
//! Only final privileged executors enter here; teardown does not enter it.

#[cfg(windows)]
mod imp {
    use std::{marker::PhantomData, ptr::null_mut, rc::Rc};
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::System::Threading::*;

    const NAME: &str = r"Global\SpiderVPN-Lifecycle-Transaction-G1";
    const RIGHTS: u32 = 0x0012_0001; // SYNCHRONIZE | READ_CONTROL | MUTEX_MODIFY_STATE
    const SDDL: &str = "O:BAD:P(A;;0x00120001;;;SY)(A;;0x00120001;;;BA)";
    const BA: &str = "S-1-5-32-544";
    const SY: &str = "S-1-5-18";

    fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }
    fn last(label: &str) -> String { format!("{label} win32={}", unsafe { GetLastError() }) }

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) { if !self.0.is_null() { unsafe { CloseHandle(self.0); } } }
    }
    struct Local(*mut core::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) { if !self.0.is_null() { unsafe { LocalFree(self.0); } } }
    }
    fn process_token(process: HANDLE) -> Result<Handle, String> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
            return Err(last("G1_TOKEN_OPEN"));
        }
        Ok(Handle(token))
    }
    fn require_elevated(process: HANDLE) -> Result<(), String> {
        let token = process_token(process)?;
        let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let mut actual = 0;
        if unsafe { GetTokenInformation(token.0, TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(), size, &mut actual) } == 0 {
            return Err(last("G1_TOKEN_ELEVATION_QUERY"));
        }
        if actual != size || elevation.TokenIsElevated == 0 {
            return Err("G1_TOKEN_NOT_ELEVATED".into());
        }
        Ok(())
    }

    fn descriptor(sddl: &str) -> Result<Local, String> {
        let mut sd = null_mut();
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) } == 0 || sd.is_null() {
            return Err(last("G1_DESCRIPTOR"));
        }
        Ok(Local(sd.cast()))
    }
    fn sid_text(sid: *mut core::ffi::c_void) -> Result<String, String> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 { return Err("G1_INVALID_SID".into()); }
        let mut p = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut p) } == 0 || p.is_null() {
            return Err(last("G1_SID_TEXT"));
        }
        let _p = Local(p.cast());
        let mut n = 0;
        while n < 256 && unsafe { *p.add(n) } != 0 { n += 1; }
        if n == 256 { return Err("G1_SID_LENGTH".into()); }
        String::from_utf16(unsafe { std::slice::from_raw_parts(p, n) })
            .map_err(|_| "G1_SID_UTF16".into())
    }
    // Read owner/control and exact non-inherited ACEs of the SAME object,
    // using the actual kernel handle, never the input SDDL as evidence.
    fn verify_descriptor(handle: HANDLE) -> Result<(), String> {
        let mut owner = null_mut();
        let mut acl: *mut ACL = null_mut();
        let mut sd = null_mut();
        let rc = unsafe { GetSecurityInfo(handle, SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner, null_mut(), &mut acl, null_mut(), &mut sd) };
        let _sd = Local(sd.cast());
        if rc != 0 || sd.is_null() || owner.is_null() || acl.is_null() {
            return Err(format!("G1_ACL_QUERY win32={rc}"));
        }
        let who = sid_text(owner)?;
        if who != BA { return Err(format!("G1_OWNER owner={who}")); }
        let mut present = 0;
        let mut defaulted = 0;
        let mut returned = null_mut();
        let mut control = 0u16;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut returned, &mut defaulted) } == 0
            || unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
            || present == 0 || defaulted != 0 || returned != acl || control & 0x1000 == 0 {
            return Err(format!("G1_ACL_CONTROL control={control:#x}"));
        }
        let count = unsafe { (*acl).AceCount };
        if count != 2 { return Err(format!("G1_ACL_COUNT count={count}")); }
        let mut seen_ba = false;
        let mut seen_sy = false;
        for i in 0..u32::from(count) {
            let mut p = null_mut();
            if unsafe { GetAce(acl, i, &mut p) } == 0 || p.is_null() {
                return Err(last("G1_ACE_READ"));
            }
            let h = unsafe { &*p.cast::<ACE_HEADER>() };
            if h.AceType != 0 || h.AceFlags != 0 || h.AceSize < 16 {
                return Err("G1_ACE_FORMAT".into());
            }
            let a = unsafe { &*p.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = std::ptr::addr_of!(a.SidStart).cast_mut().cast::<core::ffi::c_void>();
            let prefix = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
            let len = 8 + usize::from(prefix[1]) * 4;
            if len != usize::from(h.AceSize) - 8 || unsafe { IsValidSid(sid) } == 0
                || unsafe { GetLengthSid(sid) } as usize != len || a.Mask != RIGHTS {
                return Err("G1_ACE_SID_OR_MASK".into());
            }
            let trustee = sid_text(sid)?;
            match trustee.as_str() {
                BA if !seen_ba => seen_ba = true,
                SY if !seen_sy => seen_sy = true,
                _ => return Err("G1_ACE_TRUSTEE".into()),
            }
        }
        if !seen_ba || !seen_sy { return Err("G1_ACE_MISSING".into()); }
        #[cfg(test)]
        println!("G1_GATE_ACL owner={who} ace_count={count} control={control:#x} mask={RIGHTS:#x} read_rc={rc}");
        Ok(())
    }

    // Both the name and the initial-owner flag are fixed by this module.
    // CreateMutexExW requests only the rights required for use and readback.
    fn create(sddl: &str, initial_owner: bool) -> Result<(Handle, u32), String> {
        let sd = descriptor(sddl)?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let name = wide(NAME);
        unsafe { SetLastError(0); }
        let handle = unsafe { CreateMutexExW(&attrs, name.as_ptr(), u32::from(initial_owner), RIGHTS) };
        let rc = unsafe { GetLastError() };
        if handle.is_null() { return Err(format!("G1_GATE_CREATE win32={rc}")); }
        Ok((Handle(handle), rc))
    }

    /// Scope-bound, thread-owned. The Rc phantom prevents Send and Sync.
    /// No public handle, name override, adoption, reentry or transferable ticket.
    pub(crate) struct LifecycleGate {
        handle: Handle,
        _thread: PhantomData<Rc<()>>,
    }

    impl LifecycleGate {
        pub(in crate::guard) fn acquire() -> Result<Self, String> {
            require_elevated(unsafe { GetCurrentProcess() })?;
            let (handle, rc) = create(SDDL, true)?;
            if rc == ERROR_ALREADY_EXISTS {
                // Initial ownership is ignored for existing mutexes. Never
                // wait, release or use a preexisting handle for admission.
                return Err(format!("G1_GATE_EXISTING win32={rc}"));
            }
            if rc != 0 { return Err(format!("G1_GATE_CREATE_STATUS win32={rc}")); }
            let gate = Self { handle, _thread: PhantomData };
            verify_descriptor(gate.handle.0)?;
            #[cfg(test)]
            println!("G1_GATE_ACQUIRED pid={} tid={} elevated=true new=true rc=0",
                std::process::id(), unsafe { GetCurrentThreadId() });
            Ok(gate)
        }
    }
    impl Drop for LifecycleGate {
        fn drop(&mut self) {
            // The create call gave this thread initial ownership only for
            // a brand-new object. No other thread can receive this guard.
            if unsafe { ReleaseMutex(self.handle.0) } == 0 {
                eprintln!("{}", last("G1_GATE_RELEASE"));
            }
            // Handle closes after Drop, also on early descriptor refusal.
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Read;
        use std::os::windows::io::AsRawHandle;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};
        const ROLE: &str = "SPIDERVPN_G1_KERNEL_TEST_ROLE";
        const READY: &str = "SPIDERVPN_G1_KERNEL_TEST_READY";
        const TEST: &str = "guard::lifecycle_gate::imp::tests::production_gate_kernel_contract";

        fn refused() -> String {
            assert!(matches!(LifecycleGate::acquire(), Err(_)));
            // A second independent call must also reject without adoption.
            LifecycleGate::acquire().err().unwrap()
        }
        fn existing() {
            assert_eq!(refused(), "G1_GATE_EXISTING win32=183");
        }
        fn open(rights: u32) -> Handle {
            let h = unsafe { OpenMutexW(rights, 0, wide(NAME).as_ptr()) };
            assert!(!h.is_null(), "{}", last("G1_TEST_OPEN"));
            Handle(h)
        }
        fn sid(process: HANDLE) -> String {
            let token = process_token(process).unwrap();
            let mut len = 0;
            unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut len); }
            assert!(len >= std::mem::size_of::<TOKEN_USER>() as u32 && len <= 65536);
            let mut data = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
            let mut actual = 0;
            assert_ne!(unsafe { GetTokenInformation(token.0, TokenUser,
                data.as_mut_ptr().cast(), len, &mut actual) }, 0);
            assert!(actual <= len);
            sid_text(unsafe { (*data.as_ptr().cast::<TOKEN_USER>()).User.Sid }).unwrap()
        }
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill(); let _ = self.0.wait();
                }
            }
        }
        fn wait(child: &mut Child, success: bool) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(rc) = child.try_wait().unwrap() { assert_eq!(rc.success(), success); return; }
                assert!(Instant::now() < deadline, "G1 child timeout");
                std::thread::sleep(Duration::from_millis(15));
            }
        }

        #[test]
        #[ignore = "explicit isolated elevated Windows runner, fixed production gate name"]
        fn production_gate_kernel_contract() {
            if let Ok(role) = std::env::var(ROLE) {
                match role.as_str() {
                    "contend" => existing(),
                    "fresh" => { let _gate = LifecycleGate::acquire().unwrap(); }
                    "hold" => {
                        let _gate = LifecycleGate::acquire().unwrap();
                        std::fs::write(std::env::var_os(READY).unwrap(), b"ready").unwrap();
                        assert_eq!(std::io::stdin().read(&mut [0u8; 1]).unwrap(), 0);
                    }
                    _ => panic!("unknown G1 test role"),
                }
                return;
            }
            let exe = std::env::current_exe().unwrap();
            let self_sid = sid(unsafe { GetCurrentProcess() });
            let nonce = {
                use ring::rand::{SecureRandom, SystemRandom};
                let mut b = [0u8;16]; SystemRandom::new().fill(&mut b).unwrap();
                b.iter().map(|x| format!("{x:02x}")).collect::<String>()
            };
            let ready = std::env::temp_dir().join(format!("spidervpn-g1-{nonce}"));
            let spawn = |role: &str| {
                let c = ChildGuard(Command::new(&exe).args(["--ignored", "--exact", TEST, "--nocapture"])
                    .env(ROLE, role).env(READY, &ready).stdin(Stdio::piped()).spawn().unwrap());
                let h = c.0.as_raw_handle();
                // Retained process handle, actual token, not environment claims.
                require_elevated(h).unwrap();
                assert_eq!(sid(h), self_sid);
                assert_ne!(c.0.id(), std::process::id());
                println!("G1_GATE_PEER role={role} pid={} same_sid=true elevated=true", c.0.id());
                c
            };
            {
                let gate = LifecycleGate::acquire().expect("fresh production gate");
                verify_descriptor(gate.handle.0).unwrap();
                existing(); // no accidental recursive acquisition
                let thread = std::thread::spawn(|| {
                    existing();
                    let full = open(RIGHTS);
                    let limited = open(0x0010_0000);
                    assert_eq!(unsafe { ReleaseMutex(full.0) }, 0);
                    assert_eq!(unsafe { GetLastError() }, ERROR_NOT_OWNER);
                    assert_eq!(unsafe { ReleaseMutex(limited.0) }, 0);
                    let rc = unsafe { GetLastError() };
                    assert!(matches!(rc, ERROR_NOT_OWNER | ERROR_ACCESS_DENIED));
                    assert_eq!(unsafe { WaitForSingleObject(full.0, 0) }, WAIT_TIMEOUT);
                    println!("G1_GATE_NONOWNER full_rc=288 sync_rc={rc} wait_rc=258");
                });
                thread.join().unwrap();
                let mut peer = spawn("contend"); wait(&mut peer.0, true);
            }
            let mut peer = spawn("fresh"); wait(&mut peer.0, true);
            for (sddl, kind) in [(SDDL, "exact"),
                ("O:BAD:P(A;;0x00120001;;;SY)(A;;0x00120001;;;BA)(A;;0x00120001;;;WD)", "broad")] {
                let (h, rc) = create(sddl, false).unwrap();
                assert_eq!(rc, 0);
                if kind == "exact" { verify_descriptor(h.0).unwrap(); }
                else { assert!(verify_descriptor(h.0).unwrap_err().contains("G1_ACL_COUNT")); }
                existing();
                println!("G1_GATE_PRECREATE kind={kind} refused_rc=183");
            }
            {
                let h = Handle(unsafe { CreateEventW(null_mut(), 0, 0, wide(NAME).as_ptr()) });
                assert!(!h.0.is_null());
                assert_eq!(refused(), "G1_GATE_CREATE win32=6");
                println!("G1_GATE_WRONG_TYPE rc=6");
            }
            let mut holder = spawn("hold");
            let deadline = Instant::now() + Duration::from_secs(10);
            while !ready.is_file() {
                assert!(holder.0.try_wait().unwrap().is_none() && Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(15));
            }
            let observer = open(RIGHTS);
            verify_descriptor(observer.0).unwrap();
            assert_eq!(unsafe { WaitForSingleObject(observer.0, 0) }, WAIT_TIMEOUT);
            existing();
            holder.0.kill().unwrap(); wait(&mut holder.0, false);
            // The retained handle keeps the abandoned object alive. The
            // production gate still refuses it without acquiring ownership.
            existing();
            assert_eq!(unsafe { WaitForSingleObject(observer.0, 1000) }, WAIT_ABANDONED_0);
            assert_ne!(unsafe { ReleaseMutex(observer.0) }, 0);
            existing(); // still exists even though currently unowned
            drop(observer);
            std::fs::remove_file(ready).unwrap();
            let mut peer = spawn("fresh"); wait(&mut peer.0, true);
            println!("G1_GATE_KERNEL_COMPLETE same_sid=true nonowner_refused=true existing_refused=true abandoned_rc=128 fresh_after_close=true cross_sid_not_run=true history_proven=false");
        }
    }
}

#[cfg(windows)]
pub(super) use imp::LifecycleGate;

#[cfg(not(windows))]
pub(super) struct LifecycleGate;
#[cfg(not(windows))]
impl LifecycleGate {
    pub(super) fn acquire() -> Result<Self, String> { Err("G1_GATE_WINDOWS_REQUIRED".into()) }
}
