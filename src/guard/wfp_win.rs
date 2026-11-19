//! WFP 的平台层（真实 FFI）。**只把系统事实翻译成结构化数据，不决定状态。**
//!
//! 本阶段（T01）只交付「内核」：
//!
//! - 句柄与内存的 RAII：`WfpEngine` / `Txn` / `WfpBuf` / `EnumHandle`；
//! - 字符串与 GUID 的转换（`Vec<u16>` 自持 + 生命周期覆盖整次调用）；
//! - `FwpmGetAppIdFromFileName0`（**非提权可用**，身份层靠它）；
//! - 六个结构体的构造与反解（`FWPM_PROVIDER0` / `FWPM_SUBLAYER0` / `FWPM_FILTER0` …），
//!   包括 block 规则的 `ALE_APP_ID == appId` 单条件、`PERSISTENT`、`weight=0x1000`；
//! - provider / subLayer / filter 的增删读与枚举薄封装。
//!
//! 三条纪律（架构 §6.1）：
//!
//! 1. **close 与 commit 的失败不吞**：close 失败意味着「策略状态不可确认」，
//!    commit 失败意味着整笔没生效。两者都必须返回 `Err`，`Drop` 只做兜底。
//! 2. **`FwpmFreeMemory0` 只对外层数组指针调用一次**，元素不单独释放（这是一个经典陷阱：
//!    逐元素释放会二次释放堆块）。
//! 3. **本文件不判断「算不算保护」**：只输出 [`FilterRaw`] / 定义结构，判定在 `state.rs`。
//!
//! 关于 `dlltool`：`windows-sys` 用 `windows-link` 的 raw-dylib 声明，在 `*-pc-windows-gnu`
//! 目标下 rustc 需要 `dlltool.exe` 才能生成导入库。`build.ps1` 已把 WinLibs 的 bin 放进
//! PATH；裸 `cargo build` 需要自己加（见 `Cargo.toml` 注释与 README）。

#![allow(dead_code)] // T03 才把写路径接上；这里先把 ABI 与 RAII 钉死并保持可编译

/// 平台能力开关：本版是否提供 WFP 相关能力（非 Windows / 32 位一律 false）。
pub const PLATFORM_SUPPORTED: bool = cfg!(all(windows, target_pointer_width = "64"));

#[cfg(windows)]
mod imp {
    use std::path::Path;

    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as W;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };

    use super::super::identity::{device_path_from_app_id, IdentityEnv, IdentityError};
    use super::super::wfp::{
        classify, FilterRaw, Guid, Layer, ProviderDefinition, RawCondition, SubLayerDefinition,
        WfpError, ACTION_BLOCK, CONDITION_ALE_APP_ID, FILTER_FLAG_PERSISTENT, FILTER_WEIGHT_BLOCK,
        FWP_TYPE_BYTE_BLOB, FWP_TYPE_UINT64, MATCH_EQUAL, OBJECT_FLAG_PERSISTENT, OWNER_MARKER,
        PROVIDER_DESCRIPTION, PROVIDER_GUID, PROVIDER_NAME, SUBLAYER_DESCRIPTION, SUBLAYER_GUID,
        SUBLAYER_NAME, SUBLAYER_WEIGHT,
    };

    /// 本次开机的标识：开机时刻（epoch 秒，取整）。
    ///
    /// 用「当前时间 - 开机时长」而不是别的：它只需要一次调用、与系统时区无关，
    /// 且**重启后必然变化**（这正是「重启后旧证据作废」需要的语义）。
    pub fn boot_id() -> String {
        use windows_sys::Win32::System::SystemInformation::GetTickCount64;
        let uptime_ms = unsafe { GetTickCount64() };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let boot = (now - (uptime_ms as f64) / 1000.0).max(0.0);
        format!("{boot:.0}")
    }

    /// `RPC_C_AUTHN_WINNT`：本地 WFP 引擎必须用 WinNT 认证（匿名/DEFAULT 在某些系统上被拒）。
    pub const RPC_C_AUTHN_WINNT: u32 = 10;

    /// 把 Rust 字符串变成以 NUL 结尾的 UTF-16。**调用方必须持有它到整次调用结束**。
    pub fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0u16)).collect()
    }

    pub fn to_win(g: Guid) -> windows_sys::core::GUID {
        windows_sys::core::GUID { data1: g.data1, data2: g.data2, data3: g.data3, data4: g.data4 }
    }

    pub fn from_win(g: windows_sys::core::GUID) -> Guid {
        Guid { data1: g.data1, data2: g.data2, data3: g.data3, data4: g.data4 }
    }

    /// 读一个 `PWSTR`（可能是空指针）。
    unsafe fn read_pwstr(p: windows_sys::core::PWSTR) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len > 32_768 {
                // 防御：不该出现的长度（坏指针/坏数据）
                return None;
            }
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, len)))
    }

    /// 读一个 `FWP_BYTE_BLOB`（可能是空 blob）。
    unsafe fn read_blob(blob: &W::FWP_BYTE_BLOB) -> Vec<u8> {
        if blob.data.is_null() || blob.size == 0 {
            return Vec::new();
        }
        std::slice::from_raw_parts(blob.data, blob.size as usize).to_vec()
    }

    // -----------------------------------------------------------------------
    // 引擎句柄
    // -----------------------------------------------------------------------

    /// WFP 引擎句柄。
    ///
    /// 用「显式 `close_checked()` + `Drop` 兜底」的两段式：业务路径必须处理显式结果
    /// （close 失败 = 策略状态不可确认），`Drop` 只是不让句柄泄漏。
    pub struct WfpEngine {
        handle: Option<HANDLE>,
    }

    impl WfpEngine {
        /// 打开引擎。`session = NULL` 是最常见的用法：不加 `DYNAMIC`，
        /// 因此我们创建的 **persistent** 对象在进程退出后仍然存在（PRD P0-3 要求的正是这个）。
        pub fn open() -> Result<WfpEngine, WfpError> {
            let mut handle: HANDLE = std::ptr::null_mut();
            let rc = unsafe {
                W::FwpmEngineOpen0(
                    std::ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    std::ptr::null(),
                    std::ptr::null(),
                    &mut handle,
                )
            };
            if rc != 0 {
                return Err(classify(rc));
            }
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(WfpError::InvalidState);
            }
            Ok(WfpEngine { handle: Some(handle) })
        }

        /// 打开**动态** WFP 会话：本会话内的非持久过滤器在进程崩溃/
        /// 句柄被 BFE 回收后自动消失。与原有的持久安装 open() 严格分开。
        /// 这只是构造能力；未来必须由受监督的单独进程持有至引擎退出。
        pub fn open_dynamic() -> Result<WfpEngine, WfpError> {
            let mut session: W::FWPM_SESSION0 = unsafe { std::mem::zeroed() };
            session.flags = W::FWPM_SESSION_FLAG_DYNAMIC;
            let mut handle: HANDLE = std::ptr::null_mut();
            let rc = unsafe {
                W::FwpmEngineOpen0(
                    std::ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    std::ptr::null(),
                    &session,
                    &mut handle,
                )
            };
            if rc != 0 { return Err(classify(rc)); }
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(WfpError::InvalidState);
            }
            Ok(WfpEngine { handle: Some(handle) })
        }

        pub fn raw(&self) -> HANDLE {
            self.handle.unwrap_or(std::ptr::null_mut())
        }

        /// 显式关闭：失败要返回给调用方（close 失败时策略状态不可确认）。
        pub fn close_checked(mut self) -> Result<(), WfpError> {
            let Some(h) = self.handle else {
                return Ok(());
            };
            let rc = unsafe { W::FwpmEngineClose0(h) };
            if rc != 0 {
                // FwpmEngineClose0 返回失败时不能先遗失 handle。
                // 让接下来 self 的 Drop 再尝试一次关闭；临时许可持有进程
                // 结束后的 RPC rundown 仍是最后一道 fail-closed 兜底。
                return Err(classify(rc));
            }
            self.handle = None;
            Ok(())
        }
    }

    impl Drop for WfpEngine {
        fn drop(&mut self) {
            if let Some(h) = self.handle.take() {
                unsafe {
                    W::FwpmEngineClose0(h);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 事务
    // -----------------------------------------------------------------------

    /// 一个 WFP 事务。`Drop` 时若未 commit 则 abort（不留半笔改动给系统）。
    pub struct Txn<'a> {
        engine: &'a WfpEngine,
        open: bool,
    }

    impl<'a> Txn<'a> {
        pub fn begin(engine: &'a WfpEngine) -> Result<Txn<'a>, WfpError> {
            let rc = unsafe { W::FwpmTransactionBegin0(engine.raw(), 0) };
            if rc != 0 {
                return Err(classify(rc));
            }
            Ok(Txn { engine, open: true })
        }

        /// 提交。**commit 失败 = 整笔失败**，绝不当作「部分成功」。
        pub fn commit(mut self) -> Result<(), WfpError> {
            let rc = unsafe { W::FwpmTransactionCommit0(self.engine.raw()) };
            self.open = false; // 无论成败都不再 abort（系统侧事务已终结）
            if rc != 0 {
                return Err(classify(rc));
            }
            Ok(())
        }

        pub fn abort(mut self) -> Result<(), WfpError> {
            let rc = unsafe { W::FwpmTransactionAbort0(self.engine.raw()) };
            self.open = false;
            if rc != 0 {
                return Err(classify(rc));
            }
            Ok(())
        }
    }

    impl Drop for Txn<'_> {
        fn drop(&mut self) {
            if self.open {
                unsafe {
                    W::FwpmTransactionAbort0(self.engine.raw());
                }
                self.open = false;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 内存与枚举句柄
    // -----------------------------------------------------------------------

    /// `FwpmGetByKey0` / `FwpmEnum0` 返回的内存块。
    ///
    /// 纪律：`FwpmFreeMemory0` **只对最外层指针调用一次**。枚举返回的是
    /// 「指针数组」，数组元素指向同一块内存，逐元素释放会二次释放。
    pub struct WfpBuf<T> {
        ptr: *mut T,
    }

    impl<T> WfpBuf<T> {
        /// # Safety
        /// `ptr` 必须是 `fwpuclnt` 分配、尚未释放的指针（或空指针）。
        pub unsafe fn from_raw(ptr: *mut T) -> WfpBuf<T> {
            WfpBuf { ptr }
        }

        pub fn is_null(&self) -> bool {
            self.ptr.is_null()
        }

        pub fn as_ref(&self) -> Option<&T> {
            if self.ptr.is_null() {
                None
            } else {
                Some(unsafe { &*self.ptr })
            }
        }
    }

    impl<T> Drop for WfpBuf<T> {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                let mut outer = self.ptr as *mut core::ffi::c_void;
                unsafe {
                    W::FwpmFreeMemory0(&mut outer);
                }
                self.ptr = std::ptr::null_mut();
            }
        }
    }

    /// 枚举句柄（三种对象各有自己的 destroy 函数，所以用函数指针）。
    ///
    /// 函数指针类型必须写全 `unsafe extern "system"`：`windows-sys` 里的
    /// `Fwpm*DestroyEnumHandle0` 是 `extern "system"`，与 Rust 默认 ABI 不同，
    /// 少写一个 `extern "system"` 就是编译错误（不是运行时才发现）。
    pub struct EnumHandle {
        engine: HANDLE,
        handle: HANDLE,
        destroy: unsafe extern "system" fn(HANDLE, HANDLE) -> u32,
    }

    impl EnumHandle {
        /// # Safety
        /// `destroy` 必须是与该句柄匹配的 `Fwpm*DestroyEnumHandle0`。
        unsafe fn new(
            engine: HANDLE,
            handle: HANDLE,
            destroy: unsafe extern "system" fn(HANDLE, HANDLE) -> u32,
        ) -> EnumHandle {
            EnumHandle { engine, handle, destroy }
        }

        pub fn raw(&self) -> HANDLE {
            self.handle
        }
    }

    impl Drop for EnumHandle {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe {
                    (self.destroy)(self.engine, self.handle);
                }
                self.handle = std::ptr::null_mut();
            }
        }
    }

    // -----------------------------------------------------------------------
    // appId（**非提权可用**，身份层唯一依赖的 FFI）
    // -----------------------------------------------------------------------

    /// `FwpmGetAppIdFromFileName0`：把路径变成 WFP 的 appId 字节（UTF-16LE + NUL）。
    ///
    /// 本次实测（架构 §1.4）：非提权会话下这个调用**可用**，且大小 = 字符数 × 2。
    /// 文件不存在时返回 `2 / 3`（`FILE_NOT_FOUND` / `PATH_NOT_FOUND`），与「权限不足」可区分。
    pub fn app_id_from_path(path: &Path) -> Result<Vec<u8>, WfpError> {
        use std::os::windows::ffi::OsStrExt;
        let wide_path: Vec<u16> =
            path.as_os_str().encode_wide().chain(std::iter::once(0u16)).collect();
        let mut blob: *mut W::FWP_BYTE_BLOB = std::ptr::null_mut();
        let rc = unsafe { W::FwpmGetAppIdFromFileName0(wide_path.as_ptr(), &mut blob) };
        if rc != 0 {
            return Err(classify(rc));
        }
        let buf = unsafe { WfpBuf::from_raw(blob) };
        let Some(b) = buf.as_ref() else {
            return Err(WfpError::InvalidState);
        };
        let bytes = unsafe { read_blob(b) };
        if bytes.is_empty() || device_path_from_app_id(&bytes).is_empty() {
            // 解不出 device path 就不能当身份（不可诊断、不可比对）
            return Err(WfpError::InvalidState);
        }
        Ok(bytes)
    }

    // -----------------------------------------------------------------------
    // 定义构造（把“应该长什么样”变成原生结构）
    // -----------------------------------------------------------------------

    /// 已构造好的 `FWPM_PROVIDER0`。
    ///
    /// 自持所有被指向的缓冲（名字、描述、标记），并用 `Box` 固定堆地址：
    /// `Box` 移动的是指针，堆上的内容不会跟着搬，所以内部的裸指针始终有效。
    pub struct RawProvider {
        raw: W::FWPM_PROVIDER0,
        _name: Vec<u16>,
        _description: Vec<u16>,
        _marker: Vec<u8>,
    }

    impl RawProvider {
        pub fn build() -> Box<RawProvider> {
            let mut boxed = Box::new(RawProvider {
                raw: unsafe { std::mem::zeroed() },
                _name: wide(PROVIDER_NAME),
                _description: wide(PROVIDER_DESCRIPTION),
                _marker: OWNER_MARKER.to_vec(),
            });
            let name_ptr = boxed._name.as_mut_ptr();
            let desc_ptr = boxed._description.as_mut_ptr();
            let marker_ptr = boxed._marker.as_mut_ptr();
            let marker_len = boxed._marker.len() as u32;
            boxed.raw = W::FWPM_PROVIDER0 {
                providerKey: to_win(PROVIDER_GUID),
                displayData: W::FWPM_DISPLAY_DATA0 { name: name_ptr, description: desc_ptr },
                flags: OBJECT_FLAG_PERSISTENT,
                providerData: W::FWP_BYTE_BLOB { size: marker_len, data: marker_ptr },
                // 不绑定服务：否则规则的生命周期会跟着某个服务走
                serviceName: std::ptr::null_mut(),
            };
            boxed
        }

        pub fn as_ptr(&self) -> *const W::FWPM_PROVIDER0 {
            &self.raw
        }
    }

    /// 已构造好的 `FWPM_SUBLAYER0`（`providerKey` 指向自持的 GUID 副本）。
    pub struct RawSubLayer {
        raw: W::FWPM_SUBLAYER0,
        _name: Vec<u16>,
        _description: Vec<u16>,
        _marker: Vec<u8>,
        _provider_key: Box<windows_sys::core::GUID>,
    }

    impl RawSubLayer {
        pub fn build() -> Box<RawSubLayer> {
            let mut boxed = Box::new(RawSubLayer {
                raw: unsafe { std::mem::zeroed() },
                _name: wide(SUBLAYER_NAME),
                _description: wide(SUBLAYER_DESCRIPTION),
                _marker: OWNER_MARKER.to_vec(),
                _provider_key: Box::new(to_win(PROVIDER_GUID)),
            });
            let name_ptr = boxed._name.as_mut_ptr();
            let desc_ptr = boxed._description.as_mut_ptr();
            let marker_ptr = boxed._marker.as_mut_ptr();
            let marker_len = boxed._marker.len() as u32;
            let provider_ptr: *mut windows_sys::core::GUID = &mut *boxed._provider_key;
            boxed.raw = W::FWPM_SUBLAYER0 {
                subLayerKey: to_win(SUBLAYER_GUID),
                displayData: W::FWPM_DISPLAY_DATA0 { name: name_ptr, description: desc_ptr },
                flags: OBJECT_FLAG_PERSISTENT,
                providerKey: provider_ptr,
                providerData: W::FWP_BYTE_BLOB { size: marker_len, data: marker_ptr },
                weight: SUBLAYER_WEIGHT,
            };
            boxed
        }

        pub fn as_ptr(&self) -> *const W::FWPM_SUBLAYER0 {
            &self.raw
        }
    }

    // Single source of truth: the controller records every possible dynamic
    // key BEFORE request delivery; the helper's actual builder uses this exact
    // function after independently validating the supplied APP_IDs.
    pub(crate) fn dynamic_permit_key(app_id: &[u8], endpoint: std::net::SocketAddr,
        lease_nonce: &[u8]) -> Result<Guid, String>
    {
        use sha2::{Digest, Sha256};
        use super::super::egress_policy::EgressPolicy;
        if !matches!(EgressPolicy::local_proxy(&endpoint.to_string()),
            Ok(EgressPolicy::LocalProxy { .. })) {
            return Err("临时 WFP 许可必须是精确本地代理端点".into());
        }
        if app_id.is_empty() || app_id.len() % 2 != 0 || lease_nonce.len() < 16 {
            return Err("临时 WFP 许可的 APP_ID 或会话 nonce 无效".into());
        }
        let mut h = Sha256::new();
        h.update(b"SpiderVPN/WFP-v2/dynamic-permit");
        h.update((app_id.len() as u64).to_le_bytes());
        h.update(app_id);
        h.update(endpoint.to_string().as_bytes());
        h.update(lease_nonce);
        let digest = h.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        let key = Guid::from_bytes_le(bytes);
        if key == Guid::nil() { return Err("动态许可键无效".into()); }
        Ok(key)
    }

    // Only exact FWP_E_FILTER_NOT_FOUND is absence. In particular ACCESS_DENIED,
    // a failed BFE connection, generic not-found and malformed success are not.
    fn permit_key_absent_status(rc: u32, has_object: bool) -> Result<bool, String> {
        use windows_sys::Win32::Foundation::FWP_E_FILTER_NOT_FOUND;
        match rc {
            0 if has_object => Ok(false),
            n if n == FWP_E_FILTER_NOT_FOUND as u32 && !has_object => Ok(true),
            _ => Err(format!("旧动态许可读回不可确认 (Win32={rc})")),
        }
    }

    pub(crate) fn old_dynamic_permits_absent(keys: &[Guid]) -> Result<bool, String> {
        use std::collections::HashSet;
        if keys.is_empty() || keys.len() > super::super::identity::MAX_PROGRAMS
            || keys.iter().any(|key| *key == Guid::nil())
            || keys.iter().copied().collect::<HashSet<_>>().len() != keys.len()
        {
            return Err("旧动态许可完整键集合无效".into());
        }
        // Independent, read-only BFE queries. Never change ACL, delete a rule,
        // reuse the old session, or infer absence from helper exit.
        let audit = WfpEngine::open().map_err(|e| e.to_string())?;
        for key in keys {
            let native = to_win(*key);
            let mut out: *mut W::FWPM_FILTER0 = std::ptr::null_mut();
            let rc = unsafe { W::FwpmFilterGetByKey0(audit.raw(), &native, &mut out) };
            let result = unsafe { WfpBuf::from_raw(out) };
            if !permit_key_absent_status(rc, result.as_ref().is_some())? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 已构造好的 `FWPM_FILTER0`（一条 block 规则）。
    pub struct RawFilter {
        raw: W::FWPM_FILTER0,
        _name: Vec<u16>,
        _description: Vec<u16>,
        _marker: Vec<u8>,
        _app_id: Vec<u8>,
        _blob: Box<W::FWP_BYTE_BLOB>,
        _weight: Box<u64>,
        _provider_key: Box<windows_sys::core::GUID>,
        _conditions: Box<[W::FWPM_FILTER_CONDITION0]>,
        // v2 地址条件要求整个 IPv6 数组保持有效；下一跳值则必须有稳定 u64 指针。
        _scoped_v6: Option<Box<W::FWP_BYTE_ARRAY16>>,
        _scoped_luid: Option<Box<u64>>,
    }

    impl RawFilter {
        /// 一条持久 block：`layer == ALE_AUTH_CONNECT_V4/V6` 且 `ALE_APP_ID == app_id`。
        ///
        /// 结构里的三个指针（条件数组 ← 条件值 → blob 结构 → appId 字节）分三层，
        /// 每一层都必须指向**稳定的**堆地址，所以所有缓冲都放进 `Box` 再取指针。
        pub fn block(name: &str, app_id: &[u8], layer: Layer) -> Box<RawFilter> {
            let key = super::super::wfp::filter_key(app_id, layer, false);
            let mut boxed = Box::new(RawFilter {
                raw: unsafe { std::mem::zeroed() },
                _name: wide(name),
                _description: wide(PROVIDER_DESCRIPTION),
                _marker: OWNER_MARKER.to_vec(),
                _app_id: app_id.to_vec(),
                _blob: Box::new(W::FWP_BYTE_BLOB { size: app_id.len() as u32, data: std::ptr::null_mut() }),
                _weight: Box::new(FILTER_WEIGHT_BLOCK),
                _provider_key: Box::new(to_win(PROVIDER_GUID)),
                _scoped_v6: None,
                _scoped_luid: None,
                _conditions: Box::new([W::FWPM_FILTER_CONDITION0 {
                    fieldKey: to_win(CONDITION_ALE_APP_ID),
                    matchType: MATCH_EQUAL,
                    conditionValue: W::FWP_CONDITION_VALUE0 {
                        r#type: FWP_TYPE_BYTE_BLOB,
                        Anonymous: W::FWP_CONDITION_VALUE0_0 { byteBlob: std::ptr::null_mut() },
                    },
                }]),
            });
            // 1) blob → appId 字节（最内层）
            boxed._blob.data = boxed._app_id.as_mut_ptr();
            boxed._blob.size = boxed._app_id.len() as u32;
            // 2) 条件值 → blob（中间层）
            let blob_ptr: *mut W::FWP_BYTE_BLOB = &mut *boxed._blob;
            boxed._conditions[0].conditionValue.Anonymous.byteBlob = blob_ptr;
            // 3) 现在取最后一级指针
            let name_ptr = boxed._name.as_mut_ptr();
            let desc_ptr = boxed._description.as_mut_ptr();
            let marker_ptr = boxed._marker.as_mut_ptr();
            let marker_len = boxed._marker.len() as u32;
            let weight_ptr: *mut u64 = &mut *boxed._weight;
            let provider_ptr: *mut windows_sys::core::GUID = &mut *boxed._provider_key;
            let conditions_ptr = boxed._conditions.as_mut_ptr();
            boxed.raw = W::FWPM_FILTER0 {
                filterKey: to_win(key),
                displayData: W::FWPM_DISPLAY_DATA0 { name: name_ptr, description: desc_ptr },
                flags: FILTER_FLAG_PERSISTENT,
                providerKey: provider_ptr,
                providerData: W::FWP_BYTE_BLOB { size: marker_len, data: marker_ptr },
                layerKey: to_win(layer.guid()),
                subLayerKey: to_win(SUBLAYER_GUID),
                weight: W::FWP_VALUE0 {
                    r#type: FWP_TYPE_UINT64,
                    Anonymous: W::FWP_VALUE0_0 { uint64: weight_ptr },
                },
                numFilterConditions: 1,
                filterCondition: conditions_ptr,
                action: W::FWPM_ACTION0 {
                    r#type: ACTION_BLOCK,
                    Anonymous: W::FWPM_ACTION0_0 { filterType: to_win(Guid::nil()) },
                },
                Anonymous: W::FWPM_FILTER0_0 { rawContext: 0 },
                reserved: std::ptr::null_mut(),
                filterId: 0,
                effectiveWeight: unsafe { std::mem::zeroed() },
            };
            boxed
        }

        /// 仅构造候选 WFP v2 代理规则（**不调用 BFE，不安装**）。
        /// 实际持久迁移只能在隔离真实流量与事务回滚均通过后启用。
        /// TUN 仍被硬拒绝：不允许缺省略过 FWP_EMPTY/重新授权保护。
        pub fn scoped_v2_proxy(
            name: &str,
            app_id: &[u8],
            spec: &super::super::egress_policy::ScopedBlock,
        ) -> Result<Box<RawFilter>, String> {
            use super::super::egress_policy::{scoped_key, DenyTerm, IpFamily};
            if app_id.is_empty() || app_id.len() % 2 != 0 {
                return Err("WFP v2 APP_ID 必须是非空 UTF-16LE 字节".to_string());
            }
            let layer = match spec.family {
                IpFamily::V4 => Layer::V4,
                IpFamily::V6 => Layer::V6,
            };
            if spec.filter_key != scoped_key(app_id, spec.family, spec.predicate) {
                return Err("WFP v2 规则 key 与条件不一致，拒绝安装".to_string());
            }
            let mut new_filter = RawFilter::block(name, app_id, layer);
            // 不改变 v1 现有构造器的内容。仅在独立 v2 候选中重算 key 与谓词条件。
            new_filter.raw.filterKey = to_win(spec.filter_key);
            let mut conditions = vec![unsafe { std::ptr::read(&new_filter._conditions[0]) }];
            let predicate = match spec.predicate {
                DenyTerm::Any => None,
                DenyTerm::RemoteAddressNot(ip) => {
                    let value = match (spec.family, ip) {
                        (IpFamily::V4, std::net::IpAddr::V4(ip)) => W::FWP_CONDITION_VALUE0 {
                            r#type: W::FWP_UINT32,
                            Anonymous: W::FWP_CONDITION_VALUE0_0 {
                                uint32: u32::from_be_bytes(ip.octets()),
                            },
                        },
                        (IpFamily::V6, std::net::IpAddr::V6(ip)) => {
                            new_filter._scoped_v6 = Some(Box::new(W::FWP_BYTE_ARRAY16 {
                                byteArray16: ip.octets(),
                            }));
                            let ptr: *mut W::FWP_BYTE_ARRAY16 =
                                &mut **new_filter._scoped_v6.as_mut().unwrap();
                            W::FWP_CONDITION_VALUE0 {
                                r#type: W::FWP_BYTE_ARRAY16_TYPE,
                                Anonymous: W::FWP_CONDITION_VALUE0_0 { byteArray16: ptr },
                            }
                        }
                        _ => return Err("IPv4/IPv6 地址与过滤层不匹配，拒绝候选规则".to_string()),
                    };
                    Some(W::FWPM_FILTER_CONDITION0 {
                        fieldKey: W::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: W::FWP_MATCH_NOT_EQUAL,
                        conditionValue: value,
                    })
                }
                DenyTerm::RemotePortNot(port) => Some(W::FWPM_FILTER_CONDITION0 {
                    fieldKey: W::FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: W::FWP_MATCH_NOT_EQUAL,
                    conditionValue: W::FWP_CONDITION_VALUE0 {
                        r#type: W::FWP_UINT16,
                        Anonymous: W::FWP_CONDITION_VALUE0_0 { uint16: port },
                    },
                }),
                DenyTerm::ProtocolNotTcp => Some(W::FWPM_FILTER_CONDITION0 {
                    fieldKey: W::FWPM_CONDITION_IP_PROTOCOL,
                    matchType: W::FWP_MATCH_NOT_EQUAL,
                    conditionValue: W::FWP_CONDITION_VALUE0 {
                        r#type: W::FWP_UINT8,
                        Anonymous: W::FWP_CONDITION_VALUE0_0 { uint8: 6 },
                    },
                }),
                DenyTerm::NextHopNot(_) | DenyTerm::MissingNextHop => {
                    return Err("真实 TUN 下一跳与 FWP_EMPTY 重新授权未完成，拒绝 v2 持久构造".to_string());
                }
            };
            if let Some(condition) = predicate {
                conditions.push(condition);
            }
            new_filter._conditions = conditions.into_boxed_slice();
            new_filter.raw.numFilterConditions = new_filter._conditions.len() as u32;
            new_filter.raw.filterCondition = new_filter._conditions.as_mut_ptr();
            Ok(new_filter)
        }

        /// 候选的临时许可：只对精确可信环回 IP+port 的 TCP 新连接放行。
        /// 不修改任何 WFP 对象；调用者必须通过动态 WFP Session 安装且在
        /// 引擎寿命终止时关闭该 Session，保证 v1 持久 BLOCK 始终保留。
        ///
        /// lease_nonce 必须从一次独立连接会话产生，避免新的许可复用旧 FilterKey。
        /// 这里并不证明 sing-box 进程身份；必须由调用方先验证 owner PID/exe。
        fn ephemeral_proxy_permit(
            name: &str, app_id: &[u8], endpoint: std::net::SocketAddr, lease_nonce: &[u8],
        ) -> Result<Box<RawFilter>, String> {
            let permit_key = dynamic_permit_key(app_id, endpoint, lease_nonce)?;
            let layer = if endpoint.is_ipv4() { Layer::V4 } else { Layer::V6 };

            let mut permit = RawFilter::block(name, app_id, layer);
            // 不得修改已有持久 v1 BLOCK；必须高于旧 BLOCK 0x1000 的权重。
            permit.raw.filterKey = to_win(permit_key);
            permit.raw.flags = 0; // 不持久、不禁用、不清空其它安全产品的 action right
            // v1 guard 的 snapshot/sync 仅枚举 PROVIDER_GUID 下的持久 BLOCK。
            // 动态许可不能使用这个 provider，否则会被误判为“多余过滤器”，
            // 甚至在交易名单同步时遭到删除。许可由动态 WFP 会话拥有，
            // 必须始终使用 NULL provider + 空 providerData；但继续引用
            // 相同 sublayer，以保证与 v1 BLOCK 在同一子层内进行权重仲裁。
            permit.raw.providerKey = std::ptr::null_mut();
            permit.raw.providerData = W::FWP_BYTE_BLOB { size: 0, data: std::ptr::null_mut() };
            permit.raw.action.r#type = W::FWP_ACTION_PERMIT;
            *permit._weight = super::super::wfp::FILTER_WEIGHT_PERMIT;

            let addr_value = match endpoint.ip() {
                std::net::IpAddr::V4(ip) => W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT32,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from_be_bytes(ip.octets()),
                    },
                },
                std::net::IpAddr::V6(ip) => {
                    permit._scoped_v6 = Some(Box::new(W::FWP_BYTE_ARRAY16 {
                        byteArray16: ip.octets(),
                    }));
                    let pointer: *mut W::FWP_BYTE_ARRAY16 =
                        &mut **permit._scoped_v6.as_mut().unwrap();
                    W::FWP_CONDITION_VALUE0 {
                        r#type: W::FWP_BYTE_ARRAY16_TYPE,
                        Anonymous: W::FWP_CONDITION_VALUE0_0 { byteArray16: pointer },
                    }
                }
            };
            let conditions = vec![
                // ALE_APP_ID is the first condition as in the existing v1 BLOCK builder.
                unsafe { std::ptr::read(&permit._conditions[0]) },
                W::FWPM_FILTER_CONDITION0 {
                    fieldKey: W::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: W::FWP_MATCH_EQUAL,
                    conditionValue: addr_value,
                },
                W::FWPM_FILTER_CONDITION0 {
                    fieldKey: W::FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: W::FWP_MATCH_EQUAL,
                    conditionValue: W::FWP_CONDITION_VALUE0 {
                        r#type: W::FWP_UINT16,
                        Anonymous: W::FWP_CONDITION_VALUE0_0 { uint16: endpoint.port() },
                    },
                },
                W::FWPM_FILTER_CONDITION0 {
                    fieldKey: W::FWPM_CONDITION_IP_PROTOCOL,
                    matchType: W::FWP_MATCH_EQUAL,
                    conditionValue: W::FWP_CONDITION_VALUE0 {
                        r#type: W::FWP_UINT8,
                        Anonymous: W::FWP_CONDITION_VALUE0_0 { uint8: 6 },
                    },
                },
            ];
            permit._conditions = conditions.into_boxed_slice();
            permit.raw.numFilterConditions = permit._conditions.len() as u32;
            permit.raw.filterCondition = permit._conditions.as_mut_ptr();
            Ok(permit)
        }

        /// TUN 正向临时许可的**内部候选构造器**：
        ///    APP_ID == 交易软件 && NEXTHOP_INTERFACE == 经验证的 TUN LUID。
        ///
        /// 持久的 v1 APP_ID BLOCK 永不移除：字段为 FWP_EMPTY、接口改变、
        /// 非 TUN 流量时，上述正向许可不匹配，继续由 v1 BLOCK 阻断。
        /// 因此无需依赖 NOT_EQUAL 在缺失字段上的语义来实现 fail-closed。
        ///
        /// 这里只生成原生结构，不安装、不同步、不向 UI 暴露。真实 Wintun 和
        /// ALE 重新授权尚未通过验证时，不得将它用于生产连接。
        fn candidate_ephemeral_tun_permit(
            name: &str,
            app_id: &[u8],
            layer: Layer,
            expected_luid: u64,
            lease_nonce: &[u8],
        ) -> Result<Box<RawFilter>, String> {
            use sha2::{Digest, Sha256};
            if expected_luid == 0 || app_id.is_empty() || app_id.len() % 2 != 0
                || lease_nonce.len() < 16
            {
                return Err("TUN 临时许可的 LUID、APP_ID 或 nonce 不合法".into());
            }
            let mut hash = Sha256::new();
            hash.update(b"SpiderVPN/WFP-v2/dynamic-tun-permit/");
            hash.update(match layer { Layer::V4 => b"ipv4", Layer::V6 => b"ipv6" });
            hash.update((app_id.len() as u64).to_le_bytes());
            hash.update(app_id);
            hash.update(expected_luid.to_le_bytes());
            hash.update(lease_nonce);
            let digest = hash.finalize();
            let mut key_bytes = [0u8; 16];
            key_bytes.copy_from_slice(&digest[..16]);

            let mut permit = RawFilter::block(name, app_id, layer);
            permit.raw.filterKey = to_win(Guid::from_bytes_le(key_bytes));
            permit.raw.flags = 0;
            // 与代理动态许可一致：不归入 v1 持久 BLOCK 的 provider 枚举。
            permit.raw.providerKey = std::ptr::null_mut();
            permit.raw.providerData = W::FWP_BYTE_BLOB { size: 0, data: std::ptr::null_mut() };
            permit.raw.action.r#type = W::FWP_ACTION_PERMIT;
            *permit._weight = super::super::wfp::FILTER_WEIGHT_PERMIT;
            permit._scoped_luid = Some(Box::new(expected_luid));
            let luid_ptr: *mut u64 = &mut **permit._scoped_luid.as_mut().unwrap();
            permit._conditions = vec![
                unsafe { std::ptr::read(&permit._conditions[0]) },
                W::FWPM_FILTER_CONDITION0 {
                    fieldKey: W::FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
                    matchType: W::FWP_MATCH_EQUAL,
                    conditionValue: W::FWP_CONDITION_VALUE0 {
                        r#type: W::FWP_UINT64,
                        Anonymous: W::FWP_CONDITION_VALUE0_0 { uint64: luid_ptr },
                    },
                },
            ].into_boxed_slice();
            permit.raw.numFilterConditions = permit._conditions.len() as u32;
            permit.raw.filterCondition = permit._conditions.as_mut_ptr();
            Ok(permit)
        }

        /// 在调用端遗漏进程归属检查的情况下也不可能从公共入口生成许可。
        /// 验证当前 TCP LISTEN 所属 PID 和 EXE，出错即拒绝构造。
        ///
        /// 重要：这是当前时刻的身份检查，不构成对后续端口重新绑定的永久担保。
        /// 未来安装方仍须将动态 WFP 会话寿命绑定到引擎进程，并在安装前再次核验。
        pub fn trusted_ephemeral_proxy_permit(
            name: &str,
            app_id: &[u8],
            endpoint: std::net::SocketAddr,
            expected_pid: u32,
            expected_executable: &Path,
            lease_nonce: &[u8],
        ) -> Result<Box<RawFilter>, String> {
            super::super::proxy_identity::verify_proxy_owner(
                endpoint, expected_pid, expected_executable,
            )?;
            Self::ephemeral_proxy_permit(name, app_id, endpoint, lease_nonce)
        }

        // Test-only constructor for the joint native pipe/BFE fixture. Reuse
        // the real permit and block builders, but never touch the product
        // provider, sublayer, persistent flags, or deterministic rule IDs.
        #[cfg(test)]
        pub fn isolated_lifecycle_filter(app_id: &[u8], endpoint: Option<std::net::SocketAddr>,
            nonce: &[u8]) -> Result<Box<RawFilter>, String>
        {
            let mut filter = match endpoint {
                Some(addr) => Self::ephemeral_proxy_permit("isolated pipe lease test", app_id, addr, nonce)?,
                None => Self::block("isolated pipe baseline test", app_id, Layer::V4),
            };
            // Keep the real deterministic permit key for independent readback.
            // Only the fixture baseline block uses a fresh BFE-assigned key.
            if endpoint.is_none() {
                filter.raw.filterKey = windows_sys::core::GUID::default();
            }
            filter.raw.flags = 0;
            filter.raw.providerKey = std::ptr::null_mut();
            filter.raw.providerData = W::FWP_BYTE_BLOB { size: 0, data: std::ptr::null_mut() };
            filter.raw.subLayerKey = W::FWPM_SUBLAYER_UNIVERSAL;
            Ok(filter)
        }

        pub fn as_ptr(&self) -> *const W::FWPM_FILTER0 {
            &self.raw
        }
    }

    /// 严格核验一条 WFP v2 scoped 规则：必须核对条件真实值，而不能仅凭
    /// filterKey / provider / “有 2 条条件”就宣称保护已生效。
    ///
    /// # Safety
    /// raw 必须是当前调用期间有效的 FWPM_FILTER0（内存来自 WFP 读回或
    /// RawFilter::scoped_v2_proxy 拥有的缓冲），且其中引用的指针有效。
    /// TUN 条件在真正的断线/重授权测试完成前一律不接受。
    unsafe fn scoped_native_matches(
        raw: *const W::FWPM_FILTER0,
        app_id: &[u8],
        spec: &super::super::egress_policy::ScopedBlock,
    ) -> bool {
        use super::super::egress_policy::{scoped_key, DenyTerm, IpFamily};
        if raw.is_null() || app_id.is_empty()
            || spec.filter_key != scoped_key(app_id, spec.family, spec.predicate)
        { return false; }
        let f = &*raw;
        let layer = match spec.family { IpFamily::V4 => Layer::V4, IpFamily::V6 => Layer::V6 };
        if from_win(f.filterKey) != spec.filter_key
            || f.providerKey.is_null()
            || from_win(*f.providerKey) != PROVIDER_GUID
            || from_win(f.subLayerKey) != SUBLAYER_GUID
            || from_win(f.layerKey) != layer.guid()
            || f.action.r#type != ACTION_BLOCK
            || from_win(f.action.Anonymous.filterType) != Guid::nil()
            || f.flags & FILTER_FLAG_PERSISTENT == 0
            || f.flags & W::FWPM_FILTER_FLAG_DISABLED != 0
            || f.flags & !(FILTER_FLAG_PERSISTENT | W::FWPM_FILTER_FLAG_DISABLED
                           | W::FWPM_FILTER_FLAG_INDEXED) != 0
            || read_blob(&f.providerData) != OWNER_MARKER
            // 当 HAS_PROVIDER_CONTEXT 未置位时，这个 union 的有效字段是
            // rawContext (u64)，不能把它按 16 字节的 providerContextKey 读取。
            || f.flags & W::FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT != 0
            || f.Anonymous.rawContext != 0
            || f.weight.r#type != FWP_TYPE_UINT64
            || f.weight.Anonymous.uint64.is_null()
            || *f.weight.Anonymous.uint64 != FILTER_WEIGHT_BLOCK
        { return false; }

        let expected_count = if spec.predicate == DenyTerm::Any { 1 } else { 2 };
        if f.numFilterConditions != expected_count || f.filterCondition.is_null() { return false; }
        let conditions = std::slice::from_raw_parts(f.filterCondition, expected_count as usize);
        let app = &conditions[0];
        if from_win(app.fieldKey) != CONDITION_ALE_APP_ID
            || app.matchType != MATCH_EQUAL
            || app.conditionValue.r#type != FWP_TYPE_BYTE_BLOB
            || app.conditionValue.Anonymous.byteBlob.is_null()
            || read_blob(&*app.conditionValue.Anonymous.byteBlob) != app_id
        { return false; }

        let Some(extra) = conditions.get(1) else {
            return spec.predicate == DenyTerm::Any;
        };
        if extra.matchType != W::FWP_MATCH_NOT_EQUAL { return false; }
        match spec.predicate {
            DenyTerm::Any => false,
            DenyTerm::RemoteAddressNot(ip) => {
                if from_win(extra.fieldKey) != from_win(W::FWPM_CONDITION_IP_REMOTE_ADDRESS) {
                    return false;
                }
                match (spec.family, ip) {
                    (IpFamily::V4, std::net::IpAddr::V4(ip)) =>
                        extra.conditionValue.r#type == W::FWP_UINT32
                            && extra.conditionValue.Anonymous.uint32 == u32::from_be_bytes(ip.octets()),
                    (IpFamily::V6, std::net::IpAddr::V6(ip)) =>
                        extra.conditionValue.r#type == W::FWP_BYTE_ARRAY16_TYPE
                            && !extra.conditionValue.Anonymous.byteArray16.is_null()
                            && (*extra.conditionValue.Anonymous.byteArray16).byteArray16 == ip.octets(),
                    _ => false,
                }
            }
            DenyTerm::RemotePortNot(port) =>
                from_win(extra.fieldKey) == from_win(W::FWPM_CONDITION_IP_REMOTE_PORT)
                    && extra.conditionValue.r#type == W::FWP_UINT16
                    && extra.conditionValue.Anonymous.uint16 == port,
            DenyTerm::ProtocolNotTcp =>
                from_win(extra.fieldKey) == from_win(W::FWPM_CONDITION_IP_PROTOCOL)
                    && extra.conditionValue.r#type == W::FWP_UINT8
                    && extra.conditionValue.Anonymous.uint8 == 6,
            DenyTerm::NextHopNot(_) | DenyTerm::MissingNextHop => false,
        }
    }

    /// 仅用于未来显式 v2 迁移的严格读回原语；不修改现有 v1 快照或状态。
    /// 返回的 id 是 BFE 实际分配的 id，字段不合格则整笔拒绝。
    pub fn scoped_v2_get_validated(
        engine: &WfpEngine,
        app_id: &[u8],
        spec: &super::super::egress_policy::ScopedBlock,
    ) -> Result<Option<u64>, WfpError> {
        let key = to_win(spec.filter_key);
        let mut raw: *mut W::FWPM_FILTER0 = std::ptr::null_mut();
        let rc = unsafe { W::FwpmFilterGetByKey0(engine.raw(), &key, &mut raw) };
        if rc != 0 {
            let err = classify(rc);
            return if err.is_absent() { Ok(None) } else { Err(err) };
        }
        let owned = unsafe { WfpBuf::from_raw(raw) };
        let Some(native) = owned.as_ref() else { return Err(WfpError::InvalidState); };
        let valid = unsafe { scoped_native_matches(native, app_id, spec) };
        if !valid || native.filterId == 0 {
            return Err(WfpError::InvalidState);
        }
        Ok(Some(native.filterId))
    }

    #[cfg(test)]
    mod scoped_v2_tests {
        use super::*;
        use super::super::super::egress_policy::{
            compile_scoped_blocks, scoped_key, DenyTerm, EgressPolicy, IpFamily, ScopedBlock,
        };

        fn app() -> Vec<u8> {
            "trader.exe".encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect()
        }

        #[test]
        fn dynamic_proxy_permit_is_nonpersistent_precise_and_unique_per_lease() {
            let app = app();
            let nonce = [0xA5u8; 16];
            for endpoint in ["127.0.0.1:17890", "[::1]:17890"] {
                let endpoint: std::net::SocketAddr = endpoint.parse().unwrap();
                let p = RawFilter::ephemeral_proxy_permit("Trader", &app, endpoint, &nonce).unwrap();
                assert_eq!(p.raw.flags, 0);
                assert!(p.raw.providerKey.is_null(), "动态许可不能进入 v1 持久规则 provider 枚举");
                assert_eq!(p.raw.providerData.size, 0);
                assert!(p.raw.providerData.data.is_null());
                assert_eq!(p.raw.action.r#type, W::FWP_ACTION_PERMIT);
                assert_eq!(p.raw.numFilterConditions, 4);
                assert_eq!(*p._weight, super::super::super::wfp::FILTER_WEIGHT_PERMIT);
                assert_eq!(p.raw.weight.r#type, FWP_TYPE_UINT64);
                assert_eq!(from_win(p.raw.subLayerKey), SUBLAYER_GUID);
                for c in p._conditions.iter() {
                    assert_eq!(c.matchType, W::FWP_MATCH_EQUAL);
                }
                assert_eq!(from_win(p._conditions[0].fieldKey), from_win(W::FWPM_CONDITION_ALE_APP_ID));
                assert_eq!(from_win(p._conditions[1].fieldKey), from_win(W::FWPM_CONDITION_IP_REMOTE_ADDRESS));
                assert_eq!(from_win(p._conditions[2].fieldKey), from_win(W::FWPM_CONDITION_IP_REMOTE_PORT));
                assert_eq!(from_win(p._conditions[3].fieldKey), from_win(W::FWPM_CONDITION_IP_PROTOCOL));
                assert_eq!(unsafe { p._conditions[2].conditionValue.Anonymous.uint16 }, endpoint.port());
                assert_eq!(unsafe { p._conditions[3].conditionValue.Anonymous.uint8 }, 6);
                match endpoint.ip() {
                    std::net::IpAddr::V4(ip) => {
                        assert_eq!(p._conditions[1].conditionValue.r#type, W::FWP_UINT32);
                        assert_eq!(unsafe { p._conditions[1].conditionValue.Anonymous.uint32 },
                            u32::from_be_bytes(ip.octets()));
                    }
                    std::net::IpAddr::V6(ip) => {
                        assert_eq!(p._conditions[1].conditionValue.r#type, W::FWP_BYTE_ARRAY16_TYPE);
                        assert_eq!(unsafe { (*p._conditions[1].conditionValue.Anonymous.byteArray16).byteArray16 },
                            ip.octets());
                    }
                }
                let mut alternate = nonce;
                alternate[0] ^= 1;
                let other = RawFilter::ephemeral_proxy_permit("Trader", &app, endpoint, &alternate).unwrap();
                assert_ne!(from_win(p.raw.filterKey), from_win(other.raw.filterKey), "旧会话不能共享新许可 key");
                assert_ne!(from_win(p.raw.filterKey),
                    from_win(RawFilter::block("Trader", &app, if endpoint.is_ipv4() { Layer::V4 } else { Layer::V6 }).raw.filterKey),
                    "动态许可不能覆盖 v1 持久 BLOCK filterKey");
            }
        }

        #[test]
        fn candidate_tun_permit_is_exact_nonpersistent_and_rejects_missing_luid() {
            let app = app();
            let nonce = [0x6Au8; 16];
            for layer in [Layer::V4, Layer::V6] {
                let permit = RawFilter::candidate_ephemeral_tun_permit(
                    "Trader", &app, layer, 424242, &nonce).unwrap();
                assert_eq!(permit.raw.flags, 0);
                assert!(permit.raw.providerKey.is_null(), "TUN 候选许可不得污染 v1 BLOCK provider");
                assert_eq!(permit.raw.providerData.size, 0);
                assert!(permit.raw.providerData.data.is_null());
                assert_eq!(permit.raw.action.r#type, W::FWP_ACTION_PERMIT);
                assert_eq!(*permit._weight, super::super::super::wfp::FILTER_WEIGHT_PERMIT);
                assert_eq!(permit._conditions.len(), 2);
                assert_eq!(from_win(permit._conditions[0].fieldKey), from_win(W::FWPM_CONDITION_ALE_APP_ID));
                assert_eq!(from_win(permit._conditions[1].fieldKey), from_win(W::FWPM_CONDITION_IP_NEXTHOP_INTERFACE));
                assert_eq!(permit._conditions[1].matchType, W::FWP_MATCH_EQUAL);
                assert_eq!(permit._conditions[1].conditionValue.r#type, W::FWP_UINT64);
                assert_eq!(unsafe { *permit._conditions[1].conditionValue.Anonymous.uint64 }, 424242);
                assert_ne!(from_win(permit.raw.filterKey), from_win(RawFilter::block("Trader", &app, layer).raw.filterKey));
                let mut other = nonce;
                other[15] ^= 1;
                let rotated = RawFilter::candidate_ephemeral_tun_permit(
                    "Trader", &app, layer, 424242, &other).unwrap();
                assert_ne!(from_win(permit.raw.filterKey), from_win(rotated.raw.filterKey));
                assert!(RawFilter::candidate_ephemeral_tun_permit(
                    "Trader", &app, layer, 0, &nonce).is_err());
                assert!(RawFilter::candidate_ephemeral_tun_permit(
                    "Trader", &app, layer, 424242, &[]).is_err());
            }
        }

        #[test]
        fn trusted_dynamic_permit_requires_the_real_listener_process() {
            let app = app();
            let nonce = [0xD3u8; 16];
            let exe = std::env::current_exe().unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap();
            assert!(RawFilter::trusted_ephemeral_proxy_permit(
                "Trader", &app, endpoint, std::process::id(), &exe, &nonce
            ).is_ok(), "正确端口、PID、可执行文件才能生成临时许可");
            assert!(RawFilter::trusted_ephemeral_proxy_permit(
                "Trader", &app, endpoint, std::process::id() + 1, &exe, &nonce
            ).is_err(), "错误 PID 不得生成许可");
            let wrong = std::env::temp_dir().join("not-the-proxy-engine.exe");
            assert!(RawFilter::trusted_ephemeral_proxy_permit(
                "Trader", &app, endpoint, std::process::id(), &wrong, &nonce
            ).is_err(), "错误 EXE 不得生成许可");
            drop(listener);
            assert!(RawFilter::trusted_ephemeral_proxy_permit(
                "Trader", &app, endpoint, std::process::id(), &exe, &nonce
            ).is_err(), "端口释放后不能复用已失效的可信验证");
        }

        #[test]
        fn dynamic_proxy_permit_rejects_unspecified_untrusted_destinations() {
            let app = app();
            let nonce = [0xBBu8; 16];
            for bad in ["0.0.0.0:17890", "127.0.0.2:17890",
                        "192.168.1.5:17890", "127.0.0.1:0",
                        "[::ffff:127.0.0.1]:17890"] {
                let address: std::net::SocketAddr = bad.parse().unwrap();
                assert!(RawFilter::ephemeral_proxy_permit("Trader", &app, address, &nonce).is_err(), "{bad}");
            }
            assert!(RawFilter::ephemeral_proxy_permit("Trader", &app, "127.0.0.1:17890".parse().unwrap(), &[]).is_err());
            assert!(RawFilter::ephemeral_proxy_permit("Trader", &[], "127.0.0.1:17890".parse().unwrap(), &nonce).is_err());
        }

        #[test]
        fn v1_filter_projection_reads_only_the_live_union_member() {
            let app = app();
            let raw = RawFilter::block("Trader", &app, Layer::V4);
            let projected = unsafe { filter_raw_from(raw.as_ptr()) };
            assert_eq!(projected.provider_context_key, Guid::nil());
            assert!(super::super::super::wfp::recognize(&projected, &app, Layer::V4).ok(),
                "修正 v1 union 读取不能破坏旧版规则识别");
        }

        #[test]
        fn native_candidate_fields_are_owned_and_match_scoped_v2_ids() {
            let app = app();
            let candidates = compile_scoped_blocks(
                EgressPolicy::local_proxy("127.0.0.1:17890").unwrap(), &app).unwrap();
            assert_eq!(candidates.len(), 4);
            for candidate in candidates {
                let raw = RawFilter::scoped_v2_proxy("Trader", &app, &candidate).unwrap();
                let projection = unsafe { filter_raw_from(raw.as_ptr()) };
                assert_eq!(projection.filter_key, candidate.filter_key);
                assert_eq!(projection.provider_key, PROVIDER_GUID);
                assert_eq!(projection.flags & FILTER_FLAG_PERSISTENT, FILTER_FLAG_PERSISTENT);
                let num = if candidate.predicate == DenyTerm::Any { 1 } else { 2 };
                assert_eq!(projection.num_conditions, num);
                assert_eq!(projection.conditions[0].field_key, CONDITION_ALE_APP_ID);
                if num == 2 {
                    assert_eq!(projection.conditions[1].match_type, W::FWP_MATCH_NOT_EQUAL);
                }
            }
        }

        #[test]
        fn strict_native_readback_rejects_tampered_conditions_or_flags() {
            let app = app();
            for endpoint in ["127.0.0.1:17890", "[::1]:17890"] {
                let rules = compile_scoped_blocks(EgressPolicy::local_proxy(endpoint).unwrap(), &app).unwrap();
                for candidate in rules {
                    let mut raw = RawFilter::scoped_v2_proxy("Trader", &app, &candidate).unwrap();
                    assert!(unsafe { scoped_native_matches(raw.as_ptr(), &app, &candidate) },
                        "v2 预期规则未被严格识别 endpoint={endpoint}, candidate={candidate:?}, actual={:?}",
                        unsafe { filter_raw_from(raw.as_ptr()) });
                    // Wrong app identity and stale endpoint can never be certified.
                    let another_app = "other.exe".encode_utf16().chain(Some(0))
                        .flat_map(u16::to_le_bytes).collect::<Vec<_>>();
                    assert!(!unsafe { scoped_native_matches(raw.as_ptr(), &another_app, &candidate) });

                    raw.raw.flags |= W::FWPM_FILTER_FLAG_DISABLED;
                    assert!(!unsafe { scoped_native_matches(raw.as_ptr(), &app, &candidate) });
                    raw.raw.flags &= !W::FWPM_FILTER_FLAG_DISABLED;
                    raw.raw.action.r#type = W::FWP_ACTION_PERMIT;
                    assert!(!unsafe { scoped_native_matches(raw.as_ptr(), &app, &candidate) });
                    raw.raw.action.r#type = ACTION_BLOCK;
                    if candidate.predicate == DenyTerm::Any { continue; }
                    raw._conditions[1].matchType = W::FWP_MATCH_EQUAL;
                    assert!(!unsafe { scoped_native_matches(raw.as_ptr(), &app, &candidate) });
                    raw._conditions[1].matchType = W::FWP_MATCH_NOT_EQUAL;
                    assert!(unsafe { scoped_native_matches(raw.as_ptr(), &app, &candidate) });

                    if candidate.predicate == DenyTerm::RemotePortNot(17890) {
                        raw._conditions[1].conditionValue.Anonymous.uint16 = 17891;
                        assert!(!unsafe { scoped_native_matches(raw.as_ptr(), &app, &candidate) });
                    }
                }
            }
        }

        #[test]
        fn invalid_or_tun_predicates_fail_before_any_native_wfp_write() {
            let app = app();
            let bad = ScopedBlock {
                family: IpFamily::V4, predicate: DenyTerm::NextHopNot(42),
                filter_key: scoped_key(&app, IpFamily::V4, DenyTerm::NextHopNot(42)),
            };
            assert!(RawFilter::scoped_v2_proxy("Trader", &app, &bad).is_err());
            let altered = ScopedBlock { filter_key: Guid::nil(), ..bad };
            assert!(RawFilter::scoped_v2_proxy("Trader", &app, &altered).is_err());
        }
    }

    /// 持有 Windows 内核进程对象 HANDLE，避免仅靠 PID 轮询造成 PID 复用误判。
    /// 它只负责监听引擎存活，并不赋予任何 WFP 放行权限。
    struct WatchedEngineProcess(HANDLE);

    impl WatchedEngineProcess {
        fn open(pid: u32) -> Result<Self, String> {
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };
            if pid == 0 { return Err("不能监控 PID=0 的引擎进程".into()); }
            // SYNCHRONIZE 标准权限位（winnt.h），用于 WaitForSingleObject。
            const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
            let handle = unsafe {
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS, 0, pid)
            };
            if handle.is_null() {
                return Err("无法打开受监督引擎进程句柄，拒绝临时放行".into());
            }
            let watched = Self(handle);
            watched.require_alive()?;
            Ok(watched)
        }

        fn wait(&self, millis: u32) -> u32 {
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            unsafe { WaitForSingleObject(self.0, millis) }
        }

        fn require_alive(&self) -> Result<(), String> {
            use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
            if self.wait(0) != WAIT_TIMEOUT {
                return Err("可信引擎已经退出或存活状态不可读，拒绝 WFP 临时放行".into());
            }
            Ok(())
        }
    }

    impl Drop for WatchedEngineProcess {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0); }
                self.0 = std::ptr::null_mut();
            }
        }
    }

    /// 临时代理许可的 RAII 句柄。**不写持久规则**，Drop 必然关闭动态会话。
    /// 未来的独立监督进程必须持有它，并在引擎退出或监听身份变化时丢弃。
    /// 目前不接入任何正式连接入口，不能把它解释为已上线的 Kill Switch。
    pub struct DynamicProxyLease {
        engine: WfpEngine,
        endpoint: std::net::SocketAddr,
        owner_pid: u32,
        watched_process: WatchedEngineProcess,
        // 在独立提权 helper 中同时监控发起连接的主程序；
        // 如果主程序已退出，不能继续仅凭 sing-box 存活保留 WFP 许可。
        controller_process: WatchedEngineProcess,
        permitted_filters: Vec<u64>,
    }

    /// 动态许可是提权操作：不能信任父进程或请求文件直接提交的 APP_ID。
    /// 重新走正式交易名单的路径、reparse、WFP AppId 校验，并拒绝重复身份。
    /// 必须在打开 WFP 动态会话和安装任何 PERMIT 之前完整执行。
    fn validate_lease_identities(
        ids: &[super::super::identity::ProgramIdentity],
    ) -> Result<(), String> {
        use super::super::identity::{resolve_entry, MAX_PROGRAMS};
        if ids.is_empty() || ids.len() > MAX_PROGRAMS {
            return Err(format!("许可名单必须包含 1 至 {MAX_PROGRAMS} 条有效程序身份"));
        }
        let env = SystemIdentityEnv::new();
        let mut seen = std::collections::HashSet::new();
        for identity in ids {
            if identity.name.trim().is_empty() {
                return Err("交易程序名称为空，拒绝创建许可".into());
            }
            let path = identity.path.to_str().ok_or_else(|| {
                "交易程序路径包含无法表达的 Unicode，拒绝创建许可".to_string()
            })?;
            let expected = resolve_entry(&identity.name, Some(path), &env)
                .map_err(|e| format!("交易程序「{}」身份复核失败：{}", identity.name, e.reason()))?;
            if expected.app_id != identity.app_id
                || expected.device_path != identity.device_path
            {
                return Err(format!(
                    "交易程序「{}」路径、设备身份与传入 APP_ID 不一致，拒绝动态许可",
                    identity.name
                ));
            }
            if !seen.insert(expected.app_id) {
                return Err("交易程序 APP_ID 在许可名单中重复，拒绝生成歧义规则".into());
            }
        }
        Ok(())
    }

    // A3b-DENY: the production machine-wide history and writer fence do not
    // exist yet. Even the first controller might follow an older live writer.
    // No caller-supplied proof, environment, test switch, empty enumeration,
    // process exit, or acquired mutex can turn this boundary into success.
    pub(crate) const UNKNOWN_MACHINE_HISTORY_REASON: &str =
        "全机旧 WFP 许可历史与迟到写入屏障尚无法可信证明，暂不发放实验动态许可";

    fn require_verified_machine_history() -> Result<(), String> {
        Err(UNKNOWN_MACHINE_HISTORY_REASON.into())
    }

    impl DynamicProxyLease {
        /// 唯一允许构造临时代理许可的内部入口，拒绝在持久阻断缺失时开放通道。
        pub fn acquire(
            ids: &[super::super::identity::ProgramIdentity],
            endpoint: std::net::SocketAddr,
            owner_pid: u32,
            controller_pid: u32,
            executable: &Path,
            lease_nonce: &[u8],
        ) -> Result<Self, String> {
            if ids.is_empty() || lease_nonce.len() < 16 {
                return Err("保护名单为空或许可会话 nonce 不足，拒绝临时放行".into());
            }
            validate_lease_identities(ids)?;
            // 与现有 install/sync/remove 使用完全相同的跨进程互斥，
            // 保证检查持久 BLOCK → 安装许可之间不会被另一笔 Guard 变更打断。
            // 仅保护创建时的原子前置检查；lease 运行期间不能长期占有互斥。
            let lock_name = format!(
                "{}{}",
                super::super::GUARD_MUTEX_PREFIX,
                super::super::wfp::PROVIDER_KEY.replace('-', "").to_uppercase(),
            );
            let _guard_lock = NamedMutex::acquire(&lock_name)?;
            let watched_process = WatchedEngineProcess::open(owner_pid)?;
            let controller_process = WatchedEngineProcess::open(controller_pid)?;
            // 活着的 PID 不等于可信主程序：提权侧独立确认它就是当前
            // SpiderVPN exe，不能用一个任意长寿进程冒充控制者。
            let controller_exe = std::env::current_exe()
                .map_err(|e| format!("无法确认 WFP helper 自身程序路径：{e}"))?;
            unsafe {
                super::super::proxy_identity::verify_live_process_handle(
                    controller_process.0, controller_pid, &controller_exe,
                )?;
                super::super::proxy_identity::verify_proxy_owner_on_handle(
                    endpoint, owner_pid, executable, watched_process.0,
                )?;
            }
            watched_process.require_alive()?;
            controller_process.require_alive()?;
            // Enforce at the actual elevated acquisition entry, before even
            // opening the writable dynamic session. Keep the candidate
            // BLOCK validation, permit builder and supervision below intact
            // for a separately authorized future trustworthy history gate.
            require_verified_machine_history()?;
            let engine = WfpEngine::open_dynamic().map_err(|e| e.to_string())?;
            let provider = provider_get(&engine, PROVIDER_GUID).map_err(|e| e.to_string())?;
            let sublayer = sublayer_get(&engine, SUBLAYER_GUID).map_err(|e| e.to_string())?;
            if !provider.as_ref().is_some_and(ProviderDefinition::is_ours)
                || !sublayer.as_ref().is_some_and(SubLayerDefinition::is_ours)
            {
                return Err("持久 WFP 保护基础设施缺失或身份不可信，不创建任何动态许可".into());
            }
            // snapshot 使用相同的 provider 枚举及 recognize 逻辑。额外规则、
            // 重复条目、禁用的 BLOCK 都必须拒绝，不能“有一个就算安全”。
            let existing = WindowsWfp::enumerate_ours(&engine).map_err(|e| e.to_string())?;
            let mut wanted = std::collections::HashSet::new();
            for id in ids {
                if id.app_id.is_empty() { return Err("保护名单 APP_ID 为空".into()); }
                for layer in Layer::ALL {
                    let key = super::super::wfp::filter_key(&id.app_id, layer, false);
                    if !wanted.insert(key) {
                        return Err("交易保护名单含重复 APP_ID，拒绝不确定的持久规则集".into());
                    }
                    let matching: Vec<_> = existing.iter().filter(|f| f.filter_key == key).collect();
                    if matching.len() != 1
                        || !super::super::wfp::recognize(matching[0], &id.app_id, layer).ok()
                    {
                        return Err(format!("{} 的 {:?} 持久 BLOCK 不完整，拒绝动态许可", id.name, layer));
                    }
                }
            }
            if existing.len() != wanted.len() {
                return Err("WFP provider 存在未预期或重复过滤器，拒绝临时放行".into());
            }
            // owner 检查可能与 BFE 枚举并发；真正写入之前再次核验。
            unsafe { super::super::proxy_identity::verify_proxy_owner_on_handle(
                endpoint, owner_pid, executable, watched_process.0,
            )?; }
            let mut permits = Vec::with_capacity(ids.len());
            for id in ids {
                let raw = RawFilter::trusted_ephemeral_proxy_permit(
                    &id.name, &id.app_id, endpoint, owner_pid, executable, lease_nonce,
                )?;
                // 这里仍然只能写临时许可；RawFilter 内部使用 NULL providerKey，
                // 不会在后续持久 Guard snapshot/sync 中被当作多余规则。
                let installed = filter_add(&engine, &raw).map_err(|e| e.to_string())?;
                if installed == 0 {
                    return Err("动态 WFP 许可未返回有效 filterId".into());
                }
                permits.push(installed);
            }
            // 安装过程也可能跨越代理退出或端口重新绑定；失败直接 Drop
            // 动态 engine，BFE 会移除已经装上的所有 permits。
            unsafe { super::super::proxy_identity::verify_proxy_owner_on_handle(
                endpoint, owner_pid, executable, watched_process.0,
            )?; }
            watched_process.require_alive()?;
            controller_process.require_alive()?;
            Ok(Self {
                engine, endpoint, owner_pid, watched_process, controller_process,
                permitted_filters: permits,
            })
        }

        /// 每次接到存活检查都必须**消耗**旧 lease。失败时旧会话立即 Drop，
        /// 防止监控调用方忘记主动撤销。不能代替实时进程退出通知机制。
        pub fn revalidate(self, executable: &Path) -> Result<Self, String> {
            self.controller_process.require_alive()?;
            self.watched_process.require_alive()?;
            unsafe { super::super::proxy_identity::verify_proxy_owner_on_handle(
                self.endpoint, self.owner_pid, executable, self.watched_process.0,
            )?; }
            self.watched_process.require_alive()?;
            self.controller_process.require_alive()?;
            Ok(self)
        }

        /// 只供未来独立的提升权限 helper 线程调用，不能在 UI/IPC 主线程运行。
        /// 引擎退出立即关闭动态许可；每 200ms 复查一次代理监听进程身份。
        /// 临时许可进程本身崩溃时，由 WFP 动态会话的 RPC rundown 兜底。
        pub fn supervise_until_exit(mut self, executable: &Path) -> Result<(), String> {
            use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows_sys::Win32::System::Threading::WaitForMultipleObjects;
            loop {
                // 不要单靠 PID 查询：已打开的 Windows HANDLE 精确绑定进程对象，
                // 也不受系统复用 PID 影响。两个对象任何一个退出都撤销会话。
                let handles = [self.watched_process.0, self.controller_process.0];
                let result = unsafe {
                    WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, 200)
                };
                match result {
                    WAIT_OBJECT_0 => {
                        return self.close().map_err(|e| e.to_string());
                    }
                    n if n == WAIT_OBJECT_0 + 1 => {
                        // 控制程序退出：即使引擎仍活着，也不保留交易许可。
                        return self.close().map_err(|e| e.to_string());
                    }
                    WAIT_TIMEOUT => {
                        // 端口被接管、控制程序无法确认等任一异常都消费并 Drop 租约。
                        self = self.revalidate(executable)?;
                    }
                    _ => return Err("受监督进程等待状态异常，动态许可已撤销".into()),
                }
            }
        }

        /// 显式关闭，便于未来 helper 在退出前把关闭错误反馈给控制进程。
        pub fn close(self) -> Result<(), WfpError> {
            let Self { engine, .. } = self;
            engine.close_checked()
        }

        pub fn count(&self) -> usize { self.permitted_filters.len() }
    }

    #[cfg(test)]
    mod dynamic_proxy_lease_tests {
        use super::*;

        #[test]
        fn actual_acquire_denies_unknown_machine_history_with_live_listener() {
            use super::super::super::identity::resolve_entry;
            use std::io::Read;
            use std::process::{Child, Command, Stdio};
            const ROLE: &str = "SPIDERVPN_DENY_ACQUIRE_CONTROLLER_FIXTURE";
            if std::env::var(ROLE).as_deref() == Ok("1") {
                // Test process synchronization only; no production gate reads it.
                let mut byte = [0u8; 1];
                assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
                return;
            }
            struct ChildGuard(Child);
            impl Drop for ChildGuard {
                fn drop(&mut self) {
                    if self.0.try_wait().ok().flatten().is_none() {
                        let _ = self.0.kill();
                        let _ = self.0.wait();
                    }
                }
            }
            let exe = std::env::current_exe().unwrap();
            let id = resolve_entry("Trader", exe.to_str(), &SystemIdentityEnv::new()).unwrap();
            let mut controller = ChildGuard(Command::new(&exe)
                .args(["--exact", "guard::wfp_win::imp::dynamic_proxy_lease_tests::actual_acquire_denies_unknown_machine_history_with_live_listener", "--nocapture"])
                .env(ROLE, "1").stdin(Stdio::piped()).spawn().unwrap());
            let owner_pid = std::process::id();
            let controller_pid = controller.0.id();
            assert_ne!(owner_pid, controller_pid);
            let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let v6 = std::net::TcpListener::bind("[::1]:0").unwrap();
            for (index, listener) in [v4, v6].iter().enumerate() {
                let endpoint = listener.local_addr().unwrap();
                super::super::super::proxy_identity::verify_proxy_owner(endpoint, owner_pid, &exe).unwrap();
                assert!(controller.0.try_wait().unwrap().is_none());
                let nonce = [index as u8 + 1; 16];
                let result = DynamicProxyLease::acquire(
                    &[id.clone()], endpoint, owner_pid, controller_pid, &exe, &nonce,
                );
                let reason = match result {
                    Err(reason) => reason,
                    Ok(lease) => { let _ = lease.close(); panic!("unknown history granted a real lease"); }
                };
                assert_eq!(reason, UNKNOWN_MACHINE_HISTORY_REASON);
                // Input-negative controls still fail earlier, not by silently
                // replacing the original identity/nonce validation.
                let mut forged = id.clone();
                forged.app_id[0] ^= 1;
                let err = DynamicProxyLease::acquire(
                    &[forged], endpoint, owner_pid, controller_pid, &exe, &nonce,
                ).err().expect("forged APP_ID refused");
                assert_ne!(err, UNKNOWN_MACHINE_HISTORY_REASON);
                let err = DynamicProxyLease::acquire(
                    &[id.clone()], endpoint, owner_pid, 0, &exe, &nonce,
                ).err().expect("missing controller refused");
                assert_ne!(err, UNKNOWN_MACHINE_HISTORY_REASON);
                println!("A3B_DENY_ACQUIRE endpoint={endpoint} owner_pid={owner_pid} controller_pid={controller_pid} live_listener_verified=true history_refused=true earlier_negative_controls=true");
            }
            drop(controller.0.stdin.take());
            assert!(controller.0.wait().unwrap().success());
        }

        #[test]
        fn old_permit_absence_requires_exact_native_not_found() {
            use windows_sys::Win32::Foundation::{FWP_E_FILTER_NOT_FOUND, ERROR_ACCESS_DENIED, ERROR_NOT_FOUND};
            assert_eq!(permit_key_absent_status(FWP_E_FILTER_NOT_FOUND as u32, false), Ok(true));
            assert_eq!(permit_key_absent_status(0, true), Ok(false));
            assert!(permit_key_absent_status(0, false).is_err());
            assert!(permit_key_absent_status(FWP_E_FILTER_NOT_FOUND as u32, true).is_err());
            assert!(permit_key_absent_status(ERROR_ACCESS_DENIED, false).is_err());
            assert!(permit_key_absent_status(ERROR_NOT_FOUND, false).is_err());
            assert!(old_dynamic_permits_absent(&[]).is_err());
            assert!(old_dynamic_permits_absent(&[Guid::nil()]).is_err());
            let addr = "127.0.0.1:12345".parse().unwrap();
            let key = dynamic_permit_key(&[1, 0], addr, &[1; 16]).unwrap();
            assert_ne!(key, dynamic_permit_key(&[2, 0], addr, &[1; 16]).unwrap());
            assert_ne!(key, dynamic_permit_key(&[1, 0], "127.0.0.1:12346".parse().unwrap(), &[1; 16]).unwrap());
            assert_ne!(key, dynamic_permit_key(&[1, 0], addr, &[2; 16]).unwrap());
            assert!(old_dynamic_permits_absent(&[key, key]).is_err());
        }

        #[test]
        fn lease_rejects_forged_appid_and_device_path_before_bfe_writes() {
            use super::super::super::identity::resolve_entry;
            let exe = std::env::current_exe().unwrap();
            let good = resolve_entry("Trader", exe.to_str(), &SystemIdentityEnv::new())
                .expect("用于测试的可执行文件必须可被 Windows 识别");
            assert!(validate_lease_identities(&[good.clone()]).is_ok());

            let mut forged_app = good.clone();
            forged_app.app_id[0] ^= 1;
            assert!(validate_lease_identities(&[forged_app]).is_err());

            let mut forged_device = good.clone();
            forged_device.device_path.push_str("-other");
            assert!(validate_lease_identities(&[forged_device]).is_err());

            assert!(validate_lease_identities(&[good.clone(), good]).is_err(),
                "重复程序身份不能导致重复许可");
        }

        #[test]
        fn lease_rejects_empty_invalid_and_oversized_identities() {
            use super::super::super::identity::{ProgramIdentity, MAX_PROGRAMS};
            let exe = std::env::current_exe().unwrap();
            let identity = ProgramIdentity {
                name: String::new(),
                path: exe,
                app_id: vec![1, 0],
                device_path: String::new(),
            };
            assert!(validate_lease_identities(&[]).is_err());
            assert!(validate_lease_identities(&[identity.clone()]).is_err());
            assert!(validate_lease_identities(&vec![identity; MAX_PROGRAMS + 1]).is_err());
        }

        #[test]
        fn lease_rejects_missing_controller_pid_before_creating_dynamic_rules() {
            let exe = std::env::current_exe().unwrap();
            let id = super::super::super::identity::resolve_entry(
                "Trader", exe.to_str(), &SystemIdentityEnv::new(),
            ).expect("test exe identity");
            assert!(DynamicProxyLease::acquire(
                &[id], "127.0.0.1:17890".parse().unwrap(),
                std::process::id(), 0, &exe, &[1u8; 16],
            ).is_err(), "缺少主程序 PID 不能开启长期动态放行");
        }

        #[test]
        fn supervised_process_handle_rejects_invalid_pid_and_accepts_current() {
            assert!(WatchedEngineProcess::open(0).is_err());
            let process = WatchedEngineProcess::open(std::process::id()).unwrap();
            assert!(process.require_alive().is_ok());
        }

        #[test]
        fn process_handle_detects_actual_child_exit_without_pid_reuse_guessing() {
            use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
            let mut child = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 1"])
                .spawn().expect("Windows PowerShell subprocess");
            let watched = WatchedEngineProcess::open(child.id())
                .expect("must capture actual child process object before exit");
            assert!(watched.require_alive().is_ok());
            let result = child.wait().expect("child must exit");
            assert!(result.success());
            assert_eq!(watched.wait(0), WAIT_OBJECT_0);
            assert!(watched.require_alive().is_err());
        }

        #[test]
        fn lease_rejects_missing_ids_without_modifying_bfe() {
            let exe = std::env::current_exe().unwrap();
            assert!(DynamicProxyLease::acquire(
                &[], "127.0.0.1:17890".parse().unwrap(),
                std::process::id(), std::process::id(), &exe, &[1u8; 16],
            ).is_err());
        }

        #[test]
        fn lease_rejects_short_nonce_before_touching_bfe() {
            let exe = std::env::current_exe().unwrap();
            let one = super::super::super::identity::ProgramIdentity {
                name: "Trader".into(), path: exe.clone(),
                app_id: vec![1u8, 0], device_path: String::new(),
            };
            assert!(DynamicProxyLease::acquire(
                &[one], "127.0.0.1:17890".parse().unwrap(),
                std::process::id(), std::process::id(), &exe, &[2u8; 8],
            ).is_err());
        }
    }

    // -----------------------------------------------------------------------
    // 反解（原生结构 → 结构化事实）
    // -----------------------------------------------------------------------

    /// # Safety
    /// `raw` 必须指向一条有效的 `FWPM_FILTER0`（由 `fwpuclnt` 分配，调用期间有效）。
    pub unsafe fn filter_raw_from(raw: *const W::FWPM_FILTER0) -> FilterRaw {
        let f = &*raw;
        let provider_key = if f.providerKey.is_null() { Guid::nil() } else { from_win(*f.providerKey) };
        let conditions: Vec<RawCondition> = (0..f.numFilterConditions)
            .filter(|_| !f.filterCondition.is_null())
            .map(|i| {
                let c = &*f.filterCondition.add(i as usize);
                let (value_type, blob) = condition_value(&c.conditionValue);
                RawCondition {
                    field_key: from_win(c.fieldKey),
                    match_type: c.matchType,
                    value_type,
                    blob,
                }
            })
            .collect();
        let weight = if f.weight.r#type == FWP_TYPE_UINT64 {
            let p = f.weight.Anonymous.uint64;
            if p.is_null() {
                None
            } else {
                Some(*p)
            }
        } else {
            None
        };
        FilterRaw {
            filter_key: from_win(f.filterKey),
            filter_id: f.filterId,
            provider_key,
            sublayer_key: from_win(f.subLayerKey),
            layer: from_win(f.layerKey),
            action_type: f.action.r#type,
            action_filter_type: from_win(f.action.Anonymous.filterType),
            flags: f.flags,
            provider_data: read_blob(&f.providerData),
            num_conditions: f.numFilterConditions,
            conditions,
            weight,
            // FWPM_FILTER0 的匿名 union：无 HAS_PROVIDER_CONTEXT 时只能读
            // rawContext(u64)，不得无条件按 providerContextKey(GUID/16B) 读取。
            // 旧规则若 rawContext 非 0，转成非零 Guid 让原识别判据拒绝它。
            provider_context_key: if f.flags & W::FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT != 0 {
                from_win(f.Anonymous.providerContextKey)
            } else {
                Guid::from_u128(f.Anonymous.rawContext as u128)
            },
        }
    }

    /// 读一个条件值（目前只关心 byte blob，其它类型原样带 `type` 回去）。
    unsafe fn condition_value(v: &W::FWP_CONDITION_VALUE0) -> (i32, Option<Vec<u8>>) {
        if v.r#type == FWP_TYPE_BYTE_BLOB {
            let p = v.Anonymous.byteBlob;
            if p.is_null() {
                (v.r#type, None)
            } else {
                (v.r#type, Some(read_blob(&*p)))
            }
        } else {
            (v.r#type, None)
        }
    }

    /// # Safety
    /// `raw` 必须指向一条有效的 `FWPM_PROVIDER0`。
    pub unsafe fn provider_definition_from(raw: *const W::FWPM_PROVIDER0) -> ProviderDefinition {
        let p = &*raw;
        ProviderDefinition {
            key: from_win(p.providerKey),
            display_name: read_pwstr(p.displayData.name).unwrap_or_default(),
            flags: p.flags,
            marker: read_blob(&p.providerData),
            service_name: read_pwstr(p.serviceName),
        }
    }

    /// # Safety
    /// `raw` 必须指向一条有效的 `FWPM_SUBLAYER0`。
    pub unsafe fn sublayer_definition_from(raw: *const W::FWPM_SUBLAYER0) -> SubLayerDefinition {
        let s = &*raw;
        SubLayerDefinition {
            key: from_win(s.subLayerKey),
            display_name: read_pwstr(s.displayData.name).unwrap_or_default(),
            flags: s.flags,
            provider_key: if s.providerKey.is_null() { None } else { Some(from_win(*s.providerKey)) },
            marker: read_blob(&s.providerData),
            weight: s.weight,
        }
    }

    // -----------------------------------------------------------------------
    // 增 / 删 / 读（薄封装；本阶段不被调用）
    // -----------------------------------------------------------------------

    pub fn provider_add(engine: &WfpEngine, provider: &RawProvider) -> Result<(), WfpError> {
        let rc = unsafe {
            W::FwpmProviderAdd0(engine.raw(), provider.as_ptr(), std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(classify(rc));
        }
        Ok(())
    }

    pub fn provider_get(
        engine: &WfpEngine,
        key: Guid,
    ) -> Result<Option<ProviderDefinition>, WfpError> {
        let win_key = to_win(key);
        let mut out: *mut W::FWPM_PROVIDER0 = std::ptr::null_mut();
        let rc = unsafe { W::FwpmProviderGetByKey0(engine.raw(), &win_key, &mut out) };
        if rc != 0 {
            let err = classify(rc);
            // 「不存在」是正常结局，不是错误（含泛化的 FWP_E_NOT_FOUND）
            return if err.is_absent() { Ok(None) } else { Err(err) };
        }
        let buf = unsafe { WfpBuf::from_raw(out) };
        match buf.as_ref() {
            Some(raw) => Ok(Some(unsafe { provider_definition_from(raw as *const _) })),
            None => Ok(None),
        }
    }

    pub fn provider_delete(engine: &WfpEngine, key: Guid) -> Result<(), WfpError> {
        let win_key = to_win(key);
        let rc = unsafe { W::FwpmProviderDeleteByKey0(engine.raw(), &win_key) };
        if rc != 0 {
            return Err(classify(rc));
        }
        Ok(())
    }

    pub fn sublayer_add(engine: &WfpEngine, sublayer: &RawSubLayer) -> Result<(), WfpError> {
        let rc = unsafe {
            W::FwpmSubLayerAdd0(engine.raw(), sublayer.as_ptr(), std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(classify(rc));
        }
        Ok(())
    }

    pub fn sublayer_get(
        engine: &WfpEngine,
        key: Guid,
    ) -> Result<Option<SubLayerDefinition>, WfpError> {
        let win_key = to_win(key);
        let mut out: *mut W::FWPM_SUBLAYER0 = std::ptr::null_mut();
        let rc = unsafe { W::FwpmSubLayerGetByKey0(engine.raw(), &win_key, &mut out) };
        if rc != 0 {
            let err = classify(rc);
            return if err.is_absent() { Ok(None) } else { Err(err) };
        }
        let buf = unsafe { WfpBuf::from_raw(out) };
        match buf.as_ref() {
            Some(raw) => Ok(Some(unsafe { sublayer_definition_from(raw as *const _) })),
            None => Ok(None),
        }
    }

    pub fn sublayer_delete(engine: &WfpEngine, key: Guid) -> Result<(), WfpError> {
        let win_key = to_win(key);
        let rc = unsafe { W::FwpmSubLayerDeleteByKey0(engine.raw(), &win_key) };
        if rc != 0 {
            return Err(classify(rc));
        }
        Ok(())
    }

    pub fn filter_add(engine: &WfpEngine, filter: &RawFilter) -> Result<u64, WfpError> {
        let mut id: u64 = 0;
        let rc = unsafe {
            W::FwpmFilterAdd0(engine.raw(), filter.as_ptr(), std::ptr::null_mut(), &mut id)
        };
        if rc != 0 {
            return Err(classify(rc));
        }
        Ok(id)
    }

    pub fn filter_get_by_id(engine: &WfpEngine, id: u64) -> Result<Option<FilterRaw>, WfpError> {
        let mut out: *mut W::FWPM_FILTER0 = std::ptr::null_mut();
        let rc = unsafe { W::FwpmFilterGetById0(engine.raw(), id, &mut out) };
        if rc != 0 {
            let err = classify(rc);
            return if err.is_absent() { Ok(None) } else { Err(err) };
        }
        let buf = unsafe { WfpBuf::from_raw(out) };
        match buf.as_ref() {
            Some(raw) => Ok(Some(unsafe { filter_raw_from(raw as *const _) })),
            None => Ok(None),
        }
    }

    pub fn filter_delete_by_id(engine: &WfpEngine, id: u64) -> Result<(), WfpError> {
        let rc = unsafe { W::FwpmFilterDeleteById0(engine.raw(), id) };
        if rc != 0 {
            return Err(classify(rc));
        }
        Ok(())
    }

    /// 枚举某 provider 在**某一个层**上的全部 filter。
    ///
    /// 参数口径与旧版的 `EnumerateFilters` 对齐：
    /// `enumType = FWP_FILTER_ENUM_FULLY_CONTAINED(0)`、
    /// `flags = INCLUDE_BOOTTIME(0x8) | INCLUDE_DISABLED(0x10)`（禁用/开机规则也要看得见，
    /// 否则「有规则但被禁用」会被误判成「没有规则」）。
    ///
    /// 注意：非提权会话下这个调用会被拒（实测返回 `FWP_E_NEVER_MATCH` 或 `ACCESS_DENIED`），
    /// 所以「普通权限每次快照去 WFP 看一眼」在 OS 层面就不成立（架构 §1.4）。
    pub fn filter_enumerate(
        engine: &WfpEngine,
        provider: Guid,
        layer: Layer,
    ) -> Result<Vec<FilterRaw>, WfpError> {
        const FWP_FILTER_ENUM_FULLY_CONTAINED: i32 = 0;
        const FLAG_INCLUDE_BOOTTIME: u32 = 0x8;
        const FLAG_INCLUDE_DISABLED: u32 = 0x10;

        let mut provider_key = to_win(provider);
        let mut template: W::FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.providerKey = &mut provider_key;
        template.layerKey = to_win(layer.guid());
        template.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        template.flags = FLAG_INCLUDE_BOOTTIME | FLAG_INCLUDE_DISABLED;
        template.actionMask = 0xFFFF_FFFF;

        let mut handle: HANDLE = std::ptr::null_mut();
        let rc = unsafe { W::FwpmFilterCreateEnumHandle0(engine.raw(), &template, &mut handle) };
        if rc != 0 {
            return Err(classify(rc));
        }
        let enumerator = unsafe {
            EnumHandle::new(engine.raw(), handle, W::FwpmFilterDestroyEnumHandle0)
        };

        let mut out: Vec<FilterRaw> = Vec::new();
        loop {
            let mut entries: *mut *mut W::FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned: u32 = 0;
            let rc = unsafe {
                W::FwpmFilterEnum0(
                    engine.raw(),
                    enumerator.raw(),
                    64,
                    &mut entries,
                    &mut returned,
                )
            };
            if rc != 0 {
                return Err(classify(rc));
            }
            if returned == 0 || entries.is_null() {
                break;
            }
            let buf = unsafe { WfpBuf::from_raw(entries) };
            let slice = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
            for item in slice {
                if !item.is_null() {
                    out.push(unsafe { filter_raw_from(*item as *const _) });
                }
            }
            drop(buf); // 只释放外层数组
            if returned < 64 {
                break;
            }
        }
        Ok(out)
    }

    // A3b evidence lab only. Unlike the production provider-limited reader,
    // enumerate the entire requested ALE layer, including NULL providers and
    // disabled/boot-time objects. A completed snapshot is NOT a writer fence.
    #[cfg(test)]
    #[derive(Clone, Debug)]
    pub(crate) struct LabFilter {
        pub raw: FilterRaw,
        pub null_provider: bool,
    }

    #[cfg(test)]
    pub(crate) fn lab_enum_layer(engine: &WfpEngine, layer: Layer, max_pages: usize)
        -> Result<Vec<LabFilter>, String>
    {
        use std::collections::HashSet;
        const PAGE: u32 = 7; // deliberately exercise pagination
        let mut template: W::FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.providerKey = std::ptr::null_mut();
        template.layerKey = to_win(layer.guid());
        template.enumType = 0; // FWP_FILTER_ENUM_FULLY_CONTAINED
        template.flags = 0x8 | 0x10; // INCLUDE_BOOTTIME | INCLUDE_DISABLED
        template.actionMask = u32::MAX;
        let mut handle: HANDLE = std::ptr::null_mut();
        let rc = unsafe { W::FwpmFilterCreateEnumHandle0(engine.raw(), &template, &mut handle) };
        if rc != 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!("lab enum create incomplete layer={layer:?} rc={rc:#x}"));
        }
        let enumerator = unsafe { EnumHandle::new(engine.raw(), handle, W::FwpmFilterDestroyEnumHandle0) };
        let mut rows = Vec::new();
        let mut keys = HashSet::new();
        for page in 0..max_pages {
            let mut entries: *mut *mut W::FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned = 0u32;
            let rc = unsafe { W::FwpmFilterEnum0(engine.raw(), enumerator.raw(), PAGE, &mut entries, &mut returned) };
            let _buf = unsafe { WfpBuf::from_raw(entries) };
            if rc != 0 || returned > PAGE || (returned != 0 && entries.is_null()) {
                return Err(format!("lab enum page incomplete layer={layer:?} page={page} rc={rc:#x} count={returned}"));
            }
            if returned == 0 {
                let nulls = rows.iter().filter(|r: &&LabFilter| r.null_provider).count();
                let disabled = rows.iter().filter(|r| r.raw.flags & W::FWPM_FILTER_FLAG_DISABLED != 0).count();
                println!("A3B_ENUM layer={layer:?} rows={} pages={} terminal_zero=true null_provider={nulls} disabled={disabled}", rows.len(), page + 1);
                return Ok(rows);
            }
            for item in unsafe { std::slice::from_raw_parts(entries, returned as usize) } {
                if item.is_null() {
                    return Err("lab enum returned a null filter".into());
                }
                let raw = unsafe { filter_raw_from(*item) };
                if raw.layer != layer.guid() || raw.filter_key.is_nil() || !keys.insert(raw.filter_key)
                    || raw.num_conditions as usize != raw.conditions.len()
                {
                    return Err("lab enum malformed, duplicate, or wrong-layer object".into());
                }
                rows.push(LabFilter { raw, null_provider: unsafe { (**item).providerKey.is_null() } });
            }
        }
        Err(format!("lab enum incomplete: layer={layer:?} page budget exhausted"))
    }

    // The fixture uses an isolated random provider only for its BLOCKs and
    // the existing UNIVERSAL sublayer. BFE prohibits cross-session references
    // to dynamic sublayers; do not create a persistent fixture sublayer.
    #[cfg(test)]
    pub(crate) fn lab_add_provider(engine: &WfpEngine, key: Guid) {
        assert!(!key.is_nil() && key != PROVIDER_GUID);
        let mut provider = RawProvider::build();
        provider._name = wide("SpiderVPN isolated A3b lab provider");
        provider._description = wide("Disposable dynamic test provider");
        provider.raw.providerKey = to_win(key);
        provider.raw.displayData.name = provider._name.as_mut_ptr();
        provider.raw.displayData.description = provider._description.as_mut_ptr();
        provider.raw.flags = 0;
        provider.raw.providerData = W::FWP_BYTE_BLOB { size: 0, data: std::ptr::null_mut() };
        provider_add(engine, &provider).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn lab_block(app: &[u8], layer: Layer, provider: Option<Guid>, key: Guid)
        -> Box<RawFilter>
    {
        assert!(!app.is_empty() && !key.is_nil());
        let mut raw = RawFilter::block("isolated A3b lab BLOCK", app, layer);
        raw.raw.filterKey = to_win(key);
        raw.raw.flags = 0;
        raw.raw.subLayerKey = W::FWPM_SUBLAYER_UNIVERSAL;
        raw.raw.providerData = W::FWP_BYTE_BLOB { size: 0, data: std::ptr::null_mut() };
        if let Some(provider) = provider {
            assert!(!provider.is_nil() && provider != PROVIDER_GUID);
            *raw._provider_key = to_win(provider);
            raw.raw.providerKey = &mut *raw._provider_key;
        } else {
            raw.raw.providerKey = std::ptr::null_mut();
        }
        raw
    }

    #[cfg(test)]
    pub(crate) fn lab_try_disabled_block(engine: &WfpEngine, app: &[u8], key: Guid)
        -> Result<u64, u32>
    {
        let mut raw = lab_block(app, Layer::V4, None, key);
        // The SDK documents that DISABLED is BFE-owned/read-only. Try the
        // actual API on a disposable BLOCK, never on a product rule.
        raw.raw.flags = W::FWPM_FILTER_FLAG_DISABLED;
        let mut id = 0;
        let rc = unsafe { W::FwpmFilterAdd0(engine.raw(), raw.as_ptr(), std::ptr::null_mut(), &mut id) };
        if rc == 0 { Ok(id) } else { Err(rc) }
    }

    #[cfg(test)]
    pub(crate) fn lab_native_enum_error(engine: &WfpEngine) -> u32 {
        let mut entries: *mut *mut W::FWPM_FILTER0 = std::ptr::null_mut();
        let mut count = 0;
        // Invalid enumeration handle, valid engine. No writes or ACL change.
        let rc = unsafe { W::FwpmFilterEnum0(engine.raw(), std::ptr::null_mut(), 7, &mut entries, &mut count) };
        let _buf = unsafe { WfpBuf::from_raw(entries) };
        rc
    }

    /// 枚举全部 provider（用于识别 旧版留下的对象 —— 它的 key 我们不知道，
    /// 只能靠 `providerData` 标记扫出来）。
    pub fn provider_enumerate(engine: &WfpEngine) -> Result<Vec<ProviderDefinition>, WfpError> {
        let mut handle: HANDLE = std::ptr::null_mut();
        let rc = unsafe {
            W::FwpmProviderCreateEnumHandle0(engine.raw(), std::ptr::null(), &mut handle)
        };
        if rc != 0 {
            return Err(classify(rc));
        }
        let enumerator =
            unsafe { EnumHandle::new(engine.raw(), handle, W::FwpmProviderDestroyEnumHandle0) };
        let mut out = Vec::new();
        loop {
            let mut entries: *mut *mut W::FWPM_PROVIDER0 = std::ptr::null_mut();
            let mut returned: u32 = 0;
            let rc = unsafe {
                W::FwpmProviderEnum0(
                    engine.raw(),
                    enumerator.raw(),
                    64,
                    &mut entries,
                    &mut returned,
                )
            };
            if rc != 0 {
                return Err(classify(rc));
            }
            if returned == 0 || entries.is_null() {
                break;
            }
            let buf = unsafe { WfpBuf::from_raw(entries) };
            let slice = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
            for item in slice {
                if !item.is_null() {
                    out.push(unsafe { provider_definition_from(*item as *const _) });
                }
            }
            drop(buf);
            if returned < 64 {
                break;
            }
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // 生产环境注入点
    // -----------------------------------------------------------------------

    /// 生产环境的 [`IdentityEnv`]：文件属性用 `GetFileAttributesW`，appId 用 WFP。
    ///
    /// 为什么 reparse point 一定要问系统而不是 `std::fs::symlink_metadata`：
    /// Windows 上「目录联接（junction）」和「挂载点」都是 reparse point，但 std 的
    /// `is_symlink()` 并不保证对它们全部返回 true。这里是安全判定，宁可问系统。
    pub struct SystemIdentityEnv;

    impl SystemIdentityEnv {
        pub fn new() -> SystemIdentityEnv {
            SystemIdentityEnv
        }

        fn attributes(path: &Path) -> Option<u32> {
            use std::os::windows::ffi::OsStrExt;
            let wide_path: Vec<u16> =
                path.as_os_str().encode_wide().chain(std::iter::once(0u16)).collect();
            let attrs = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
            if attrs == INVALID_FILE_ATTRIBUTES {
                None
            } else {
                Some(attrs)
            }
        }
    }

    impl IdentityEnv for SystemIdentityEnv {
        fn exists(&self, path: &Path) -> bool {
            match Self::attributes(path) {
                // 目录不能当程序身份
                Some(attrs) => attrs & 0x0000_0010 == 0, // FILE_ATTRIBUTE_DIRECTORY
                None => false,
            }
        }

        fn is_reparse_point(&self, path: &Path) -> bool {
            match Self::attributes(path) {
                Some(attrs) => attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                // 查不到属性时**保守判定为是**：宁可把这条判成「不参与保护」，
                // 也不要因为一次读取失败就把一条有嫌疑的路径当成干净的。
                None => true,
            }
        }

        fn app_id(&self, path: &Path) -> Result<Vec<u8>, IdentityError> {
            app_id_from_path(path).map_err(|_| IdentityError::AppIdFailed)
        }
    }

    // -----------------------------------------------------------------------
    // 时钟（A-14：单调优先，抗墙钟回拨）
    // -----------------------------------------------------------------------

    /// 当前墙钟（epoch 秒）。
    pub fn now_epoch() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }

    /// 单调毫秒（开机以来）。
    ///
    /// `GetTickCount64` 的语义（架构 A-14 spike 结论）：改系统时间不影响它，
    /// 跨睡眠/待机仍继续增长。所以时龄用它算，墙钟只做展示。
    pub fn tick_ms() -> u64 {
        use windows_sys::Win32::System::SystemInformation::GetTickCount64;
        unsafe { GetTickCount64() }
    }

    /// 生产时钟（`state::Clock` 的实现）。
    pub struct SystemClock;

    impl SystemClock {
        pub fn new() -> SystemClock {
            SystemClock
        }
    }

    impl super::super::state::Clock for SystemClock {
        fn now_epoch(&self) -> f64 {
            now_epoch()
        }
        fn tick_ms(&self) -> u64 {
            tick_ms()
        }
    }

    // -----------------------------------------------------------------------
    // 并发互斥（一次只允许一个交易保护动作）
    // -----------------------------------------------------------------------

    /// 命名互斥。**名字必须以 `Global\SpiderVPN-` 开头**（与旧版完全分开）。
    pub struct NamedMutex {
        handle: HANDLE,
    }

    impl NamedMutex {
        /// 拿互斥。拿不到（别人正持有）返回 `Err("另一个交易保护操作正在进行")`。
        pub fn acquire(name: &str) -> Result<NamedMutex, String> {
            use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0u16)).collect();
            let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
            if handle.is_null() {
                return Err("创建交易保护互斥失败".to_string());
            }
            // 已存在不等于被占用：用 0 超时试一次，WAIT_OBJECT_0 才算拿到。
            let wait = unsafe { WaitForSingleObject(handle, 0) };
            if wait == WAIT_TIMEOUT {
                unsafe { CloseHandle(handle) };
                return Err("另一个交易保护操作正在进行，请稍后再试".to_string());
            }
            if wait != WAIT_OBJECT_0 {
                unsafe { CloseHandle(handle) };
                return Err("等待交易保护互斥失败".to_string());
            }
            Ok(NamedMutex { handle })
        }
    }

    impl Drop for NamedMutex {
        fn drop(&mut self) {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::ReleaseMutex;
            if !self.handle.is_null() {
                unsafe {
                    ReleaseMutex(self.handle);
                    CloseHandle(self.handle);
                }
                self.handle = std::ptr::null_mut();
            }
        }
    }

    // -----------------------------------------------------------------------
    // 运行中的交易程序（P0-13 前置提示；非提权）
    // -----------------------------------------------------------------------

    /// 名单里哪些程序现在正在运行。
    ///
    /// 用 Toolhelp 快照 + `QueryFullProcessImageNameW` 取**完整路径**再按 appId 比对：
    /// 只看进程名会把「别的目录里的同名 exe」也算进来（误报），而误报会让用户
    /// 被要求退出一个根本没在保护的程序的同名进程。
    pub fn running_programs(ids: &[super::super::identity::ProgramIdentity]) -> Vec<String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        if ids.is_empty() {
            return Vec::new();
        }
        let wanted: Vec<(String, Vec<u8>)> = ids
            .iter()
            .map(|i| (i.path.to_string_lossy().to_lowercase(), i.app_id.clone()))
            .collect();
        let mut out: Vec<String> = Vec::new();
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
        while ok != 0 {
            let pid = entry.th32ProcessID;
            if pid != 0 && pid != std::process::id() {
                let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
                if !handle.is_null() {
                    let mut buf = [0u16; 1024];
                    let mut len = buf.len() as u32;
                    let got = unsafe {
                        QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len)
                    };
                    unsafe { CloseHandle(handle) };
                    if got != 0 {
                        let path = String::from_utf16_lossy(&buf[..len as usize]);
                        let lower = path.to_lowercase();
                        if let Some((name, _)) =
                            wanted.iter().find(|(want, _)| want == &lower).map(|w| (w.0.clone(), w.1.clone()))
                        {
                            let short = lower.rsplit('\\').next().unwrap_or(&lower).to_string();
                            let _ = name;
                            if !out.iter().any(|x| x.eq_ignore_ascii_case(&short)) {
                                out.push(short);
                            }
                        }
                    }
                }
            }
            ok = unsafe { Process32NextW(snap, &mut entry) };
        }
        unsafe { CloseHandle(snap) };
        out
    }

    // -----------------------------------------------------------------------
    // 真实后端：GuardBackend 的 Windows 实现
    // -----------------------------------------------------------------------

    /// 真实 WFP 后端。**只在 `--guard-apply` 子进程里被调用**（需要提权）。
    ///
    /// 每次动作开/关一个引擎会话，不持有长连接：这样「进程退出 = 会话结束」不会留下
    /// 动态对象，也避免跨动作的事务污染。
    pub struct WindowsWfp;

    impl WindowsWfp {
        pub fn new() -> WindowsWfp {
            WindowsWfp
        }

        /// 确保基础设施在位（同一事务内）。
        fn ensure_infrastructure(engine: &WfpEngine) -> Result<super::super::state::GuardDetection, WfpError> {
            let mut detection = super::super::state::GuardDetection { bfe_ready: true, ..Default::default() };

            // 先看定义对不对：同一个 GUID、但不是本版定义 —— 真机上就是**我们自己早期版本**
            // 装的（老 marker / 老显示名）。这种情况必须整套替换，否则 install 与 remove
            // 都会返回 InvalidState，用户永久卡在「未完整启用」。
            // 只有真正的 旧版（LEGACY_MARKER）才拒绝：那是别人的策略，不接管也不删。
            let provider_def = provider_get(engine, PROVIDER_GUID)?;
            let sublayer_def = sublayer_get(engine, SUBLAYER_GUID)?;
            if let Some(def) = &provider_def {
                detection.provider_present = true;
                detection.legacy_guard_present |= def.is_legacy();
                if def.is_legacy() {
                    return Err(WfpError::InvalidState);
                }
            }
            if let Some(def) = &sublayer_def {
                detection.sublayer_present = true;
                detection.legacy_guard_present |= def.is_legacy();
                if def.is_legacy() {
                    return Err(WfpError::InvalidState);
                }
            }
            let need_reset = provider_def.as_ref().map(|d| !d.is_ours()).unwrap_or(false)
                || sublayer_def.as_ref().map(|d| !d.is_ours()).unwrap_or(false);
            if need_reset {
                // 顺序不能反：provider 被过滤器引用时删除会 `IN_USE`（真机报过
                // 「规则仍被占用，暂时无法删除」）。过滤器 → sublayer → provider。
                for f in Self::enumerate_ours(engine)? {
                    filter_delete_by_id(engine, f.filter_id)?;
                }
                let _ = sublayer_delete(engine, SUBLAYER_GUID);
                let _ = provider_delete(engine, PROVIDER_GUID);
                detection.provider_present = false;
                detection.sublayer_present = false;
            }

            if !detection.provider_present {
                let provider = RawProvider::build();
                provider_add(engine, &provider)?;
                detection.provider_present = true;
            }
            if !detection.sublayer_present {
                let sub = RawSubLayer::build();
                sublayer_add(engine, &sub)?;
                detection.sublayer_present = true;
            }
            detection.infrastructure_verified = detection.provider_present && detection.sublayer_present;
            Ok(detection)
        }

        /// 枚举我们自己 provider 在两个层上的全部规则。
        fn enumerate_ours(engine: &WfpEngine) -> Result<Vec<FilterRaw>, WfpError> {
            let mut all = Vec::new();
            for layer in Layer::ALL {
                let mut got = filter_enumerate(engine, PROVIDER_GUID, layer)?;
                // 枚举模板已经按 provider 过滤；这里再确认一次（防御 + 语义清楚）
                if got.iter().any(|f| f.provider_key != PROVIDER_GUID) {
                    // 陌生 provider 混进来 → 整笔拒绝（旧版同语义）
                    return Err(WfpError::Native(super::super::wfp::FWP_E_INVALID_PARAMETER));
                }
                all.append(&mut got);
            }
            Ok(all)
        }

        /// 读回：逐程序 × 逐协议族识别。**这是唯一能当证据的东西**（A19）。
        fn snapshot(
            engine: &WfpEngine,
            ids: &[super::super::identity::ProgramIdentity],
            detection: super::super::state::GuardDetection,
        ) -> Result<super::super::state::GuardEvidence, WfpError> {
            let filters = Self::enumerate_ours(engine)?;
            let mut programs = Vec::with_capacity(ids.len());
            let mut extra = 0usize;
            let mut matched_keys: Vec<Guid> = Vec::new();
            for id in ids {
                let mut slots = [super::super::wfp::FilterSlot::absent(); 2];
                for (idx, layer) in Layer::ALL.iter().enumerate() {
                    let want = super::super::wfp::filter_key(&id.app_id, *layer, false);
                    match filters.iter().find(|f| f.filter_key == want) {
                        Some(f) => {
                            slots[idx] = super::super::wfp::recognize(f, &id.app_id, *layer);
                            matched_keys.push(want);
                        }
                        None => slots[idx] = super::super::wfp::FilterSlot::absent(),
                    }
                }
                programs.push(super::super::state::ProgramEvidence {
                    name: id.name.clone(),
                    path: id.path.to_string_lossy().to_string(),
                    app_id: id.app_id.clone(),
                    ipv4: slots[0],
                    ipv6: slots[1],
                });
            }
            // 属于我们 provider、但不是「参与程序 × 两族」之一的规则 = 多余
            for f in &filters {
                if !matched_keys.contains(&f.filter_key) {
                    extra += 1;
                }
            }
            Ok(super::super::state::GuardEvidence {
                programs,
                detection,
                read_error: None,
                verified_at_epoch: Some(now_epoch()),
                verified_at_tick_ms: Some(tick_ms()),
                source: super::super::state::GuardSource::ElevatedVerify,
                config_digest: String::new(), // 由调用方（子进程）填
                boot_id: String::new(),
                extra_owned_filters: extra,
                legacy_running_at_verify: false,
                store_kind: String::new(),
            })
        }

        fn write_blocks(
            engine: &WfpEngine,
            ids: &[super::super::identity::ProgramIdentity],
        ) -> Result<(), WfpError> {
            let existing = Self::enumerate_ours(engine)?;
            for id in ids {
                for layer in Layer::ALL {
                    let want = super::super::wfp::filter_key(&id.app_id, layer, false);
                    let found = existing.iter().find(|f| f.filter_key == want);
                    match found {
                        Some(f) => {
                            let slot = super::super::wfp::recognize(f, &id.app_id, layer);
                            if !slot.ok() {
                                // 我们的 key 上有一条不合格的规则：删掉重建（只删自有的）
                                if f.provider_key == PROVIDER_GUID {
                                    filter_delete_by_id(engine, f.filter_id)?;
                                } else {
                                    return Err(WfpError::InvalidState);
                                }
                            } else {
                                continue;
                            }
                        }
                        None => {}
                    }
                    let raw = RawFilter::block(&id.name, &id.app_id, layer);
                    filter_add(engine, &raw)?;
                }
            }
            Ok(())
        }
    }

    impl super::super::GuardBackend for WindowsWfp {
        fn available(&self) -> bool {
            true
        }

        fn read(
            &self,
            ids: &[super::super::identity::ProgramIdentity],
            _expect: &super::super::Expect,
        ) -> Result<super::super::state::GuardEvidence, WfpError> {
            let engine = WfpEngine::open()?;
            let result = (|| {
                let mut detection = super::super::state::GuardDetection { bfe_ready: true, ..Default::default() };
                detection.provider_present = provider_get(&engine, PROVIDER_GUID)?.is_some();
                detection.sublayer_present = sublayer_get(&engine, SUBLAYER_GUID)?.is_some();
                detection.infrastructure_verified = detection.provider_present && detection.sublayer_present;
                Self::snapshot(&engine, ids, detection)
            })();
            let closed = engine.close_checked();
            match (result, closed) {
                (Ok(ev), Ok(())) => Ok(ev),
                (Ok(_), Err(e)) => Err(e),
                (Err(e), _) => Err(e),
            }
        }

        fn install(
            &self,
            ids: &[super::super::identity::ProgramIdentity],
            _expect: &super::super::Expect,
        ) -> Result<super::super::state::GuardEvidence, WfpError> {
            let engine = WfpEngine::open()?;
            let result = (|| {
                let txn = Txn::begin(&engine)?;
                let detection = Self::ensure_infrastructure(&engine)?;
                // 不裁剪旧程序：install 是「叠加且幂等」（与参考实现同语义）
                Self::write_blocks(&engine, ids)?;
                txn.commit()?;
                // 同一会话内逐条读回（A19：这才是证据）
                Self::snapshot(&engine, ids, detection)
            })();
            let closed = engine.close_checked();
            match (result, closed) {
                (Ok(ev), Ok(())) => Ok(ev),
                (Ok(_), Err(e)) => Err(e),
                (Err(e), _) => Err(e),
            }
        }

        fn sync(
            &self,
            ids: &[super::super::identity::ProgramIdentity],
            _expect: &super::super::Expect,
        ) -> Result<super::super::state::GuardEvidence, WfpError> {
            let engine = WfpEngine::open()?;
            let result = (|| {
                let txn = Txn::begin(&engine)?;
                let detection = Self::ensure_infrastructure(&engine)?;
                let existing = Self::enumerate_ours(&engine)?;
                // 只删「自有且 Recognized」的 block（不是我们的 key 一律不动）
                let mut keep: Vec<Guid> = Vec::new();
                for id in ids {
                    for layer in Layer::ALL {
                        keep.push(super::super::wfp::filter_key(&id.app_id, layer, false));
                    }
                }
                for f in &existing {
                    if f.provider_key != PROVIDER_GUID {
                        // 别的 provider 的对象：整笔拒绝，保留旧策略（§5.5）
                        return Err(WfpError::InvalidState);
                    }
                    if keep.contains(&f.filter_key) {
                        continue;
                    }
                    // **同 provider 下的旧过滤器一律删掉**：真机上遇到过「上一版留下的过滤器
                    // 不带本版 OWNER_MARKER」→ 旧实现整笔拒绝，于是 install 与 remove 双双
                    // 返回 InvalidState，用户再也装不上也解不掉（界面只显示「退出码 3」）。
                    // provider GUID 就是归属判据：这个 provider 是我们私有创建的，里面的
                    // 对象只可能是我们历史版本留下的，删它不会碰到别人的策略。
                    filter_delete_by_id(&engine, f.filter_id)?;
                }
                Self::write_blocks(&engine, ids)?;
                txn.commit()?;
                Self::snapshot(&engine, ids, detection)
            })();
            let closed = engine.close_checked();
            match (result, closed) {
                (Ok(ev), Ok(())) => Ok(ev),
                (Ok(_), Err(e)) => Err(e),
                (Err(e), _) => Err(e),
            }
        }

        fn remove(&self) -> Result<super::super::state::GuardEvidence, WfpError> {
            let engine = WfpEngine::open()?;
            let result = (|| {
                let txn = Txn::begin(&engine)?;
                let existing = Self::enumerate_ours(&engine)?;
                for f in &existing {
                    if f.provider_key != PROVIDER_GUID {
                        return Err(WfpError::InvalidState);
                    }
                    // 同上：同 provider 下的对象都算我们的（含旧版残留），必须删得掉，
                    // 否则「解除」会永久失败。
                    filter_delete_by_id(&engine, f.filter_id)?;
                }
                // 顺序：filter → subLayer → provider（被占用会以 IN_USE 失败，不做无关清扫）
                match sublayer_delete(&engine, SUBLAYER_GUID) {
                    Ok(()) => {}
                    Err(WfpError::SubLayerNotFound) => {}
                    Err(e) => return Err(e),
                }
                match provider_delete(&engine, PROVIDER_GUID) {
                    Ok(()) => {}
                    Err(WfpError::ProviderNotFound) => {}
                    Err(e) => return Err(e),
                }
                txn.commit()?;
                // 回读：必须确认 provider 真的没了
                let mut detection = super::super::state::GuardDetection { bfe_ready: true, ..Default::default() };
                detection.provider_present = provider_get(&engine, PROVIDER_GUID)?.is_some();
                detection.sublayer_present = sublayer_get(&engine, SUBLAYER_GUID)?.is_some();
                Ok(super::super::state::GuardEvidence {
                    programs: Vec::new(),
                    detection,
                    read_error: None,
                    verified_at_epoch: Some(now_epoch()),
                    verified_at_tick_ms: Some(tick_ms()),
                    source: super::super::state::GuardSource::ElevatedVerify,
                    config_digest: String::new(),
                    boot_id: String::new(),
                    extra_owned_filters: 0,
                    legacy_running_at_verify: false,
                    store_kind: String::new(),
                })
            })();
            let closed = engine.close_checked();
            match (result, closed) {
                (Ok(ev), Ok(())) => Ok(ev),
                (Ok(_), Err(e)) => Err(e),
                (Err(e), _) => Err(e),
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    use super::super::identity::{IdentityEnv, IdentityError};
    use super::super::wfp::WfpError;

    /// 非 Windows 构建不提供该能力（PRD §2.3：不出三态卡，也不假装「未启用」）。
    pub const RPC_C_AUTHN_WINNT: u32 = 10;

    /// 非 Windows 下没有「开机标识」这个概念；空串会让 [`super::super::boot_id`] 的比较
    /// 自然失败（`same_boot("", x) == false`），从而把任何记录都判成不可归属。
    pub fn boot_id() -> String {
        String::new()
    }

    pub fn app_id_from_path(_path: &Path) -> Result<Vec<u8>, WfpError> {
        Err(WfpError::Unsupported)
    }

    /// 非 Windows 下的身份环境：一切都是「不存在」，因此所有条目都是 `NotFound`
    /// （不会有人因此看到「已保护」）。
    pub struct SystemIdentityEnv;

    impl SystemIdentityEnv {
        pub fn new() -> SystemIdentityEnv {
            SystemIdentityEnv
        }
    }

    impl IdentityEnv for SystemIdentityEnv {
        fn exists(&self, _path: &Path) -> bool {
            false
        }

        fn is_reparse_point(&self, _path: &Path) -> bool {
            true
        }

        fn app_id(&self, _path: &Path) -> Result<Vec<u8>, IdentityError> {
            Err(IdentityError::AppIdFailed)
        }
    }

    pub fn now_epoch() -> f64 {
        0.0
    }

    pub fn tick_ms() -> u64 {
        0
    }

    /// 非 Windows：时钟恒 0（状态必然是 `Unknown{Unsupported}`，时龄无意义）。
    pub struct SystemClock;

    impl SystemClock {
        pub fn new() -> SystemClock {
            SystemClock
        }
    }

    impl super::super::state::Clock for SystemClock {
        fn now_epoch(&self) -> f64 {
            0.0
        }
        fn tick_ms(&self) -> u64 {
            0
        }
    }

    /// 非 Windows：没有命名互斥（并发保护退化为进程内锁）。
    pub struct NamedMutex;

    impl NamedMutex {
        pub fn acquire(_name: &str) -> Result<NamedMutex, String> {
            Ok(NamedMutex)
        }
    }

    pub fn running_programs(_ids: &[super::super::identity::ProgramIdentity]) -> Vec<String> {
        Vec::new()
    }

    /// 非 Windows：没有 WFP 后端。
    pub struct WindowsWfp;

    impl WindowsWfp {
        pub fn new() -> WindowsWfp {
            WindowsWfp
        }
    }

    impl super::super::GuardBackend for WindowsWfp {
        fn available(&self) -> bool {
            false
        }
        fn read(
            &self,
            _ids: &[super::super::identity::ProgramIdentity],
            _expect: &super::super::Expect,
        ) -> Result<super::super::state::GuardEvidence, WfpError> {
            Err(WfpError::Unsupported)
        }
        fn install(
            &self,
            _ids: &[super::super::identity::ProgramIdentity],
            _expect: &super::super::Expect,
        ) -> Result<super::super::state::GuardEvidence, WfpError> {
            Err(WfpError::Unsupported)
        }
        fn sync(
            &self,
            _ids: &[super::super::identity::ProgramIdentity],
            _expect: &super::super::Expect,
        ) -> Result<super::super::state::GuardEvidence, WfpError> {
            Err(WfpError::Unsupported)
        }
        fn remove(&self) -> Result<super::super::state::GuardEvidence, WfpError> {
            Err(WfpError::Unsupported)
        }
    }
}

pub use imp::*;
