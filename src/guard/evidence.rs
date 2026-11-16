//! 证据的唯一读写口（架构 A-13/A-13b、§4.4、§4.5）。
//!
//! # 落点
//!
//! 生产：`HKLM\SOFTWARE\SpiderVPN\Guard` 的 `Evidence` 值（`REG_BINARY`，UTF-8 JSON）。
//! 隔离：`<SPIDERVPN_ROOT>\guard\evidence.json`（测试/夹具专用）。
//!
//! # 为什么不是「数据根下的文件」
//!
//! 数据根必须由**未提权宿主**写（`config.json`、`runtime.json`），所以它天然是
//! 「同用户任何进程都能写」的。把「谁是 `Protected`」押在那样一棵目录树上，等于把防伪
//! 交给「我们的安装器记得设 ACL 且设对了」。改用 HKLM：**伪造面由内核的令牌/ACL 判定关闭**
//! ——未提权会话里 `Administrators` 是 deny-only，所以同用户的普通进程写不进去。
//!
//! 不做签名（§6.10.3）：能签的私钥必须在提权进程能读的地方；放受信位置则 ACL 已经解决，
//! 放普通位置则任何同用户进程都能签。签名在这里是安全剧场。`Sha256` 只挡损坏。
//!
//! # 唯一选择点
//!
//! [`select`] 是全程序**唯一**决定「用哪个 store」的地方。别处不许自己拼路径、自己开键。
//! 记录里的 `StoreKind` 与本次所选 store 必须一致，否则 `Unknown{StoreMismatch}`——
//! 这样「手工造的测试文件塞进生产路径」和「测试读到真实生产证据」都不会成立。
//!
//! # 自动测试永不打开 HKLM
//!
//! [`RegistryStore`] 的所有方法在检测到 `SPIDERVPN_ROOT` 时**直接 panic**：
//! 那说明我们在隔离环境里却想去碰生产键。这条断言是给未来的人看的，不是给测试看的。

use std::path::{Path, PathBuf};

use super::state::{GuardRecord, RecordError, RECORD_SCHEMA};

/// 生产键路径（本程序自有命名空间；与旧版无交集）。
pub const REG_PATH: &str = "SOFTWARE\\SpiderVPN\\Guard";
/// 生产值名（单值 = 原子替换，读者只会看到旧值或新值）。
pub const REG_VALUE: &str = "Evidence";
/// 「用户已主动解除」标记值名（Q8）。它只影响文案与旧证据失效，不是权限判断。
pub const REG_REMOVED_VALUE: &str = "Removed";

/// 证据记录长度上限（64 KiB）。超限直接拒绝：不让一条异常记录把读取路径拖进大分配。
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// 允许的记录长度下限（再小就不可能是合法 JSON）。
pub const MIN_RECORD_BYTES: usize = 16;

/// 存储种类。**进状态与诊断**：QA 一眼能看出这次测的是哪条路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Registry,
    IsolatedFile,
}

impl StoreKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StoreKind::Registry => "Registry",
            StoreKind::IsolatedFile => "IsolatedFile",
        }
    }

    pub fn parse(text: &str) -> Option<StoreKind> {
        match text.trim() {
            "Registry" => Some(StoreKind::Registry),
            "IsolatedFile" => Some(StoreKind::IsolatedFile),
            _ => None,
        }
    }
}

/// 「用户已主动解除」的标记（Q8）。
///
/// 为什么需要它：光看名单分不清「保护故障」与「用户自己关掉的」——前者要提示、
/// 后者不该反复催促。它**不是**启用开关，也不参与权限判断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedMarker {
    pub removed_at_utc: String,
    /// 谁写的（`ElevatedRemove` / 测试夹具名）。
    pub by: String,
}

impl RemovedMarker {
    pub fn new(removed_at_utc: &str, by: &str) -> RemovedMarker {
        RemovedMarker { removed_at_utc: removed_at_utc.to_string(), by: by.to_string() }
    }

    fn to_json(&self) -> String {
        serde_json::json!({
            "RemovedAtUtc": self.removed_at_utc,
            "By": self.by,
        })
        .to_string()
    }

    fn from_json(text: &str) -> Option<RemovedMarker> {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        Some(RemovedMarker {
            removed_at_utc: v.get("RemovedAtUtc")?.as_str()?.to_string(),
            by: v.get("By").and_then(|b| b.as_str()).unwrap_or("").to_string(),
        })
    }
}

/// 选择存储失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// 隔离根没设但要求隔离存储 / 路径越界。
    PathOutsideRoot(String),
    Io(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::PathOutsideRoot(p) => {
                write!(f, "证据路径不在隔离数据根之下，拒绝使用：{p}")
            }
            StoreError::Io(e) => write!(f, "证据存储不可用：{e}"),
        }
    }
}

/// 证据存储。**只有两条实现**：生产注册表 / 隔离文件。
pub trait EvidenceStore {
    fn kind(&self) -> StoreKind;
    /// 严格读：任何异常都是 `Err`，**绝不宽松兜底**。
    fn read(&self) -> Result<GuardRecord, RecordError>;
    /// 写（**只允许提权子进程调用**）：写完必须回读校验，写不进去要当场失败。
    fn write(&self, rec: &GuardRecord) -> Result<(), String>;
    /// 无副作用能力探测：我能不能写这个存储？
    fn writable_by_me(&self) -> bool;
    /// 内容是否可信（见各实现的说明；**不要**写成 `!writable_by_me()` 的通用公式）。
    fn trusted(&self) -> bool;
    /// 「用户已主动解除」标记。
    fn read_removed(&self) -> Option<RemovedMarker>;
    fn write_removed(&self, marker: &RemovedMarker) -> Result<(), String>;
    /// 清标记（下次连接安装成功后调用）。
    fn clear_removed(&self) -> Result<(), String>;
    /// 作废当前证据（强制失效事件）：之后 `read()` 必须读不到旧记录。
    fn invalidate(&self, reason: &str) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// 记录字节的严格校验（纯函数：两个 store 共用，测试也能直接覆盖）
// ---------------------------------------------------------------------------

/// 把存储里的原始字节解析成记录。**严格**：长度、JSON、schema、StoreKind、Sha256、来源。
///
/// 这个函数在两个 store 之间共享，所以「损坏/串场/来源不明」的判定只有一份实现。
pub fn parse_record(bytes: &[u8], expected: StoreKind) -> Result<GuardRecord, RecordError> {
    if bytes.len() < MIN_RECORD_BYTES {
        return Err(RecordError::Corrupt(format!("记录过短（{} 字节）", bytes.len())));
    }
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError::Corrupt(format!("记录超过 {} KiB", MAX_RECORD_BYTES / 1024)));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| RecordError::Parse(format!("不是 UTF-8：{e}")))?;
    let rec: GuardRecord =
        serde_json::from_str(text).map_err(|e| RecordError::Parse(e.to_string()))?;
    if rec.schema_version != RECORD_SCHEMA {
        return Err(RecordError::Schema(rec.schema_version));
    }
    // StoreKind 交叉校验：生产读到测试记录（或反之）一律不认。
    let got = StoreKind::parse(&rec.store_kind)
        .ok_or_else(|| RecordError::StoreMismatch(rec.store_kind.clone()))?;
    if got != expected {
        return Err(RecordError::StoreMismatch(rec.store_kind.clone()));
    }
    // 损坏检测（**挡不住管理员**：管理员能重算 Sha256，§4.4.5 已写明）。
    if !rec.verify_seal() {
        return Err(RecordError::Corrupt("Sha256 校验不通过".into()));
    }
    // 来源：`UserRemoved` 是标记不是证据，允许（状态层会单独处理）；
    // 其余必须是我们认识的三种提权来源之一。
    if !rec.is_user_removed() && super::state::GuardSource::parse(&rec.source).is_none() {
        return Err(RecordError::Source(rec.source.clone()));
    }
    if !rec.is_user_removed() && !rec.verifier_elevated {
        // 未提权写入的记录一律不认（记录本身声明了它是谁写的）
        return Err(RecordError::Source(rec.source.clone()));
    }
    Ok(rec)
}

/// 把记录序列化成存储字节（含 `Sha256`）。
pub fn record_bytes(rec: &GuardRecord) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(rec).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(format!("记录超过 {} KiB 上限", MAX_RECORD_BYTES / 1024));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// 隔离文件存储（测试/夹具；路径必须在 SPIDERVPN_ROOT 之下）
// ---------------------------------------------------------------------------

/// `<root>\guard\evidence.json`。**不做 ACL**（它本来就是可写的测试件）。
pub struct IsolatedFileStore {
    pub path: PathBuf,
    root: PathBuf,
}

impl IsolatedFileStore {
    /// 在隔离根下建 store。路径**必须**在该根之下，否则 `Err`。
    pub fn new(root: &Path) -> Result<IsolatedFileStore, StoreError> {
        let root = root.to_path_buf();
        let path = root.join("guard").join("evidence.json");
        if !path.starts_with(&root) {
            return Err(StoreError::PathOutsideRoot(path.display().to_string()));
        }
        Ok(IsolatedFileStore { path, root })
    }

    fn marker_path(&self) -> PathBuf {
        self.root.join("guard").join("removed.json")
    }

    fn ensure_dir(&self) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("建证据目录失败：{e}"))?;
        }
        Ok(())
    }
}

impl EvidenceStore for IsolatedFileStore {
    fn kind(&self) -> StoreKind {
        StoreKind::IsolatedFile
    }

    fn read(&self) -> Result<GuardRecord, RecordError> {
        if !self.path.exists() {
            return Err(RecordError::Missing);
        }
        let bytes = std::fs::read(&self.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                RecordError::AccessDenied
            } else {
                RecordError::Io(e.to_string())
            }
        })?;
        parse_record(&bytes, self.kind())
    }

    fn write(&self, rec: &GuardRecord) -> Result<(), String> {
        self.ensure_dir()?;
        let bytes = record_bytes(rec)?;
        // 原子替换：临时文件 + rename（与 config 的写法一致）。
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| format!("写证据临时文件失败：{e}"))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("替换证据文件失败：{e}"))?;
        // 写完必须回读校验：写不进去/写坏了要当场知道。
        let back = self.read().map_err(|e| e.message())?;
        if back.nonce != rec.nonce {
            return Err("证据回读的 nonce 与写入不一致".to_string());
        }
        if !back.verify_seal() {
            return Err("证据回读的 Sha256 校验不通过".to_string());
        }
        Ok(())
    }

    fn writable_by_me(&self) -> bool {
        // 隔离 store 本来就是可写的测试件：这里如实说「是」。
        true
    }

    fn trusted(&self) -> bool {
        // **刻意与 `writable_by_me()` 不是取反关系**（架构 §4.5 明确提醒）：
        // 隔离 store 没有伪造语义，它的存在本身就是「这是测试」。
        true
    }

    fn read_removed(&self) -> Option<RemovedMarker> {
        let text = std::fs::read_to_string(self.marker_path()).ok()?;
        RemovedMarker::from_json(&text)
    }

    fn write_removed(&self, marker: &RemovedMarker) -> Result<(), String> {
        self.ensure_dir()?;
        std::fs::write(self.marker_path(), marker.to_json())
            .map_err(|e| format!("写解除标记失败：{e}"))
    }

    fn clear_removed(&self) -> Result<(), String> {
        match std::fs::remove_file(self.marker_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("清解除标记失败：{e}")),
        }
    }

    fn invalidate(&self, reason: &str) -> Result<(), String> {
        if !self.path.exists() {
            return Ok(());
        }
        // 改名留档（改名失败则删除）：**旧证据不能再被 read() 读到**。
        let invalid = self.path.with_extension("invalid.json");
        if std::fs::rename(&self.path, &invalid).is_err() {
            std::fs::remove_file(&self.path).map_err(|e| format!("作废证据失败：{e}"))?;
        }
        let note = format!("reason={reason}\n");
        let _ = std::fs::write(self.path.with_extension("invalid-reason.txt"), note);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 生产注册表存储（HKLM，单值 REG_BINARY）
// ---------------------------------------------------------------------------

/// `HKLM\SOFTWARE\SpiderVPN\Guard`。
pub struct RegistryStore {
    /// 仅供诊断输出（不参与读写）。
    pub path: String,
}

impl Default for RegistryStore {
    fn default() -> Self {
        RegistryStore { path: REG_PATH.to_string() }
    }
}

impl RegistryStore {
    pub fn new() -> RegistryStore {
        RegistryStore::default()
    }

    /// 隔离环境里绝不许碰生产键（否则一次测试就会污染真实机器）。
    fn guard_isolated() {
        if std::env::var("SPIDERVPN_ROOT").map(|v| !v.trim().is_empty()).unwrap_or(false) {
            panic!(
                "隔离环境（SPIDERVPN_ROOT 已设置）里禁止访问生产注册表键 {REG_PATH}：\
                 请改用 IsolatedFileStore"
            );
        }
    }
}

#[cfg(windows)]
mod registry {
    use super::*;
    use winreg::enums::{
        HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_BINARY,
    };
    use winreg::RegKey;

    /// 读/探测都带 `KEY_WOW64_64KEY`：本程序只支持 x64，避免将来 32 位构建悄悄落到
    /// `Wow6432Node` 看不到自己的键。
    fn open(flags: u32) -> std::io::Result<RegKey> {
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(REG_PATH, flags)
    }

    impl EvidenceStore for RegistryStore {
        fn kind(&self) -> StoreKind {
            StoreKind::Registry
        }

        fn read(&self) -> Result<GuardRecord, RecordError> {
            RegistryStore::guard_isolated();
            let key = match open(KEY_READ | KEY_WOW64_64KEY) {
                Ok(k) => k,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(RecordError::Missing)
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(RecordError::AccessDenied)
                }
                Err(e) => return Err(RecordError::Io(e.to_string())),
            };
            let value = match key.get_raw_value(REG_VALUE) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(RecordError::Missing)
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(RecordError::AccessDenied)
                }
                Err(e) => return Err(RecordError::Io(e.to_string())),
            };
            if value.vtype != REG_BINARY {
                return Err(RecordError::Corrupt(format!("值类型不是 REG_BINARY：{:?}", value.vtype)));
            }
            parse_record(&value.bytes, StoreKind::Registry)
        }

        fn write(&self, rec: &GuardRecord) -> Result<(), String> {
            RegistryStore::guard_isolated();
            let bytes = record_bytes(rec)?;
            let key = RegKey::predef(HKEY_LOCAL_MACHINE)
                .create_subkey(REG_PATH)
                .map_err(|e| format!("打开/创建证据键失败：{e}"))?
                .0;
            key.set_raw_value(
                REG_VALUE,
                &winreg::RegValue { bytes: bytes.clone().into(), vtype: REG_BINARY },
            )
            .map_err(|e| format!("写证据值失败：{e}"))?;
            // 回读校验（Nonce + Sha256）：写不进去/写坏了当场知道。
            let back = self.read().map_err(|e| format!("证据回读失败：{}", e.message()))?;
            if back.nonce != rec.nonce {
                return Err("证据回读的 nonce 与写入不一致".to_string());
            }
            if !back.verify_seal() {
                return Err("证据回读的 Sha256 校验不通过".to_string());
            }
            Ok(())
        }

        fn writable_by_me(&self) -> bool {
            RegistryStore::guard_isolated();
            // 只 open，不写任何东西（连探针值都不创建）。
            open(KEY_SET_VALUE | KEY_WOW64_64KEY).is_ok()
        }

        fn trusted(&self) -> bool {
            // 注册表：能写 = 同用户任何进程都能写 = 内容不可信（§4.4.4）。
            !self.writable_by_me()
        }

        fn read_removed(&self) -> Option<RemovedMarker> {
            RegistryStore::guard_isolated();
            let key = open(KEY_READ | KEY_WOW64_64KEY).ok()?;
            let value = key.get_raw_value(REG_REMOVED_VALUE).ok()?;
            RemovedMarker::from_json(&String::from_utf8_lossy(&value.bytes))
        }

        fn write_removed(&self, marker: &RemovedMarker) -> Result<(), String> {
            RegistryStore::guard_isolated();
            let key = RegKey::predef(HKEY_LOCAL_MACHINE)
                .create_subkey(REG_PATH)
                .map_err(|e| format!("打开/创建证据键失败：{e}"))?
                .0;
            let bytes = marker.to_json().into_bytes();
            key.set_raw_value(
                REG_REMOVED_VALUE,
                &winreg::RegValue { bytes: bytes.into(), vtype: REG_BINARY },
            )
            .map_err(|e| format!("写解除标记失败：{e}"))
        }

        fn clear_removed(&self) -> Result<(), String> {
            RegistryStore::guard_isolated();
            let key = match open(KEY_ALL_ACCESS | KEY_WOW64_64KEY) {
                Ok(k) => k,
                // 键不存在/没权限：没有标记可清（幂等）
                Err(_) => return Ok(()),
            };
            match key.delete_value(REG_REMOVED_VALUE) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("清解除标记失败：{e}")),
            }
        }

        fn invalidate(&self, _reason: &str) -> Result<(), String> {
            RegistryStore::guard_isolated();
            // 删掉 `Evidence` 值：之后 read() 得到 Missing。
            // 不删键本身（键里可能还有 Removed 标记；且删键需要 DELETE 权限）。
            let key = match open(KEY_ALL_ACCESS | KEY_WOW64_64KEY) {
                Ok(k) => k,
                Err(_) => return Ok(()),
            };
            match key.delete_value(REG_VALUE) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("作废证据失败：{e}")),
            }
        }
    }
}

#[cfg(not(windows))]
mod registry {
    use super::*;

    impl EvidenceStore for RegistryStore {
        fn kind(&self) -> StoreKind {
            StoreKind::Registry
        }
        fn read(&self) -> Result<GuardRecord, RecordError> {
            Err(RecordError::Missing)
        }
        fn write(&self, _rec: &GuardRecord) -> Result<(), String> {
            Err("当前平台不支持注册表证据存储".to_string())
        }
        fn writable_by_me(&self) -> bool {
            false
        }
        fn trusted(&self) -> bool {
            true
        }
        fn read_removed(&self) -> Option<RemovedMarker> {
            None
        }
        fn write_removed(&self, _marker: &RemovedMarker) -> Result<(), String> {
            Err("当前平台不支持".to_string())
        }
        fn clear_removed(&self) -> Result<(), String> {
            Ok(())
        }
        fn invalidate(&self, _reason: &str) -> Result<(), String> {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// 唯一选择点
// ---------------------------------------------------------------------------

/// 选存储：**有 `SPIDERVPN_ROOT` → 隔离文件；没有 → 生产注册表**。
///
/// 之所以要「唯一选择点」而不是各处自己拼：生产/测试串场的后果是「测试假通过」或
/// 「真实机器被测试污染」，两种都极难在事后发现。记录里的 `StoreKind` 是第二道锁。
pub fn select(root: &Path) -> Result<Box<dyn EvidenceStore>, StoreError> {
    let isolated_by_env =
        std::env::var("SPIDERVPN_ROOT").map(|v| !v.trim().is_empty()).unwrap_or(false);
    // 安全网：单测/夹具常用 `%TEMP%` 当数据根，但不能靠全局环境变量（并行测试会互相踩）。
    // 只要根在系统临时目录下，一律走隔离文件，绝不允许一次测试摸到生产 HKLM。
    let isolated_by_path = root.starts_with(std::env::temp_dir());
    if isolated_by_env || isolated_by_path {
        Ok(Box::new(IsolatedFileStore::new(root)?))
    } else {
        Ok(Box::new(RegistryStore::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::state::GuardSource;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-ev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn record(store: StoreKind) -> GuardRecord {
        let mut rec = crate::guard::state::GuardRecord {
            schema_version: RECORD_SCHEMA,
            store_kind: store.as_str().to_string(),
            record_version: 1,
            nonce: "n-1".into(),
            boot_id: "1762333200".into(),
            config_digest: "digest".into(),
            verified_at_utc: "2026-11-05T09:12:31.250Z".into(),
            verified_at_tick_ms: 18_422_311,
            source: GuardSource::ElevatedVerify.as_str().to_string(),
            verifier_pid: 42,
            verifier_elevated: true,
            app_version: "0.1.4".into(),
            provider_present: true,
            sublayer_present: true,
            infrastructure_verified: true,
            legacy_guard_present: false,
            legacy_running_at_verify: false,
            bfe_ready: true,
            extra_owned_filters: 0,
            programs: Vec::new(),
            sha256: String::new(),
        };
        rec.seal();
        rec
    }

    #[test]
    fn isolated_store_round_trips_and_is_always_trusted() {
        let dir = tmp("iso");
        let store = IsolatedFileStore::new(&dir).unwrap();
        assert_eq!(store.kind(), StoreKind::IsolatedFile);
        assert_eq!(store.read().unwrap_err(), RecordError::Missing, "还没写过");
        let rec = record(StoreKind::IsolatedFile);
        store.write(&rec).unwrap();
        let back = store.read().unwrap();
        assert_eq!(back, rec);
        // 隔离 store：可写但**仍然可信**（两者不是取反关系）
        assert!(store.writable_by_me());
        assert!(store.trusted());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn isolated_store_rejects_a_registry_record() {
        let dir = tmp("cross");
        let store = IsolatedFileStore::new(&dir).unwrap();
        // 直接把一条 Registry 记录塞进隔离路径
        let rec = record(StoreKind::Registry);
        let bytes = record_bytes(&rec).unwrap();
        std::fs::create_dir_all(dir.join("guard")).unwrap();
        std::fs::write(dir.join("guard").join("evidence.json"), bytes).unwrap();
        assert_eq!(
            store.read().unwrap_err(),
            RecordError::StoreMismatch("Registry".into()),
            "生产记录不许在隔离侧生效"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_and_unknown_schema_are_rejected_without_guessing() {
        let dir = tmp("corrupt");
        let store = IsolatedFileStore::new(&dir).unwrap();
        std::fs::create_dir_all(dir.join("guard")).unwrap();
        let path = dir.join("guard").join("evidence.json");

        // 半截 JSON
        std::fs::write(&path, b"{\"SchemaVersion\":1,").unwrap();
        assert!(matches!(store.read(), Err(RecordError::Parse(_))));
        // 太短
        std::fs::write(&path, b"{}").unwrap();
        assert!(matches!(store.read(), Err(RecordError::Corrupt(_))));
        // schema 不认识
        let mut rec = record(StoreKind::IsolatedFile);
        rec.schema_version = 7;
        rec.seal();
        std::fs::write(&path, record_bytes(&rec).unwrap()).unwrap();
        assert_eq!(store.read().unwrap_err(), RecordError::Schema(7));
        // 内容被改（Sha256 不符）
        let rec = record(StoreKind::IsolatedFile);
        std::fs::write(&path, record_bytes(&rec).unwrap()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap().replace("\"digest\"", "\"other\"");
        std::fs::write(&path, text).unwrap();
        assert!(matches!(store.read(), Err(RecordError::Corrupt(_))));
        // 来源不明
        let mut rec = record(StoreKind::IsolatedFile);
        rec.source = "SomebodyElse".into();
        rec.seal();
        std::fs::write(&path, record_bytes(&rec).unwrap()).unwrap();
        assert!(matches!(store.read(), Err(RecordError::Source(_))));
        // 未提权写的记录不认
        let mut rec = record(StoreKind::IsolatedFile);
        rec.verifier_elevated = false;
        rec.seal();
        std::fs::write(&path, record_bytes(&rec).unwrap()).unwrap();
        assert!(matches!(store.read(), Err(RecordError::Source(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_records_are_refused() {
        let bytes = vec![b'{'; MAX_RECORD_BYTES + 1];
        assert!(matches!(parse_record(&bytes, StoreKind::IsolatedFile), Err(RecordError::Corrupt(_))));
    }

    #[test]
    fn removed_marker_round_trips_and_can_be_cleared() {
        let dir = tmp("marker");
        let store = IsolatedFileStore::new(&dir).unwrap();
        assert!(store.read_removed().is_none());
        let marker = RemovedMarker::new("2026-11-05T10:00:00Z", "ElevatedRemove");
        store.write_removed(&marker).unwrap();
        assert_eq!(store.read_removed().unwrap(), marker);
        store.clear_removed().unwrap();
        assert!(store.read_removed().is_none(), "清除后必须没有");
        // 清两次也幂等
        store.clear_removed().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalidate_makes_the_old_record_unreadable() {
        let dir = tmp("inval");
        let store = IsolatedFileStore::new(&dir).unwrap();
        store.write(&record(StoreKind::IsolatedFile)).unwrap();
        store.invalidate("connect").unwrap();
        assert_eq!(store.read().unwrap_err(), RecordError::Missing, "作废后读不到旧证据");
        // 再作废一次：幂等
        store.invalidate("connect").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_keeps_the_marker_but_deletes_the_evidence_value() {
        // A22 的形状：`Removed` 标记保留用户意图；`Evidence` 本体必须消失，
        // 把解除前的证据复制回去也不能再撑起 Protected。
        let dir = tmp("removed");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let rec = record(StoreKind::IsolatedFile);
        store.write(&rec).unwrap();
        store
            .write_removed(&RemovedMarker::new("2026-11-05T10:00:00.000Z", "ElevatedRemove"))
            .unwrap();
        store.invalidate("user-remove").unwrap();

        assert_eq!(store.read().unwrap_err(), RecordError::Missing, "旧证据必须物理消失");
        assert!(store.read_removed().is_some(), "用户意图要跨打开仍可读");
        let marker = store.read_removed().unwrap();
        assert_eq!(marker.by, "ElevatedRemove");

        // 反作弊：把解除前的证据原样写回去 → read() 又能读到，但标记仍在，
        // 判定层的 user_removed 会挡住 Protected（state.rs 有专门测试）。
        store.write(&rec).unwrap();
        assert!(store.read_removed().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_prefers_the_isolated_store_when_the_root_is_set() {
        // 这里只验证「有隔离根 → 文件 store」。生产侧（注册表）不能在自动测试里打开，
        // 由 `RegistryStore::guard_isolated()` 的 panic 兜住（见 tests/guard_evidence_sink.rs）。
        let dir = tmp("select");
        std::env::set_var("SPIDERVPN_ROOT", &dir);
        let store = select(&dir).unwrap();
        assert_eq!(store.kind(), StoreKind::IsolatedFile);
        std::env::remove_var("SPIDERVPN_ROOT");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
