//! 独立的长期 WFP 代理许可 helper（仅 Windows 的内部入口）。
//!
//! 与一次性 --guard-apply 严格分离：动态会话必须在 helper 内持续持有，
//! 并在主程序或 sing-box 退出时立即撤销。**此阶段尚未接入生产连接按钮**。
//!
//! Windows 通过受保护的本机命名管道交换有界 JSON，不接受旧文件路径入口。
//! Ready 仅在 DynamicProxyLease::acquire 已核验完整持久 BLOCK 并成功写入动态
//! PERMIT 之后写出。服务流程不做任何持久 WFP 变更或证据存储写入。

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use super::identity::{ProgramIdentity, MAX_PROGRAMS};

/// 最大 64 条交易程序，路径和 device_path 可较长；比一次性 Guard 8K 更宽，
/// 但仍严格限制不可信 JSON 的内存与解析成本。
const MAX_LEASE_IPC_BYTES: usize = 256 * 1024;
pub const LEASE_FLAG: &str = "--guard-lease-serve";
const LEASE_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub schema: u32,
    /// 32 个十六进制字符，生成方必须使用系统随机源；用来绑定一次请求/回执。
    pub nonce: String,
    pub endpoint: SocketAddr,
    pub engine_pid: u32,
    pub controller_pid: u32,
    pub engine_executable: PathBuf,
    pub programs: Vec<ProgramIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseReply {
    pub schema: u32,
    pub nonce: String,
    /// "Ready" 仅允许真正持有动态 WFP 会话之后写出。
    pub state: LeaseState,
    pub reason: String,
    pub filter_count: usize,
    pub helper_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LeaseState {
    Ready,
    Accepted,
    Committed,
    Receipt,
    Active,
    Rejected,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseAck {
    schema: u32,
    nonce: String,
    accepted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseFinish {
    schema: u32,
    nonce: String,
    state: LeaseState,
}

#[cfg(any(windows, test))]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LeaseHeartbeat {
    schema: u32,
    nonce: String,
    sequence: u64,
    challenge: String,
}

#[cfg(any(windows, test))]
fn decode_heartbeat(body: &[u8], nonce: &str, sequence: u64) -> Result<LeaseHeartbeat, String> {
    let msg: LeaseHeartbeat = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if msg.schema != LEASE_SCHEMA || msg.nonce != nonce || msg.sequence != sequence || sequence == 0 {
        return Err("租约心跳会话、版本或顺序异常".into());
    }
    decode_nonce(&msg.challenge)?;
    Ok(msg)
}

fn validate_finish(body: &[u8], nonce: &str) -> Result<(), String> {
    validate_finish_stage(body, nonce, LeaseState::Committed)
}

fn validate_finish_stage(body: &[u8], nonce: &str, expected: LeaseState) -> Result<(), String> {
    let finish: LeaseFinish = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if finish.schema != LEASE_SCHEMA || finish.nonce != nonce || finish.state != expected {
        return Err("最终授权确认阶段不匹配".into());
    }
    Ok(())
}

/// 从同一个已打开的对象验证文件类型、链接数、长度，再有界读取。
/// Windows 不跟随末级 reparse point，且读取期间不共享写入或删除。
/// 这不是目录 DACL 或 IPC 对端身份认证的替代品。
#[cfg(test)]
fn open_ipc_file(path: &Path, limit: usize, consume: bool)
    -> Result<Option<(std::fs::File, Vec<u8>)>, String>
{
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).share_mode(FILE_SHARE_READ);
        if consume {
            // DELETE (standard access right 0x00010000) plus GENERIC_READ.
            // 独占打开请求：不允许另一个 helper 同时消费同一个文件对象。
            use windows_sys::Win32::Foundation::GENERIC_READ;
            options.access_mode(GENERIC_READ | 0x0001_0000).share_mode(0);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = consume;
        // 非 Windows 只有协议测试，不运行 WFP；避免跟随普通符号链接。
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(_) => return Err("租约 IPC 不是普通文件".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("检查租约 IPC 失败：{e}")),
        }
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("打开租约 IPC 失败：{e}")),
    };
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || info.nNumberOfLinks != 1
        {
            return Err("租约 IPC 文件身份不可确认或存在重解析点/硬链接".into());
        }
    }
    let meta = file.metadata().map_err(|e| format!("读取租约 IPC 元数据失败：{e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err("租约 IPC 不允许硬链接".into());
        }
    }
    if !meta.is_file() || meta.len() == 0 || meta.len() > limit as u64 {
        return Err("租约 IPC 不是有效的普通有界文件".into());
    }
    let mut body = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut body)
        .map_err(|e| format!("读取租约 IPC 失败：{e}"))?;
    if body.is_empty() || body.len() > limit || body.len() as u64 != meta.len() {
        return Err("租约 IPC 内容长度异常或在读取期间改变".into());
    }
    Ok(Some((file, body)))
}

#[cfg(test)]
fn read_ipc_file(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    Ok(open_ipc_file(path, limit, false)?.map(|(_, body)| body))
}

/// Ready 只是启动协商，不能孤立地当作父进程已接管成功。
/// 辅助进程只接受同一个随机目录的 ack.json，绝不接受另一会话旧 nonce。
#[cfg(test)]
fn read_ack(path: &Path, nonce: &str) -> Result<bool, String> {
    let Some(body) = read_ipc_file(path, 4096)? else {
        return Ok(false);
    };
    parse_ack(&body, nonce)?;
    Ok(true)
}

fn parse_ack(body: &[u8], nonce: &str) -> Result<(), String> {
    let ack: LeaseAck = serde_json::from_slice(body)
        .map_err(|e| format!("租约确认文件不是合法协议：{e}"))?;
    if ack.schema != LEASE_SCHEMA || ack.nonce != nonce || !ack.accepted {
        return Err("启动方确认的会话版本、nonce 或决定不匹配".into());
    }
    Ok(())
}

#[cfg(all(test, windows))]
fn consume_ack(path: &Path, nonce: &str) -> Result<bool, String> {
    let Some((file, body)) = open_ipc_file(path, 4096, true)? else {
        return Ok(false);
    };
    parse_ack(&body, nonce)?;
    delete_consumed_file(file)?;
    Ok(true)
}

fn decode_nonce(text: &str) -> Result<[u8; 16], String> {
    if text.len() != 32 || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("租约 nonce 必须是 32 位十六进制串".into());
    }
    let mut nonce = [0u8; 16];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let a = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        nonce[index] = u8::from_str_radix(a, 16).map_err(|e| e.to_string())?;
    }
    if nonce.iter().all(|&b| b == 0) {
        return Err("全零 nonce 不能作为动态租约标识".into());
    }
    Ok(nonce)
}

/// 纯输入闸门。不能把请求的 PID / exe / AppId 直接当已授权证据。
/// 身份、PID 存活、可执行路径及 WFP BLOCK 的最终核验由 acquire 在提权侧完成。
pub fn validate_request(req: &LeaseRequest) -> Result<[u8; 16], String> {
    if req.schema != LEASE_SCHEMA {
        return Err("未知租约请求版本，拒绝向前兼容猜测".into());
    }
    let nonce = decode_nonce(&req.nonce)?;
    if req.engine_pid == 0 || req.controller_pid == 0
        || req.engine_pid == req.controller_pid
    {
        return Err("引擎与主程序必须是两个有效且不同的 PID".into());
    }
    if req.programs.is_empty() || req.programs.len() > MAX_PROGRAMS {
        return Err(format!("交易名单数量必须在 1 至 {MAX_PROGRAMS} 之间"));
    }
    if !req.engine_executable.is_absolute() || !req.engine_executable
        .extension().is_some_and(|v| v.to_string_lossy().eq_ignore_ascii_case("exe"))
    {
        return Err("引擎可执行路径必须是绝对 .exe 路径".into());
    }
    if req.endpoint.port() == 0 {
        return Err("代理端口不能为零".into());
    }
    match req.endpoint.ip() {
        IpAddr::V4(ip) if ip.octets() == [127, 0, 0, 1] => {}
        IpAddr::V6(ip) if ip == std::net::Ipv6Addr::LOCALHOST => {}
        _ => return Err("仅支持精确 127.0.0.1 或 ::1 环回代理".into()),
    }
    Ok(nonce)
}

/// 限制提权 helper 的文件系统写入范围：不能允许命令行把回执路径
/// 指向任意用户文件。要求两个文件处于同一独立临时子目录，且只能用固定文件名。
/// 这是启动器/子进程双重验证的一半；启动器还必须负责目录 ACL 与随机性。
#[cfg(test)]
fn validate_transport_paths(request: &Path, response: &Path) -> Result<(), String> {
    use std::path::Component;
    if !request.is_absolute() || !response.is_absolute() {
        return Err("租约 IPC 必须采用绝对路径".into());
    }
    if request.file_name().and_then(|x| x.to_str()) != Some("request.json")
        || response.file_name().and_then(|x| x.to_str()) != Some("reply.json")
    {
        return Err("租约 IPC 文件名不符合内部协议".into());
    }
    let dir = request.parent().ok_or("租约请求缺少目录")?;
    if dir != response.parent().ok_or("租约回执缺少目录")? {
        return Err("请求与回执必须处于同一隔离目录".into());
    }
    if request.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || response.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("租约 IPC 路径不允许相对跳转组件".into());
    }
    let name = dir.file_name().and_then(|v| v.to_str()).unwrap_or_default();
    if !name.starts_with("spidervpn-lease-")
        || name.len() < "spidervpn-lease-".len() + 16
        || !name["spidervpn-lease-".len()..]
            .bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("租约 IPC 目录必须使用独立的随机十六进制标识".into());
    }
    // canonicalize 在 Windows 上可能自动加 \\?\ 前缀，不能直接与原 PathBuf
    // 比较，否则有效的普通目录也会被误判为不安全。
    // 确认目录存在，随后用 Win32 FILE_ATTRIBUTE_REPARSE_POINT 逐级排除 junction。
    let canonical = std::fs::canonicalize(dir)
        .map_err(|e| format!("租约 IPC 目录不可访问：{e}"))?;
    let temp_parent = std::fs::canonicalize(std::env::temp_dir())
        .map_err(|e| format!("系统临时目录不可访问：{e}"))?;
    if canonical.parent() != Some(temp_parent.as_path()) {
        return Err("租约 IPC 只能写入当前用户的系统临时目录子层".into());
    }
    // Windows 目录联接/junction 也需要拒绝（不能只靠 std::is_symlink）。
    #[cfg(windows)]
    {
        use super::identity::IdentityEnv;
        let env = super::wfp_win::SystemIdentityEnv::new();
        if super::identity::reparse_chain(dir).iter().any(|p| env.is_reparse_point(p)) {
            return Err("租约 IPC 目录路径包含重解析点，拒绝提升写入".into());
        }
    }
    Ok(())
}

/// 请求必须绑定到启动器为本次会话生成的完整 128-bit 目录标识。
#[cfg(test)]
fn validate_session_directory(path: &Path, nonce: &str) -> Result<(), String> {
    decode_nonce(nonce)?;
    let expected = format!("spidervpn-lease-{nonce}");
    if path.parent().and_then(Path::file_name).and_then(|name| name.to_str())
        != Some(expected.as_str())
    {
        return Err("租约目录与请求 nonce 不一致".into());
    }
    Ok(())
}

#[cfg(test)]
fn read_request(path: &Path) -> Result<LeaseRequest, String> {
    let data = read_ipc_file(path, MAX_LEASE_IPC_BYTES)?
        .ok_or("租约请求不存在")?;
    serde_json::from_slice(&data).map_err(|e| format!("租约 JSON 无效：{e}"))
}

/// 验证后消费同一个打开的请求对象；不能通过再次解析路径来删除文件。
/// 删除失败必须拒绝许可，不能留下可直接重复消费的原请求。
#[cfg(all(test, windows))]
fn consume_request(path: &Path) -> Result<LeaseRequest, String> {
    let (file, data) = open_ipc_file(path, MAX_LEASE_IPC_BYTES, true)?
        .ok_or("租约请求不存在或已经消费")?;
    let req: LeaseRequest = serde_json::from_slice(&data)
        .map_err(|e| format!("租约 JSON 无效：{e}"))?;
    validate_request(&req)?;
    validate_session_directory(path, &req.nonce)?;
    delete_consumed_file(file)?;
    Ok(req)
}

#[cfg(all(test, windows))]
fn delete_consumed_file(file: std::fs::File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(), FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0 {
        return Err(format!("消费租约请求失败：{}", std::io::Error::last_os_error()));
    }
    drop(file);
    Ok(())
}

/// 发布时由文件系统原子拒绝已存在的目标，而不是依赖事前 exists 检查。
/// 尚不解决父目录路径替换或同用户伪造，仍需可信目录和对端认证。
#[cfg(test)]
fn publish_new_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
        let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::fs::hard_link(source, destination)?;
        std::fs::remove_file(source)
    }
}

/// 先写临时文件再原子改名，防止父进程把半截 Ready 当成功。
/// 回执仅在 helper 拥有会话时表示 Ready，不代表长期守护已完成全机验收。
#[cfg(test)]
fn write_reply(path: &Path, reply: &LeaseReply) -> Result<(), String> {
    let data = serde_json::to_vec(reply).map_err(|e| e.to_string())?;
    if data.len() > MAX_LEASE_IPC_BYTES {
        return Err("租约回执超过大小上限".into());
    }
    if !path.is_absolute() || path.extension().and_then(|s| s.to_str()) != Some("json") {
        return Err("租约回执必须是绝对 .json 路径".into());
    }
    if path.exists() {
        return Err("已有租约回执，拒绝覆盖旧会话状态".into());
    }
    let tmp = path.with_extension("json.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&tmp).map_err(|e| format!("建立租约回执临时文件失败：{e}"))?;
    use std::io::Write;
    if let Err(e) = file.write_all(&data).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("写租约回执失败：{e}"));
    }
    drop(file);
    if let Err(e) = publish_new_file(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("提交租约回执失败：{e}"));
    }
    Ok(())
}

/// 父进程必须检查回执来自本次会话且 filter_count 与请求完全一致；
/// "Ready" 文件本身不能证明子进程仍活着，启动器还必须检查 hProcess。
#[cfg(test)]
fn read_ready(path: &Path, nonce: &str, expected_count: usize, expected_helper_pid: u32) -> Result<Option<()>, String> {
    read_stage(path, nonce, expected_count, expected_helper_pid, LeaseState::Ready)
}

#[cfg(test)]
fn read_stage(path: &Path, nonce: &str, expected_count: usize, expected_helper_pid: u32,
    expected_state: LeaseState) -> Result<Option<()>, String>
{
    let Some(body) = read_ipc_file(path, 4096)? else {
        return Ok(None);
    };
    validate_stage(&body, nonce, expected_count, expected_helper_pid, expected_state)?;
    Ok(Some(()))
}

fn validate_stage(body: &[u8], nonce: &str, expected_count: usize,
    expected_helper_pid: u32, expected_state: LeaseState) -> Result<(), String>
{
    let reply: LeaseReply = serde_json::from_slice(body)
        .map_err(|e| format!("租约回执无效：{e}"))?;
    if reply.schema != LEASE_SCHEMA || reply.nonce != nonce {
        return Err("租约 Ready 回执版本或 nonce 不匹配".into());
    }
    if reply.state != expected_state {
        return Err(format!("租约 helper 拒绝启动：{}", reply.reason));
    }
    if expected_helper_pid == 0 || reply.helper_pid != expected_helper_pid {
        return Err("租约 Ready 回执与启动的 helper 进程 PID 不匹配".into());
    }
    if reply.filter_count != expected_count || !reply.reason.is_empty() {
        return Err("租约 Ready 报告的过滤器数量或状态异常".into());
    }
    Ok(())
}

#[cfg(test)]
fn write_ack(path: &Path, nonce: &str, accepted: bool) -> Result<(), String> {
    let data = serde_json::to_vec(&LeaseAck {
        schema: LEASE_SCHEMA, nonce: nonce.into(), accepted,
    }).map_err(|e| e.to_string())?;
    // ack.json 同样必须原子发布；直接写正式文件会让 helper 的
    // 100ms 轮询读到半截 JSON，并把有效握手误判成攻击而撤销许可。
    let temporary = path.with_extension("json.tmp");
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
        .open(&temporary).map_err(|e| format!("建立租约确认临时文件失败：{e}"))?;
    use std::io::Write;
    if let Err(err) = file.write_all(&data).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("写租约确认失败：{err}"));
    }
    drop(file);
    if let Err(err) = publish_new_file(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("提交租约确认失败：{err}"));
    }
    Ok(())
}

/// 启动器显式返回的子进程句柄。释放 handle 不会结束 Windows 进程；
/// helper 自己负责在 sing-box 或主程序退出时撤销动态 WFP 许可。
// Exactly one local experimental controller registration. Never infer an
// external process's ownership from a runtime PID or a file.
#[cfg(windows)]
#[derive(Default)]
struct LocalLeaseSlot(std::sync::Mutex<LocalLeaseState>);

#[cfg(windows)]
#[derive(Default)]
struct LocalLeaseState {
    current: Option<std::sync::Arc<LocalLeaseControl>>,
    disconnects: usize,
}

#[cfg(windows)]
struct LocalLeaseControl {
    nonce: String,
    controller_pid: u32,
    controller_stamp: u64,
    engine_pid: u32,
    engine_stamp: u64,
    engine: std::os::windows::io::OwnedHandle,
    // Once any request may have reached a helper, keep that process identity
    // until it has actually exited. Pipe closure initiates revocation, but
    // alone is not proof that an old WFP session has already closed.
    helper: std::sync::Mutex<Option<std::os::windows::io::OwnedHandle>>,
    owner_finished: std::sync::atomic::AtomicBool,
    cancelled: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    observed_sequence: std::sync::atomic::AtomicU64,
    // Serialize cancellation with the final gate and each nonblocking write.
    // No polling, sleeping, UAC or BFE work under this lock.
    write_gate: std::sync::Mutex<()>,
}

#[cfg(windows)]
static LOCAL_LEASE: LocalLeaseSlot = LocalLeaseSlot(std::sync::Mutex::new(
    LocalLeaseState { current: None, disconnects: 0 }
));

#[cfg(windows)]
impl LocalLeaseControl {
    fn require_active(&self) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        if self.cancelled.load(Ordering::Acquire) {
            return Err("本次实验租约已取消".into());
        }
        Ok(())
    }

    fn require_identity(&self) -> Result<(), String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId};
        self.require_active()?;
        let handle = self.engine.as_raw_handle();
        pipe_ipc::require_live(handle)?;
        if unsafe { GetProcessId(handle) } != self.engine_pid
            || pipe_ipc::creation_stamp(handle)? != self.engine_stamp
            || self.controller_pid != std::process::id()
            || pipe_ipc::creation_stamp(unsafe { GetCurrentProcess() })? != self.controller_stamp
        {
            return Err("实验租约控制者或引擎身份已变化".into());
        }
        self.require_active()
    }

    fn bind_helper(&self, handle: windows_sys::Win32::Foundation::HANDLE) -> Result<(), String> {
        let duplicate = pipe_ipc::duplicate_process_handle(handle)?;
        let mut helper = self.helper.lock().map_err(|_| "实验租约 helper 身份登记异常")?;
        if helper.is_some() { return Err("实验租约 helper 已登记".into()); }
        *helper = Some(duplicate);
        Ok(())
    }

    fn finished_and_helper_exited(&self) -> bool {
        use std::os::windows::io::AsRawHandle;
        use std::sync::atomic::Ordering;
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        if !self.owner_finished.load(Ordering::Acquire) { return false; }
        let Ok(helper) = self.helper.lock() else { return false; };
        match helper.as_ref() {
            None => true, // no request could have reached an unregistered helper
            Some(h) => unsafe { WaitForSingleObject(h.as_raw_handle(), 0) == WAIT_OBJECT_0 },
        }
    }

    fn authorized<T>(&self, action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _gate = self.write_gate.lock().map_err(|_| "租约取消门状态异常")?;
        self.require_active()?;
        action()
    }

    fn cancel(&self) {
        // On poison still revoke. Never turn poison into authorization.
        let _gate = self.write_gate.lock().unwrap_or_else(|e| e.into_inner());
        self.cancelled.store(true, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(windows)]
pub(crate) struct LocalLeaseRegistration<'a> {
    slot: &'a LocalLeaseSlot,
    control: std::sync::Arc<LocalLeaseControl>,
}

#[cfg(windows)]
impl Drop for LocalLeaseRegistration<'_> {
    fn drop(&mut self) {
        self.control.cancel();
        self.control.owner_finished.store(true, std::sync::atomic::Ordering::Release);
        let mut slot = self.slot.0.lock().unwrap_or_else(|e| e.into_inner());
        if slot.current.as_ref().is_some_and(|current| std::sync::Arc::ptr_eq(current, &self.control))
            && self.control.finished_and_helper_exited()
        {
            slot.current = None;
        }
    }
}

#[cfg(windows)]
impl LocalLeaseSlot {
    fn register(&self, engine_pid: u32, executable: &Path) -> Result<LocalLeaseRegistration<'_>, String> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        use ring::rand::{SecureRandom, SystemRandom};
        let mut slot = self.0.lock().map_err(|_| "实验租约登记状态异常")?;
        if slot.disconnects != 0 { return Err("本进程正在断开，不启动实验租约".into()); }
        Self::reap_finished(&mut slot);
        if slot.current.is_some() { return Err("本进程已有尚未退出的实验租约".into()); }
        if engine_pid == 0 || engine_pid == std::process::id() {
            return Err("实验租约引擎 PID 无效".into());
        }
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000, 0, engine_pid) };
        if raw.is_null() { return Err("无法取得实验引擎真实进程句柄".into()); }
        let engine = unsafe { OwnedHandle::from_raw_handle(raw) };
        unsafe { super::proxy_identity::verify_live_process_handle(engine.as_raw_handle(), engine_pid, executable)?; }
        let engine_stamp = pipe_ipc::creation_stamp(engine.as_raw_handle())?;
        let controller_stamp = pipe_ipc::creation_stamp(unsafe { GetCurrentProcess() })?;
        let mut bytes = [0u8; 16];
        SystemRandom::new().fill(&mut bytes).map_err(|_| "生成动态许可 nonce 失败".to_string())?;
        let nonce = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        decode_nonce(&nonce)?;
        let control = std::sync::Arc::new(LocalLeaseControl {
            nonce, controller_pid: std::process::id(), controller_stamp,
            engine_pid, engine_stamp, engine,
            helper: std::sync::Mutex::new(None),
            owner_finished: std::sync::atomic::AtomicBool::new(false),
            cancelled: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            observed_sequence: std::sync::atomic::AtomicU64::new(0),
            write_gate: std::sync::Mutex::new(()),
        });
        slot.current = Some(control.clone());
        Ok(LocalLeaseRegistration { slot: self, control })
    }

    fn reap_finished(slot: &mut LocalLeaseState) {
        if slot.current.as_ref().is_some_and(|c| c.finished_and_helper_exited()) {
            slot.current = None;
        }
    }

    fn begin_disconnect(&self) -> LocalDisconnectGuard<'_> {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::reap_finished(&mut slot);
        // Prevent a new startup throughout the existing disconnect operation,
        // even if there was no active registration at this instant.
        slot.disconnects = slot.disconnects.checked_add(1).expect("disconnect nesting overflow");
        if let Some(control) = slot.current.as_ref() { control.cancel(); }
        // Do not free the slot here. Only its pipe-owning registration drops it.
        LocalDisconnectGuard(self)
    }

    #[cfg(test)]
    fn cancel_current(&self) {
        drop(self.begin_disconnect());
    }
}

#[cfg(windows)]
pub(crate) struct LocalDisconnectGuard<'a>(&'a LocalLeaseSlot);

#[cfg(windows)]
impl Drop for LocalDisconnectGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.0.0.lock().unwrap_or_else(|e| e.into_inner());
        state.disconnects -= 1;
    }
}

#[cfg(windows)]
pub(crate) fn register_experimental_lease(engine_pid: u32, executable: &Path)
    -> Result<LocalLeaseRegistration<'static>, String>
{
    LOCAL_LEASE.register(engine_pid, executable)
}

#[cfg(windows)]
pub(crate) fn begin_experimental_disconnect() -> LocalDisconnectGuard<'static> {
    LOCAL_LEASE.begin_disconnect()
}

#[cfg(all(windows, test))]
fn cancel_current_experimental_lease() {
    LOCAL_LEASE.cancel_current();
}

// Field order is significant: close the sole client pipe before releasing
// the reservation, even when spawning the worker fails or unwinding.
#[cfg(windows)]
struct RegisteredChannel<'a> {
    pipe: pipe_ipc::Pipe,
    registration: LocalLeaseRegistration<'a>,
}

#[cfg(windows)]
pub struct LeaseChild {
    handle: windows_sys::Win32::Foundation::HANDLE,
    control: std::sync::Arc<LocalLeaseControl>,
    // TerminateProcess is best-effort, never the authority for revocation.
    confirmed: bool,
}
#[cfg(windows)]
impl LeaseChild {
    pub fn running(&self) -> bool {
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
        self.control.require_active().is_ok()
            && unsafe { WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT }
    }
}
#[cfg(windows)]
impl Drop for LeaseChild {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if !self.confirmed {
                // Best effort only; the helper independently fails closed
                // on disconnect or timeout.
                self.control.cancel();
                unsafe { windows_sys::Win32::System::Threading::TerminateProcess(self.handle, 1); }
            }
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle); }
            self.handle = std::ptr::null_mut();
        }
        // The process-lifetime worker owns the confirmed pipe and duplicated
        // process handle. Dropping this startup handle is not cancellation.
    }
}

/// 默认关闭的实验入口调用此启动器；不改变生产连接或持久规则。
#[cfg(windows)]
pub(crate) fn launch_elevated(request: &LeaseRequest, registration: LocalLeaseRegistration<'static>) -> Result<LeaseChild, String> {
    use pipe_ipc::*;
    use std::os::windows::ffi::OsStrExt;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW, SEE_MASK_NOCLOSEPROCESS};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    if request.controller_pid != std::process::id() {
        return Err("只有正在运行的发起进程可以申请本次动态租约".into());
    }
    let own = unsafe { GetCurrentProcess() };
    let controller_token = token_identity(own)?;
    let controller_stamp = creation_stamp(own)?;
    let control = registration.control.clone();
    control.require_identity()?;
    if request.engine_pid != control.engine_pid || controller_stamp != control.controller_stamp {
        return Err("实验租约登记与请求身份不匹配".into());
    }
    let nonce = control.nonce.clone();
    let mut req = request.clone();
    req.nonce = nonce.clone();
    validate_request(&req)?;
    let data = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    if data.len() > MAX_LEASE_IPC_BYTES { return Err("租约请求过大".into()); }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    // Existing main dispatch takes exactly two values. Neither is a filesystem path.
    let args_w: Vec<u16> = format!("{LEASE_FLAG} {nonce} {}-{controller_stamp}", req.controller_pid)
        .encode_utf16().chain(Some(0)).collect();
    let verb_w: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb_w.as_ptr();
    info.lpFile = exe_w.as_ptr();
    info.lpParameters = args_w.as_ptr();
    info.nShow = SW_HIDE;
    control.require_identity()?;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(format!("无法启动提权 WFP helper（Win32={}）", unsafe { GetLastError() }));
    }
    if info.hProcess.is_null() { return Err("启动后未获得 helper 进程句柄".into()); }
    let mut child = LeaseChild { handle: info.hProcess, control: control.clone(), confirmed: false };
    control.require_identity()?;
    let helper_pid = unsafe { GetProcessId(child.handle) };
    verify_same_image(child.handle, helper_pid)?;
    let helper_stamp = creation_stamp(child.handle)?;
    let helper_token = token_identity(child.handle)?;
    if !helper_token.elevated || helper_token.session != controller_token.session {
        return Err("helper 未提权或不在相同交互会话".into());
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let pipe = Pipe::client(&nonce, deadline, || {
        control.require_identity()?;
        require_live(child.handle)
    })?;
    let check = || -> Result<(), String> {
        control.require_identity()?;
        require_live(child.handle)?;
        pipe.require_peer(helper_pid, false)?;
        pipe.require_connected()
    };
    check()?;
    // Authenticate the actual connected process BEFORE sending any request bytes.
    if creation_stamp(child.handle)? != helper_stamp || token_identity(child.handle)? != helper_token {
        return Err("helper 创建时间或 token 变化".into());
    }
    // The old slot cannot be replaced after pipe closure until the actual
    // helper exits. Bind before the first request write, even on later error.
    control.bind_helper(child.handle)?;
    pipe.send_guarded(&data, deadline, &check, &control)?;
    let ready = pipe.receive(4096, deadline, &check)?;
    validate_stage(&ready, &nonce, req.programs.len(), helper_pid, LeaseState::Ready)?;
    let ack = serde_json::to_vec(&LeaseAck { schema: LEASE_SCHEMA, nonce: nonce.clone(), accepted: true })
        .map_err(|e| e.to_string())?;
    pipe.send_guarded(&ack, deadline, &check, &control)?;
    let accepted = pipe.receive(4096, deadline, &check)?;
    validate_stage(&accepted, &nonce, req.programs.len(), helper_pid, LeaseState::Accepted)?;
    // A distinct final authorization is sent only after the authenticated consumption
    // receipt was actually read. An abandoned handshake cannot transition on ACK alone.
    if token_identity(child.handle)? != helper_token || creation_stamp(child.handle)? != helper_stamp {
        return Err("helper 最终身份复验失败".into());
    }
    let finish = serde_json::to_vec(&LeaseFinish { schema: LEASE_SCHEMA, nonce: nonce.clone(), state: LeaseState::Committed })
        .map_err(|e| e.to_string())?;
    pipe.send_guarded(&finish, deadline, &check, &control)?;
    let committed = pipe.receive(4096, deadline, &check)?;
    validate_stage(&committed, &nonce, req.programs.len(), helper_pid, LeaseState::Committed)?;
    check()?;
    let receipt = serde_json::to_vec(&LeaseFinish { schema: LEASE_SCHEMA, nonce: nonce.clone(), state: LeaseState::Receipt })
        .map_err(|e| e.to_string())?;
    pipe.send_guarded(&receipt, deadline, &check, &control)?;
    // Closing either end is NEVER success.
    let active = pipe.receive(4096, deadline, &check)?;
    validate_stage(&active, &nonce, req.programs.len(), helper_pid, LeaseState::Active)?;
    check()?;
    // Active alone is not evidence that the helper has consumed a valid
    // heartbeat. The next challenge can only follow an authenticated round.
    // Keep ownership here: any failure before worker authorization drops pipe.
    let pending = confirm_first_heartbeat(&pipe, child.handle, &nonce, helper_pid,
        helper_stamp, &helper_token, deadline, Some(&control))?;
    let helper_monitor = duplicate_process_handle(child.handle)?;
    if !child.running() || Instant::now() >= deadline {
        return Err("最终租约回执超期或进程退出".into());
    }
    // The existing connection caller drops LeaseChild after checking running().
    // Transfer the sole client pipe to a process-lifetime worker only on success.
    // On thread creation failure the captured pipe is dropped, independently
    // of whether the parent can terminate the elevated process.
    let channel = RegisteredChannel { pipe, registration };
    let start = spawn_controller_worker(channel, helper_monitor, nonce, helper_pid,
        helper_stamp, helper_token, pending, deadline)?;
    if !child.running() || Instant::now() >= deadline {
        return Err("租约监督移交前已超时或 helper 退出".into());
    }
    control.authorized(|| start.send(()).map_err(|_| "租约监督线程未接管".to_string()))?;
    // No fallible caller-side operation can occur after authorizing renewal.
    child.confirmed = true;
    Ok(child)
}

#[cfg(any(windows, test))]
fn reply(nonce: &str, state: LeaseState, reason: String, count: usize) -> LeaseReply {
    LeaseReply { schema: LEASE_SCHEMA, nonce: nonce.to_owned(), state, reason, filter_count: count, helper_pid: std::process::id() }
}

#[cfg(test)]
fn directory_receipt(directory: &Path) -> PathBuf {
    directory.join("accepted.json")
}

// Parse only the new two-value internal protocol. Old request/reply paths fail without I/O.
fn parse_pipe_arguments(nonce: &Path, controller: &Path) -> Result<(String, u32, u64), String> {
    let nonce = nonce.to_str().ok_or("无效的租约 nonce")?;
    decode_nonce(nonce)?;
    let controller = controller.to_str().ok_or("无效的租约控制进程参数")?;
    let (pid, stamp) = controller.split_once('-').ok_or("缺少控制进程创建时间")?;
    let pid: u32 = pid.parse().map_err(|_| "控制进程 PID 无效")?;
    let stamp: u64 = stamp.parse().map_err(|_| "控制进程创建时间无效")?;
    if pid == 0 || stamp == 0 || controller != format!("{pid}-{stamp}") {
        return Err("控制进程参数不符合严格协议".into());
    }
    Ok((nonce.to_owned(), pid, stamp))
}

/// Elevated helper. No privileged filesystem transport, even for failure replies.
pub fn serve(nonce_arg: &Path, controller_arg: &Path) -> i32 {
    let Ok((nonce, pid, stamp)) = parse_pipe_arguments(nonce_arg, controller_arg) else { return 2; };
    #[cfg(windows)]
    {
        if !super::elevate::is_elevated() { return 2; }
        match serve_pipe(&nonce, pid, stamp) {
            Ok(()) => 0,
            Err(_) => 6,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (nonce, pid, stamp);
        3
    }
}

#[cfg(windows)]
fn serve_pipe(nonce: &str, pid: u32, stamp: u64) -> Result<(), String> {
    use pipe_ipc::*;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let controller = open_controller(pid, stamp)?;
    let controller_token = token_identity(controller.0)?;
    let helper_token = token_identity(unsafe { GetCurrentProcess() })?;
    if !helper_token.elevated || helper_token.session != controller_token.session {
        return Err("租约双方 token 不属于允许的交互会话".into());
    }
    let pipe = Pipe::server(nonce, &controller_token, &helper_token)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    pipe.accept(deadline, || require_live(controller.0))?;
    let check = || -> Result<(), String> {
        require_live(controller.0)?;
        pipe.require_peer(pid, true)?;
        pipe.require_connected()
    };
    check()?;
    if token_identity(controller.0)? != controller_token || creation_stamp(controller.0)? != stamp {
        return Err("租约控制进程 token 或创建时间不匹配".into());
    }
    let body = pipe.receive(MAX_LEASE_IPC_BYTES, deadline, &check)?;
    // The token attached to actual pipe traffic must agree with the retained
    // controller process token. Query at Identification level, never use it for I/O.
    pipe.require_client_token(&controller_token)?;
    let req: LeaseRequest = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    let nonce_bytes = validate_request(&req)?;
    if req.nonce != nonce || req.controller_pid != pid {
        return Err("租约请求与操作系统对端不一致".into());
    }
    verify_same_image(controller.0, pid)?;
    check()?;
    if Instant::now() >= deadline { return Err("租约请求超期".into()); }
    let lease = match super::wfp_win::DynamicProxyLease::acquire(
        &req.programs, req.endpoint, req.engine_pid, pid, &req.engine_executable, &nonce_bytes,
    ) {
        Ok(lease) => lease,
        Err(reason) => {
            if let Ok(body) = serde_json::to_vec(&reply(nonce, LeaseState::Rejected, reason.clone(), 0)) {
                let _ = pipe.send(&body, deadline, &check);
            }
            return Err(reason);
        }
    };
    let count = lease.count();
    let mut lease = Some(lease);
    // Every handshake poll revalidates the live lease; a failure consumes the lease.
    let mut check_lease = || -> Result<(), String> {
        check()?;
        let current = lease.take().ok_or("动态租约不可用")?;
        lease = Some(current.revalidate(&req.engine_executable)?);
        Ok(())
    };
    let ready = serde_json::to_vec(&reply(nonce, LeaseState::Ready, String::new(), count))
        .map_err(|e| e.to_string())?;
    pipe.send(&ready, deadline, &mut check_lease)?;
    let ack = pipe.receive(4096, deadline, &mut check_lease)?;
    parse_ack(&ack, nonce)?;
    pipe.require_client_token(&controller_token)?;
    check_lease()?;
    if token_identity(controller.0)? != controller_token || creation_stamp(controller.0)? != stamp {
        return Err("租约控制进程最终身份复验失败".into());
    }
    let accepted = serde_json::to_vec(&reply(nonce, LeaseState::Accepted, String::new(), count))
        .map_err(|e| e.to_string())?;
    pipe.send(&accepted, deadline, &mut check_lease)?;
    let finish = pipe.receive(4096, deadline, &mut check_lease)?;
    validate_finish(&finish, nonce)?;
    check_lease()?;
    let committed = serde_json::to_vec(&reply(nonce, LeaseState::Committed, String::new(), count))
        .map_err(|e| e.to_string())?;
    pipe.send(&committed, deadline, &mut check_lease)?;
    let result = finish_and_supervise(&pipe, nonce, count, &controller_token, deadline, &mut check_lease);
    let close = match lease.take() {
        Some(lease) => lease.close().map_err(|e| e.to_string()),
        None => Ok(()),
    };
    result.and(close)
}

// Shared by the real helper and the different-process regression; no mock transport.
#[cfg(windows)]
fn finish_and_supervise(pipe: &pipe_ipc::Pipe, nonce: &str, count: usize,
    identity: &pipe_ipc::TokenIdentity, deadline: std::time::Instant,
    mut check: impl FnMut() -> Result<(), String>) -> Result<(), String>
{
    let receipt = pipe.receive(4096, deadline, &mut check)?;
    validate_finish_stage(&receipt, nonce, LeaseState::Receipt)?;
    pipe.require_client_token(identity)?;
    check()?;
    if std::time::Instant::now() >= deadline { return Err("最终回执消费超时".into()); }
    let active = serde_json::to_vec(&reply(nonce, LeaseState::Active, String::new(), count))
        .map_err(|e| e.to_string())?;
    pipe.send(&active, deadline, &mut check)?;
    supervise_authenticated_channel(pipe, nonce, identity, &mut check)
}

#[cfg(windows)]
const HEARTBEAT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
#[cfg(windows)]
const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

// Shared by startup and the long-lived worker. Never reply to a challenge whose
// sequence, peer process object or token cannot be authenticated.
#[cfg(windows)]
fn controller_heartbeat_check(pipe: &pipe_ipc::Pipe,
    handle: windows_sys::Win32::Foundation::HANDLE, pid: u32, stamp: u64,
    identity: &pipe_ipc::TokenIdentity) -> Result<(), String>
{
    use pipe_ipc::*;
    require_live(handle)?;
    pipe.require_peer(pid, false)?;
    pipe.require_connected()?;
    if creation_stamp(handle)? != stamp || &token_identity(handle)? != identity {
        return Err("租约监督期间 helper 身份变化".into());
    }
    Ok(())
}

#[cfg(windows)]
fn confirm_first_heartbeat(pipe: &pipe_ipc::Pipe,
    handle: windows_sys::Win32::Foundation::HANDLE, nonce: &str, pid: u32, stamp: u64,
    identity: &pipe_ipc::TokenIdentity, startup_deadline: std::time::Instant,
    control: Option<&LocalLeaseControl>) -> Result<Vec<u8>, String>
{
    use std::time::Instant;
    let deadline = startup_deadline.min(Instant::now() + HEARTBEAT_TIMEOUT + HEARTBEAT_INTERVAL);
    let check = || {
        if let Some(control) = control { control.require_identity()?; }
        controller_heartbeat_check(pipe, handle, pid, stamp, identity)
    };
    let first = pipe.receive(4096, deadline, &check)?;
    decode_heartbeat(&first, nonce, 1)?;
    match control {
        Some(control) => pipe.send_guarded(&first, deadline, &check, control)?,
        None => pipe.send(&first, deadline, &check)?,
    }
    // Sequence 2 is issued by the authenticated helper only after the first
    // response was consumed, verified and the lease revalidated. No extra
    // unauthenticated "success" message or disconnect-as-success path.
    let next = pipe.receive(4096, deadline, &check)?;
    decode_heartbeat(&next, nonce, 2)?;
    check()?;
    if Instant::now() >= deadline { return Err("首轮租约心跳确认超时".into()); }
    Ok(next)
}

// Both production and the real-process+BFE fixture exercise this exact
// worker handoff, including the one-shot authorization gate.
#[cfg(windows)]
fn spawn_controller_worker(channel: RegisteredChannel<'static>,
    helper: std::os::windows::io::OwnedHandle, nonce: String, pid: u32, stamp: u64,
    identity: pipe_ipc::TokenIdentity, pending: Vec<u8>, deadline: std::time::Instant)
    -> Result<std::sync::mpsc::SyncSender<()>, String>
{
    use std::time::Instant;
    let (start, permission) = std::sync::mpsc::sync_channel::<()>(1);
    std::thread::Builder::new().name("spidervpn-lease-channel".into())
        .spawn(move || {
            // Capture the whole struct, never disjoint fields in the closure.
            let channel = channel;
            if permission.recv_timeout(deadline.saturating_duration_since(Instant::now())).is_err()
                || Instant::now() >= deadline
                || channel.registration.control.require_identity().is_err()
            {
                return;
            }
            let _ = maintain_controller_channel(&channel.pipe, helper, &nonce, pid,
                stamp, &identity, pending, &channel.registration.control);
        }).map_err(|e| format!("启动租约信道监督失败：{e}"))?;
    Ok(start)
}

#[cfg(windows)]
fn maintain_controller_channel(pipe: &pipe_ipc::Pipe, helper: std::os::windows::io::OwnedHandle,
    nonce: &str, pid: u32, stamp: u64, identity: &pipe_ipc::TokenIdentity,
    pending: Vec<u8>, control: &LocalLeaseControl) -> Result<(), String>
{
    use std::os::windows::io::AsRawHandle;
    use std::time::Instant;
    let check = || {
        control.require_identity()?;
        controller_heartbeat_check(pipe, helper.as_raw_handle(), pid, stamp, identity)
    };
    let mut sequence = 2u64;
    let mut pending = Some(pending);
    loop {
        let deadline = Instant::now() + HEARTBEAT_TIMEOUT + HEARTBEAT_INTERVAL;
        let body = match pending.take() {
            Some(body) => body,
            None => pipe.receive(4096, deadline, &check)?,
        };
        decode_heartbeat(&body, nonce, sequence)?;
        #[cfg(test)]
        control.observed_sequence.store(sequence, std::sync::atomic::Ordering::Release);
        pipe.send_guarded(&body, deadline, &check, control)?;
        sequence = sequence.checked_add(1).ok_or("租约心跳顺序溢出")?;
    }
}

#[cfg(windows)]
fn supervise_authenticated_channel(pipe: &pipe_ipc::Pipe, nonce: &str,
    identity: &pipe_ipc::TokenIdentity, mut check: impl FnMut() -> Result<(), String>) -> Result<(), String>
{
    use ring::rand::{SecureRandom, SystemRandom};
    use std::time::Instant;
    let random = SystemRandom::new();
    let mut sequence = 1u64;
    loop {
        check()?;
        let deadline = Instant::now() + HEARTBEAT_TIMEOUT;
        let mut bytes = [0u8; 16];
        random.fill(&mut bytes).map_err(|_| "生成租约心跳挑战失败".to_string())?;
        let challenge = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        decode_nonce(&challenge)?;
        let expected = LeaseHeartbeat { schema: LEASE_SCHEMA, nonce: nonce.into(), sequence, challenge };
        let encoded = serde_json::to_vec(&expected).map_err(|e| e.to_string())?;
        pipe.send(&encoded, deadline, &mut check)?;
        let body = pipe.receive(4096, deadline, &mut check)?;
        if decode_heartbeat(&body, nonce, sequence)? != expected {
            return Err("租约心跳挑战不匹配".into());
        }
        pipe.require_client_token(identity)?;
        check()?;
        if Instant::now() >= deadline { return Err("租约心跳超时".into()); }
        sequence = sequence.checked_add(1).ok_or("租约心跳顺序溢出")?;
        std::thread::sleep(HEARTBEAT_INTERVAL);
    }
}

#[cfg(windows)]
mod pipe_ipc {
    use super::*;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::Pipes::*;
    use windows_sys::Win32::System::Threading::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle as StdOwnedHandle};

    pub(super) struct OwnedHandle(pub(super) HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0); }
            }
        }
    }

    fn os_error(context: &str) -> String {
        format!("{context}: {}", std::io::Error::last_os_error())
    }

    pub(super) fn require_live(handle: HANDLE) -> Result<(), String> {
        if unsafe { WaitForSingleObject(handle, 0) } != WAIT_TIMEOUT {
            return Err("租约对端进程已退出或不可核验".into());
        }
        Ok(())
    }

    pub(super) fn creation_stamp(handle: HANDLE) -> Result<u64, String> {
        let (mut created, mut exited, mut kernel, mut user) = unsafe {
            (std::mem::zeroed::<FILETIME>(), std::mem::zeroed::<FILETIME>(),
             std::mem::zeroed::<FILETIME>(), std::mem::zeroed::<FILETIME>())
        };
        if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
            return Err(os_error("读取租约对端进程创建时间失败"));
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct TokenIdentity {
        pub(super) sid: String,
        pub(super) session: u32,
        pub(super) elevated: bool,
        authentication_id: u64,
    }

    // The token belongs to the actual retained process object, not a SID in JSON.
    pub(super) fn token_identity(process: HANDLE) -> Result<TokenIdentity, String> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(os_error("读取租约对端 token 失败"));
        }
        let token = OwnedHandle(token);
        read_token(&token)
    }

    fn read_token(token: &OwnedHandle) -> Result<TokenIdentity, String> {
        let mut length = 0u32;
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut length); }
        if length < std::mem::size_of::<TOKEN_USER>() as u32 || length > 65536 {
            return Err("租约 token SID 长度异常".into());
        }
        // TOKEN_USER contains a pointer and requires native alignment.
        let mut data = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        let mut actual = length;
        if unsafe { GetTokenInformation(token.0, TokenUser, data.as_mut_ptr().cast(), length, &mut actual) } == 0
            || actual < std::mem::size_of::<TOKEN_USER>() as u32 || actual > length
        {
            return Err(os_error("读取租约 token 用户失败"));
        }
        let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
        let mut sid_text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0 || sid_text.is_null() {
            return Err(os_error("转换租约 token SID 失败"));
        }
        // Windows owns the nul terminated string, LocalFree after the bounded copy.
        let mut n = 0usize;
        while n < 256 && unsafe { *sid_text.add(n) } != 0 { n += 1; }
        let sid = if n < 256 {
            String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, n) }).ok()
        } else { None };
        unsafe { LocalFree(sid_text.cast()); }
        let sid = sid.ok_or("租约 token SID 字符串异常")?;
        if !sid.starts_with("S-1-") || !sid.bytes().all(|v| v == b'S' || v == b'-' || v.is_ascii_digit()) {
            return Err("租约 token SID 格式异常".into());
        }
        let mut session = 0u32;
        let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
        if unsafe { GetTokenInformation(token.0, TokenSessionId, (&mut session as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32, &mut actual) } == 0
            || actual != std::mem::size_of::<u32>() as u32
        {
            return Err(os_error("读取租约 token 会话失败"));
        }
        if unsafe { GetTokenInformation(token.0, TokenElevation, (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut actual) } == 0
            || actual != std::mem::size_of::<TOKEN_ELEVATION>() as u32
        {
            return Err(os_error("读取租约 token 提权状态失败"));
        }
        let mut stats: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
        if unsafe { GetTokenInformation(token.0, TokenStatistics, (&mut stats as *mut TOKEN_STATISTICS).cast(),
            std::mem::size_of::<TOKEN_STATISTICS>() as u32, &mut actual) } == 0
            || actual != std::mem::size_of::<TOKEN_STATISTICS>() as u32
        {
            return Err(os_error("读取租约 token 登录会话失败"));
        }
        let authentication_id = (u64::from(stats.AuthenticationId.HighPart as u32) << 32)
            | u64::from(stats.AuthenticationId.LowPart);
        Ok(TokenIdentity { sid, session, elevated: elevation.TokenIsElevated != 0, authentication_id })
    }

    pub(super) fn open_controller(pid: u32, stamp: u64) -> Result<OwnedHandle, String> {
        if pid == 0 || pid == std::process::id() || stamp == 0 {
            return Err("租约控制进程身份不合法".into());
        }
        let h = OwnedHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000, 0, pid) });
        if h.0.is_null() { return Err(os_error("打开租约控制进程失败")); }
        require_live(h.0)?;
        if creation_stamp(h.0)? != stamp {
            return Err("租约控制进程创建时间不匹配".into());
        }
        verify_same_image(h.0, pid)?;
        Ok(h)
    }

    pub(super) fn verify_same_image(handle: HANDLE, pid: u32) -> Result<(), String> {
        require_live(handle)?;
        if pid == 0 || unsafe { GetProcessId(handle) } != pid {
            return Err("租约进程句柄与 PID 不匹配".into());
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        // This exact process object is already retained by the launcher/server.
        unsafe { super::super::proxy_identity::verify_live_process_handle(handle, pid, &exe)?; }
        require_live(handle)
    }

    fn name(nonce: &str) -> Result<Vec<u16>, String> {
        decode_nonce(nonce)?;
        Ok(format!(r"\\.\pipe\SpiderVPN.Lease.{nonce}").encode_utf16().chain(Some(0)).collect())
    }

    pub(super) fn duplicate_process_handle(handle: HANDLE) -> Result<StdOwnedHandle, String> {
        let current = unsafe { GetCurrentProcess() };
        let mut duplicate = std::ptr::null_mut();
        if unsafe { DuplicateHandle(current, handle, current, &mut duplicate, 0, 0, DUPLICATE_SAME_ACCESS) } == 0 {
            return Err(os_error("复制租约监督进程句柄失败"));
        }
        if duplicate.is_null() || duplicate == INVALID_HANDLE_VALUE {
            return Err("复制租约监督进程句柄无效".into());
        }
        Ok(unsafe { StdOwnedHandle::from_raw_handle(duplicate) })
    }

    pub(super) struct Pipe(StdOwnedHandle);

    impl Pipe {
        fn raw(&self) -> HANDLE { self.0.as_raw_handle() }

        pub(super) fn require_connected(&self) -> Result<(), String> {
            let mut available = 0u32;
            if unsafe { PeekNamedPipe(self.raw(), std::ptr::null_mut(), 0,
                std::ptr::null_mut(), &mut available, std::ptr::null_mut()) } == 0
            {
                return Err(os_error("租约认证信道已关闭或不可核验"));
            }
            Ok(())
        }

        // Only exact process-token user SIDs. No Everyone/Users/Administrators group ACE.
        // The controller needs data and attribute access, not FILE_CREATE_PIPE_INSTANCE.
        // Medium mandatory integrity permits the intended ordinary UI to connect.
        pub(super) fn server(nonce: &str, controller: &TokenIdentity, helper: &TokenIdentity) -> Result<Self, String> {
            let name = name(nonce)?;
            let sddl: Vec<u16> = format!("D:P(A;;GA;;;{})(A;;0x00120183;;;{})S:(ML;;NW;;;ME)",
                helper.sid, controller.sid).encode_utf16().chain(Some(0)).collect();
            let mut sd = std::ptr::null_mut();
            if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1,
                &mut sd, std::ptr::null_mut()) } == 0 || sd.is_null()
            {
                return Err(os_error("建立租约管道安全描述符失败"));
            }
            let attr = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let h = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1, 65536, 65536, 0, &attr) };
            unsafe { LocalFree(sd.cast()); }
            if h == INVALID_HANDLE_VALUE || h.is_null() {
                return Err(os_error("建立唯一租约命名管道失败"));
            }
            Ok(Self(unsafe { StdOwnedHandle::from_raw_handle(h) }))
        }

        pub(super) fn client(nonce: &str, deadline: Instant, mut check: impl FnMut() -> Result<(), String>) -> Result<Self, String> {
            let name = name(nonce)?;
            loop {
                check()?;
                if Instant::now() >= deadline { return Err("连接租约管道超时".into()); }
                let h = unsafe { CreateFileW(name.as_ptr(), 0x00120183, 0, std::ptr::null(),
                    OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, std::ptr::null_mut()) };
                if h != INVALID_HANDLE_VALUE && !h.is_null() {
                    let pipe = Self(unsafe { StdOwnedHandle::from_raw_handle(h) });
                    let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
                    if unsafe { SetNamedPipeHandleState(pipe.raw(), &mode, std::ptr::null(), std::ptr::null()) } == 0 {
                        return Err(os_error("设置租约管道非阻塞模式失败"));
                    }
                    return Ok(pipe);
                }
                let err = unsafe { GetLastError() };
                if err != ERROR_FILE_NOT_FOUND && err != ERROR_PIPE_BUSY {
                    return Err(format!("打开本地租约管道失败：Win32={err}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        pub(super) fn accept(&self, deadline: Instant, mut check: impl FnMut() -> Result<(), String>) -> Result<(), String> {
            loop {
                check()?;
                if Instant::now() >= deadline { return Err("等待租约控制端超时".into()); }
                if unsafe { ConnectNamedPipe(self.raw(), std::ptr::null_mut()) } != 0 {
                    return Ok(());
                }
                let err = unsafe { GetLastError() };
                if err == ERROR_PIPE_CONNECTED { return Ok(()); }
                if err != ERROR_PIPE_LISTENING {
                    return Err(format!("租约管道连接失败：Win32={err}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        pub(super) fn require_peer(&self, expected: u32, server_end: bool) -> Result<(), String> {
            let mut actual = 0u32;
            let ok = unsafe {
                if server_end { GetNamedPipeClientProcessId(self.raw(), &mut actual) }
                else { GetNamedPipeServerProcessId(self.raw(), &mut actual) }
            };
            if ok == 0 || expected == 0 || actual != expected {
                return Err("操作系统返回的租约管道对端 PID 不匹配".into());
            }
            Ok(())
        }

        pub(super) fn require_client_token(&self, expected: &TokenIdentity) -> Result<(), String> {
            // Successful impersonation is immediately scoped. Never access files,
            // WFP or other privileged resources under the peer token.
            if unsafe { ImpersonateNamedPipeClient(self.raw()) } == 0 {
                return Err(os_error("无法核验实际管道客户端 token"));
            }
            struct Revert;
            impl Drop for Revert {
                fn drop(&mut self) {
                    if unsafe { RevertToSelf() } == 0 {
                        // Cannot safely continue elevated work with uncertain identity.
                        std::process::abort();
                    }
                }
            }
            let revert = Revert;
            let mut token = std::ptr::null_mut();
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
                return Err(os_error("读取实际管道客户端 token 失败"));
            }
            let token = OwnedHandle(token);
            let actual = read_token(&token)?;
            drop(token);
            drop(revert);
            if &actual != expected {
                return Err("实际管道客户端 SID/登录会话/token 与控制进程不匹配".into());
            }
            Ok(())
        }

        #[cfg(test)]
        pub(super) fn wait_server_closed(&self, deadline: Instant,
            mut check: impl FnMut() -> Result<(), String>) -> Result<(), String>
        {
            loop {
                check()?;
                if Instant::now() >= deadline { return Err("等待最终回执消费超时".into()); }
                let mut available = 0u32;
                let ok = unsafe { PeekNamedPipe(self.raw(), std::ptr::null_mut(), 0,
                    std::ptr::null_mut(), &mut available, std::ptr::null_mut()) };
                if ok == 0 {
                    let err = unsafe { GetLastError() };
                    if err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED {
                        check()?;
                        return Ok(());
                    }
                    return Err(format!("等待租约管道正常关闭失败：Win32={err}"));
                }
                if available != 0 { return Err("最终确认后存在额外管道数据".into()); }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        fn transfer(&self, read: bool, bytes: &mut [u8], deadline: Instant,
            check: &mut impl FnMut() -> Result<(), String>,
            control: Option<&super::LocalLeaseControl>) -> Result<(), String>
        {
            let mut offset = 0usize;
            while offset < bytes.len() {
                check()?;
                if Instant::now() >= deadline { return Err("租约管道 I/O 超时".into()); }
                let chunk = &mut bytes[offset..];
                let mut count = 0u32;
                let mut io = || {
                    let ok = unsafe {
                        if read { ReadFile(self.raw(), chunk.as_mut_ptr(), chunk.len() as u32, &mut count, std::ptr::null_mut()) }
                        else { WriteFile(self.raw(), chunk.as_ptr(), chunk.len() as u32, &mut count, std::ptr::null_mut()) }
                    };
                    // Capture thread-local Win32 error before releasing gate.
                    Ok((ok, if ok == 0 { unsafe { GetLastError() } } else { 0 }))
                };
                let (ok, err) = match control {
                    Some(control) => control.authorized(io)?,
                    None => io()?,
                };
                if ok == 0 {
                    if err != ERROR_NO_DATA {
                        return Err(format!("租约管道 I/O 失败：Win32={err}"));
                    }
                    // A closing pipe also returns NO_DATA; bounded timeout is fail closed.
                    if count != 0 { return Err("租约管道部分失败".into()); }
                }
                if count as usize > chunk.len() { return Err("租约管道长度越界".into()); }
                offset += count as usize;
                if count == 0 { std::thread::sleep(Duration::from_millis(50)); }
            }
            check()?;
            if Instant::now() >= deadline { return Err("租约管道消息已超期".into()); }
            Ok(())
        }

        pub(super) fn send(&self, bytes: &[u8], deadline: Instant,
            mut check: impl FnMut() -> Result<(), String>) -> Result<(), String>
        {
            if bytes.is_empty() || bytes.len() > MAX_LEASE_IPC_BYTES {
                return Err("租约管道发送长度异常".into());
            }
            let mut frame = Vec::with_capacity(bytes.len() + 4);
            frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            frame.extend_from_slice(bytes);
            self.transfer(false, &mut frame, deadline, &mut check, None)
        }

        pub(super) fn send_guarded(&self, bytes: &[u8], deadline: Instant,
            mut check: impl FnMut() -> Result<(), String>, control: &super::LocalLeaseControl) -> Result<(), String>
        {
            if bytes.is_empty() || bytes.len() > MAX_LEASE_IPC_BYTES {
                return Err("租约管道发送长度异常".into());
            }
            let mut frame = Vec::with_capacity(bytes.len() + 4);
            frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            frame.extend_from_slice(bytes);
            self.transfer(false, &mut frame, deadline, &mut check, Some(control))
        }

        pub(super) fn receive(&self, limit: usize, deadline: Instant,
            mut check: impl FnMut() -> Result<(), String>) -> Result<Vec<u8>, String>
        {
            let mut header = [0u8; 4];
            self.transfer(true, &mut header, deadline, &mut check, None)?;
            let size = u32::from_le_bytes(header) as usize;
            if size == 0 || size > limit || size > MAX_LEASE_IPC_BYTES {
                return Err("租约管道消息长度异常".into());
            }
            let mut body = vec![0u8; size];
            self.transfer(true, &mut body, deadline, &mut check, None)?;
            Ok(body)
        }
    }


}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use super::pipe_ipc::*;
    #[cfg(windows)]
    use std::time::{Duration, Instant};
    #[cfg(windows)]
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    #[cfg(windows)]
    fn random_nonce() -> String {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0u8; 16];
        SystemRandom::new().fill(&mut bytes).unwrap();
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[cfg(windows)]
    #[test]
    fn real_pipe_rejects_wrong_peer_and_duplicate_instance_and_bounds_frames() {
        let nonce = random_nonce();
        let token = token_identity(unsafe { GetCurrentProcess() }).unwrap();
        let server = Pipe::server(&nonce, &token, &token).unwrap();
        assert!(Pipe::server(&nonce, &token, &token).is_err());
        let deadline = Instant::now() + Duration::from_secs(3);
        let client = Pipe::client(&nonce, deadline, || Ok(())).unwrap();
        server.accept(deadline, || Ok(())).unwrap();
        let pid = std::process::id();
        server.require_peer(pid, true).unwrap();
        client.require_peer(pid, false).unwrap();
        assert!(server.require_peer(pid ^ 1, true).is_err());
        assert!(client.require_peer(pid ^ 1, false).is_err());
        client.send(b"ack", deadline, || Ok(())).unwrap();
        assert_eq!(server.receive(3, deadline, || Ok(())).unwrap(), b"ack");
        server.require_client_token(&token).unwrap();
        assert_eq!(token_identity(unsafe { GetCurrentProcess() }).unwrap(), token);
        server.send(b"accepted", deadline, || Ok(())).unwrap();
        assert_eq!(client.receive(8, deadline, || Ok(())).unwrap(), b"accepted");
        client.send(b"oversize", deadline, || Ok(())).unwrap();
        assert!(server.receive(3, deadline, || Ok(())).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn real_pipe_absent_ack_times_out_and_closed_peer_fails() {
        let nonce = random_nonce();
        let token = token_identity(unsafe { GetCurrentProcess() }).unwrap();
        let server = Pipe::server(&nonce, &token, &token).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let client = Pipe::client(&nonce, deadline, || Ok(())).unwrap();
        server.accept(deadline, || Ok(())).unwrap();
        assert!(server.receive(4096, Instant::now() + Duration::from_millis(150), || Ok(())).is_err());
        drop(client);
        assert!(server.receive(4096, Instant::now() + Duration::from_millis(200), || Ok(())).is_err());
    }


    #[cfg(windows)]
    #[test]
    fn final_pipe_receipt_must_be_read_before_server_close() {
        let nonce = random_nonce();
        let token = token_identity(unsafe { GetCurrentProcess() }).unwrap();
        let server = Pipe::server(&nonce, &token, &token).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let client = Pipe::client(&nonce, deadline, || Ok(())).unwrap();
        server.accept(deadline, || Ok(())).unwrap();
        server.send(b"committed", deadline, || Ok(())).unwrap();
        assert_eq!(client.receive(9, deadline, || Ok(())).unwrap(), b"committed");
        assert!(client.wait_server_closed(Instant::now() + Duration::from_millis(150), || Ok(())).is_err());
        client.send(b"receipt", deadline, || Ok(())).unwrap();
        assert_eq!(server.receive(7, deadline, || Ok(())).unwrap(), b"receipt");
        server.require_client_token(&token).unwrap();
        drop(server);
        client.wait_server_closed(deadline, || Ok(())).unwrap();
    }

    #[test]
    fn old_file_transport_arguments_fail_without_io() {
        let nonce = "0123456789abcdef0123456789abcdef";
        assert!(parse_pipe_arguments(Path::new(nonce), Path::new("42-1234")).is_ok());
        for invalid in ["42", "0-5", "42-0", "042-1", "42-1-2", "42-+1", "42-01"] {
            assert!(parse_pipe_arguments(Path::new(nonce), Path::new(invalid)).is_err(), "{invalid}");
        }
        let root = std::env::temp_dir().join("spidervpn-legacy-not-opened");
        let req = root.join("request.json");
        let res = root.join("reply.json");
        assert_eq!(serve(&req, &res), 2);
    }

    #[test]
    fn finish_is_distinct_from_ack_and_bound_to_nonce() {
        let nonce = sample().nonce;
        let ack = serde_json::to_vec(&LeaseAck { schema: LEASE_SCHEMA, nonce: nonce.clone(), accepted: true }).unwrap();
        assert!(validate_finish(&ack, &nonce).is_err());
        for state in [LeaseState::Ready, LeaseState::Accepted, LeaseState::Receipt, LeaseState::Active, LeaseState::Rejected, LeaseState::Closed] {
            let bad = serde_json::to_vec(&LeaseFinish { schema: LEASE_SCHEMA, nonce: nonce.clone(), state }).unwrap();
            assert!(validate_finish(&bad, &nonce).is_err());
        }
        let good = serde_json::to_vec(&LeaseFinish { schema: LEASE_SCHEMA, nonce: nonce.clone(), state: LeaseState::Committed }).unwrap();
        assert!(validate_finish(&good, &nonce).is_ok());
        assert!(validate_finish(&good, "ffffffffffffffffffffffffffffffff").is_err());
    }

    // Invokes itself as a separate test executable process, with a narrowly scoped
    // worker branch. The outer test never calls TerminateProcess on a passing path.
    #[cfg(windows)]
    #[test]
    fn real_process_channel_faults_revoke_without_kill() {
        run_channel_fault_cases(false);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "显式隔离 BFE runner：真实产品监督函数与动态 WFP 过滤器联合验证"]
    fn real_process_channel_faults_with_bfe() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        run_channel_fault_cases(true);
    }

    #[cfg(windows)]
    fn run_channel_fault_cases(native_bfe: bool) {
        use super::super::wfp_win::{WfpEngine, RawFilter, app_id_from_path, filter_add, filter_get_by_id};
        use std::net::{TcpListener, TcpStream, SocketAddr};
        use std::os::windows::io::AsRawHandle;
        use std::process::{Child, Command};
        use windows_sys::Win32::System::Threading::GetProcessId;

        fn wait_for(deadline: Instant, mut condition: impl FnMut() -> bool, why: &str) {
            while !condition() {
                assert!(Instant::now() < deadline, "{why}");
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        fn assert_flow(listener: &TcpListener, permit: bool) {
            let addr = listener.local_addr().unwrap();
            let outcome = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
            assert_eq!(outcome.is_ok(), permit, "new TCP classification for {addr}");
            if let Ok(stream) = outcome {
                let deadline = Instant::now() + Duration::from_secs(2);
                wait_for(deadline, || match listener.accept() {
                    Ok(_) => true,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
                    Err(e) => panic!("listener acceptance failed: {e}"),
                }, "positive flow was not accepted");
                drop(stream);
            }
        }

        // A third, real engine process remains live through every cancellation
        // case. Its stdin is closed only after the parent verifies all teardown.
        const ENGINE: &str = "SPIDERVPN_LEASE_CANCEL_ENGINE_FIXTURE";
        if std::env::var(ENGINE).as_deref() == Ok("1") {
            assert!(native_bfe);
            use std::io::Read;
            let mut byte = [0u8; 1];
            assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
            return;
        }

        const WORKER: &str = "SPIDERVPN_LEASE_CHANNEL_TEST_WORKER";
        if let Ok(nonce) = std::env::var(WORKER) {
            let controller_pid: u32 = std::env::var("SPIDERVPN_LEASE_TEST_PID").unwrap().parse().unwrap();
            let stamp: u64 = std::env::var("SPIDERVPN_LEASE_TEST_STAMP").unwrap().parse().unwrap();
            assert!(open_controller(controller_pid, stamp ^ 1).is_err());
            let controller = open_controller(controller_pid, stamp).unwrap();
            let mut identity = token_identity(controller.0).unwrap();
            let own = token_identity(unsafe { GetCurrentProcess() }).unwrap();
            let pipe = Pipe::server(&nonce, &identity, &own).unwrap();
            let deadline = Instant::now() + Duration::from_secs(8);
            pipe.accept(deadline, || require_live(controller.0)).unwrap();
            assert!(pipe.require_peer(std::process::id(), true).is_err());
            let check = || {
                require_live(controller.0)?;
                pipe.require_peer(controller_pid, true)?;
                pipe.require_connected()
            };
            // The opt-in joint fixture uses the real filter builders, targeting
            // only this disposable test executable; both sessions are dynamic.
            let mut fixture = None;
            let mut fixture_dir = None;
            if native_bfe {
                let dir = std::path::PathBuf::from(std::env::var_os("SPIDERVPN_LEASE_BFE_DIR").unwrap());
                let endpoint: SocketAddr = std::env::var("SPIDERVPN_LEASE_BFE_ENDPOINT").unwrap().parse().unwrap();
                let app = app_id_from_path(&std::env::current_exe().unwrap()).unwrap();
                let engine = WfpEngine::open_dynamic().unwrap();
                let raw = RawFilter::isolated_lifecycle_filter(&app, Some(endpoint), &decode_nonce(&nonce).unwrap()).unwrap();
                let id = filter_add(&engine, &raw).unwrap();
                std::fs::write(dir.join("permit"), id.to_string()).unwrap();
                fixture = Some(engine);
                fixture_dir = Some(dir);
            }
            let committed = serde_json::to_vec(&reply(&nonce, LeaseState::Committed, String::new(), 1)).unwrap();
            pipe.send(&committed, deadline, &check).unwrap();
            // The exact final-receipt/lifecycle function used by serve_pipe.
            // The old portable test still runs without BFE. Only the explicitly
            // enabled variant holds a real dynamic WFP session.
            match std::env::var("SPIDERVPN_LEASE_TEST_FAULT").as_deref() {
                // Actual connected token is unchanged; pinned identity is wrong.
                Ok("wrong-token") => identity.session ^= 1,
                Ok("wrong-sid") => identity.sid.push_str("-999"),
                _ => {}
            }
            let result = finish_and_supervise(&pipe, &nonce, 1, &identity,
                Instant::now() + Duration::from_secs(3), &check);
            assert!(result.is_err(), "an abandoned or forged channel must not return success");
            require_live(controller.0).expect("controller stayed alive; no owner exit shortcut");
            if let Some(engine) = fixture.take() {
                engine.close_checked().expect("close real WFP dynamic session");
                drop(pipe); // release immediately, before waiting for independent readback
                let dir = fixture_dir.unwrap();
                std::fs::write(dir.join("revoked"), b"closed").unwrap();
                // Keep process ALIVE after WFP close, proving more than RPC rundown.
                wait_for(Instant::now() + Duration::from_secs(10), || dir.join("exit").exists(),
                    "parent did not verify BFE teardown");
            }
            return;
        }

        struct Cleanup(Child);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // Only panic/failure cleanup; success path already reaps a normal exit.
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }

        let pid = std::process::id();
        let stamp = creation_stamp(unsafe { GetCurrentProcess() }).unwrap();
        let mut bfe = None;
        if native_bfe {
            let a = TcpListener::bind("127.0.0.1:0").unwrap();
            let b = TcpListener::bind("127.0.0.1:0").unwrap();
            a.set_nonblocking(true).unwrap();
            b.set_nonblocking(true).unwrap();
            assert_flow(&a, true);
            assert_flow(&b, true);
            let app = app_id_from_path(&std::env::current_exe().unwrap()).unwrap();
            let baseline = WfpEngine::open_dynamic().unwrap();
            let audit = WfpEngine::open().unwrap();
            let filter = RawFilter::isolated_lifecycle_filter(&app, None, &[1u8; 16]).unwrap();
            let block = filter_add(&baseline, &filter).unwrap();
            assert!(filter_get_by_id(&audit, block).unwrap().is_some());
            assert_flow(&a, false);
            assert_flow(&b, false);
            bfe = Some((baseline, audit, block, a, b));
        }
        let mut engine = if native_bfe {
            Some(Cleanup(Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "guard::lease_helper::tests::real_process_channel_faults_with_bfe", "--nocapture"])
                .env(ENGINE, "1").stdin(std::process::Stdio::piped()).spawn().unwrap()))
        } else { None };

        // Preserve the original nine scenarios and original evidence count.
        let old_modes = ["before-receipt", "late-receipt", "after-receipt", "silent-active", "wrong-challenge", "valid-then-close", "wrong-token", "wrong-sid", "replay"];
        let cancel_modes = ["cancel-start", "cancel-handoff", "cancel-active-kill-error",
            "cancel-active-normal", "cancel-no-runtime", "cancel-corrupt-runtime", "cancel-shutdown"];
        let mut completed_modes = 0usize;
        let mut cancelled_modes = 0usize;
        let mut retired: Option<std::sync::Arc<LocalLeaseControl>> = None;
        for mode in old_modes.into_iter().chain(cancel_modes.into_iter().filter(|_| native_bfe)) {
            let is_cancel = mode.starts_with("cancel-");
            if native_bfe {
                println!("{}_BEGIN mode={mode}", if is_cancel { "CANCEL_BFE" } else { "JOINT_BFE" });
            }
            let mut registration = if is_cancel {
                let engine = engine.as_ref().unwrap();
                let reg = register_experimental_lease(engine.0.id(), &std::env::current_exe().unwrap()).unwrap();
                if let Some(stale) = retired.take() {
                    assert_ne!(stale.nonce, reg.control.nonce);
                    stale.cancel();
                    assert!(stale.authorized(|| Ok(())).is_err());
                    reg.control.require_identity().unwrap();
                }
                Some(reg)
            } else { None };
            let control = registration.as_ref().map(|reg| reg.control.clone());
            let nonce = control.as_ref().map(|c| c.nonce.clone()).unwrap_or_else(random_nonce);
            let mut command = Command::new(std::env::current_exe().unwrap());
            let test_name = if native_bfe {
                command.arg("--ignored");
                "guard::lease_helper::tests::real_process_channel_faults_with_bfe"
            } else {
                "guard::lease_helper::tests::real_process_channel_faults_revoke_without_kill"
            };
            command.args(["--exact", test_name, "--nocapture"])
                .env(WORKER, &nonce)
                .env("SPIDERVPN_LEASE_TEST_PID", pid.to_string())
                .env("SPIDERVPN_LEASE_TEST_STAMP", stamp.to_string())
                .env("SPIDERVPN_LEASE_TEST_FAULT", mode);
            let mut fixture_dir = None;
            if let Some((_, _, _, a, _)) = &bfe {
                let dir = std::env::temp_dir().join(format!("spidervpn-joint-bfe-{nonce}"));
                std::fs::create_dir(&dir).unwrap();
                command.env("SPIDERVPN_LEASE_BFE_DIR", &dir)
                    .env("SPIDERVPN_LEASE_BFE_ENDPOINT", a.local_addr().unwrap().to_string());
                fixture_dir = Some(dir);
            }
            let mut child = Cleanup(command.spawn().unwrap());
            let helper_pid = child.0.id();
            assert_ne!(helper_pid, pid);
            let handle = child.0.as_raw_handle();
            assert_eq!(unsafe { GetProcessId(handle) }, helper_pid);
            if let Some(control) = control.as_ref() { control.bind_helper(handle).unwrap(); }
            let deadline = Instant::now() + Duration::from_secs(10);
            let pipe = Pipe::client(&nonce, deadline, || require_live(handle)).unwrap();
            pipe.require_peer(helper_pid, false).unwrap();
            assert!(pipe.require_peer(pid, false).is_err());
            let committed = pipe.receive(4096, deadline, || require_live(handle)).unwrap();
            validate_stage(&committed, &nonce, 1, helper_pid, LeaseState::Committed).unwrap();
            let mut permit_id = None;
            if let Some((_, audit, block, a, b)) = &bfe {
                let dir = fixture_dir.as_ref().unwrap();
                let id: u64 = std::fs::read_to_string(dir.join("permit")).unwrap().parse().unwrap();
                assert!(filter_get_by_id(audit, id).unwrap().is_some());
                assert!(filter_get_by_id(audit, *block).unwrap().is_some());
                assert_flow(a, true);
                assert_flow(b, false);
                permit_id = Some(id);
                // Actually attempt termination with a handle lacking that right.
                // The full Child handle is reserved for panic cleanup only.
                use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, TerminateProcess};
                use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED};
                let limited = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, helper_pid) };
                assert!(!limited.is_null());
                let ok = unsafe { TerminateProcess(limited, 1) };
                let error = unsafe { GetLastError() };
                unsafe { CloseHandle(limited); }
                assert_eq!(ok, 0);
                assert_eq!(error, ERROR_ACCESS_DENIED);
                println!("{}_LIVE mode={mode} permit_present=true block_present=true tcp_exact_allowed=true tcp_other_denied=true terminate_access_denied=true",
                    if is_cancel { "CANCEL_BFE" } else { "JOINT_BFE" });
            }
            let mut keep_open = Some(pipe);
            if mode == "cancel-start" {
                let control = control.as_ref().unwrap();
                let dir = fixture_dir.as_ref().unwrap();
                // Actual disconnect, while this startup registration owns the pipe.
                invoke_fixture_disconnect(mode, dir, control);
                let pipe = keep_open.as_ref().unwrap();
                let receipt = serde_json::to_vec(&LeaseFinish { schema: LEASE_SCHEMA,
                    nonce: nonce.clone(), state: LeaseState::Receipt }).unwrap();
                assert!(pipe.send_guarded(&receipt, deadline, || Ok(()), control).is_err(),
                    "canceled startup wrote a late Receipt");
                assert!(register_experimental_lease(control.engine_pid, &std::env::current_exe().unwrap()).is_err());
                drop(keep_open.take());
                drop(registration.take());
            } else if mode == "before-receipt" {
                drop(keep_open.take());
            } else if mode == "late-receipt" {
                // Keep the live pipe without sending Receipt past the deadline.
            } else {
                let pipe = keep_open.as_ref().unwrap();
                let receipt = serde_json::to_vec(&LeaseFinish { schema: LEASE_SCHEMA,
                    nonce: nonce.clone(), state: LeaseState::Receipt }).unwrap();
                // For negative modes the helper may close immediately after
                // consuming the entire frame. Do not require it to stay alive
                // after sending; the bounded receive and exit assertions decide.
                pipe.send(&receipt, deadline, || Ok(())).unwrap();
                if mode == "wrong-token" || mode == "wrong-sid" {
                    assert!(pipe.receive(4096, deadline, || require_live(handle)).is_err(),
                        "wrong token must not receive Active");
                } else {
                    let active = pipe.receive(4096, deadline, || require_live(handle)).unwrap();
                    validate_stage(&active, &nonce, 1, helper_pid, LeaseState::Active).unwrap();
                }
                if is_cancel {
                    let control = control.as_ref().unwrap();
                    let identity = token_identity(handle).unwrap();
                    let stamp = creation_stamp(handle).unwrap();
                    let pending = confirm_first_heartbeat(pipe, handle, &nonce, helper_pid,
                        stamp, &identity, deadline, Some(control)).unwrap();
                    let channel = RegisteredChannel {
                        pipe: keep_open.take().unwrap(),
                        registration: registration.take().unwrap(),
                    };
                    let start = spawn_controller_worker(channel, duplicate_process_handle(handle).unwrap(),
                        nonce.clone(), helper_pid, stamp, identity, pending, deadline).unwrap();
                    if mode == "cancel-handoff" {
                        // Cancellation wins before authorization of the real worker.
                        invoke_fixture_disconnect(mode, fixture_dir.as_ref().unwrap(), control);
                        assert!(control.authorized(|| start.send(()).map_err(|e| e.to_string())).is_err());
                        drop(start);
                    } else {
                        control.authorized(|| start.send(()).map_err(|e| e.to_string())).unwrap();
                        // Seq3 proves the real helper consumed the worker's seq2.
                        wait_for(deadline, || control.observed_sequence.load(std::sync::atomic::Ordering::Acquire) >= 3,
                            "worker never completed an authenticated renewal");
                        invoke_fixture_disconnect(mode, fixture_dir.as_ref().unwrap(), control);
                    }
                } else if mode == "after-receipt" {
                    drop(keep_open.take());
                } else if mode == "valid-then-close" {
                    // Exercise the exact startup confirmation used by launch_elevated
                    // with the real different-process helper and BFE variant.
                    let identity = token_identity(handle).unwrap();
                    let stamp = creation_stamp(handle).unwrap();
                    let next = confirm_first_heartbeat(pipe, handle, &nonce, helper_pid,
                        stamp, &identity, deadline, None).unwrap();
                    assert_eq!(decode_heartbeat(&next, &nonce, 2).unwrap().sequence, 2);
                    drop(keep_open.take());
                } else if mode != "silent-active" && mode != "wrong-token" && mode != "wrong-sid" {
                    let challenge = pipe.receive(4096, deadline, || require_live(handle)).unwrap();
                    let mut heartbeat = decode_heartbeat(&challenge, &nonce, 1).unwrap();
                    if mode == "wrong-challenge" {
                        // Well-formed but not the helper's actual challenge.
                        let replacement = if heartbeat.challenge.starts_with('1') { "2" } else { "1" };
                        heartbeat.challenge.replace_range(..1, replacement);
                    }
                    let response = serde_json::to_vec(&heartbeat).unwrap();
                    pipe.send(&response, deadline, || Ok(())).unwrap();
                    if mode == "replay" {
                        let next = pipe.receive(4096, deadline, || require_live(handle)).unwrap();
                        decode_heartbeat(&next, &nonce, 2).unwrap();
                        pipe.send(&response, deadline, || Ok(())).unwrap();
                    }
                }
            }
            // In silent modes keep the handle open until helper times itself out.
            // Joint fixture proves filter removal while both processes remain alive.
            if let Some((_, audit, block, a, b)) = &bfe {
                let dir = fixture_dir.as_ref().unwrap();
                wait_for(deadline, || {
                    assert!(child.0.try_wait().unwrap().is_none(), "owner exited before teardown proof");
                    dir.join("revoked").exists()
                }, "helper did not close its BFE session");
                let id = permit_id.unwrap();
                wait_for(deadline, || filter_get_by_id(audit, id).unwrap().is_none(),
                    "dynamic permit remained in BFE");
                assert!(child.0.try_wait().unwrap().is_none());
                assert!(filter_get_by_id(audit, *block).unwrap().is_some());
                assert_flow(a, false);
                assert_flow(b, false);
                assert!(child.0.try_wait().unwrap().is_none());
                println!("{}_REVOKED mode={mode} permit_absent=true block_present=true tcp_exact_denied=true tcp_other_denied=true owner_alive=true",
                    if is_cancel { "CANCEL_BFE" } else { "JOINT_BFE" });
                if let Some(control) = control.as_ref() {
                    assert!(control.require_active().is_err());
                    assert!(control.authorized(|| Ok(())).is_err());
                    assert!(engine.as_mut().unwrap().0.try_wait().unwrap().is_none(),
                        "engine must remain live through readback");
                    wait_for(deadline, || control.owner_finished.load(std::sync::atomic::Ordering::Acquire),
                        "canceled channel owner did not finish");
                    assert!(register_experimental_lease(control.engine_pid, &std::env::current_exe().unwrap()).is_err(),
                        "old helper still alive; cannot replace its registration");
                    cancel_current_experimental_lease(); // still cannot replace old helper
                }
                std::fs::write(dir.join("exit"), b"verified").unwrap();
            }
            // Parent stays alive, no call to kill, and child must exit normally.
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success(), "worker failed for {mode}: {status}");
                    break;
                }
                assert!(Instant::now() < deadline, "helper orphaned after {mode}");
                std::thread::sleep(Duration::from_millis(25));
            }
            if mode == "late-receipt" {
                let late = serde_json::to_vec(&LeaseFinish { schema: LEASE_SCHEMA,
                    nonce: nonce.clone(), state: LeaseState::Receipt }).unwrap();
                assert!(keep_open.as_ref().unwrap().send(&late,
                    Instant::now() + Duration::from_millis(250), || Ok(())).is_err(),
                    "late Receipt must not resurrect an expired channel");
            }
            drop(keep_open);
            if let Some(dir) = fixture_dir {
                std::fs::remove_dir_all(dir).unwrap();
            }
            if is_cancel {
                // Only observed actual helper exit allows the old slot to be reaped.
                cancel_current_experimental_lease();
                assert!(LOCAL_LEASE.0.lock().unwrap().current.is_none());
                retired = control;
                cancelled_modes += 1;
                println!("CANCEL_BFE_PASS mode={mode} engine_alive=true");
            } else {
                completed_modes += 1;
                if native_bfe { println!("JOINT_BFE_PASS mode={mode}"); }
            }
        }
        assert_eq!(completed_modes, 9, "all nine distinct fault modes must run");
        if native_bfe {
            assert_eq!(cancelled_modes, cancel_modes.len());
            println!("CANCEL_BFE_COMPLETE modes={cancelled_modes} stale_rejected=true repeat_noop=true engine_alive=true");
        }
        if let Some(engine) = engine.as_mut() {
            drop(engine.0.stdin.take());
            wait_for(Instant::now() + Duration::from_secs(5), || engine.0.try_wait().unwrap().is_some(),
                "engine fixture did not exit after explicit release");
            assert!(engine.0.wait().unwrap().success());
        }
        if let Some((baseline, audit, block, a, b)) = bfe {
            baseline.close_checked().unwrap();
            assert!(filter_get_by_id(&audit, block).unwrap().is_none());
            assert_flow(&a, true);
            assert_flow(&b, true);
            println!("JOINT_BFE_COMPLETE modes={completed_modes} baseline_removed=true tcp_restored=true");
        }
    }

    // The real connect.rs disconnect entry, with a disposable runtime directory.
    // The injected kill result deliberately never terminates the engine. For
    // kill-error also call the native API with a real restricted engine handle.
    #[cfg(windows)]
    fn invoke_fixture_disconnect(mode: &str, dir: &Path, control: &LocalLeaseControl) {
        use std::cell::Cell;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::TerminateProcess;
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED};
        let runtime = dir.join("runtime.json");
        let journal = dir.join("proxy-journal.json");
        if mode == "cancel-corrupt-runtime" {
            std::fs::write(&runtime, b"not-json").unwrap();
        } else if mode != "cancel-no-runtime" {
            std::fs::write(&runtime, serde_json::json!({
                "SchemaVersion": 1, "SupervisorPid": std::process::id(),
                "EnginePid": control.engine_pid, "StartedAt": "2026-10-26T00:00:00Z",
                "State": "Running", "Error": null, "CleanupError": false,
                "TradingDirectAccessBlocked": true, "BootStartedAt": "2026-10-26T00:00:00Z"
            }).to_string()).unwrap();
        }
        let store = crate::proxy::ProxyStore { key_path: format!("Software\\SpiderVPN\\tests\\cancel-{}", control.nonce) };
        let calls = Cell::new(0);
        let kill = |pid: i64| {
            calls.set(calls.get() + 1);
            assert_eq!(pid, i64::from(control.engine_pid));
            assert!(control.require_active().is_err(), "cancel must precede the existing kill");
            assert!(register_experimental_lease(control.engine_pid, &std::env::current_exe().unwrap()).is_err(),
                "new registration forbidden while disconnect executes");
            if mode == "cancel-active-kill-error" {
                let ok = unsafe { TerminateProcess(control.engine.as_raw_handle(), 1) };
                let error = unsafe { GetLastError() };
                assert_eq!(ok, 0);
                assert_eq!(error, ERROR_ACCESS_DENIED, "real limited engine handle cannot terminate");
                return Err("injected stop error after native ACCESS_DENIED".to_string());
            }
            Ok(())
        };
        let deps = crate::connect::Deps {
            store: &store, apply: &|_, _| panic!("no proxy writes expected"),
            spawn: &|_| panic!("disconnect cannot spawn"), kill: &kill,
            alive: &|_| true, elevated: &|| true, journal_path: &journal,
            runtime_path: &runtime, now: 1_700_000_000.0, guard: None,
        };
        let origin = crate::events::Origin::other();
        if mode == "cancel-shutdown" {
            assert!(!crate::connect::shutdown_cleanup(None, &deps, &origin).unwrap().is_empty());
        } else {
            let result = crate::connect::disconnect_with_origin(None, &deps, &origin);
            match mode {
                "cancel-active-kill-error" => {
                    assert_eq!(result.unwrap_err(), "injected stop error after native ACCESS_DENIED");
                    assert!(runtime.exists(), "old kill error must preserve runtime record");
                }
                "cancel-no-runtime" | "cancel-corrupt-runtime" =>
                    assert_eq!(result.unwrap(), crate::connect::Outcome::AlreadyDone),
                _ => assert!(matches!(result.unwrap(), crate::connect::Outcome::Done(_))),
            }
        }
        assert_eq!(calls.get(), if matches!(mode, "cancel-no-runtime" | "cancel-corrupt-runtime") { 0 } else { 1 });
        assert!(control.require_active().is_err());
        cancel_current_experimental_lease();
        cancel_current_experimental_lease();
        pipe_ipc::require_live(control.engine.as_raw_handle()).unwrap();
        println!("CANCEL_ENTRY mode={mode} cancelled_before_stop=true old_result_preserved=true engine_alive=true");
    }

    #[cfg(windows)]
    #[test]
    fn local_cancel_gate_serializes_writes_disconnects_and_stale_registrations() {
        use std::io::Read;
        use std::process::{Command, Stdio};
        const ENGINE: &str = "SPIDERVPN_CANCEL_GATE_ENGINE_CHILD";
        if std::env::var(ENGINE).as_deref() == Ok("1") {
            let mut byte = [0u8; 1];
            assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
            return;
        }
        struct Cleanup(std::process::Child);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        let exe = std::env::current_exe().unwrap();
        let mut engine = Cleanup(Command::new(&exe)
            .args(["--exact", "guard::lease_helper::tests::local_cancel_gate_serializes_writes_disconnects_and_stale_registrations", "--nocapture"])
            .env(ENGINE, "1").stdin(Stdio::piped()).spawn().unwrap());
        let engine_pid = engine.0.id();
        let slot = LocalLeaseSlot::default();
        // Cancellation with no current lease remains a safe registration barrier
        // until every overlapping disconnect returns.
        let d1 = slot.begin_disconnect();
        let d2 = slot.begin_disconnect();
        assert!(slot.register(engine_pid, &exe).is_err());
        drop(d1);
        assert!(slot.register(engine_pid, &exe).is_err());
        drop(d2);
        let reg = slot.register(engine_pid, &exe).unwrap();
        let stale = reg.control.clone();
        assert!(slot.register(engine_pid, &exe).is_err());
        let identity = token_identity(unsafe { GetCurrentProcess() }).unwrap();
        let server = Pipe::server(&stale.nonce, &identity, &identity).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let client = Pipe::client(&stale.nonce, deadline, || Ok(())).unwrap();
        server.accept(deadline, || Ok(())).unwrap();
        client.send_guarded(b"before", deadline, || Ok(()), &stale).unwrap();
        assert_eq!(server.receive(4096, deadline, || Ok(())).unwrap(), b"before");
        // A real concurrent cancellation competes with the exact authorization gate.
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let gate = stale.write_gate.lock().unwrap();
            scope.spawn(|| {
                barrier.wait();
                slot.cancel_current();
            });
            barrier.wait();
            drop(gate);
        });
        assert!(stale.require_identity().is_err());
        assert!(stale.authorized(|| Ok(())).is_err());
        assert!(client.send_guarded(b"after", deadline, || Ok(()), &stale).is_err());
        assert!(slot.register(engine_pid, &exe).is_err());
        drop(client);
        assert!(server.require_connected().is_err());
        drop(server);
        drop(reg);
        slot.cancel_current();
        let new_reg = slot.register(engine_pid, &exe).unwrap();
        assert_ne!(new_reg.control.nonce, stale.nonce);
        stale.cancel();
        assert!(stale.authorized(|| Ok(())).is_err());
        new_reg.control.require_identity().unwrap();
        let disconnect = slot.begin_disconnect();
        assert!(new_reg.control.require_identity().is_err());
        drop(new_reg);
        // With no current reservation the in-flight disconnect still forbids startup.
        assert!(slot.register(engine_pid, &exe).is_err());
        drop(disconnect);
        assert!(slot.register(engine_pid, &exe).is_ok());
        assert!(engine.0.try_wait().unwrap().is_none());
        drop(engine.0.stdin.take());
        assert!(engine.0.wait().unwrap().success());
    }

    #[cfg(windows)]
    #[test]
    fn first_heartbeat_requires_next_authenticated_sequence_before_success() {
        let token = token_identity(unsafe { GetCurrentProcess() }).unwrap();
        let stamp = creation_stamp(unsafe { GetCurrentProcess() }).unwrap();
        let pid = std::process::id();
        for mode in ["valid", "disconnect", "repeat", "silence"] {
            let nonce = random_nonce();
            let server = Pipe::server(&nonce, &token, &token).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let controller = Pipe::client(&nonce, deadline, || Ok(())).unwrap();
            server.accept(deadline, || Ok(())).unwrap();
            let server_nonce = nonce.clone();
            let worker = std::thread::spawn(move || {
                let first = LeaseHeartbeat { schema: LEASE_SCHEMA,
                    nonce: server_nonce.clone(), sequence: 1,
                    challenge: "1234567890abcdef1234567890abcdef".into() };
                let data = serde_json::to_vec(&first).unwrap();
                server.send(&data, deadline, || Ok(())).unwrap();
                assert_eq!(server.receive(4096, deadline, || Ok(())).unwrap(), data);
                if mode == "disconnect" { return; }
                if mode == "silence" {
                    std::thread::sleep(Duration::from_millis(600));
                    return;
                }
                let next = LeaseHeartbeat { sequence: if mode == "repeat" { 1 } else { 2 }, ..first };
                server.send(&serde_json::to_vec(&next).unwrap(), deadline, || Ok(())).unwrap();
                // Keep the authenticated server end open until the caller completes.
                let _ = server.receive(4096, deadline, || Ok(()));
            });
            let result = confirm_first_heartbeat(&controller, unsafe { GetCurrentProcess() },
                &nonce, pid, stamp, &token, Instant::now() + Duration::from_millis(400), None);
            assert_eq!(result.is_ok(), mode == "valid", "first heartbeat mode {mode}");
            drop(controller);
            worker.join().unwrap();
        }
    }

    #[test]
    fn heartbeat_rejects_replay_wrong_session_and_zero_challenge() {
        let nonce = sample().nonce;
        let good = LeaseHeartbeat { schema: LEASE_SCHEMA, nonce: nonce.clone(), sequence: 2,
            challenge: "1234567890abcdef1234567890abcdef".into() };
        let body = serde_json::to_vec(&good).unwrap();
        assert_eq!(decode_heartbeat(&body, &nonce, 2).unwrap(), good);
        assert!(decode_heartbeat(&body, &nonce, 3).is_err());
        assert!(decode_heartbeat(&body, "ffffffffffffffffffffffffffffffff", 2).is_err());
        let zero = LeaseHeartbeat { challenge: "0".repeat(32), ..good };
        assert!(decode_heartbeat(&serde_json::to_vec(&zero).unwrap(), &nonce, 2).is_err());
    }

    fn sample() -> LeaseRequest {
        LeaseRequest {
            schema: LEASE_SCHEMA,
            nonce: "0123456789abcdef0123456789abcdef".into(),
            endpoint: "127.0.0.1:17890".parse().unwrap(),
            engine_pid: 51,
            controller_pid: 52,
            engine_executable: if cfg!(windows) {
                PathBuf::from(r"C:\Program Files\SpiderVPN\sing-box.exe")
            } else {
                PathBuf::from("/opt/spidervpn/sing-box.exe")
            },
            programs: vec![ProgramIdentity {
                name: "Trading".into(),
                path: PathBuf::from("trader.exe"),
                app_id: vec![1, 0],
                device_path: "a".into(),
            }],
        }
    }

    #[cfg(windows)]
    #[test]
    fn validated_request_is_consumed_once_by_handle() {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0u8; 16];
        SystemRandom::new().fill(&mut bytes).unwrap();
        let mut req = sample();
        req.nonce = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let root = std::env::temp_dir().join(format!("spidervpn-lease-{}", req.nonce));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("request.json");
        std::fs::write(&path, serde_json::to_vec(&req).unwrap()).unwrap();
        let alias = root.join("alias.json");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(consume_request(&path).is_err());
        assert!(path.exists() && alias.exists(), "拒绝硬链接不得删除目标");
        std::fs::remove_file(&alias).unwrap();
        assert_eq!(consume_request(&path).unwrap().nonce, req.nonce);
        assert!(!path.exists());
        assert!(consume_request(&path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ipc_publication_never_replaces_existing_destination() {
        let root = std::env::temp_dir().join(format!("spidervpn-lease-publish-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("reply.json.tmp");
        let destination = root.join("reply.json");
        std::fs::write(&source, b"new").unwrap();
        std::fs::write(&destination, b"old").unwrap();
        assert!(publish_new_file(&source, &destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        assert_eq!(std::fs::read(&source).unwrap(), b"new");
        std::fs::remove_file(&destination).unwrap();
        publish_new_file(&source, &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"new");
        assert!(!source.exists());
        let ack = root.join("ack.json");
        let nonce = sample().nonce;
        write_ack(&ack, &nonce, false).unwrap();
        assert!(write_ack(&ack, &nonce, true).is_err());
        assert!(read_ack(&ack, &nonce).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn session_directory_requires_exact_request_nonce() {
        let nonce = sample().nonce;
        let root = std::env::temp_dir();
        let request = root.join(format!("spidervpn-lease-{nonce}")).join("request.json");
        assert!(validate_session_directory(&request, &nonce).is_ok());
        assert!(validate_session_directory(&request, "ffffffffffffffffffffffffffffffff").is_err());
        let short = root.join("spidervpn-lease-0123456789abcdef").join("request.json");
        assert!(validate_session_directory(&short, &nonce).is_err());
    }

    #[test]
    fn ipc_readers_reject_hardlinks_even_with_valid_protocol() {
        let root = std::env::temp_dir().join(format!("spidervpn-lease-hardlink-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let req = sample();
        let request = root.join("request.json");
        let response = root.join("reply.json");
        let ack = root.join("ack.json");
        std::fs::write(&request, serde_json::to_vec(&req).unwrap()).unwrap();
        write_reply(&response, &reply(&req.nonce, LeaseState::Ready, String::new(), 1)).unwrap();
        write_ack(&ack, &req.nonce, true).unwrap();
        assert!(read_request(&request).is_ok());
        assert!(read_ready(&response, &req.nonce, 1, std::process::id()).unwrap().is_some());
        assert!(read_ack(&ack, &req.nonce).unwrap());
        for path in [&request, &response, &ack] {
            std::fs::hard_link(path, path.with_extension("linked")).unwrap();
        }
        assert!(read_request(&request).is_err());
        assert!(read_ready(&response, &req.nonce, 1, std::process::id()).is_err());
        assert!(read_ack(&ack, &req.nonce).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ipc_reads_are_bounded_and_reject_nonfiles() {
        let root = std::env::temp_dir().join(format!("spidervpn-lease-bounds-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("reply.json");
        assert!(read_ipc_file(&path, 4096).unwrap().is_none());
        std::fs::write(&path, vec![b'x'; 4096]).unwrap();
        assert_eq!(read_ipc_file(&path, 4096).unwrap().unwrap().len(), 4096);
        std::fs::write(&path, vec![b'x'; 4097]).unwrap();
        assert!(read_ipc_file(&path, 4096).is_err());
        std::fs::write(&path, []).unwrap();
        assert!(read_ipc_file(&path, 4096).is_err());
        assert!(read_ipc_file(&root, 4096).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_request_gate_rejects_untrusted_or_unsafe_inputs() {
        let base = sample();
        assert!(validate_request(&base).is_ok());
        for bad in [
            LeaseRequest { schema: 2, ..base.clone() },
            LeaseRequest { nonce: "0".repeat(32), ..base.clone() },
            LeaseRequest { nonce: "z".repeat(32), ..base.clone() },
            LeaseRequest { engine_pid: 0, ..base.clone() },
            LeaseRequest { controller_pid: 0, ..base.clone() },
            LeaseRequest { controller_pid: base.engine_pid, ..base.clone() },
            LeaseRequest { endpoint: "0.0.0.0:17890".parse().unwrap(), ..base.clone() },
            LeaseRequest { endpoint: "127.0.0.2:17890".parse().unwrap(), ..base.clone() },
            LeaseRequest { endpoint: "[::ffff:127.0.0.1]:17890".parse().unwrap(), ..base.clone() },
            LeaseRequest { programs: Vec::new(), ..base.clone() },
            LeaseRequest { programs: vec![base.programs[0].clone(); MAX_PROGRAMS + 1], ..base.clone() },
        ] {
            assert!(validate_request(&bad).is_err(), "bad input accepted: {bad:?}");
        }
    }

    #[test]
    fn ack_is_bound_to_exact_nonce_and_never_accepts_replay() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-lease-{:016x}", std::process::id() as u64 + 1,
        ));
        let _ = std::fs::create_dir_all(&root);
        let path = root.join("ack.json");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_ack(&path, &sample().nonce).unwrap(), false);
        let base = LeaseAck {
            schema: LEASE_SCHEMA, nonce: sample().nonce.clone(), accepted: true,
        };
        std::fs::write(&path, serde_json::to_vec(&base).unwrap()).unwrap();
        assert!(read_ack(&path, &base.nonce).unwrap());
        assert!(read_ack(&path, "ffffffffffffffffffffffffffffffff").is_err());
        std::fs::write(&path, serde_json::to_vec(&LeaseAck {
            accepted: false, ..base.clone()
        }).unwrap()).unwrap();
        assert!(read_ack(&path, &base.nonce).is_err());
        std::fs::write(&path, b"{bad-json").unwrap();
        assert!(read_ack(&path, &base.nonce).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_ready_rejects_replayed_nonce_wrong_count_and_rejected_status() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-lease-{:016x}", std::process::id() as u64 + 2,
        ));
        let _ = std::fs::create_dir_all(&root);
        let path = root.join("reply.json");
        let _ = std::fs::remove_file(&path);
        let nonce = sample().nonce;
        assert!(read_ready(&path, &nonce, 1, std::process::id()).unwrap().is_none());
        let good = reply(&nonce, LeaseState::Ready, String::new(), 1);
        std::fs::write(&path, serde_json::to_vec(&good).unwrap()).unwrap();
        assert!(read_ready(&path, &nonce, 1, std::process::id()).unwrap().is_some());
        assert!(read_ready(&path, &nonce, 2, std::process::id()).is_err());
        assert!(read_ready(&path, &nonce, 1, 0).is_err());
        assert!(read_ready(&path, &nonce, 1, std::process::id() ^ 1).is_err());
        assert!(read_ready(&path, "ffffffffffffffffffffffffffffffff", 1, std::process::id()).is_err());
        std::fs::write(&path, serde_json::to_vec(&reply(
            &nonce, LeaseState::Rejected, "not protected".into(), 0
        )).unwrap()).unwrap();
        assert!(read_ready(&path, &nonce, 1, std::process::id()).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn ack_consumption_rejects_alias_and_removes_only_valid_object() {
        let root = std::env::temp_dir().join(format!("spidervpn-lease-ack-consume-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("ack.json");
        let alias = root.join("alias.json");
        let nonce = sample().nonce;
        assert!(!consume_ack(&path, &nonce).unwrap());
        write_ack(&path, &nonce, true).unwrap();
        assert!(consume_ack(&path, "ffffffffffffffffffffffffffffffff").is_err());
        assert!(path.exists());
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(consume_ack(&path, &nonce).is_err());
        assert!(path.exists() && alias.exists());
        std::fs::remove_file(alias).unwrap();
        assert!(consume_ack(&path, &nonce).unwrap());
        assert!(!path.exists());
        assert!(!consume_ack(&path, &nonce).unwrap());
        write_ack(&path, &nonce, false).unwrap();
        assert!(consume_ack(&path, &nonce).is_err());
        assert!(path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn final_receipt_requires_accepted_stage_and_matching_identity() {
        let root = std::env::temp_dir().join(format!("spidervpn-lease-final-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = directory_receipt(&root);
        let nonce = sample().nonce;
        let pid = std::process::id();
        let check = || read_stage(&path, &nonce, 1, pid, LeaseState::Accepted);
        assert!(check().unwrap().is_none());
        write_reply(&path, &reply(&nonce, LeaseState::Ready, String::new(), 1)).unwrap();
        assert!(check().is_err());
        std::fs::remove_file(&path).unwrap();
        write_reply(&path, &reply(&nonce, LeaseState::Accepted, String::new(), 1)).unwrap();
        assert!(check().unwrap().is_some());
        assert!(read_ready(&path, &nonce, 1, pid).is_err());
        assert!(read_stage(&path, &nonce, 1, pid ^ 1, LeaseState::Accepted).is_err());
        assert!(read_stage(&path, &nonce, 2, pid, LeaseState::Accepted).is_err());
        assert!(read_stage(&path, "ffffffffffffffffffffffffffffffff", 1, pid, LeaseState::Accepted).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transport_rejects_arbitrary_writable_locations() {
        let good_dir = std::env::temp_dir().join("spidervpn-lease-0123456789abcdef");
        let _ = std::fs::create_dir_all(&good_dir);
        let request = good_dir.join("request.json");
        let response = good_dir.join("reply.json");
        assert!(validate_transport_paths(&request, &response).is_ok());
        assert!(validate_transport_paths(&request, &good_dir.join("config.json")).is_err());
        assert!(validate_transport_paths(&request, &std::env::temp_dir().join("other.json")).is_err());
        assert!(validate_transport_paths(
            &std::env::temp_dir().join("request.json"), &response,
        ).is_err());
        let _ = std::fs::remove_dir_all(good_dir);
    }

    #[test]
    fn ipc_roundtrip_and_replay_guard() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-lease-{:016x}", std::process::id(),
        ));
        let _ = std::fs::create_dir_all(&root);
        let rq = root.join("request.json");
        let rs = root.join("reply.json");
        assert!(validate_transport_paths(&rq, &rs).is_ok());
        let _ = std::fs::remove_file(&rq);
        let _ = std::fs::remove_file(&rs);
        let raw = serde_json::to_vec(&sample()).unwrap();
        std::fs::write(&rq, &raw).unwrap();
        let actual = read_request(&rq).unwrap();
        assert_eq!(validate_request(&actual).unwrap(), decode_nonce(&actual.nonce).unwrap());
        write_reply(&rs, &reply(&actual.nonce, LeaseState::Rejected, "test".into(), 0)).unwrap();
        let ack_path = root.join("ack.json");
        assert!(write_ack(&ack_path, &actual.nonce, true).is_ok());
        assert!(read_ack(&ack_path, &actual.nonce).unwrap());
        assert!(!ack_path.with_extension("json.tmp").exists(),
            "不能遗留半写的临时 ack 文件");
        assert_eq!(read_request(&rq).unwrap().engine_pid, 51);
        assert!(write_reply(&rs, &reply(&actual.nonce, LeaseState::Ready, String::new(), 1)).is_err(),
            "old receipt cannot be silently overwritten");
        assert_eq!(std::fs::read_to_string(&rs).unwrap().contains("Rejected"), true);
        let _ = std::fs::remove_dir_all(root);
    }
}
