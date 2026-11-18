//! 独立的长期 WFP 代理许可 helper（仅 Windows 的内部入口）。
//!
//! 与一次性 --guard-apply 严格分离：动态会话必须在 helper 内持续持有，
//! 并在主程序或 sing-box 退出时立即撤销。**此阶段尚未接入生产连接按钮**。
//!
//! 请求与回执是有界 JSON；任何失败都只能写 Rejected，绝不伪造 Ready。
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

/// 从同一个已打开的对象验证文件类型、链接数、长度，再有界读取。
/// Windows 不跟随末级 reparse point，且读取期间不共享写入或删除。
/// 这不是目录 DACL 或 IPC 对端身份认证的替代品。
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

#[cfg(windows)]
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

#[cfg(any(test, not(windows)))]
fn read_request(path: &Path) -> Result<LeaseRequest, String> {
    let data = read_ipc_file(path, MAX_LEASE_IPC_BYTES)?
        .ok_or("租约请求不存在")?;
    serde_json::from_slice(&data).map_err(|e| format!("租约 JSON 无效：{e}"))
}

/// 验证后消费同一个打开的请求对象；不能通过再次解析路径来删除文件。
/// 删除失败必须拒绝许可，不能留下可直接重复消费的原请求。
#[cfg(windows)]
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

#[cfg(windows)]
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
fn read_ready(path: &Path, nonce: &str, expected_count: usize, expected_helper_pid: u32) -> Result<Option<()>, String> {
    read_stage(path, nonce, expected_count, expected_helper_pid, LeaseState::Ready)
}

fn read_stage(path: &Path, nonce: &str, expected_count: usize, expected_helper_pid: u32,
    expected_state: LeaseState) -> Result<Option<()>, String>
{
    let Some(body) = read_ipc_file(path, 4096)? else {
        return Ok(None);
    };
    let reply: LeaseReply = serde_json::from_slice(&body)
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
    Ok(Some(()))
}

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
#[cfg(windows)]
pub struct LeaseChild {
    handle: windows_sys::Win32::Foundation::HANDLE,
    pub directory: PathBuf,
    // 未得到可靠 Ready/ACK 确认的 helper，父进程退出此作用域时必须
    // 立即终止，不能让一个半启动的动态许可继续放行最多 15 秒。
    confirmed: bool,
}
#[cfg(windows)]
impl LeaseChild {
    pub fn running(&self) -> bool {
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
        unsafe { WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT }
    }
}
#[cfg(windows)]
impl Drop for LeaseChild {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if !self.confirmed {
                // 未完成双向握手：主动终止未信任 helper，让 BFE 动态会话
                // 立即 rundown；如果 OS 拒绝 TerminateProcess，helper 自己
                // 仍必须在 15 秒无 ACK 时撤销许可，形成双重保护。
                unsafe { windows_sys::Win32::System::Threading::TerminateProcess(self.handle, 1); }
            }
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle); }
            self.handle = std::ptr::null_mut();
        }
        // 已确认的 helper 正常运行期间不能因父端局部 handle Drop 而被杀，
        // 它自己通过真实进程句柄监控引擎和主程序生命期。
    }
}

/// 从非提权主程序启动长期 helper。**目前不在正式连接路径调用**。
/// 这条能力仅为后续隔离实机验收准备，避免在尚未验证 TUN 时改变交互。
#[cfg(windows)]
pub fn launch_elevated(request: &LeaseRequest) -> Result<LeaseChild, String> {
    use ring::rand::{SecureRandom, SystemRandom};
    use std::os::windows::ffi::OsStrExt;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW, SEE_MASK_NOCLOSEPROCESS};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    if request.controller_pid != std::process::id() {
        return Err("只有正在运行的发起进程可以申请本次动态租约".into());
    }
    let random = SystemRandom::new();
    let mut bytes = [0u8; 16];
    random.fill(&mut bytes).map_err(|_| "生成动态许可 nonce 失败".to_string())?;
    let nonce = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut req = request.clone();
    req.nonce = nonce.clone();
    validate_request(&req)?;
    let directory = std::env::temp_dir().join(format!("spidervpn-lease-{nonce}"));
    std::fs::create_dir(&directory)
        .map_err(|e| format!("创建独立租约目录失败：{e}"))?;
    let request_path = directory.join("request.json");
    let reply_path = directory.join("reply.json");
    let ack_path = directory.join("ack.json");
    validate_transport_paths(&request_path, &reply_path)?;
    validate_session_directory(&request_path, &nonce)?;
    let data = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    if data.len() > MAX_LEASE_IPC_BYTES {
        return Err("交易保护租约名单超过 IPC 大小限制".into());
    }
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
        .open(&request_path).map_err(|e| format!("创建独立租约请求失败：{e}"))?;
    use std::io::Write;
    file.write_all(&data).and_then(|_| file.sync_all())
        .map_err(|e| format!("写入租约请求失败：{e}"))?;
    drop(file);

    let to_wide = |s: &std::ffi::OsStr| -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    };
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_w = to_wide(exe.as_os_str());
    let args_w = to_wide(std::ffi::OsStr::new(&format!(
        "{LEASE_FLAG} \"{}\" \"{}\"", request_path.display(), reply_path.display(),
    )));
    let verb_w: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb_w.as_ptr();
    info.lpFile = exe_w.as_ptr();
    info.lpParameters = args_w.as_ptr();
    info.nShow = SW_HIDE;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!("无法启动提权 WFP helper（Win32={code}）"));
    }
    if info.hProcess.is_null() {
        return Err("启动 WFP helper 后未获取进程句柄".into());
    }
    let mut child = LeaseChild { handle: info.hProcess, directory, confirmed: false };
    let helper_pid = unsafe { windows_sys::Win32::System::Threading::GetProcessId(child.handle) };
    if helper_pid == 0 {
        return Err("不能从启动的 helper 句柄确认 PID".into());
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() >= deadline {
            let _ = write_ack(&ack_path, &nonce, false);
            return Err("长期 WFP helper 就绪超时，拒绝将其视为已保护".into());
        }
        if unsafe { WaitForSingleObject(child.handle, 0) } != WAIT_TIMEOUT {
            return Err("长期 WFP helper 在 Ready 前已退出，未启用临时许可".into());
        }
        match read_ready(&reply_path, &nonce, req.programs.len(), helper_pid) {
            Ok(Some(())) => {
                // Ready 只是第一阶段；必须写 nonce-bound ACK 并确认进程尚存活。
                if Instant::now() >= deadline {
                    return Err("租约 Ready 超出启动期限".into());
                }
                write_ack(&ack_path, &nonce, true)?;
                if !child.running() || Instant::now() >= deadline {
                    return Err("租约确认后 helper 已退出，拒绝报告连接已受保护".into());
                }
                // Do not treat publishing ACK as proof that the helper consumed it.
                let accepted_path = directory_receipt(&child.directory);
                loop {
                    if !child.running() || Instant::now() >= deadline {
                        return Err("等待 helper 实际消费 ACK 超时或进程退出".into());
                    }
                    if read_stage(&accepted_path, &nonce, req.programs.len(), helper_pid,
                        LeaseState::Accepted)?.is_some()
                    {
                        if !child.running() || Instant::now() >= deadline {
                            return Err("最终租约回执已失效".into());
                        }
                        child.confirmed = true;
                        return Ok(child);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            Err(e) => {
                let _ = write_ack(&ack_path, &nonce, false);
                return Err(e);
            }
            Ok(None) => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn directory_receipt(directory: &Path) -> PathBuf {
    directory.join("accepted.json")
}

fn reply(nonce: &str, state: LeaseState, reason: String, count: usize) -> LeaseReply {
    LeaseReply { schema: LEASE_SCHEMA, nonce: nonce.to_owned(), state, reason, filter_count: count, helper_pid: std::process::id() }
}

/// 提权 helper 的进程主入口。成功时长期阻塞在 Windows 进程对象等待中。
///
/// 失败时写 Rejected（如果回执路径允许写），返回非零；不会留下动态许可。
/// 启动者必须使用严格路径 ACL 与独立随机目录，不能与 v1 guard 请求目录复用。
pub fn serve(req_path: &Path, reply_path: &Path) -> i32 {
    // 拒绝利用提权 helper 对任意路径执行回执文件写入。
    if validate_transport_paths(req_path, reply_path).is_err() {
        return 2;
    }
    // 运行中辅助进程不允许普通权限降级继续：否则 Ready 是假证据。
    if !super::elevate::is_elevated() {
        let _ = write_reply(reply_path, &reply("", LeaseState::Rejected,
            "没有管理员权限，动态交易许可未开启".into(), 0));
        return 2;
    }
    #[cfg(windows)]
    let request = consume_request(req_path);
    #[cfg(not(windows))]
    let request = read_request(req_path);
    let req = match request {
        Ok(req) => req,
        Err(reason) => {
            let _ = write_reply(reply_path, &reply("", LeaseState::Rejected, reason, 0));
            return 2;
        }
    };
    let nonce = match validate_request(&req) {
        Ok(v) => v,
        Err(reason) => {
            let _ = write_reply(reply_path, &reply(&req.nonce, LeaseState::Rejected, reason, 0));
            return 2;
        }
    };
    // Windows 已通过原始文件句柄消费请求；仍需独立的目录与对端认证。
    if validate_session_directory(req_path, &req.nonce).is_err() {
        return 2;
    }

    #[cfg(windows)]
    {
        let lease = match super::wfp_win::DynamicProxyLease::acquire(
            &req.programs, req.endpoint, req.engine_pid, req.controller_pid,
            &req.engine_executable, &nonce,
        ) {
            Ok(lease) => lease,
            Err(reason) => {
                let _ = write_reply(reply_path, &reply(&req.nonce, LeaseState::Rejected, reason, 0));
                return 3;
            }
        };
        let count = lease.count();
        // 如果无法写 Ready，lease 在 return 时被 Drop，动态 WFP 权限自动撤销。
        if write_reply(reply_path, &reply(&req.nonce, LeaseState::Ready,
            String::new(), count)).is_err()
        {
            return 4;
        }
        // 双向握手：如果 parent 退出、读取回执失败或拒绝确认，15 秒内
        // 自动撤销；等待期间每 100ms 重新核验引擎、主进程与监听身份。
        // 不允许“只有 Ready 文件就长期放行”的失败状态。
        let ack_path = reply_path.with_file_name("ack.json");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut lease = lease;
        loop {
            if std::time::Instant::now() >= deadline {
                return 6;
            }
            let accepted = match consume_ack(&ack_path, &req.nonce) {
                Ok(value) => value,
                Err(_) => return 6, // lease 被 Drop，动态会话随之关闭
            };
            lease = match lease.revalidate(&req.engine_executable) {
                Ok(value) => value,
                Err(_) => return 6,
            };
            // ACK 已存在也必须经过存活检查，且不能在截止之后接管租约。
            if std::time::Instant::now() >= deadline {
                return 6;
            }
            if accepted {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // Only publish the second-stage receipt after accepting ACK and revalidating.
        let accepted_path = directory_receipt(reply_path.parent().expect("validated parent"));
        if write_reply(&accepted_path, &reply(&req.nonce, LeaseState::Accepted,
            String::new(), count)).is_err()
        {
            return 6;
        }
        // helper 自己退出/崩溃时，BFE 动态 session 自动撤销临时 PERMIT。
        return if lease.supervise_until_exit(&req.engine_executable).is_ok() { 0 } else { 5 };
    }

    #[cfg(not(windows))]
    {
        let _ = nonce;
        let _ = write_reply(reply_path, &reply(&req.nonce, LeaseState::Rejected,
            "WFP 租约只支持 Windows".into(), 0));
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
