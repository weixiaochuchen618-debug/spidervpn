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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LeaseState {
    Ready,
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

/// Ready 只是启动协商，不能孤立地当作父进程已接管成功。
/// 辅助进程只接受同一个随机目录的 ack.json，绝不接受另一会话旧 nonce。
fn read_ack(path: &Path, nonce: &str) -> Result<bool, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("检查租约确认文件失败：{e}")),
    };
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 4096 {
        return Err("租约确认文件不是有效普通小文件".into());
    }
    let body = std::fs::read(path).map_err(|e| format!("读取租约确认文件失败：{e}"))?;
    let ack: LeaseAck = serde_json::from_slice(&body)
        .map_err(|e| format!("租约确认文件不是合法协议：{e}"))?;
    if ack.schema != LEASE_SCHEMA || ack.nonce != nonce || !ack.accepted {
        return Err("启动方确认的会话版本、nonce 或决定不匹配".into());
    }
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
    std::fs::canonicalize(dir)
        .map_err(|e| format!("租约 IPC 目录不可访问：{e}"))?;
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

fn read_request(path: &Path) -> Result<LeaseRequest, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("读取租约请求元数据失败：{e}"))?;
    if !meta.file_type().is_file() || meta.len() == 0
        || meta.len() as usize > MAX_LEASE_IPC_BYTES
    {
        return Err("租约请求不是普通文件，或者大小无效".into());
    }
    let data = std::fs::read(path).map_err(|e| format!("读取租约请求失败：{e}"))?;
    if data.len() > MAX_LEASE_IPC_BYTES {
        return Err("租约请求超出大小限制".into());
    }
    serde_json::from_slice(&data).map_err(|e| format!("租约 JSON 无效：{e}"))
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
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("提交租约回执失败：{e}"));
    }
    Ok(())
}

fn reply(nonce: &str, state: LeaseState, reason: String, count: usize) -> LeaseReply {
    LeaseReply { schema: LEASE_SCHEMA, nonce: nonce.to_owned(), state, reason, filter_count: count }
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
    let req = match read_request(req_path) {
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
    // 解析后立即尽力删除请求，缩短可修改请求文件的存在时间。
    let _ = std::fs::remove_file(req_path);

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
            match read_ack(&ack_path, &req.nonce) {
                Ok(true) => break,
                Err(_) => return 6, // lease 被 Drop，动态会话随之关闭
                Ok(false) => {}
            }
            if std::time::Instant::now() >= deadline {
                return 6;
            }
            lease = match lease.revalidate(&req.engine_executable) {
                Ok(value) => value,
                Err(_) => return 6,
            };
            std::thread::sleep(std::time::Duration::from_millis(100));
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
        assert_eq!(read_request(&rq).unwrap().engine_pid, 51);
        assert!(write_reply(&rs, &reply(&actual.nonce, LeaseState::Ready, String::new(), 1)).is_err(),
            "old receipt cannot be silently overwritten");
        assert_eq!(std::fs::read_to_string(&rs).unwrap().contains("Rejected"), true);
        let _ = std::fs::remove_dir_all(root);
    }
}
