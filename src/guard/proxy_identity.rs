//! Read-only Windows ownership check for a precisely scoped local TCP proxy.
//!
//! An IP+port is not a trusted endpoint by itself: any other process might own
//! that listener. Production WFP v2 must validate the sing-box process identity
//! and revalidate immediately before an atomic filter migration.
//!
//! This module does NOT change firewall rules, system proxy, or engine state.
//! A successful snapshot is evidence of current ownership only, not a durable
//! assertion about future port rebinds or PID reuse.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerOwner {
    pub endpoint: SocketAddr,
    pub pid: u32,
}

pub fn verify_proxy_owner(
    endpoint: SocketAddr,
    expected_pid: u32,
    expected_executable: &Path,
) -> Result<ListenerOwner, String> {
    if expected_pid == 0 {
        return Err("可信代理引擎 PID 为 0，拒绝授权".into());
    }
    match endpoint.ip() {
        IpAddr::V4(ip) if ip.is_loopback() && ip.octets() == [127, 0, 0, 1] => {}
        IpAddr::V6(ip) if ip == std::net::Ipv6Addr::LOCALHOST => {}
        _ => return Err("仅允许精确 127.0.0.1 或 ::1 代理端点".into()),
    }
    if endpoint.port() == 0 {
        return Err("无效的本地代理端口".into());
    }
    let owners = platform::listening_owners(endpoint)?;
    if owners.len() != 1 || owners[0] != expected_pid {
        return Err(format!(
            "代理端点 {endpoint} 的监听进程与预期引擎 PID={expected_pid} 不符（实际={owners:?}），拒绝授权"
        ));
    }
    platform::verify_executable(expected_pid, expected_executable)?;
    Ok(ListenerOwner { endpoint, pid: expected_pid })
}

/// 独立的进程身份核验：长期 WFP helper 必须确认 controller PID
/// 指向正在运行的 SpiderVPN 主程序，而不是仅监控任意存活 PID。
pub fn verify_process_executable(pid: u32, expected_executable: &Path) -> Result<(), String> {
    if pid == 0 {
        return Err("程序 PID 为 0，拒绝进程身份确认".into());
    }
    platform::verify_executable(pid, expected_executable)
}

#[cfg(windows)]
mod platform {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper as Ip;
    use windows_sys::Win32::System::Threading as Thread;

    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const MAX_TCP_TABLE_BYTES: usize = 8 * 1024 * 1024;
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_STATE_LISTEN: u32 = 2;

    fn table(endpoint: SocketAddr) -> Result<Vec<u64>, String> {
        let family = if endpoint.is_ipv4() { AF_INET } else { AF_INET6 };
        let mut needed: u32 = 0;
        let rc = unsafe {
            Ip::GetExtendedTcpTable(
                std::ptr::null_mut(), &mut needed, 0, family,
                Ip::TCP_TABLE_OWNER_PID_LISTENER, 0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return Err(format!("TCP 监听表长度查询失败（Win32={rc}, bytes={needed}）"));
        }
        for _ in 0..3 {
            let capacity = needed as usize;
            if capacity > MAX_TCP_TABLE_BYTES || capacity < 4 {
                return Err("TCP 监听表大小异常，拒绝信任代理".into());
            }
            // Vec<u64> provides 8-byte alignment for all MIB TCP rows.
            let mut storage = vec![0u64; capacity.div_ceil(8)];
            let mut actual = storage.len() * 8;
            let mut bytes = actual as u32;
            let rc = unsafe {
                Ip::GetExtendedTcpTable(
                    storage.as_mut_ptr().cast(), &mut bytes, 0, family,
                    Ip::TCP_TABLE_OWNER_PID_LISTENER, 0,
                )
            };
            if rc == 0 {
                if bytes as usize > actual { return Err("TCP 表发生长度越界".into()); }
                return Ok(storage);
            }
            if rc != ERROR_INSUFFICIENT_BUFFER {
                return Err(format!("Windows TCP 监听表读取失败（Win32={rc}）"));
            }
            needed = bytes;
        }
        Err("TCP 监听表持续变化，无法确认引擎进程归属".into())
    }

    fn network_port(port: u32) -> u16 {
        // Win32 stores the network-order 16-bit port in the low 16 bits of a DWORD.
        u16::from_be_bytes((port as u16).to_ne_bytes())
    }

    fn is_exact_ipv4(raw: u32, ip: std::net::Ipv4Addr) -> bool {
        raw.to_ne_bytes() == ip.octets()
    }

    pub fn listening_owners(endpoint: SocketAddr) -> Result<Vec<u32>, String> {
        let storage = table(endpoint)?;
        let base = storage.as_ptr().cast::<u8>();
        let count = unsafe { *(base.cast::<u32>()) } as usize;
        let capacity = storage.len() * 8;
        let mut pids = Vec::new();

        match endpoint.ip() {
            IpAddr::V4(target) => {
                let offset = std::mem::offset_of!(Ip::MIB_TCPTABLE_OWNER_PID, table);
                let row_size = std::mem::size_of::<Ip::MIB_TCPROW_OWNER_PID>();
                if offset > capacity || count > (capacity - offset) / row_size {
                    return Err("IPv4 TCP 监听表条目数越界".into());
                }
                for i in 0..count {
                    let row = unsafe {
                        &*(base.add(offset + i * row_size).cast::<Ip::MIB_TCPROW_OWNER_PID>())
                    };
                    if row.dwState == TCP_STATE_LISTEN
                        && is_exact_ipv4(row.dwLocalAddr, target)
                        && network_port(row.dwLocalPort) == endpoint.port()
                    {
                        pids.push(row.dwOwningPid);
                    }
                }
            }
            IpAddr::V6(target) => {
                let offset = std::mem::offset_of!(Ip::MIB_TCP6TABLE_OWNER_PID, table);
                let row_size = std::mem::size_of::<Ip::MIB_TCP6ROW_OWNER_PID>();
                if offset > capacity || count > (capacity - offset) / row_size {
                    return Err("IPv6 TCP 监听表条目数越界".into());
                }
                for i in 0..count {
                    let row = unsafe {
                        &*(base.add(offset + i * row_size).cast::<Ip::MIB_TCP6ROW_OWNER_PID>())
                    };
                    if row.dwState == TCP_STATE_LISTEN
                        && row.ucLocalAddr == target.octets()
                        && network_port(row.dwLocalPort) == endpoint.port()
                    {
                        pids.push(row.dwOwningPid);
                    }
                }
            }
        }
        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }

    struct ProcessHandle(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
            }
        }
    }

    pub fn verify_executable(pid: u32, expected: &Path) -> Result<(), String> {
        let expected = expected.canonicalize()
            .map_err(|e| format!("可信引擎 exe 路径不可核验：{e}"))?;
        let process = ProcessHandle(unsafe {
            Thread::OpenProcess(Thread::PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
        });
        if process.0.is_null() {
            return Err("无法读取代理监听进程路径，拒绝将端口视为可信".into());
        }
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let ok = unsafe {
            Thread::QueryFullProcessImageNameW(process.0, 0, buf.as_mut_ptr(), &mut len)
        };
        if ok == 0 || len == 0 {
            return Err("读取引擎进程 exe 路径失败".into());
        }
        let actual = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]))
            .canonicalize()
            .map_err(|e| format!("监听进程 exe 路径不可核验：{e}"))?;
        if !actual.to_string_lossy().eq_ignore_ascii_case(&expected.to_string_lossy()) {
            return Err(format!(
                "代理监听进程 exe 路径不匹配（预期={}），拒绝授权", expected.display()
            ));
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn listening_owners(_endpoint: SocketAddr) -> Result<Vec<u32>, String> {
        Err("只有 Windows 支持监听进程归属核验".into())
    }
    pub fn verify_executable(_pid: u32, _expected: &Path) -> Result<(), String> {
        Err("只有 Windows 支持监听进程路径核验".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn controller_process_must_match_current_exe() {
        let exe = std::env::current_exe().unwrap();
        assert!(verify_process_executable(std::process::id(), &exe).is_ok());
        assert!(verify_process_executable(0, &exe).is_err());
        assert!(verify_process_executable(
            std::process::id(),
            &std::env::temp_dir().join("not-spidervpn.exe"),
        ).is_err());
    }

    #[test]
    fn invalid_endpoints_fail_before_looking_at_windows_tcp_table() {
        let executable = std::env::current_exe().unwrap();
        for endpoint in ["0.0.0.0:7890", "127.0.0.2:7890",
                         "[::ffff:127.0.0.1]:7890", "127.0.0.1:0",
                         "[fe80::1]:7890"] {
            let address: SocketAddr = endpoint.parse().unwrap();
            assert!(verify_proxy_owner(address, std::process::id(), &executable).is_err(),
                    "{endpoint} 不允许被当作可信端点");
        }
        assert!(verify_proxy_owner("127.0.0.1:7890".parse().unwrap(), 0, &executable).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_real_loopback_listener_is_owned_by_the_expected_executable() {
        use std::net::TcpListener;
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(bind).unwrap();
            let endpoint = listener.local_addr().unwrap();
            let expected = std::env::current_exe().unwrap();
            let owner = verify_proxy_owner(endpoint, std::process::id(), &expected).unwrap();
            assert_eq!(owner.pid, std::process::id());
            assert_eq!(owner.endpoint, endpoint);
            assert!(verify_proxy_owner(endpoint, std::process::id() + 1, &expected).is_err(),
                    "错误 PID 不能复用相同端点的可信判定");
            let other = std::env::temp_dir().join("spidervpn-fake-other.exe");
            assert!(verify_proxy_owner(endpoint, std::process::id(), &other).is_err(),
                    "不可拿与实际进程不相同的 exe 路径授权");
            drop(listener);
            assert!(verify_proxy_owner(endpoint, std::process::id(), &expected).is_err(),
                    "监听器关闭后不能沿用旧 PID 证明");
        }
    }
}
