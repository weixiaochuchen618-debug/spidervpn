//! Windows TUN 下一跳接口身份的只读候选发现。
//!
//! 仅发现“当前系统里名为 SpiderVPN 的活动接口”的 LUID；它本身**不证明**
//! 这张网卡属于运行中的 sing-box，不证明流量按该 LUID 离开，也不会写 WFP。
//! 未来持久 WFP v2 在安装前必须再通过进程、路由、ALE 真正分类以及断线验证。
//! 在全部验证通过前不得仅凭本函数结果授权交易流量。

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunCandidate {
    pub alias: String,
    pub luid: u64,
    pub if_index: u32,
}

pub fn identify_tun_candidate(alias: &str) -> Result<TunCandidate, String> {
    if alias.trim().is_empty() || alias.trim() != alias || alias.contains('\0') {
        return Err("TUN 接口名称为空、含空格边界或 NUL，拒绝推断身份".to_string());
    }
    identify_windows(alias)
}

#[cfg(windows)]
fn identify_windows(alias: &str) -> Result<TunCandidate, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper as Ip;
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = 0u64;
    // NET_LUID_LH 的 ABI 是 8 字节 union。用 raw u64 作接收缓冲，
    // 不依赖它不同 Windows 绑定版本的 union 成员命名。
    let rc = unsafe { Ip::ConvertInterfaceAliasToLuid(wide.as_ptr(), (&mut luid as *mut u64).cast()) };
    if rc != 0 || luid == 0 {
        return Err(format!("找不到目标 TUN 接口「{alias}」或没有有效 LUID（Win32={rc}）"));
    }

    let mut row: Ip::MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    if std::mem::size_of_val(&row.InterfaceLuid) != std::mem::size_of::<u64>() {
        return Err("Windows NET_LUID 结构布局不符合 64 位预期".to_string());
    }
    unsafe {
        std::ptr::write_unaligned((&mut row.InterfaceLuid as *mut _).cast::<u64>(), luid);
    }
    let rc = unsafe { Ip::GetIfEntry2(&mut row) };
    if rc != 0 {
        return Err(format!("无法回读 TUN 接口状态（Win32={rc}），不授权交易出口"));
    }
    let readback = unsafe { std::ptr::read_unaligned((&row.InterfaceLuid as *const _).cast::<u64>()) };
    let n = row.Alias.iter().position(|&ch| ch == 0).unwrap_or(row.Alias.len());
    let actual_alias = String::from_utf16_lossy(&row.Alias[..n]);
    if readback != luid || !actual_alias.eq_ignore_ascii_case(alias) {
        return Err("TUN 接口身份回读不匹配（LUID 或名称已变化）".to_string());
    }
    // IF_OPER_STATUS::IfOperStatusUp=1，24=IF_TYPE_SOFTWARE_LOOPBACK。
    // 单纯拿到虚拟/环回网卡的 LUID 不等于建立可信 TUN 出口。
    if row.OperStatus != 1 || row.InterfaceIndex == 0 || row.Type == 24 {
        return Err(format!(
            "TUN 接口非活动网卡（状态={}，index={}，type={}），拒绝授权",
            row.OperStatus, row.InterfaceIndex, row.Type
        ));
    }
    Ok(TunCandidate { alias: actual_alias, luid, if_index: row.InterfaceIndex })
}

#[cfg(not(windows))]
fn identify_windows(_alias: &str) -> Result<TunCandidate, String> {
    Err("仅 Windows 系统支持 TUN LUID 查找".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_names_are_rejected_before_any_win32_lookup() {
        for bad in ["", " ", " SpiderVPN", "SpiderVPN ", "SpiderVPN\0other"] {
            assert!(identify_tun_candidate(bad).is_err());
        }
    }

    #[test]
    fn absent_adapter_does_not_become_a_trusted_default() {
        // 真实客户端的 TUN 名称是 SpiderVPN。这里特意查询一个不存在的别名，
        // 不依赖 runner 是否安装 Wintun；失败不得兜底为任意默认网卡。
        assert!(identify_tun_candidate("SpiderVPN-Does-Not-Exist-EgressTest").is_err());
    }
}
