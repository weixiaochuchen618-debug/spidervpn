//! WFP P0：交易出口策略的纯 Rust 规格（不触碰 BFE，不安装过滤器）。
//!
//! 阻断名单中的交易程序不能笼统地“允许 localhost”，更不能把“存在一条
//! ALE_APP_ID BLOCK 规则”直接当作“既防泄漏又能正常走 VPN”的证据。
//!
//! 这个模块定义后续 WFP v2 应满足的出口判定，并且刻意独立于 FFI：
//! 1. 代理只允许精确的环回 IP + 端口 + TCP（任意其它环回代理不受信任）；
//! 2. TUN 只允许经精确匹配的下一跳接口 LUID；接口不确定时拒绝；
//! 3. 无可信出口时拒绝一切新连接。
//!
//! 注意：纯函数通过只能证明期望行为，不能证明 Windows ALE 分类里真的具备
//! 相应条件，也不能证明 BFE 的层间仲裁。必须经过隔离 Windows 真机流量
//! 测试后，才能将 v2 转为持久过滤器；不要用本模块的单测宣称 WFP 已修复。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 只有以下几种出站方式可以列为 v2 候选。缺省 FailClosed。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPolicy {
    /// 没有可信通道，或正在进行切换/断线恢复。
    DenyAll,
    /// 只有这个 *IP 地址和端口* 才是可信的本机代理。排除 DNS 主机名与宽泛 127/8。
    LocalProxy { endpoint: SocketAddr },
    /// 只接受通过明确核验的 TUN 下一跳接口。
    TunInterface { luid: u64 },
}

/// 此处的协议是 ALE 分层的 IP_PROTOCOL，而不是 TCP 入站里用户自选的传输模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Other(u8),
}

/// 纯 WFP 策略的出站判定输入：可由隔离测试和未来真实分类器填充。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub remote: SocketAddr,
    pub protocol: NetworkProtocol,
    /// WFP 下一跳接口 LUID；不可观测时必须为 None，不允许凭路由表猜。
    pub next_hop_luid: Option<u64>,
}

impl EgressPolicy {
    /// 只接受字面 IP；绝不做 DNS 查询或自动把 localhost 扩展为多个地址。
    ///
    /// Windows 在 IPv4/IPv6 的 ALE 层分开分类，因此配置 127.0.0.1
    /// 并不自动授权 ::1。以后若两个端口确有需要，必须显式配置两个精确端点。
    pub fn local_proxy(endpoint: &str) -> Result<Self, String> {
        let addr: SocketAddr = endpoint.parse()
            .map_err(|_| "交易代理出口必须是明确的环回 IP:端口（不允许主机名）".to_string())?;
        let trusted = match addr.ip() {
            IpAddr::V4(v) => v == Ipv4Addr::LOCALHOST,
            IpAddr::V6(v) => v == Ipv6Addr::LOCALHOST,
        };
        if !trusted || addr.port() == 0 {
            return Err("交易代理出口只能是 127.0.0.1 或 [::1]，且端口必须大于 0".into());
        }
        Ok(EgressPolicy::LocalProxy { endpoint: addr })
    }

    /// 未拿到有效 LUID 时采用 DenyAll；拒绝默认值 0（非有效接口身份）。
    pub fn tun_interface(luid: Option<u64>) -> Self {
        match luid {
            Some(n) if n != 0 => EgressPolicy::TunInterface { luid: n },
            _ => EgressPolicy::DenyAll,
        }
    }

    /// v2 出站行为的真值表。这里只描述期望，不直接做 FWP API 的允许/阻断承诺。
    pub fn permits(self, flow: &Flow) -> bool {
        match self {
            EgressPolicy::DenyAll => false,
            EgressPolicy::LocalProxy { endpoint } => {
                flow.protocol == NetworkProtocol::Tcp && flow.remote == endpoint
            }
            EgressPolicy::TunInterface { luid } => flow.next_hop_luid == Some(luid),
        }
    }

    /// 仅在可信端点已核验且能重新观测时才可视为“有出口”，并非 WFP 已安装。
    pub fn configured(self) -> bool {
        !matches!(self, EgressPolicy::DenyAll)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(remote: &str, luid: Option<u64>) -> Flow {
        Flow { remote: remote.parse().unwrap(), protocol: NetworkProtocol::Tcp, next_hop_luid: luid }
    }

    #[test]
    fn local_proxy_accepts_only_one_exact_loopback_endpoint() {
        let p = EgressPolicy::local_proxy("127.0.0.1:17890").unwrap();
        assert!(p.permits(&tcp("127.0.0.1:17890", None)));
        assert!(!p.permits(&tcp("127.0.0.1:17891", None)), "代理端口不同，不可信");
        assert!(!p.permits(&tcp("127.0.0.2:17890", None)), "环回网段 != 本机可信代理");
        assert!(!p.permits(&tcp("10.0.0.1:17890", None)));
        assert!(!p.permits(&tcp("203.0.113.42:17890", None)));
        assert!(!p.permits(&tcp("[::1]:17890", None)), "IPv4 代理不能隐式授权 IPv6");
    }

    #[test]
    fn local_proxy_requires_tcp_not_generic_local_udp() {
        let p = EgressPolicy::local_proxy("127.0.0.1:17890").unwrap();
        let mut flow = tcp("127.0.0.1:17890", None);
        flow.protocol = NetworkProtocol::Udp;
        assert!(!p.permits(&flow));
        flow.protocol = NetworkProtocol::Other(1);
        assert!(!p.permits(&flow));
    }

    #[test]
    fn local_proxy_refuses_untrusted_or_ambiguous_configuration() {
        for v in [
            "", "localhost:17890", "127.0.0.2:17890", "0.0.0.0:17890",
            "192.168.1.1:17890", "127.0.0.1:0", "127.0.0.1",
            "[fe80::1]:17890", "[::ffff:127.0.0.1]:17890",
        ] {
            assert!(EgressPolicy::local_proxy(v).is_err(), "{v} 不能成为可信出口");
        }
    }

    #[test]
    fn ipv6_local_proxy_is_a_distinct_trusted_endpoint() {
        let p = EgressPolicy::local_proxy("[::1]:17890").unwrap();
        assert!(p.permits(&tcp("[::1]:17890", None)));
        assert!(!p.permits(&tcp("127.0.0.1:17890", None)));
        assert!(!p.permits(&tcp("[::1]:17891", None)));
    }

    #[test]
    fn tun_requires_exactly_the_confirmed_next_hop() {
        let p = EgressPolicy::tun_interface(Some(1729));
        assert!(p.permits(&tcp("203.0.113.42:443", Some(1729))));
        assert!(!p.permits(&tcp("203.0.113.42:443", Some(1730))));
        assert!(!p.permits(&tcp("203.0.113.42:443", None)));
        assert!(!p.permits(&tcp("127.0.0.1:17890", None)));
    }

    #[test]
    fn no_tun_identity_means_no_direct_access_even_during_reconnect() {
        for luid in [None, Some(0)] {
            let p = EgressPolicy::tun_interface(luid);
            assert_eq!(p, EgressPolicy::DenyAll);
            assert!(!p.configured());
            assert!(!p.permits(&tcp("203.0.113.42:443", None)));
        }
    }
}
